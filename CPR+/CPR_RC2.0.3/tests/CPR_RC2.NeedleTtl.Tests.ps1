# Needle TTL (RC2.0.3): any needle line in needles_local.cfg may end with
#   |expires=<UTC ISO-8601 (2026-11-13T03:40:00Z) or YYYY-MM-DD (= 00:00Z that day)>
# Lines without the token behave exactly as before (they never expire).
#
#   * Read-NeedleFile skips expired lines, skips lines whose token is unparseable, and
#     (local file only) skips lines expiring further out than the TTL cap (default 30d).
#   * Invoke-LocalNeedlePrune physically removes expired lines (reroll time only).
#   * Get-LocalNeedleNextExpiry feeds NextLocalExpiry in the reroll stamp, so
#     Test-RerollNeeded can decide "anything to prune?" from one value it already reads.
#   * haystack_action.ps1 carries its own parser and must understand the token too.

BeforeAll {
    $script:ReleaseRoot        = Split-Path -Parent $PSScriptRoot
    $script:HaystackPath       = Join-Path $script:ReleaseRoot 'haystack.ps1'
    $script:HaystackActionPath = Join-Path $script:ReleaseRoot 'haystack_action.ps1'

    $hsContent = Get-Content -LiteralPath $script:HaystackPath -Raw
    $hsPre     = ($hsContent -split '(?ms)^# =+\r?\n# Entry Point')[0]
    Invoke-Expression $hsPre.Substring($hsPre.IndexOf('function Write-HSLog'))

    foreach ($stub in 'Get-ScheduledTask') {
        if (-not (Get-Command $stub -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:$stub" -Value { param([string]$TaskName, [string]$TaskPath) return $null }
        }
    }

    function New-Utc { param([int]$y,[int]$mo,[int]$d,[int]$h=0,[int]$mi=0,[int]$s=0) New-Object DateTime $y,$mo,$d,$h,$mi,$s,([DateTimeKind]::Utc) }
    $script:Now = New-Utc 2026 10 30 12 0 0

    function Get-FnSource {
        param([string]$Path, [string]$Name)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true) | Select-Object -First 1
        if (-not $fn) { return $null }
        return $fn.Extent.Text
    }
}

Describe 'Split-NeedleExpiry' {
    It 'returns the line untouched when there is no token' {
        $r = Split-NeedleExpiry -Line 'NEEDLE|Application|100||Foo|0'
        $r.HasExpiry | Should -BeFalse
        $r.Line | Should -Be 'NEEDLE|Application|100||Foo|0'
        $r.Expires | Should -BeNullOrEmpty
    }
    It 'parses a UTC ISO-8601 token and strips it' {
        $r = Split-NeedleExpiry -Line 'NEEDLE|Application|100||Foo|0|expires=2026-11-13T03:40:00Z'
        $r.HasExpiry | Should -BeTrue
        $r.Line | Should -Be 'NEEDLE|Application|100||Foo|0'
        $r.Expires.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') | Should -Be '2026-11-13T03:40:00Z'
        $r.Expires.Kind | Should -Be 'Utc'
    }
    It 'treats a bare date as 00:00Z that day' {
        $r = Split-NeedleExpiry -Line 'SESSION|SessionUnlock|Foo|expires=2026-11-13'
        $r.Line | Should -Be 'SESSION|SessionUnlock|Foo'
        $r.Expires.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') | Should -Be '2026-11-13T00:00:00Z'
    }
    It 'is case-insensitive and tolerates spaces around the token' {
        $r = Split-NeedleExpiry -Line 'HEADER|*|Foo | Expires = 2026-11-13T00:00:00Z '
        $r.HasExpiry | Should -BeTrue
        $r.Line | Should -Be 'HEADER|*|Foo '
        $r.Expires | Should -Not -BeNullOrEmpty
    }
    It 'flags an unparseable token (HasExpiry true, Expires null)' {
        $r = Split-NeedleExpiry -Line 'NEEDLE|Application|100||Foo|0|expires=next-tuesday'
        $r.HasExpiry | Should -BeTrue
        $r.Expires | Should -BeNullOrEmpty
        $r.Line | Should -Be 'NEEDLE|Application|100||Foo|0'
    }
}

Describe 'Read-NeedleFile expiry handling' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog { param($Message, $Level) $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
        $script:F = Join-Path $TestDrive 'needles_local.cfg'
    }

    It 'loads a not-yet-expired needle with its fields intact (token does not leak into ExtendedLogging)' {
        'NEEDLE|Application|100||Live|all|expires=2026-11-13T03:40:00Z' | Set-Content $script:F
        $r = @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now)
        $r.Count | Should -Be 1
        $r[0].Label | Should -Be 'Live'
        $r[0].ExtendedLogging | Should -Be 'all'
    }
    It 'skips an expired needle and logs it' {
        'NEEDLE|Application|100||Old|0|expires=2026-10-30T11:59:59Z' | Set-Content $script:F
        @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now).Count | Should -Be 0
        @($script:LogBuffer | Where-Object { $_.Message -match 'needle_expired' }).Count | Should -BeGreaterThan 0
    }
    It 'treats the exact expiry instant as expired' {
        'NEEDLE|Application|100||Edge|0|expires=2026-10-30T12:00:00Z' | Set-Content $script:F
        @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now).Count | Should -Be 0
    }
    It 'skips a line whose expires token cannot be parsed, with a warning' {
        'NEEDLE|Application|100||Bad|0|expires=whenever' | Set-Content $script:F
        @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now).Count | Should -Be 0
        @($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match 'expires' }).Count | Should -BeGreaterThan 0
    }
    It 'enforces the TTL cap on the local file only' {
        'NEEDLE|Application|100||Far|0|expires=2027-12-31T00:00:00Z' | Set-Content $script:F
        @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now).Count | Should -Be 0
        @($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match 'cap' }).Count | Should -BeGreaterThan 0
        @(Read-NeedleFile -Path $script:F -SourceTag 'share' -NowUtc $script:Now).Count | Should -Be 1
    }
    It 'accepts an expiry exactly at the cap' {
        $edge = $script:Now.AddDays(30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        "NEEDLE|Application|100||Edge|0|expires=$edge" | Set-Content $script:F
        @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now).Count | Should -Be 1
    }
    It 'handles the token on every needle type' {
        @(
            'SESSION|SessionUnlock|S1|expires=2026-11-13',
            'DEFENDER|SomeRule|6|D1|0|expires=2026-11-13',
            'HEADER|*|H1|expires=2026-11-13',
            'SESSION|SessionLock|S2|expires=2026-10-01'
        ) | Set-Content $script:F
        $r = @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now)
        @($r.Label) | Should -Be @('S1', 'D1', 'H1')
    }
    It 'leaves lines without the token completely unchanged (never expire)' {
        @('# comment', 'NEEDLE|Application|100||Plain|0', 'SESSION|SessionUnlock|S1') | Set-Content $script:F
        @(Read-NeedleFile -Path $script:F -SourceTag 'local' -NowUtc $script:Now).Count | Should -Be 2
    }
}

Describe 'Invoke-LocalNeedlePrune' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog { param($Message, $Level) $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
        $script:F = Join-Path $TestDrive 'needles_prune.cfg'
    }

    It 'removes only expired lines, keeps comments, blanks, plain and future lines, and reports labels' {
        $text = "# header comment`nNEEDLE|Application|1||Old|0|expires=2026-10-01T00:00:00Z`n`nNEEDLE|Application|2||Plain|0`nSESSION|SessionUnlock|SOld|expires=2026-10-02`nNEEDLE|Application|3||Future|0|expires=2026-11-10T00:00:00Z`n"
        [IO.File]::WriteAllText($script:F, $text)
        $r = Invoke-LocalNeedlePrune -Path $script:F -NowUtc $script:Now
        @($r.Removed.Label) | Should -Be @('Old', 'SOld')
        $left = [IO.File]::ReadAllText($script:F)
        $left | Should -Be "# header comment`n`nNEEDLE|Application|2||Plain|0`nNEEDLE|Application|3||Future|0|expires=2026-11-10T00:00:00Z`n"
        @($script:LogBuffer | Where-Object { $_.Message -match 'needle_expired' -and $_.Message -match 'Old' }).Count | Should -BeGreaterThan 0
    }
    It 'preserves CRLF line endings' {
        [IO.File]::WriteAllText($script:F, "NEEDLE|Application|1||Old|0|expires=2026-10-01T00:00:00Z`r`nNEEDLE|Application|2||Keep|0`r`n")
        $null = Invoke-LocalNeedlePrune -Path $script:F -NowUtc $script:Now
        [IO.File]::ReadAllText($script:F) | Should -Be "NEEDLE|Application|2||Keep|0`r`n"
    }
    It 'does not touch the file when nothing is expired' {
        [IO.File]::WriteAllText($script:F, "NEEDLE|Application|2||Keep|0|expires=2026-11-10T00:00:00Z`n")
        $before = (Get-Item $script:F).LastWriteTimeUtc
        Start-Sleep -Milliseconds 50
        $r = Invoke-LocalNeedlePrune -Path $script:F -NowUtc $script:Now
        @($r.Removed).Count | Should -Be 0
        (Get-Item $script:F).LastWriteTimeUtc | Should -Be $before
    }
    It 'keeps lines with an unparseable token (the parser warns about them)' {
        [IO.File]::WriteAllText($script:F, "NEEDLE|Application|2||Bad|0|expires=whenever`n")
        $null = Invoke-LocalNeedlePrune -Path $script:F -NowUtc $script:Now
        [IO.File]::ReadAllText($script:F) | Should -Be "NEEDLE|Application|2||Bad|0|expires=whenever`n"
    }
    It 'is a no-op for a missing file' {
        $r = Invoke-LocalNeedlePrune -Path (Join-Path $TestDrive 'nope.cfg') -NowUtc $script:Now
        @($r.Removed).Count | Should -Be 0
    }
}

Describe 'Get-LocalNeedleNextExpiry' {
    BeforeEach {
        Mock Write-HSLog { }
        $script:F = Join-Path $TestDrive 'needles_next.cfg'
    }
    It 'returns the earliest future expiry' {
        @('NEEDLE|Application|1||A|0|expires=2026-11-20T00:00:00Z', 'NEEDLE|Application|2||B|0|expires=2026-11-05T00:00:00Z', 'NEEDLE|Application|3||C|0') | Set-Content $script:F
        (Get-LocalNeedleNextExpiry -Path $script:F -NowUtc $script:Now).ToString('yyyy-MM-ddTHH:mm:ssZ') | Should -Be '2026-11-05T00:00:00Z'
    }
    It 'returns $null when no line expires or the file is missing' {
        'NEEDLE|Application|1||A|0' | Set-Content $script:F
        Get-LocalNeedleNextExpiry -Path $script:F -NowUtc $script:Now | Should -BeNullOrEmpty
        Get-LocalNeedleNextExpiry -Path (Join-Path $TestDrive 'nope.cfg') -NowUtc $script:Now | Should -BeNullOrEmpty
    }
}

Describe 'Reroll stamp carries NextLocalExpiry' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog { param($Message, $Level) $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
        $script:LocalNeedlesFile       = Join-Path $TestDrive 'needles.cfg'
        $script:LocalNeedlesFile_Local = Join-Path $TestDrive 'needles_local.cfg'
        $script:RerollStampFile        = Join-Path $TestDrive 'haystack_reroll.stamp'
        Remove-Item $script:RerollStampFile, $script:LocalNeedlesFile_Local -ErrorAction SilentlyContinue
        $script:TsTaskName = 'HayStack_Monitor'; $script:TsTaskPath = '\HayStack\'
        'version:1' | Set-Content $script:LocalNeedlesFile
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'HayStack_Monitor' } }
    }

    It 'Write-RerollStamp stores the earliest local expiry and Get-RerollStampData reads it back' {
        $when = (Get-Date).ToUniversalTime().AddDays(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
        @('version:1', "NEEDLE|Application|1||A|0|expires=$when") | Set-Content $script:LocalNeedlesFile_Local
        Write-RerollStamp
        (Get-RerollStampData).NextLocalExpiry | Should -Be $when
    }
    It 'stores no expiry when the local file has none' {
        'NEEDLE|Application|1||A|0' | Set-Content $script:LocalNeedlesFile_Local
        Write-RerollStamp
        (Get-RerollStampData).NextLocalExpiry | Should -BeNullOrEmpty
    }
    It 'Test-RerollNeeded forces a reroll once NextLocalExpiry is due, even with nothing else changed' {
        'NEEDLE|Application|1||A|0' | Set-Content $script:LocalNeedlesFile_Local
        Write-RerollStamp
        $past = (Get-Date).ToUniversalTime().AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $txt  = (Get-Content $script:RerollStampFile -Raw) -replace '"NextLocalExpiry":\s*(null|"[^"]*")', ('"NextLocalExpiry": "' + $past + '"')
        $txt | Should -Match 'NextLocalExpiry": "20'
        Set-Content -Path $script:RerollStampFile -Value $txt
        Test-RerollNeeded | Should -BeTrue
        @($script:LogBuffer | Where-Object { $_.Message -match 'expiry due' }).Count | Should -BeGreaterThan 0
    }
    It 'Test-RerollNeeded does not reroll while NextLocalExpiry is in the future and nothing else changed' {
        $when = (Get-Date).ToUniversalTime().AddDays(3).ToString('yyyy-MM-ddTHH:mm:ssZ')
        "NEEDLE|Application|1||A|0|expires=$when" | Set-Content $script:LocalNeedlesFile_Local
        Write-RerollStamp
        Test-RerollNeeded | Should -BeFalse
    }
}

Describe 'haystack_action.ps1 understands the token too' {
    BeforeAll {
        function Invoke-ActionRead {
            param([string]$File, [datetime]$NowUtc)
            $src = (Get-FnSource -Path $script:HaystackActionPath -Name 'Split-NeedleExpiry') + "`n" +
                   (Get-FnSource -Path $script:HaystackActionPath -Name 'Get-NeedleLineLabel') + "`n" +
                   (Get-FnSource -Path $script:HaystackActionPath -Name 'Read-NeedleFile')
            & {
                param($src, $file, $now)
                function Write-HALog { param([string]$Message, [string]$Level = 'INFO') }
                Invoke-Expression $src
                @(Read-NeedleFile -Path $file -SourceTag 'local' -NowUtc $now)
            } $src $File $NowUtc
        }
    }
    It 'defines character-identical <Fn> in both scripts' -ForEach @(@{ Fn = 'Split-NeedleExpiry' }, @{ Fn = 'Get-NeedleLineLabel' }) {
        $a = Get-FnSource -Path $script:HaystackActionPath -Name $Fn
        $a | Should -Not -BeNullOrEmpty
        $a | Should -BeExactly (Get-FnSource -Path $script:HaystackPath -Name $Fn)
    }
    It 'strips the token and skips expired needles' {
        $f = Join-Path $TestDrive 'action_needles.cfg'
        @('NEEDLE|Application|1||Live|all|expires=2026-11-13T00:00:00Z', 'NEEDLE|Application|2||Dead|0|expires=2026-10-01T00:00:00Z', 'NEEDLE|Application|3||Plain|0') | Set-Content $f
        $r = Invoke-ActionRead -File $f -NowUtc $script:Now
        @($r.Label) | Should -Be @('Live', 'Plain')
        ($r | Where-Object Label -eq 'Live').ExtendedLogging | Should -Be 'all'
    }
}
