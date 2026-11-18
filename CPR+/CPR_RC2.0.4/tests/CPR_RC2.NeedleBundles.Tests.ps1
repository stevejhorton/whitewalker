# Needle bundles (RC2.0.3): bundles\needle_bundles.cfg + the tech console picker.
#
#   * The real catalog is parsed by the real needle parser, so a typo fails here, not on a box.
#   * Applying a bundle writes prefixed labels (bundle.<name>.<label>) and |expires= on every
#     line, is idempotent, and never touches other lines. Removing deletes exactly that bundle.
#   * Local needles are capped at 30 days; the default is 14.

BeforeAll {
    $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot

    $hsContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'haystack.ps1') -Raw
    $hsPre     = ($hsContent -split '(?ms)^# =+\r?\n# Entry Point')[0]
    Invoke-Expression $hsPre.Substring($hsPre.IndexOf('function Write-HSLog'))

    $script:WWRoot           = $TestDrive
    $script:WWLogDir         = Join-Path $TestDrive 'logs'
    $script:AdminActionLog   = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
    $script:HaystackScript   = Join-Path $TestDrive 'haystack.ps1'
    $script:ActiveTeeProfile = Join-Path $TestDrive 'WW_tee_events.psd1'
    $script:RemoteNeedlesFile = Join-Path $TestDrive 'remote_needles.cfg'
    $script:LocalNeedlesFile  = Join-Path $TestDrive 'local_needles.cfg'

    $actionContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'admin/Invoke-WhiteWalkerAction.ps1') -Raw
    $actionPre     = ($actionContent -split "(?ms)^if \(-not \(\`$MyInvocation")[0]
    Invoke-Expression $actionPre.Substring($actionPre.IndexOf('function Write-WWAdminLog'))

    $script:RealCatalog = Join-Path $script:ReleaseRoot 'bundles/needle_bundles.cfg'

    function New-TestCatalog {
        param([string]$Name = 'cat.cfg', [string[]]$Lines)
        $p = Join-Path $TestDrive $Name
        [System.IO.File]::WriteAllText($p, (($Lines -join "`n") + "`n"))
        return $p
    }
    $script:GoodCatalogLines = @(
        'version:test1',
        '# a comment',
        '[bundle:alpha]',
        'description=Alpha things',
        'default_days=7',
        'volume=high',
        'NEEDLE|Application|1000||one|1',
        'NEEDLE|System|41|*[System[Provider[@Name=''Microsoft-Windows-Kernel-Power''] and EventID=41]]|two|1',
        'SESSION|SessionUnlock|three',
        'HEADER|*|four|RefreshHours=6',
        '',
        '[bundle:beta_2]',
        'description=Beta things',
        'DEFENDER|SomeRule|6|five|0'
    )
}

Describe 'Read-WWBundleCatalog' {
    It 'parses bundles, metadata and defaults' {
        $c = Read-WWBundleCatalog -Path (New-TestCatalog -Lines $script:GoodCatalogLines)
        @($c.Errors).Count | Should -Be 0
        $c.Version | Should -Be 'test1'
        @($c.Bundles).Count | Should -Be 2
        $a = $c.Bundles | Where-Object Name -eq 'alpha'
        $a.DefaultDays | Should -Be 7
        $a.Volume | Should -Be 'high'
        @($a.Lines).Count | Should -Be 4
        $b = $c.Bundles | Where-Object Name -eq 'beta_2'
        $b.DefaultDays | Should -Be 14
        $b.Volume | Should -Be 'low'
    }
    It 'reports every kind of mistake' -ForEach @(
        @{ Why = 'content before a header';  Lines = @('NEEDLE|Application|1||x'); Match = 'before any' }
        @{ Why = 'bad bundle name';          Lines = @('[bundle:Bad-Name]', 'description=d', 'NEEDLE|Application|1||x'); Match = 'lowercase' }
        @{ Why = 'duplicate bundle';         Lines = @('[bundle:a]', 'description=d', 'NEEDLE|Application|1||x', '[bundle:a]', 'description=d', 'NEEDLE|Application|2||y'); Match = 'duplicate bundle' }
        @{ Why = 'default_days over the cap'; Lines = @('[bundle:a]', 'description=d', 'default_days=31', 'NEEDLE|Application|1||x'); Match = 'default_days' }
        @{ Why = 'bad volume';               Lines = @('[bundle:a]', 'description=d', 'volume=loud', 'NEEDLE|Application|1||x'); Match = 'volume' }
        @{ Why = 'expires in the catalog';   Lines = @('[bundle:a]', 'description=d', 'NEEDLE|Application|1||x|0|expires=2026-12-01'); Match = 'expires' }
        @{ Why = 'empty bundle';             Lines = @('[bundle:a]', 'description=d'); Match = 'no needle lines' }
        @{ Why = 'missing description';      Lines = @('[bundle:a]', 'NEEDLE|Application|1||x'); Match = 'no description' }
        @{ Why = 'unrecognized line';        Lines = @('[bundle:a]', 'description=d', 'NEEDLE|Application|1||x', 'what is this'); Match = 'unrecognized' }
    ) {
        $c = Read-WWBundleCatalog -Path (New-TestCatalog -Lines $Lines)
        (@($c.Errors) -join "`n") | Should -Match $Match
    }
    It 'reports a missing file instead of throwing' {
        $c = Read-WWBundleCatalog -Path (Join-Path $TestDrive 'nope.cfg')
        @($c.Bundles).Count | Should -Be 0
        (@($c.Errors) -join ' ') | Should -Match 'not found'
    }
}

Describe 'Test-WWBundleCatalog' {
    BeforeEach { Mock Write-HSLog { } }

    It 'is clean for a good catalog' {
        $c = Read-WWBundleCatalog -Path (New-TestCatalog -Lines $script:GoodCatalogLines)
        @(Test-WWBundleCatalog -Catalog $c).Count | Should -Be 0
    }
    It 'flags a line the real needle parser rejects' {
        $c = Read-WWBundleCatalog -Path (New-TestCatalog -Lines @('[bundle:a]', 'description=d', 'NEEDLE|Application|notanumber||x'))
        (@(Test-WWBundleCatalog -Catalog $c) -join "`n") | Should -Match 'parser rejects'
    }
    It 'flags a repeated label and repeated event content within a bundle' {
        $c = Read-WWBundleCatalog -Path (New-TestCatalog -Lines @('[bundle:a]', 'description=d', 'NEEDLE|Application|1||same', 'NEEDLE|Application|2||same', 'NEEDLE|Application|3||p', 'NEEDLE|application|3||q'))
        $text = @(Test-WWBundleCatalog -Catalog $c) -join "`n"
        $text | Should -Match "label 'same' used twice"
        $text | Should -Match "'q' repeats the content of 'p'"
    }
}

Describe 'the shipped bundles\needle_bundles.cfg' {
    BeforeAll { Mock Write-HSLog { } }

    It 'exists, has bundles, and validates with zero problems' {
        Test-Path -LiteralPath $script:RealCatalog | Should -BeTrue
        $c = Read-WWBundleCatalog -Path $script:RealCatalog
        @($c.Bundles).Count | Should -BeGreaterThan 0
        $problems = @(Test-WWBundleCatalog -Catalog $c)
        $problems.Count | Should -Be 0 -Because ($problems -join "`n")
    }
    It 'has a version line' {
        (Read-WWBundleCatalog -Path $script:RealCatalog).Version | Should -Not -BeNullOrEmpty
    }
    It 'is mirrored to endpoints by the installer' {
        (Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'install.ps1') -Raw) | Should -Match 'Label = "bundles"'
    }
}

Describe 'Add-WWBundleToLocal / Remove-WWBundleFromLocal / Get-WWAppliedBundles' {
    BeforeEach {
        Mock Write-HSLog { }
        $script:Local = Join-Path $TestDrive 'needles_local_bundles.cfg'
        [System.IO.File]::WriteAllText($script:Local, "version:1`nNEEDLE|Application|9999||my_own|0`n")
        $c = Read-WWBundleCatalog -Path (New-TestCatalog -Name 'apply.cfg' -Lines $script:GoodCatalogLines)
        $script:Alpha = $c.Bundles | Where-Object Name -eq 'alpha'
        $script:Beta  = $c.Bundles | Where-Object Name -eq 'beta_2'
    }

    It 'writes prefixed, expiring lines that the real parser loads as local needles' {
        $r = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 10
        $r.Added | Should -Be 4
        $loaded = @(Read-NeedleFile -Path $script:Local -SourceTag 'local')
        @($loaded.Label) | Should -Contain 'my_own'
        @($loaded.Label | Where-Object { $_ -like 'bundle.alpha.*' }).Count | Should -Be 4
        @($loaded.Label) | Should -Contain 'bundle.alpha.one'
        @($loaded.Label) | Should -Contain 'bundle.alpha.three'
        ([System.IO.File]::ReadAllText($script:Local)) | Should -Match '# bundle:alpha applied'
    }
    It 'accepts the maximum 30 days and the lines still load (cap not tripped)' {
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 30
        @(Read-NeedleFile -Path $script:Local -SourceTag 'local' | Where-Object { $_.Label -like 'bundle.alpha.*' }).Count | Should -Be 4
    }
    It 'is idempotent: applying twice leaves one copy and one provenance comment' {
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 5
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 9
        $text = [System.IO.File]::ReadAllText($script:Local)
        ([regex]::Matches($text, 'bundle\.alpha\.one')).Count | Should -Be 1
        ([regex]::Matches($text, '# bundle:alpha applied')).Count | Should -Be 1
        $text | Should -Match 'my_own'
    }
    It 'preserves CRLF when the file uses it, and adds a missing final newline' {
        [System.IO.File]::WriteAllText($script:Local, "NEEDLE|Application|9999||my_own|0")
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Beta -Days 3
        $text = [System.IO.File]::ReadAllText($script:Local)
        $text | Should -Match 'my_own\|0(\r)?\n# bundle:beta_2'
        [System.IO.File]::WriteAllText($script:Local, "NEEDLE|Application|9999||my_own|0`r`n")
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Beta -Days 3
        ([System.IO.File]::ReadAllText($script:Local)) | Should -Not -Match "(?<!`r)`n"
    }
    It 'removes exactly one bundle and its comment, leaving everything else byte for byte' {
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 5
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Beta  -Days 5
        $removed = Remove-WWBundleFromLocal -Path $script:Local -Name 'alpha'
        $removed | Should -Be 4
        $text = [System.IO.File]::ReadAllText($script:Local)
        $text | Should -Not -Match 'bundle\.alpha\.'
        $text | Should -Not -Match '# bundle:alpha '
        $text | Should -Match 'bundle\.beta_2\.five'
        $text | Should -Match '# bundle:beta_2 applied'
        $text | Should -Match 'my_own'
    }
    It 'does not confuse a bundle with another whose name starts the same' {
        $other = [pscustomobject]@{ Name = 'alpha_two'; Lines = @('NEEDLE|Application|2222||x|0') }
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 5
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $other -Days 5
        $null = Remove-WWBundleFromLocal -Path $script:Local -Name 'alpha'
        ([System.IO.File]::ReadAllText($script:Local)) | Should -Match 'bundle\.alpha_two\.x'
    }
    It 'leaves the file untouched when removing a bundle that is not there' {
        $before = [System.IO.File]::ReadAllText($script:Local)
        (Remove-WWBundleFromLocal -Path $script:Local -Name 'nothere') | Should -Be 0
        ([System.IO.File]::ReadAllText($script:Local)) | Should -Be $before
    }
    It 'reports applied bundles with their count and earliest expiry' {
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 5
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Beta  -Days 20
        $a = @(Get-WWAppliedBundles -Path $script:Local)
        @($a.Name) | Should -Be @('alpha', 'beta_2')
        ($a | Where-Object Name -eq 'alpha').Count | Should -Be 4
        ($a | Where-Object Name -eq 'alpha').Expires | Should -BeLessThan ([datetime]::UtcNow.AddDays(6))
        ($a | Where-Object Name -eq 'beta_2').Expires | Should -BeGreaterThan ([datetime]::UtcNow.AddDays(19))
    }
    It 'expired bundle lines are pruned by HayStack like any other needle (end to end)' {
        $null = Add-WWBundleToLocal -Path $script:Local -Bundle $script:Alpha -Days 1
        $r = Invoke-LocalNeedlePrune -Path $script:Local -NowUtc ([datetime]::UtcNow.AddDays(2))
        @($r.Removed).Count | Should -Be 4
        ([System.IO.File]::ReadAllText($script:Local)) | Should -Match 'my_own'
        @(Get-WWAppliedBundles -Path $script:Local).Count | Should -Be 0
    }
}

Describe 'Resolve-WWTtlDays / limits' {
    It 'defaults to 14 and accepts 1..30 only' {
        Resolve-WWTtlDays -Text '' | Should -Be 14
        Resolve-WWTtlDays -Text '  ' | Should -Be 14
        Resolve-WWTtlDays -Text '7' | Should -Be 7
        Resolve-WWTtlDays -Text '30' | Should -Be 30
        Resolve-WWTtlDays -Text '0' | Should -BeNullOrEmpty
        Resolve-WWTtlDays -Text '31' | Should -BeNullOrEmpty
        Resolve-WWTtlDays -Text 'abc' | Should -BeNullOrEmpty
        Resolve-WWTtlDays -Text '-3' | Should -BeNullOrEmpty
    }
    It 'the admin cap matches the HayStack parser cap (both 30)' {
        $adminSrc = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'admin/Invoke-WhiteWalkerAction.ps1') -Raw
        $adminSrc | Should -Match '\$script:MaxNeedleTtlDays\s*=\s*30'
        (Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'haystack.ps1') -Raw) | Should -Match '\[int\]\$MaxTtlDays = 30'
    }
}

Describe 'Reroll offer' {
    BeforeEach {
        $script:WWLogDir = Join-Path $TestDrive 'logs_offer'
        $script:AdminActionLog = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
        Mock Write-Host { }
    }
    It 'does not reroll when the tech answers n' {
        Mock Read-Host { 'n' }
        Mock Invoke-WWHaystackRerollNow { $true }
        (Invoke-WWOfferReroll) | Should -BeFalse
        Should -Invoke Invoke-WWHaystackRerollNow -Times 0 -Exactly
    }
    It 'rerolls by default (Enter) and on y' -ForEach @(@{ Answer = '' }, @{ Answer = 'y' }, @{ Answer = 'Y' }) {
        Mock Read-Host { $Answer }
        Mock Invoke-WWHaystackRerollNow { $true }
        (Invoke-WWOfferReroll) | Should -BeTrue
        Should -Invoke Invoke-WWHaystackRerollNow -Times 1 -Exactly
    }
    It 'reports failure honestly when haystack.ps1 is missing' {
        $script:HaystackScript = Join-Path $TestDrive 'definitely_missing_haystack.ps1'
        (Invoke-WWHaystackRerollNow) | Should -BeFalse
    }
}

Describe 'Invoke-WWBundlePicker' {
    BeforeEach {
        Mock Write-HSLog { }
        Mock Write-Host { }
        $script:WWLogDir = Join-Path $TestDrive 'logs_picker'
        $script:AdminActionLog = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
        $script:NeedlesLocalFile = Join-Path $TestDrive 'picker_needles_local.cfg'
        [System.IO.File]::WriteAllText($script:NeedlesLocalFile, "NEEDLE|Application|9999||my_own|0`n")
        $script:PickerCatalog = New-TestCatalog -Name 'picker.cfg' -Lines $script:GoodCatalogLines
        Mock Get-WWBundleCatalogSource { [pscustomobject]@{ Path = $script:PickerCatalog; Source = 'test' } }
        Mock Invoke-WWOfferReroll { $false }
    }

    It 'applies the chosen bundle with its default days and then offers a reroll' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1', '', 'y'))
        Mock Read-Host { $answers.Dequeue() }
        Invoke-WWBundlePicker
        ([System.IO.File]::ReadAllText($script:NeedlesLocalFile)) | Should -Match 'bundle\.alpha\.one'
        Should -Invoke Invoke-WWOfferReroll -Times 1 -Exactly
        (Get-Content -LiteralPath $script:AdminActionLog -Raw) | Should -Match "Applied bundle 'alpha'"
    }
    It 'writes nothing when the tech declines the confirmation' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1', '', 'n'))
        Mock Read-Host { $answers.Dequeue() }
        Invoke-WWBundlePicker
        ([System.IO.File]::ReadAllText($script:NeedlesLocalFile)) | Should -Not -Match 'bundle\.'
        Should -Invoke Invoke-WWOfferReroll -Times 0 -Exactly
    }
    It 'rejects out-of-range days without writing' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1', '45'))
        Mock Read-Host { $answers.Dequeue() }
        Invoke-WWBundlePicker
        ([System.IO.File]::ReadAllText($script:NeedlesLocalFile)) | Should -Not -Match 'bundle\.'
    }
    It 'removes an applied bundle' {
        $null = Add-WWBundleToLocal -Path $script:NeedlesLocalFile -Bundle ((Read-WWBundleCatalog -Path $script:PickerCatalog).Bundles | Where-Object Name -eq 'alpha') -Days 5
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('r', 'alpha', 'y'))
        Mock Read-Host { $answers.Dequeue() }
        Invoke-WWBundlePicker
        ([System.IO.File]::ReadAllText($script:NeedlesLocalFile)) | Should -Not -Match 'bundle\.alpha'
        Should -Invoke Invoke-WWOfferReroll -Times 1 -Exactly
    }
    It 'refuses to apply anything from a catalog with problems' {
        $script:PickerCatalog = New-TestCatalog -Name 'broken.cfg' -Lines @('[bundle:a]', 'description=d', 'NEEDLE|Application|notanumber||x')
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1', '', 'y'))
        Mock Read-Host { $answers.Dequeue() }
        Invoke-WWBundlePicker
        ([System.IO.File]::ReadAllText($script:NeedlesLocalFile)) | Should -Not -Match 'bundle\.'
        Should -Invoke Read-Host -Times 0 -Exactly
    }
    It 'says so and does nothing when no catalog exists' {
        Mock Get-WWBundleCatalogSource { $null }
        Mock Read-Host { throw 'should not prompt' }
        { Invoke-WWBundlePicker } | Should -Not -Throw
    }
}
