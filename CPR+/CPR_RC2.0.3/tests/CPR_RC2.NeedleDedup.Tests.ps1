# Content-based needle dedup (RC2.0.3).
#
# Rule (ACL style, first match wins): two event-log needles (Type NEEDLE) are the
# same needle when LogName (case-insensitive) + EventID + XPathFilter (whitespace
# normalized) match. Label, source and ExtendedLogging are NOT part of the match.
# Local needles are processed before share needles; within a list, file order.
# Skipped duplicates are logged. SESSION / DEFENDER / HEADER stay label-only.
#
# haystack.ps1 (registers triggers) and haystack_action.ps1 (matches events) each
# carry their own Merge-Needles, and both must dedupe identically or the registered
# triggers and the runtime matching would disagree.

BeforeAll {
    $script:ReleaseRoot        = Split-Path -Parent $PSScriptRoot
    $script:HaystackPath       = Join-Path $script:ReleaseRoot 'haystack.ps1'
    $script:HaystackActionPath = Join-Path $script:ReleaseRoot 'haystack_action.ps1'

    $hsContent = Get-Content -LiteralPath $script:HaystackPath -Raw
    $hsPre     = ($hsContent -split '(?ms)^# =+\r?\n# Entry Point')[0]
    Invoke-Expression $hsPre.Substring($hsPre.IndexOf('function Write-HSLog'))

    function Get-FnSource {
        param([string]$Path, [string]$Name)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        if ($errors -and @($errors).Count -gt 0) { throw "Parse errors in '$Path': $($errors[0].Message)" }
        $fn = $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name
        }, $true) | Select-Object -First 1
        if (-not $fn) { return $null }
        return $fn.Extent.Text
    }

    # Runs the haystack_action.ps1 copy in its own scope so it never collides with
    # the haystack.ps1 copy loaded above. Returns @{ Merged; Log }.
    function Invoke-ActionMerge {
        param([object[]]$Share, [object[]]$Local)
        $src = (Get-FnSource -Path $script:HaystackActionPath -Name 'Get-NeedleContentKey') + "`n" +
               (Get-FnSource -Path $script:HaystackActionPath -Name 'Merge-Needles')
        & {
            param($src, $share, $local)
            $script:ActionLog = [System.Collections.Generic.List[string]]::new()
            function Write-HALog { param([string]$Message, [string]$Level = 'INFO') $script:ActionLog.Add("$Level|$Message") }
            Invoke-Expression $src
            $m = @(Merge-Needles -ShareNeedles $share -LocalNeedles $local)
            [pscustomobject]@{ Merged = $m; Log = @($script:ActionLog) }
        } $src $Share $Local
    }

    function New-EvNeedle {
        param([string]$Label, [string]$Source = 'local', [string]$LogName = 'Application', [string]$EventID = '100',
              [string]$XPath = '', [string]$Ext = '0')
        [pscustomobject]@{ Type='NEEDLE'; LogName=$LogName; EventID=$EventID; XPathFilter=$XPath; Label=$Label; ExtendedLogging=$Ext; Source=$Source }
    }
}

Describe 'Get-NeedleContentKey' {
    It 'ignores label, source and ExtendedLogging' {
        $a = New-EvNeedle -Label 'A' -Source 'local' -Ext '0'
        $b = New-EvNeedle -Label 'B' -Source 'share' -Ext 'all'
        (Get-NeedleContentKey -Needle $a) | Should -Be (Get-NeedleContentKey -Needle $b)
    }
    It 'is case-insensitive on LogName but not on EventID/XPath text' {
        (Get-NeedleContentKey -Needle (New-EvNeedle -Label 'A' -LogName 'APPLICATION')) |
            Should -Be (Get-NeedleContentKey -Needle (New-EvNeedle -Label 'B' -LogName 'application'))
        (Get-NeedleContentKey -Needle (New-EvNeedle -Label 'A' -XPath '*[System[Provider[@Name="X"]]]')) |
            Should -Not -BeExactly (Get-NeedleContentKey -Needle (New-EvNeedle -Label 'B' -XPath '*[System[Provider[@Name="x"]]]'))
    }
    It 'normalizes whitespace in the XPath' {
        $a = New-EvNeedle -Label 'A' -XPath "<Select>  *[System[EventID=1]]`r`n  </Select>"
        $b = New-EvNeedle -Label 'B' -XPath "<Select> *[System[EventID=1]] </Select>"
        (Get-NeedleContentKey -Needle $a) | Should -Be (Get-NeedleContentKey -Needle $b)
    }
    It 'differs when EventID or XPath differ' {
        (Get-NeedleContentKey -Needle (New-EvNeedle -Label 'A' -EventID '100')) |
            Should -Not -Be (Get-NeedleContentKey -Needle (New-EvNeedle -Label 'B' -EventID '101'))
    }
    It 'returns $null for non-event needles and for objects without LogName/EventID' {
        (Get-NeedleContentKey -Needle ([pscustomobject]@{ Type='SESSION'; StateChange='SessionUnlock'; Label='S' })) | Should -BeNullOrEmpty
        (Get-NeedleContentKey -Needle ([pscustomobject]@{ Type='NEEDLE'; Label='bare' })) | Should -BeNullOrEmpty
        (Get-NeedleContentKey -Needle $null) | Should -BeNullOrEmpty
    }
}

Describe 'Merge-Needles content dedup (haystack.ps1 copy)' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }
    }

    It 'keeps the first of two local needles with the same content and logs the skip' {
        $local = @((New-EvNeedle -Label 'First'), (New-EvNeedle -Label 'Second'))
        $m = @(Merge-Needles -ShareNeedles @() -LocalNeedles $local)
        $m.Count | Should -Be 1
        $m[0].Label | Should -Be 'First'
        @($script:LogBuffer | Where-Object { $_.Message -match "Second" -and $_.Message -match "First" -and $_.Message -match 'duplicate' }).Count |
            Should -BeGreaterThan 0
    }

    It 'local wins over a share needle with the same content under a different label' {
        $local = @((New-EvNeedle -Label 'bundle.x.thing' -Source 'local'))
        $share = @((New-EvNeedle -Label 'ShareThing' -Source 'share'))
        $m = @(Merge-Needles -ShareNeedles $share -LocalNeedles $local)
        $m.Count | Should -Be 1
        $m[0].Source | Should -Be 'local'
    }

    It 'self-heals: once the local copy is gone, the share copy is active' {
        $share = @((New-EvNeedle -Label 'ShareThing' -Source 'share'))
        $m = @(Merge-Needles -ShareNeedles $share -LocalNeedles @())
        $m.Count | Should -Be 1
        $m[0].Label | Should -Be 'ShareThing'
    }

    It 'first share needle wins among share duplicates' {
        $share = @((New-EvNeedle -Label 'S1' -Source 'share'), (New-EvNeedle -Label 'S2' -Source 'share'))
        $m = @(Merge-Needles -ShareNeedles $share -LocalNeedles @())
        $m.Count | Should -Be 1
        $m[0].Label | Should -Be 'S1'
    }

    It 'keeps both when EventID or XPath differ' {
        $local = @((New-EvNeedle -Label 'A' -EventID '100'), (New-EvNeedle -Label 'B' -EventID '101'),
                   (New-EvNeedle -Label 'C' -EventID '100' -XPath '*[System[Level=2]]'))
        @(Merge-Needles -ShareNeedles @() -LocalNeedles $local).Count | Should -Be 3
    }

    It 'treats LogName case and XPath whitespace as the same content' {
        $local = @((New-EvNeedle -Label 'A' -LogName 'Application' -XPath '<Select>  x </Select>'),
                   (New-EvNeedle -Label 'B' -LogName 'APPLICATION' -XPath '<Select> x </Select>'))
        @(Merge-Needles -ShareNeedles @() -LocalNeedles $local).Count | Should -Be 1
    }

    It 'does not content-dedupe SESSION, DEFENDER or HEADER needles (label-only)' {
        $local = @(
            [pscustomobject]@{ Type='SESSION';  StateChange='SessionUnlock'; Label='S1'; Source='local' },
            [pscustomobject]@{ Type='SESSION';  StateChange='SessionUnlock'; Label='S2'; Source='local' },
            [pscustomobject]@{ Type='HEADER';   FieldName='*'; Label='H1'; Source='local' },
            [pscustomobject]@{ Type='HEADER';   FieldName='*'; Label='H2'; Source='local' },
            [pscustomobject]@{ Type='DEFENDER'; RuleNameMatch='x'; Label='D1'; Source='local' },
            [pscustomobject]@{ Type='DEFENDER'; RuleNameMatch='x'; Label='D2'; Source='local' }
        )
        @(Merge-Needles -ShareNeedles @() -LocalNeedles $local).Count | Should -Be 6
    }

    It 'does not content-dedupe event needles that lack LogName/EventID (legacy test objects)' {
        $local = @([pscustomobject]@{ Type='NEEDLE'; Label='L1'; Source='local' }, [pscustomobject]@{ Type='NEEDLE'; Label='L2'; Source='local' })
        @(Merge-Needles -ShareNeedles @() -LocalNeedles $local).Count | Should -Be 2
    }

    It 'notes when ExtendedLogging differs between the kept and the skipped needle' {
        $local = @((New-EvNeedle -Label 'Quiet' -Ext '0'), (New-EvNeedle -Label 'Loud' -Ext 'all'))
        $null = Merge-Needles -ShareNeedles @() -LocalNeedles $local
        @($script:LogBuffer | Where-Object { $_.Message -match 'ExtendedLogging' -and $_.Message -match 'Loud' }).Count |
            Should -BeGreaterThan 0
    }

    It 'keeps the skipped needle label claimed so a later same-label needle cannot sneak in' {
        $share = @((New-EvNeedle -Label 'Y' -Source 'share' -EventID '100'),
                   (New-EvNeedle -Label 'Y' -Source 'share' -EventID '200'))
        $local = @((New-EvNeedle -Label 'X' -Source 'local' -EventID '100'))
        $m = @(Merge-Needles -ShareNeedles $share -LocalNeedles $local)
        @($m | Where-Object Label -eq 'Y').Count | Should -Be 0
        @($m | Where-Object Label -eq 'X').Count | Should -Be 1
    }

    It 'reports the content-duplicate count in the merge summary' {
        $local = @((New-EvNeedle -Label 'A'), (New-EvNeedle -Label 'B'))
        $null = Merge-Needles -ShareNeedles @() -LocalNeedles $local
        @($script:LogBuffer | Where-Object { $_.Message -match 'Needle merge complete' -and $_.Message -match '1 content duplicate' }).Count |
            Should -Be 1
    }
}

Describe 'Merge-Needles content dedup (haystack_action.ps1 copy matches)' {
    It 'dedupes identically: local first, then share, first match wins' {
        $local = @((New-EvNeedle -Label 'L1' -Source 'local'), (New-EvNeedle -Label 'L2' -Source 'local'))
        $share = @((New-EvNeedle -Label 'S1' -Source 'share'), (New-EvNeedle -Label 'S2' -Source 'share' -EventID '200'))
        $r = Invoke-ActionMerge -Share $share -Local $local
        @($r.Merged).Count | Should -Be 2
        @($r.Merged.Label) | Should -Be @('L1', 'S2')
    }
    It 'leaves non-event needle types label-only' {
        $local = @([pscustomobject]@{ Type='SESSION'; StateChange='SessionUnlock'; Label='S1' },
                   [pscustomobject]@{ Type='SESSION'; StateChange='SessionUnlock'; Label='S2' })
        @((Invoke-ActionMerge -Share @() -Local $local).Merged).Count | Should -Be 2
    }
}

Describe 'Self-contained copies stay consistent' {
    It 'defines character-identical Get-NeedleContentKey in haystack.ps1 and haystack_action.ps1' {
        $a = Get-FnSource -Path $script:HaystackActionPath -Name 'Get-NeedleContentKey'
        $h = Get-FnSource -Path $script:HaystackPath       -Name 'Get-NeedleContentKey'
        $a | Should -Not -BeNullOrEmpty
        $a | Should -Be $h
    }
}
