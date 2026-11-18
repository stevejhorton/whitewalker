# Admin console item E: read-only "effective tee level" report.
BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Src = Join-Path $script:Root 'admin\Invoke-WhiteWalkerAction.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Src, [ref]$null, [ref]$null)
    $fn = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Invoke-WWShowEffectiveTee' }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($fn.Extent.Text))
    function Test-WWTeeProfileStale { [pscustomobject]@{ Stale = $false; Reason = 'current' } }
}
Describe 'Invoke-WWShowEffectiveTee' {
    BeforeEach {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ("effTee_" + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $d | Out-Null
        $script:WWRoot = $d; $script:WWTeeFlagDir = $d; $script:ActiveTeeProfile = Join-Path $d 'WW_tee_events.psd1'
        $script:Dir = $d
        Set-Content $script:ActiveTeeProfile "@{ Level = 5; Reason = 'manifest'; GeneratedBy = 'cpr_tee_assign'; Generated = '2026-11-05T04:00:21Z'; ProfileVersion = 'x1'; Custom = `$false; Events = @{ a = 1; b = 2 } }"
    }
    AfterEach { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }
    It 'reports level, reason and who set it' {
        $o = (Invoke-WWShowEffectiveTee 6>&1 | Out-String)
        $o | Should -Match 'Level now\s+: 5'; $o | Should -Match 'Why\s+: manifest'; $o | Should -Match 'cpr_tee_assign'; $o | Should -Match 'none - the level stays'
    }
    It 'shows a manifest stamp with the days left' {
        @{ previous_level = 1; set_level = 5; applied_at = (Get-Date).ToString('o'); expires_at = (Get-Date).AddDays(13).ToString('o'); keep = $false; source = 'manifest' } | ConvertTo-Json | Set-Content (Join-Path $script:Dir 'tee_level_revert.json')
        $o = (Invoke-WWShowEffectiveTee 6>&1 | Out-String)
        $o | Should -Match 'set by manifest; returns to level 1'; $o | Should -Match '1[23]\.\d days left'
    }
    It 'lists waiting flags and says when the share list has not been read' {
        New-Item (Join-Path $script:Dir 'cpr_tee_3.flag') -ItemType File | Out-Null
        $o = (Invoke-WWShowEffectiveTee 6>&1 | Out-String)
        $o | Should -Match 'cpr_tee_3\.flag'; $o | Should -Match 'no local copy yet'
    }
    It 'does not throw when the profile is missing' {
        Remove-Item $script:ActiveTeeProfile
        { Invoke-WWShowEffectiveTee 6>&1 | Out-Null } | Should -Not -Throw
        (Invoke-WWShowEffectiveTee 6>&1 | Out-String) | Should -Match 'missing or unreadable'
    }
    It 'is on the menu and wired to the dispatcher' {
        $t = Get-Content $script:Src -Raw
        $t | Should -Match 'E\. Show Effective Tee Level'; $t | Should -Match "'ShowEffectiveTee'"
    }
}
