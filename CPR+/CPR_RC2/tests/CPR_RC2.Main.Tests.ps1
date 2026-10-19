# Focused structural tests for the CPR RC2 WW_main decomposition.

Describe 'CPR RC2 main loader' {
    BeforeAll {
        $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot
        $script:Loader = Get-Content (Join-Path $script:ReleaseRoot 'WW_main.ps1') -Raw
        $script:MainRoot = Join-Path $script:ReleaseRoot 'main'
        $script:Order = @(
            'Main.Configuration.ps1'
            'Main.Logging.ps1'
            'Main.State.ps1'
            'Main.FlareGun.ps1'
            'Main.Network.ps1'
            'Main.CaptivePortal.ps1'
            'Main.VpnState.ps1'
            'Main.SsidChange.ps1'
            'Main.SelfUpdate.ps1'
            'Main.Entry.ps1'
        )
    }

    It 'has every ordered library and dot-sources it' {
        $previousIndex = -1
        foreach ($file in $script:Order) {
            Test-Path (Join-Path $script:MainRoot $file) | Should -BeTrue
            $index = $script:Loader.IndexOf($file)
            $index | Should -BeGreaterThan $previousIndex
            $previousIndex = $index
        }
    }

    It 'exposes the orchestration function without invoking it while dot-sourced' {
        $entry = Get-Content (Join-Path $script:MainRoot 'Main.Entry.ps1') -Raw
        $entry | Should -Match 'function Invoke-WhiteWalkerMain'
        $script:Loader | Should -Match '\$MyInvocation\.InvocationName -ne ''\.'''
    }

    It 'contains representative functions in their focused libraries' {
        $checks = @{
            'Main.Logging.ps1' = 'Write-RunHeader'
            'Main.FlareGun.ps1' = 'Send-FlareEvent'
            'Main.Network.ps1' = 'Get-NetworkInfo'
            'Main.CaptivePortal.ps1' = 'Invoke-CaptivePortalRemediation'
            'Main.VpnState.ps1' = 'Get-VpnState'
            'Main.SsidChange.ps1' = 'Invoke-SsidChangeCheck'
            'Main.SelfUpdate.ps1' = 'Invoke-SelfUpdate'
        }
        foreach ($file in $checks.Keys) {
            $content = Get-Content (Join-Path $script:MainRoot $file) -Raw
            $content | Should -Match ("function\s+" + $checks[$file])
        }
    }

    It 'uses RC2 version markers only in the new line' {
        (Get-Content (Join-Path $script:ReleaseRoot 'install.ps1') -Raw) | Should -Match '\$WW_Version\s*=\s*"RC2\.0"'
        $script:Loader | Should -Match 'Version:\s*3\.14\.0_RC2\.0'
        $script:Loader | Should -Not -Match 'Version:\s*3\.14\.0_RC1\.25'
    }
}
