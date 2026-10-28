Describe 'CPR RC2 Base evidence handback and browser-kill safety' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:captiveSource = Get-Content (Join-Path $root 'main/Main.CaptivePortal.ps1') -Raw
        $script:entrySource = Get-Content (Join-Path $root 'main/Main.Entry.ps1') -Raw
    }

    It 'logs both Base evidence blocks and safely handles older completion flags' {
        $script:captiveSource | Should -Match 'Base passive preflight:'
        $script:captiveSource | Should -Match 'Cisco WebHelper navigation:'
        $script:captiveSource | Should -Match 'completion artifact from older runner'
    }

    It 'does not start or stop Main browser-killer jobs in Base routing' {
        $script:captiveSource | Should -Match 'function Test-MainSkipCiscoBrowserKill'
        $script:captiveSource | Should -Match "\$CapPortalRunnerMode -eq 'base'"
        $script:entrySource | Should -Match 'Base observer mode preserves Cisco native browser/WebHelper evidence'
        $script:entrySource | Should -Match '\$CapPortalRunnerMode -ne ''base'' -and \$ciscoBrowserKillerJob'
    }

    It 'retains explicit false legacy browser-kill opt-in for full mode' {
        $script:captiveSource | Should -Match 'policy\.Value -eq \$false'
        $script:captiveSource | Should -Match '\$script:ciscoBrowserKillerJob = Start-CiscoBrowserKiller'
    }
}
