# RC1.25 packaging source-of-truth guard.

Describe 'CPR RC1.25 package source of truth' {
    BeforeAll {
        $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot
        $script:MainSource = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'WW_main.ps1') -Raw
        $script:InstallerSource = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'install.ps1') -Raw
    }

    It 'uses the RC1.25 directory as the package root' {
        (Split-Path -Leaf $script:ReleaseRoot) | Should -Be 'CPR_3.14_RC1.25'
    }

    It 'contains only the RC1.25 authoritative version markers' {
        $script:MainSource | Should -Match 'Version:\s*3\.14\.0_RC1\.25'
        $script:InstallerSource | Should -Match '\$WW_Version\s*=\s*"RC1\.25"'
    }

    It 'does not silently package a stale RC1.24 payload' {
        $script:MainSource | Should -Not -Match 'Version:\s*3\.14\.0_RC1\.24'
        $script:InstallerSource | Should -Not -Match '\$WW_Version\s*=\s*"RC1\.24"'
    }
}
