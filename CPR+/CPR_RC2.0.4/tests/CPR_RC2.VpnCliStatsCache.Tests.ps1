# Per-run vpncli 'stats' reuse (RC2.0.3): each real call costs ~2 s. The cache is only READ when a
# caller passes -MaxAgeSec, and only for 'stats'; every other path still makes a real call.

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.VpnState.ps1'), [ref]$null, [ref]$null)
    $def = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-VpnCliBounded' }, $true)[0]
    . ([scriptblock]::Create($def.Extent.Text))
    function Write-Log { param($m, $l) $script:logged += "$m" }
    $script:VpnCliTimeoutSec = 8; $script:VpnCliDisconnectTimeoutSec = 20
    $script:Src = Get-Content -LiteralPath (Join-Path $root 'main\Main.VpnState.ps1') -Raw
}

Describe 'Invoke-VpnCliBounded stats cache' {
    BeforeEach { $script:logged = @() }
    It 'returns a fresh-enough cached stats result without starting a process' {
        $script:VpnCliStatsCache = @{ At = [datetime]::UtcNow.AddSeconds(-1); Text = 'CACHED STATS' }
        $script:vpn_cmd = Join-Path $TestDrive 'does_not_exist.exe'
        Invoke-VpnCliBounded -Arguments 'stats' -MaxAgeSec 3 | Should -Be 'CACHED STATS'
        ($script:logged -join ' ') | Should -Match "vpncli_cache_hit cmd='stats'"
    }
    It 'ignores the cache when it is older than MaxAgeSec' {
        $script:VpnCliStatsCache = @{ At = [datetime]::UtcNow.AddSeconds(-10); Text = 'OLD' }
        $script:vpn_cmd = Join-Path $TestDrive 'does_not_exist.exe'
        { Invoke-VpnCliBounded -Arguments 'stats' -MaxAgeSec 3 } | Should -Throw   # tried a real (missing) binary
    }
    It 'never reads the cache when MaxAgeSec is not given' {
        $script:VpnCliStatsCache = @{ At = [datetime]::UtcNow; Text = 'CACHED' }
        $script:vpn_cmd = Join-Path $TestDrive 'does_not_exist.exe'
        { Invoke-VpnCliBounded -Arguments 'stats' } | Should -Throw
    }
    It 'never caches or serves anything but stats' {
        $script:VpnCliStatsCache = @{ At = [datetime]::UtcNow; Text = 'CACHED' }
        $script:vpn_cmd = Join-Path $TestDrive 'does_not_exist.exe'
        { Invoke-VpnCliBounded -Arguments 'state' -MaxAgeSec 3 } | Should -Throw
    }
    It 'a connect or disconnect clears the cached stats' {
        $script:VpnCliStatsCache = @{ At = [datetime]::UtcNow; Text = 'CACHED' }
        $script:vpn_cmd = Join-Path $TestDrive 'does_not_exist.exe'
        function Test-VpnHostscanHold { param($Where) $false }
        try { Invoke-VpnCliBounded -Arguments 'connect somehost' -TimeoutSec 1 } catch { }
        $script:VpnCliStatsCache | Should -BeNullOrEmpty
    }
    It 'serves a stats result that is 4 s old (the real-run gap) but not one that is 8 s old' {
        $script:vpn_cmd = Join-Path $TestDrive 'does_not_exist.exe'
        $script:VpnCliStatsCache = @{ At = [datetime]::UtcNow.AddSeconds(-4); Text = 'C4' }
        Invoke-VpnCliBounded -Arguments 'stats' -MaxAgeSec 6 | Should -Be 'C4'
        $script:VpnCliStatsCache = @{ At = [datetime]::UtcNow.AddSeconds(-8); Text = 'C8' }
        { Invoke-VpnCliBounded -Arguments 'stats' -MaxAgeSec 6 } | Should -Throw
    }
    It 'only Get-VpnTunnelFlavor opts in, with a short window' {
        $matches2 = [regex]::Matches($script:Src, "-Arguments 'stats'[^\r\n]*-MaxAgeSec (\d+)")
        $matches2.Count | Should -Be 1
        [int]$matches2[0].Groups[1].Value | Should -BeLessOrEqual 6
        $script:Src | Should -Match "(?s)function Get-VpnTunnelFlavor.*?-MaxAgeSec"
    }
}
