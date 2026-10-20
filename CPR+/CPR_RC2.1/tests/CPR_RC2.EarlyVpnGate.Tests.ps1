# Behavior tests for the RC2.1 early VPN gate (Pester 5). Functions are pulled out of
# the real source via AST, so these test the shipped code, not a copy.

Describe 'CPR RC2.1 early VPN gate' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $want = 'Test-AnyUsableIp', 'Test-SsidJump', 'Invoke-EarlyVpnGate', 'Invoke-GatedNwCheck'
        foreach ($f in 'Main.VpnState.ps1', 'Main.SsidChange.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root "main\$f"), [ref]$null, [ref]$null)
            $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $want }, $true)
            foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
        }
        function Write-Log { param($m, $l) }
        function Write-TeeLog { param($a, $b) }
        function Get-VpnState { 'Disconnected' }
        function Get-VpnStateStable { param($TimeoutSec) 'Disconnected' }
        function Test-RecentWakeFromSleep { param($TimeWindowSeconds) $false }
        function Test-EarlyTrustedNetwork { param($NetworkInfo) $false }
        function Invoke-EarlyVpnDisconnect { param($Reason, $VpnStateWas) $true }
        function Get-NwCheckResult { param($Url) [pscustomobject]@{ Status = 'online' } }
        $script:EarlyVpnGateEnabled = $true
        $script:VpnWakeDetection = $true
        $script:VpnWakeTimeWindow = 120
        $script:PreflightRequiresSettledVpn = $true
        $script:VpnStateMaxWaitSeconds = 12
        $script:NewPreflightURL = 'http://example.invalid'
        $script:SsidCacheFile = Join-Path $TestDrive 'ssid.flag'
        $script:NoIp  = [pscustomobject]@{ SSID = 'HomeNet'; ConnectionType = 'WiFi'; IPAddress = 'N/A'
                          Adapters = @([pscustomobject]@{ IPAddress = 'N/A' }, [pscustomobject]@{ IPAddress = '169.254.3.4' }) }
        $script:HasIp = [pscustomobject]@{ SSID = 'WLANi03'; ConnectionType = 'WiFi'; IPAddress = '10.1.1.5'
                          Adapters = @([pscustomobject]@{ IPAddress = '10.1.1.5' }) }
    }

    It 'treats APIPA and N/A as no usable IP' {
        Test-AnyUsableIp -NetworkInfo $script:NoIp | Should -BeFalse
        Test-AnyUsableIp -NetworkInfo $script:HasIp | Should -BeTrue
    }

    It 'disconnects a Reconnecting VPN when no adapter has an IP' {
        Mock Get-VpnState { 'Reconnecting' }
        Mock Invoke-EarlyVpnDisconnect { $true }
        $r = Invoke-EarlyVpnGate -NetworkInfo $script:NoIp
        $r.Acted | Should -BeTrue
        $r.Reason | Should -Be 'no_ip'
        Should -Invoke Invoke-EarlyVpnDisconnect -Times 1 -Exactly
    }

    It 'does nothing when VPN is already Disconnected' {
        Mock Get-VpnState { 'Disconnected' }
        Mock Invoke-EarlyVpnDisconnect { $true }
        $r = Invoke-EarlyVpnGate -NetworkInfo $script:HasIp
        $r.Acted | Should -BeFalse
        Should -Invoke Invoke-EarlyVpnDisconnect -Times 0 -Exactly
    }

    It 'disconnects Reconnecting VPN after a recent wake' {
        Mock Get-VpnState { 'Reconnecting' }
        Mock Test-RecentWakeFromSleep { $true }
        (Invoke-EarlyVpnGate -NetworkInfo $script:HasIp).Reason | Should -Be 'wake_blocking'
    }

    It 'disconnects Connected VPN after wake only on a trusted network' {
        Mock Get-VpnState { 'Connected' }
        Mock Test-RecentWakeFromSleep { $true }
        Mock Test-EarlyTrustedNetwork { $true }
        (Invoke-EarlyVpnGate -NetworkInfo $script:HasIp).Reason | Should -Be 'wake_trusted'
        Mock Test-EarlyTrustedNetwork { $false }
        (Invoke-EarlyVpnGate -NetworkInfo $script:HasIp).Acted | Should -BeFalse
    }

    It 'disconnects a Reconnecting VPN on an SSID jump' {
        Set-Content -Path $script:SsidCacheFile -Value 'OldNet'
        Test-SsidJump -CurrentSsid 'WLANi03' | Should -BeTrue
        Mock Get-VpnState { 'Reconnecting' }
        Mock Test-RecentWakeFromSleep { $false }
        (Invoke-EarlyVpnGate -NetworkInfo $script:HasIp).Reason | Should -Be 'ssid_jump_blocking'
    }

    It 'skips the preflight probe while VPN is in an intermediate state' {
        Mock Get-VpnStateStable { 'Reconnecting' }
        Mock Get-NwCheckResult { [pscustomobject]@{ Status = 'online' } }
        $r = Invoke-GatedNwCheck
        $r.Status | Should -Be 'unreachable'
        $r.Reason | Should -Be 'vpn_state_not_settled'
        Should -Invoke Get-NwCheckResult -Times 0 -Exactly
    }

    It 'runs the preflight probe when VPN is Disconnected or Connected' {
        Mock Get-NwCheckResult { [pscustomobject]@{ Status = 'online' } }
        (Invoke-GatedNwCheck -KnownVpnState 'Connected').Status | Should -Be 'online'
        (Invoke-GatedNwCheck -KnownVpnState 'Disconnected').Status | Should -Be 'online'
        Should -Invoke Get-NwCheckResult -Times 2 -Exactly
    }
}
