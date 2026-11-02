# Behavior tests for the RC2.1 early VPN gate (Pester 5). Functions are pulled out of
# the real source via AST, so these test the shipped code, not a copy.

Describe 'CPR RC2.1 early VPN gate' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $want = 'Test-AnyUsableIp', 'Test-SsidJump', 'Invoke-EarlyVpnGate', 'Invoke-GatedNwCheck', 'Test-XmlVaultSyncAllowed', 'Test-DcPing', 'Invoke-ConnectedUnreachableTriage', 'Test-DcPing', 'Invoke-ConnectedUnreachableTriage'
        foreach ($f in 'Main.VpnState.ps1', 'Main.SsidChange.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root "main\$f"), [ref]$null, [ref]$null)
            $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $want }, $true)
            foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
        }
        function Write-Log { param($m, $l) }
        function Write-TeeLog { param($a, $b) }
        function Get-VpnState { 'Disconnected' }
        function Test-OnPremBySuffix { $false }
        function Get-VpnStateStable { param($TimeoutSec) 'Disconnected' }
        function Test-RecentWakeFromSleep { param($TimeWindowSeconds) $false }
        function Invoke-EarlyVpnDisconnect { param($Reason, $VpnStateWas) $true }
        function Get-NwCheckResult { param($Url) [pscustomobject]@{ Status = 'online' } }
        function Start-Sleep { param($Seconds) }
        $script:StaleConnectedMaxWaitSec = 8
        $script:StaleConnectedPollSec = 2
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

    It 'never disconnects a fully Connected VPN, even after wake or SSID jump' {
        Mock Get-VpnState { 'Connected' }
        Mock Test-RecentWakeFromSleep { $true }
        Mock Invoke-EarlyVpnDisconnect { $true }
        Set-Content -Path $script:SsidCacheFile -Value 'OldNet'
        $r = Invoke-EarlyVpnGate -NetworkInfo $script:HasIp
        $r.Acted | Should -BeFalse
        $r.Wake | Should -BeTrue
        $r.Jump | Should -BeTrue
        Should -Invoke Invoke-EarlyVpnDisconnect -Times 0 -Exactly
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

    It 'allows XmlVault sync on-prem, or when VPN is Connected; blocks otherwise' {
        $script:LastVpnStateAt = $null
        Mock Test-OnPremBySuffix { $true }
        Test-XmlVaultSyncAllowed | Should -BeTrue
        Mock Test-OnPremBySuffix { $false }
        Mock Get-VpnState { 'Connected' }
        Test-XmlVaultSyncAllowed | Should -BeTrue
        Mock Get-VpnState { 'Disconnected' }
        Test-XmlVaultSyncAllowed | Should -BeFalse
    }

    It 'reuses a fresh cached VPN state instead of calling vpncli' {
        Mock Test-OnPremBySuffix { $false }
        Mock Get-VpnState { 'Disconnected' }
        $script:LastVpnState = 'Connected'; $script:LastVpnStateAt = Get-Date
        Test-XmlVaultSyncAllowed | Should -BeTrue
        Should -Invoke Get-VpnState -Times 0 -Exactly
    }

    Context 'Maintenance stage' {
        BeforeAll {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.Entry.ps1'), [ref]$null, [ref]$null)
            $d = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Invoke-MaintenanceStage', 'Write-MaintStep' }, $true)
            # exit reasons are <reason>:<state>; the maintenance offline check parses them
            $script:CprExitStates = @('on_prem','user_tun','mgmt_tun','off_prem_no_vpn','vpn_connecting','captive_portal','no_net_transient','cpr_error')
            $stAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.State.ps1'), [ref]$null, [ref]$null)
            foreach ($sd in $stAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Get-CprExitState', 'Get-CprExitReasonPart' }, $true)) { . ([scriptblock]::Create($sd.Extent.Text)) }
            foreach ($f in $d) { . ([scriptblock]::Create($f.Extent.Text)) }
            function Sync-BlackholeShutdownTask { }
            function Sync-XmlVaultTask { }
            function Invoke-SelfUpdate { }
            function Invoke-HaystackDrainKick { param($CorpReachable) }
            $script:HaystackEnabled = $false
            $script:XmlVaultEnabled = $false
            $script:WhatIf = $false
        }
        BeforeEach { $script:maintenanceRan = $false }

        It 'runs local task syncs but skips self-update when offline' {
            Mock Sync-BlackholeShutdownTask { }
            Mock Sync-XmlVaultTask { }
            Mock Invoke-SelfUpdate { }
            Mock Test-XmlVaultSyncAllowed { $true }
            Invoke-MaintenanceStage -ExitReason 'apipa_no_gateway:no_net_transient'
            Should -Invoke Sync-BlackholeShutdownTask -Times 1 -Exactly
            Should -Invoke Invoke-SelfUpdate -Times 0 -Exactly
        }
        It 'skips self-update when the share is unreachable' {
            Mock Invoke-SelfUpdate { }
            Mock Test-XmlVaultSyncAllowed { $false }
            Invoke-MaintenanceStage -ExitReason 'untrusted:off_prem_no_vpn'
            Should -Invoke Invoke-SelfUpdate -Times 0 -Exactly
        }
        It 'runs self-update when online and the share is reachable, once per run' {
            Mock Invoke-SelfUpdate { }
            Mock Test-XmlVaultSyncAllowed { $true }
            Invoke-MaintenanceStage -ExitReason 'no_action_dc_reachable:on_prem'
            Invoke-MaintenanceStage -ExitReason 'no_action_dc_reachable:on_prem'
            Should -Invoke Invoke-SelfUpdate -Times 1 -Exactly
        }
    }

    Context 'Connected-but-unreachable triage' {
        It 'dc_reachable: DC answers, preflight retried once, no polling' {
            Mock Test-DcPing { $true }
            Mock Get-VpnState { 'Connected' }
            Mock Invoke-GatedNwCheck { [pscustomobject]@{ Status = 'online' } }
            $r = Invoke-ConnectedUnreachableTriage
            $r.Outcome | Should -Be 'dc_reachable'
            $r.Preflight | Should -Be 'online'
            Should -Invoke Get-VpnState -Times 0 -Exactly
        }
        It 'state_left_connected: stale Connected flips to Reconnecting while polling' {
            Mock Test-DcPing { $false }
            Mock Get-VpnState { 'Reconnecting' }
            Mock Invoke-GatedNwCheck { [pscustomobject]@{ Status = 'online' } }
            $r = Invoke-ConnectedUnreachableTriage
            $r.Outcome | Should -Be 'state_left_connected'
            $r.VpnState | Should -Be 'Reconnecting'
            Should -Invoke Invoke-GatedNwCheck -Times 0 -Exactly
        }
        It 'dc_recovered: DC starts answering during the poll' {
            $script:pings = 0
            Mock Test-DcPing { $script:pings++; $script:pings -ge 3 }
            Mock Get-VpnState { 'Connected' }
            Mock Invoke-GatedNwCheck { [pscustomobject]@{ Status = 'unreachable' } }
            $r = Invoke-ConnectedUnreachableTriage
            $r.Outcome | Should -Be 'dc_recovered'
            $r.DcReachable | Should -BeTrue
        }
        It 'timeout: nothing changes inside the window (bounded)' {
            $script:StaleConnectedMaxWaitSec = 0
            Mock Test-DcPing { $false }
            Mock Get-VpnState { 'Connected' }
            $r = Invoke-ConnectedUnreachableTriage
            $r.Outcome | Should -Be 'timeout'
            $script:StaleConnectedMaxWaitSec = 8
        }
    }
}
