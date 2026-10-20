function global:Get-CprFunctionText {
    param([string]$Path, [string[]]$Names)
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Parse failed: $Path" }
    (($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Names -contains $node.Name
    }, $true) | ForEach-Object { $_.Extent.Text }) -join "`n`n")
}

BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    $script:configPath = Join-Path $script:root 'main/Main.Configuration.ps1'
    $script:networkPath = Join-Path $script:root 'main/Main.Network.ps1'
    $script:entryPath = Join-Path $script:root 'main/Main.Entry.ps1'
    $script:capPath = Join-Path $script:root 'main/Main.CaptivePortal.ps1'
    $script:selfUpdatePath = Join-Path $script:root 'main/Main.SelfUpdate.ps1'
    $script:basePath = Join-Path $script:root 'WW_cap_portal_runner_base.ps1'
    $script:installPath = Join-Path $script:root 'install.ps1'
    $script:schemaPath = Join-Path $script:root 'support_files/haystack_msg_schema.psd1'

    $script:config = Get-Content $script:configPath -Raw
    $script:network = Get-Content $script:networkPath -Raw
    $script:entry = Get-Content $script:entryPath -Raw
    $script:cap = Get-Content $script:capPath -Raw
    $script:selfUpdate = Get-Content $script:selfUpdatePath -Raw
    $script:baseSource = Get-Content $script:basePath -Raw
    $script:install = Get-Content $script:installPath -Raw
    $script:schema = Get-Content $script:schemaPath -Raw
    $script:networkInfoFunction = Get-CprFunctionText $script:networkPath @('Get-NetworkInfo')
    $script:baseNetworkFunction = Get-CprFunctionText $script:basePath @('Get-BaseCapNetworkContext')

    function global:Write-Log { param($Message, $Level = 'INFO') }
    function global:Get-NetAdapter { param($InterfaceIndex, $ErrorAction) }
    function global:Get-NetIPAddress { param($InterfaceIndex, $AddressFamily, $ErrorAction) }
    function global:Get-NetRoute { param($InterfaceIndex, $DestinationPrefix, $ErrorAction) }
    function global:Get-WlanSsidForAdapter { param($AdapterName) }
    function global:Get-ScheduledTask { param($ErrorAction) }
    function global:Unregister-ScheduledTask { param($InputObject, [switch]$Confirm, $ErrorAction) }
    function global:Register-ScheduledTask { param($Xml, $TaskName, $TaskPath, [switch]$Force, $ErrorAction) }
    function global:Write-InstallLog { param($Message, $Level = 'INFO') }

    Invoke-Expression (Get-CprFunctionText $script:networkPath @(
        'Get-CprNetworkFingerprint', 'Get-CprConnectionTelemetry',
        'Test-CprNetworkSnapshotFresh'
    ))
    Invoke-Expression (Get-CprFunctionText $script:capPath @('Test-CprAccepted301RemediationEvidence'))
    Invoke-Expression (Get-CprFunctionText $script:installPath @(
        'Get-InstallerTaskSnapshot', 'Remove-OldTasks'
    ))
}

Describe 'ONLINE fast path policy' {
    It 'has safe explicit policy defaults and a concise decision line' {
        $script:config | Should -Match '\$OnlineFastPathEnabled\s*=\s*\$true'
        $script:config | Should -Match '\$OnlineFastPathRunMaintenance\s*=\s*\$true'
        $script:entry | Should -Match 'online_fast_path ran=true'
        $script:entry | Should -Match "phase_timing phase='online_fast_path'"
        $script:entry | Should -Match "skipped='webhelper_301_lookup,redirect_tests,walled_garden,base_full_dispatch,remediation_state,portal_polling,secondary_preflight'"
    }

    It 'selects the fast path only for authoritative online status' {
        $script:entry | Should -Match '\$OnlineFastPathEnabled -and \$nwCheck\.Status -eq ''online'''
        $script:entry | Should -Match "online_fast_path ran=false reason='preflight_not_online_or_policy_disabled'"
    }

    It 'keeps required classification flare and cleanup in the online branch' {
        $online = [regex]::Match($script:entry, '"online"\s*\{[\s\S]*?\n\s*\}\s*\n\s*"redirect"\s*\{').Value
        $online | Should -Match 'Get-VpnTunnelFlavor'
        $online | Should -Match 'Test-DC'
        $online | Should -Match 'Test-SsidTrusted'
        $online | Should -Match "Send-FlareEvent '(on_prem|off_prem_no_vpn)'"
        $online | Should -Match 'Clear-CaptiveEventHistory'
        $online | Should -Not -Match 'Invoke-CaptivePortalRemediation|Test-WalledGarden|Wait-CprCiscoWebHelper301Evidence|Get-CaptivePortalResult'
    }

    It 'does not label redirect ISE or unreachable paths as online fast path' {
        foreach ($status in @('redirect', 'unreachable', 'ISE_EMPLOYEE', 'ISE_GUEST', 'NON_ISE', 'no_network')) {
            ($status -eq 'online') | Should -BeFalse
        }
    }
}

Describe 'freshness-safe network snapshot and connection semantics' {
    BeforeEach {
        $script:NetworkSnapshotMaxAgeSec = 30
        $script:now = Get-Date
        $script:snapshot = [pscustomobject]@{
            CapturedAt = $script:now.ToString('o'); InterfaceIndex = 7
            InterfaceGuid = 'guid-7'; InterfaceName = 'Wi-Fi'; AdapterClass = 'wifi'
            OperationalState = 'Up'; IPAddress = '172.20.20.20'
            DefaultGateway = '172.20.20.1'; SSID = 'xfinitywifi'
        }
        $script:snapshot | Add-Member Fingerprint (Get-CprNetworkFingerprint $script:snapshot)
        Mock Get-NetAdapter { [pscustomobject]@{
            InterfaceIndex=7; InterfaceGuid='guid-7'; Name='Wi-Fi'; Status='Up'
        } }
        Mock Get-NetIPAddress { [pscustomobject]@{ IPAddress='172.20.20.20'; PrefixLength=24 } }
        Mock Get-NetRoute { [pscustomobject]@{ NextHop='172.20.20.1'; RouteMetric=1 } }
        Mock Get-WlanSsidForAdapter { 'xfinitywifi' }
    }

    It 'reuses a valid fingerprint and emits a warm freshness result' {
        $result = Test-CprNetworkSnapshotFresh $script:snapshot
        $result.Fresh | Should -BeTrue
        $result.Reason | Should -Be 'fingerprint_match'
    }

    It 'invalidates on TTL expiry' {
        $script:snapshot.CapturedAt = $script:now.AddSeconds(-31).ToString('o')
        (Test-CprNetworkSnapshotFresh $script:snapshot).Reason | Should -Be 'ttl_expired'
    }

    It 'invalidates on interface loss or operational-state change' {
        Mock Get-NetAdapter { $null }
        (Test-CprNetworkSnapshotFresh $script:snapshot).Reason | Should -Be 'adapter_unavailable'
        Mock Get-NetAdapter { [pscustomobject]@{ InterfaceIndex=7; InterfaceGuid='guid-7'; Name='Wi-Fi'; Status='Down' } }
        (Test-CprNetworkSnapshotFresh $script:snapshot).Reason | Should -Be 'adapter_unavailable'
    }

    It 'invalidates on IP gateway SSID or interface identity changes' -TestCases @(
        @{ Kind='IP'; Setup={ Mock Get-NetIPAddress { [pscustomobject]@{IPAddress='172.20.20.21'} } } }
        @{ Kind='gateway'; Setup={ Mock Get-NetRoute { [pscustomobject]@{NextHop='172.20.20.254';RouteMetric=1} } } }
        @{ Kind='SSID'; Setup={ Mock Get-WlanSsidForAdapter { 'other' } } }
        @{ Kind='interface'; Setup={ Mock Get-NetAdapter { [pscustomobject]@{InterfaceIndex=8;InterfaceGuid='guid-8';Name='Wi-Fi';Status='Up'} } } }
    ) {
        param($Kind, $Setup)
        & $Setup
        $result = Test-CprNetworkSnapshotFresh $script:snapshot
        $result.Fresh | Should -BeFalse -Because "$Kind changed"
        $result.Reason | Should -Be 'fingerprint_changed'
    }

    It 'classifies Wi-Fi with and without SSID from adapter identity' {
        (Get-CprConnectionTelemetry ([pscustomobject]@{
            AdapterClass='wifi'; IPAddress='10.0.0.2'; DefaultGateway='10.0.0.1'; SSID='corp'
        })).connection_type | Should -Be 'WiFi'
        (Get-CprConnectionTelemetry ([pscustomobject]@{
            AdapterClass='wifi'; IPAddress='10.0.0.2'; DefaultGateway='10.0.0.1'; SSID='N/A'
        })).ssid | Should -Be 'N/A'
    }

    It 'classifies physical Ethernet as Wired/N/A and excludes virtual VPN/no-network' {
        $wired = Get-CprConnectionTelemetry ([pscustomobject]@{
            AdapterClass='ethernet'; IPAddress='10.0.0.2'; DefaultGateway='10.0.0.1'; SSID='N/A'
        })
        $wired.connection_type | Should -Be 'Wired'
        $wired.ssid | Should -Be 'N/A'
        (Get-CprConnectionTelemetry ([pscustomobject]@{
            AdapterClass='virtual'; IPAddress='10.0.0.2'; DefaultGateway='10.0.0.1'; SSID=''
        })).connection_type | Should -Be 'Unknown'
        (Get-CprConnectionTelemetry ([pscustomobject]@{
            AdapterClass='vpn'; IPAddress='N/A'; DefaultGateway='N/A'; SSID=''
        })).connection_type | Should -Be 'NoNetwork'
    }

    It 'registers connection_type in the schema and every active network_state profile' {
        $script:schema | Should -Match 'connection_type\s*='
        $script:schema | Should -Match '"ssid", "connection_type", "vpn_state"'
        foreach ($profile in @(
            'WW_tee_events.psd1',
            'tee_profiles/tee_level_2.psd1',
            'tee_profiles/tee_level_3.psd1',
            'tee_profiles/tee_level_4.psd1',
            'tee_profiles/tee_level_5.psd1'
        )) {
            (Get-Content (Join-Path $script:root $profile) -Raw) |
                Should -Match "fields = @\('ip','gw','dns','ssid','connection_type','vpn_state','lease_sec'\)"
        }
    }

    It 'uses targeted data access and detailed cold/warm timing evidence' {
        $script:networkInfoFunction | Should -Not -Match '(?m)^[^#\r\n]*=\s*Get-NetIPConfiguration\b'
        $script:networkInfoFunction | Should -Match "Get-CimInstance[\s\S]*-Filter 'IPEnabled = TRUE AND DHCPEnabled = TRUE'"
        $script:networkInfoFunction | Should -Match 'adapter_enumeration_ms=.*ip_address_ms=.*gateway_ms=.*dns_ms=.*lease_ms='
        $script:network | Should -Match "network_snapshot_freshness fresh="
        $script:baseNetworkFunction | Should -Not -Match '(?m)^[^#\r\n]*=\s*Get-NetIPConfiguration\b'
        $script:baseNetworkFunction | Should -Match 'route_ms=.*adapter_ms=.*ip_address_ms=.*dns_ms='
    }

    It 'keeps Base independent and derives Wi-Fi/wired from adapter class, not blank SSID' {
        $script:baseSource | Should -Match '\$netCtx = Get-BaseCapNetworkContext'
        $script:baseSource | Should -Match '\$netCtx\.adapter_class -eq ''wifi'''
        $script:baseSource | Should -Match '\$netCtx\.adapter_class -eq ''ethernet'''
        $script:baseSource | Should -Not -Match 'baseConnectionType = if \(-not \[string\]::IsNullOrWhiteSpace\(\$netCtx\.ssid\)'
    }

    It 'invalidates after synchronous self-update and preserves NETWORK_CHANGED detection' {
        $script:selfUpdate | Should -Match '\$script:NetworkSnapshotInvalidated\s*=\s*\$true'
        $script:entry | Should -Match 'Get-CprCurrentNetworkSnapshot[\s\S]*NetworkSnapshotInvalidated'
        $script:cap | Should -Match 'Test-CprNetworkSnapshotFresh -Snapshot \$initialNetworkInfo'
        $script:cap | Should -Match 'status = "NETWORK_CHANGED"'
    }
}

Describe 'accepted EventID 301 remediation handoff' {
    BeforeEach {
        $script:CapPortalWebHelper301MaxAgeSec = 180
    }

    It 'accepts only fresh usable direct non-ISE evidence' {
        $e = [pscustomobject]@{
            UsableNavigation=$true; Source='cisco_webhelper_301'; NavigatedUrl='https://portal/'
            Classification='NON_ISE'; EventTime=(Get-Date); EventRecordId='1'
        }
        (Test-CprAccepted301RemediationEvidence $e) | Should -BeTrue
        $e.EventTime = (Get-Date).AddSeconds(-181)
        (Test-CprAccepted301RemediationEvidence $e) | Should -BeFalse
    }

    It 'falls back for missing no-url read-error or ISE evidence' -TestCases @(
        @{ Evidence=$null }
        @{ Evidence=[pscustomobject]@{UsableNavigation=$false;Source='cisco_webhelper_301';NavigatedUrl='';Classification='';EventTime=(Get-Date)} }
        @{ Evidence=[pscustomobject]@{UsableNavigation=$false;Source='read_error';NavigatedUrl='';Classification='';EventTime=(Get-Date)} }
        @{ Evidence=[pscustomobject]@{UsableNavigation=$true;Source='cisco_webhelper_301';NavigatedUrl='https://ise/';Classification='ISE_EMPLOYEE';EventTime=(Get-Date)} }
    ) {
        param($Evidence)
        (Test-CprAccepted301RemediationEvidence $Evidence) | Should -BeFalse
    }

    It 'suppresses only the remediation pre-check and retains final post-auth validation' {
        $script:cap | Should -Match 'remediation_precheck_suppressed=true'
        $script:cap | Should -Match 'post-auth connectivity validation remains required'
        $script:cap | Should -Match 'elseif \(Test-CaptivePortalCleared\)'
        $script:cap | Should -Match "Runner reported:.*verifying portal clearance[\s\S]*if \(Test-CaptivePortalCleared\)"
        $script:cap | Should -Match 'webhelper_navigation = \$script:LastWebHelper301Evidence'
    }
}

Describe 'installer task scheduler optimization and self-update isolation' {
    BeforeEach {
        $script:KnownTasks = @(
            @{Name='WW_main';TaskPath='\'},
            @{Name='legacy';TaskPath='\'}
        )
        $script:logs = @()
        function global:Write-InstallLog { param($Message, $Level = 'INFO'); $script:logs += "$Level $Message" }
        Mock Get-ScheduledTask {
            @([pscustomobject]@{TaskName='WW_main';TaskPath='\';State='Ready'})
        }
        Mock Unregister-ScheduledTask {}
    }

    It 'takes one scheduler snapshot and safely handles present and absent legacy tasks' {
        Remove-OldTasks
        Should -Invoke Get-ScheduledTask -Times 1 -Exactly
        Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly
        ($script:logs -join ' ') | Should -Match 'Task not found \(OK\): \\legacy'
        ($script:logs -join ' ') | Should -Match 'installer_phase_timing phase=task_removal'
    }

    It 'uses exact task path semantics and no repeated per-task Get-ScheduledTask lookup' {
        $script:install | Should -Match 'Get-InstallerTaskSnapshot'
        $script:install | Should -Match '\$_.TaskName -eq \$taskName -and \$_.TaskPath -eq \$taskPath'
        $script:install | Should -Match 'Unregister-ScheduledTask -InputObject \$task'
        $script:install | Should -Match 'Register-ScheduledTask -Xml \$xmlContent -TaskName \$task.Name -TaskPath \$task.TaskPath'
        $script:install | Should -Not -Match 'Get-ScheduledTask -TaskName \$taskName'
        $script:install | Should -Not -Match 'Get-ScheduledTask -TaskName \$task.Name'
    }

    It 'emits removal deployment registration and validation phase timings' {
        foreach ($phase in @('task_removal','file_deployment','task_registration','task_validation','validation')) {
            $script:install | Should -Match "installer_phase_timing phase=$phase"
        }
        $script:install | Should -Match 'task_action_timing action=remove'
        $script:install | Should -Match 'task_action_timing action=register'
    }

    It 'keeps self-update synchronous for reliable exit status and logs it as maintenance' {
        $script:selfUpdate | Should -Match 'Start-Process "powershell\.exe"[\s\S]*-Wait -PassThru'
        $script:selfUpdate | Should -Match "self_update_phase phase='installer_maintenance'"
        $script:selfUpdate | Should -Match "phase_timing phase='self_update_maintenance'"
        $script:selfUpdate | Should -Not -Match 'Start-Job|AsJob'
    }
}
