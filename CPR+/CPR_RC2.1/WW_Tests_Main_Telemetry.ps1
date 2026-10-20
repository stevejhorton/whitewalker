Describe 'WW_main telemetry wiring' {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot 'WW_main.ps1'
        $null = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
        if ($errors) { throw "Failed to parse WW_main.ps1" }

        $wanted = @('Write-RunHeader','Sync-BlackholeShutdownTask','Sync-XmlVaultTask','Test-TaskRegistered')
        $functionAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $wanted -contains $node.Name
        }, $true)

        $functionSource = ($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n"
        Invoke-Expression $functionSource

        function Add-LogLine { param([string]$Line) }
        function Write-Log { param([string]$Message, [string]$Level = 'INFO') }
        function Write-TeeLog { param([string]$Tag, [hashtable]$Data) }
        function Get-ScheduledTask { param([string]$TaskName) return $null }
        function Register-ScheduledTask { param([string]$TaskName, [string]$Xml, [switch]$Force) }
        function Unregister-ScheduledTask { param([string]$TaskName, [switch]$Confirm) }
        function Get-SystemContext {
            [pscustomobject]@{
                OS = 'test-os'
                Model = 'test-model'
                SerialNumber = 'test-serial'
                LastBootTime = '2026-01-01 00:00:00'
            }
        function Get-CiscoSecureClientInfo {
            [pscustomobject]@{ CoreVersion = '1.0.0'; Source = 'test'; Modules = @() }
        }
    }

    BeforeEach {
        $script:RunId = 'run-1'
        $script:HostNm = 'host-1'
        $script:UserNm = 'user-1'
        $script:ver = '3.14.0_TEST'
        $script:LogPath = 'C:\\ProgramData\\WhiteWalker\\logs\\white_walker.main.log'
        $script:BlackholeEnabled = $false
        $script:BlackholeScriptPath = 'C:\\ProgramData\\WhiteWalker\\Set-VpnHostsEntry.ps1'
        $script:BlackholeFlagFile = 'C:\\ProgramData\\WhiteWalker\\vpn_blocked.flag'
        $script:HaystackEnabled = $true
        $script:HaystackScriptPath = 'C:\\ProgramData\\WhiteWalker\\haystack.ps1'
        $script:TeeEnabled = $true
        $script:TeeEventsFile = 'C:\\ProgramData\\WhiteWalker\\WW_tee_events.psd1'
        $script:XmlVaultEnabled = $true
        $script:XmlVaultScriptPath = 'C:\\ProgramData\\WhiteWalker\\WW_xml_vault.ps1'
        $script:CapPortalRunnerMode = 'base'
        $script:CapPortalBaseScriptPath = 'C:\\ProgramData\\WhiteWalker\\WW_cap_portal_runner_base.ps1'

        Mock Add-LogLine {}
        Mock Write-Log {}
        Mock Test-Path { $false }
        Mock Write-TeeLog {}
    }

    It 'emits vpn_profile_missing when VPN profile is not set' {
        Mock Get-ItemProperty { [pscustomobject]@{ VPN = $null } }

        Write-RunHeader

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            $Tag -eq 'vpn_profile_missing'
        }
    }

    It 'emits subsystem_task_sync_failed when blackhole task XML is missing' {
        $script:BlackholeEnabled = $true
        $script:BlackholeShutdownTaskName = 'WW_blackhole_shutdown_test'
        $script:BlackholeShutdownTaskXml = 'C:\\missing\\WW_blackhole_shutdown.xml'

        Mock Test-TaskRegistered { $false }
        Mock Test-Path { $false }

        Sync-BlackholeShutdownTask

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            $Tag -eq 'subsystem_task_sync_failed' -and
            $Data.subsystem -eq 'blackhole_shutdown' -and
            $Data.operation -eq 'register' -and
            $Data.reason -eq 'task_xml_missing'
        }
    }

    It 'emits subsystem_task_sync_failed when XmlVault task unregister fails' {
        $script:XmlVaultEnabled = $false
        $script:XmlVaultTaskName = 'WW_xml_vault_test'

        Mock Test-TaskRegistered { $true }
        Mock Unregister-ScheduledTask { throw 'boom' }

        Sync-XmlVaultTask

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            $Tag -eq 'subsystem_task_sync_failed' -and
            $Data.subsystem -eq 'xml_vault' -and
            $Data.operation -eq 'unregister' -and
            $Data.reason -eq 'unregister_failed'
        }
    }
}

# =============================================================================
# cap_portal_redirect wiring for base-mode walled-garden detection (RC1.24)
# =============================================================================
Describe 'WW_main walled-garden cap_portal_redirect wiring (base mode)' {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot 'WW_main.ps1'
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
        if ($errors) { throw "Failed to parse WW_main.ps1" }

        $wanted = @('Get-CaptivePortalRedirectTelemetry')
        $functionAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $wanted -contains $node.Name
        }, $true)
        $functionSource = ($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n"
        Invoke-Expression $functionSource

        function Write-Log { param([string]$Message, [string]$Level = 'INFO') }

        $script:rawSource = Get-Content -Path $scriptPath -Raw
    }

    It 'builds cap_portal_redirect telemetry from the walled-garden gateway IP (same helper full mode uses)' {
        $telemetry = Get-CaptivePortalRedirectTelemetry -RedirectUrl "http://192.168.1.1"

        $telemetry.url  | Should -Be "http://192.168.1.1"
        $telemetry.port | Should -Be "80"
    }

    It 'fires Write-TeeLog cap_portal_redirect before Send-FlareEvent captive_portal_browser_base in the walled-garden base-mode branch' {
        # The walled-garden detection branch is inline top-level script flow (not a
        # standalone function), so assert on source ordering/shape directly - this
        # is the same code path covered by the problem statement's root cause:
        # Invoke-CaptivePortalRemediation already fires cap_portal_redirect (line
        # ~3001) for the ISE_GUEST/NON_ISE paths; the walled-garden branch bypasses
        # that function entirely (no RedirectUrl - DNS-blocking portal) and must
        # ship its own cap_portal_redirect before pivoting on $CapPortalRunnerMode.
        $pivotIndex    = $script:rawSource.IndexOf('if ($CapPortalRunnerMode -eq "base") {')
        $walledGardenIndex = $script:rawSource.IndexOf('WALLED GARDEN CAPTIVE PORTAL DETECTED')
        $redirectIndex = $script:rawSource.IndexOf("Write-TeeLog 'cap_portal_redirect'", $walledGardenIndex)
        $baseFireIndex = $script:rawSource.IndexOf("Send-FlareEvent 'captive_portal_browser_base'", $walledGardenIndex)

        $walledGardenIndex | Should -BeGreaterThan -1
        $redirectIndex     | Should -BeGreaterThan $walledGardenIndex
        $baseFireIndex     | Should -BeGreaterThan $redirectIndex
    }

    It 'only ships one cap_portal_redirect for the walled-garden branch (no double-fire across full/base)' {
        $walledGardenIndex = $script:rawSource.IndexOf('WALLED GARDEN CAPTIVE PORTAL DETECTED')
        $nextWalledGardenBlockEnd = $script:rawSource.IndexOf('Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob', $walledGardenIndex)
        $segment = $script:rawSource.Substring($walledGardenIndex, $nextWalledGardenBlockEnd - $walledGardenIndex)

        ([regex]::Matches($segment, "Write-TeeLog 'cap_portal_redirect'")).Count | Should -Be 1
    }
}

# =============================================================================
# RC1.25 - normalized cap_portal_* payload contract
# =============================================================================
Describe 'WW_main RC1.25 normalized cap_portal telemetry' {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot 'WW_main.ps1'
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
        if ($errors) { throw "Failed to parse WW_main.ps1" }

        $wanted = @('ConvertTo-TelemetryValue','Get-CaptivePortalNetworkContext','Write-CaptivePortalOutcomeTelemetry','Get-CaptivePortalRedirectTelemetry')
        $functionAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $wanted -contains $node.Name
        }, $true)

        $functionSource = ($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n"
        Invoke-Expression $functionSource

        function Write-Log { param([string]$Message, [string]$Level = 'INFO') }
        function Write-TeeLog { param([string]$Tag, [hashtable]$Data) }

        $script:rawSource = Get-Content -Path $scriptPath -Raw
    }

    BeforeEach {
        Mock Write-Log {}
        Mock Write-TeeLog {}
        $networkInfo = [pscustomobject]@{
            SSID           = 'CorpGuest'
            IPAddress      = '10.20.30.40'
            DefaultGateway = '10.20.30.1'
            DNSServers     = @('10.20.30.1', '8.8.8.8')
        }
    }

    It 'normalizes the "not determined" placeholder <Placeholder> to an empty string' -TestCases @(
        @{ Placeholder = 'N/A' }
        @{ Placeholder = 'Unknown' }
        @{ Placeholder = 'none' }
        @{ Placeholder = '   ' }
        @{ Placeholder = $null }
    ) {
        param($Placeholder)
        ConvertTo-TelemetryValue $Placeholder | Should -Be ''
    }

    It 'keeps a real value untouched' {
        ConvertTo-TelemetryValue '10.20.30.40' | Should -Be '10.20.30.40'
    }

    It 'reads ssid/ip/gw/dns from the current run networkInfo snapshot' {
        $ctx = Get-CaptivePortalNetworkContext

        $ctx.ssid | Should -Be 'CorpGuest'
        $ctx.ip   | Should -Be '10.20.30.40'
        $ctx.gw   | Should -Be '10.20.30.1'
        $ctx.dns  | Should -Be '10.20.30.1,8.8.8.8'
    }

    It 'emits explicit empty fields (never fabricated values) when no snapshot is available' {
        $networkInfo = $null
        $ctx = Get-CaptivePortalNetworkContext

        $ctx.ip | Should -Be ''
        $ctx.gw | Should -Be ''
        Should -Invoke Write-Log -ParameterFilter { $Level -eq 'DEBUG' }
    }

    It 'ships every required normalized field, including a locally stamped EvtTime' {
        Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_passed' `
            -RedirectTelemetry @{ url = 'http://portal.example.com'; port = '80' } `
            -PortalType 'ISE_GUEST' -Status 'verified' -Reason 'ise_guest_flow' -VpnState 'Disconnected'

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            $Tag -eq 'cap_portal_remediation_passed' -and
            -not [string]::IsNullOrEmpty($Data.EvtTime) -and
            $Data.url -eq 'http://portal.example.com' -and
            $Data.port -eq '80' -and
            $Data.ssid -eq 'CorpGuest' -and
            $Data.ip -eq '10.20.30.40' -and
            $Data.gw -eq '10.20.30.1' -and
            $Data.dns -eq '10.20.30.1,8.8.8.8' -and
            $Data.vpn_state -eq 'Disconnected' -and
            $Data.portal_type -eq 'ISE_GUEST' -and
            $Data.status -eq 'verified' -and
            $Data.reason -eq 'ise_guest_flow'
        }
    }

    It 'prefers an explicitly supplied SSID over the snapshot value' {
        Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_failed' -Ssid 'OtherSSID' -Status 'timeout'

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter { $Data.ssid -eq 'OtherSSID' }
    }

    It 'exposes protocol/fqdn on the redirect telemetry so the base runner can reuse them' {
        $telemetry = Get-CaptivePortalRedirectTelemetry -RedirectUrl 'https://portal.example.com:8443/login'

        $telemetry.protocol | Should -Be 'https'
        $telemetry.fqdn     | Should -Be 'portal.example.com'
        $telemetry.port     | Should -Be '8443'
    }

    It 'writes the enriched remediation state file so the separate base runner has real context' {
        $script:rawSource | Should -Match 'cap_portal_remediation_active\.flag'
        foreach ($field in @('ssid','ip','gw','dns','vpn_state','url','port','protocol','fqdn')) {
            $script:rawSource | Should -Match "(?m)^\s+$field\s+="
        }
    }
}
