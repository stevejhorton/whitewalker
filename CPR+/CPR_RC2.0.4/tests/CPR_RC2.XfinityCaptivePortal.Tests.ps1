# CPR_RC2.XfinityCaptivePortal.Tests.ps1
#
# Focused regression tests for the four defects proven by the live xfinitywifi
# run (CPR v3.14.0_RC2.0, cap_portal_runner_mode=base):
#   1. Test-WalledGarden pinged a stale route-table gateway (10.10.69.1) instead
#      of the live adapter gateway (172.20.20.1) Get-NetworkInfo already had.
#   2. An inconclusive gateway.optum.com preflight was treated as "no portal"
#      and exited no_net_transient, so Event 778 never fired.
#   3. Base never ran its own empirical redirect probe.
#   4. FlareGun dispatch produced no normalized telemetry.
#
# AST-extraction style, per repository convention.

function global:Get-CprFunctionSource {
    param([string]$Path, [string[]]$Names)

    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Failed to parse $Path" }

    $found = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Names -contains $node.Name
    }, $true)

    return (($found | ForEach-Object { $_.Extent.Text }) -join "`n`n")
}

Describe 'Defect 1 - Test-WalledGarden gateway selection' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'main/Main.Network.ps1') -Names @('Test-WalledGarden'))

        function Write-Log { param([string]$Message, [string]$Level = 'INFO') $script:wgLogs += $Message }
        function Get-NetRoute { param($DestinationPrefix, $ErrorAction) return @([PSCustomObject]@{ NextHop = '10.10.69.1'; RouteMetric = 1 }) }
        function Test-Connection {
            param($ComputerName, $Count, [switch]$Quiet, $ErrorAction)
            $script:pingedHosts += $ComputerName
            return $false
        }
    }

    BeforeEach {
        $script:wgLogs = @()
        $script:pingedHosts = @()
    }

    It 'prefers the supplied primary adapter gateway over its own route lookup' {
        $result = Test-WalledGarden -PrimaryGateway '172.20.20.1'

        $script:pingedHosts | Should -Contain '172.20.20.1'
        $script:pingedHosts | Should -Not -Contain '10.10.69.1'
        $result.GatewayIP | Should -Be '172.20.20.1'
        $result.GatewaySource | Should -Be 'adapter'
    }

    It 'logs clearly when the route table disagrees with the adapter gateway' {
        Test-WalledGarden -PrimaryGateway '172.20.20.1' | Out-Null

        ($script:wgLogs -join "`n") | Should -Match 'DISAGREES'
        ($script:wgLogs -join "`n") | Should -Match '10\.10\.69\.1'
        ($script:wgLogs -join "`n") | Should -Match '172\.20\.20\.1'
    }

    It 'falls back to the route-table gateway when none is supplied' {
        $result = Test-WalledGarden

        $result.GatewayIP | Should -Be '10.10.69.1'
        $result.GatewaySource | Should -Be 'route_table'
        ($script:wgLogs -join "`n") | Should -Match 'falling back to route-table gateway'
    }

    It 'ignores placeholder adapter gateways and falls back' {
        $result = Test-WalledGarden -PrimaryGateway 'N/A'
        $result.GatewayIP | Should -Be '10.10.69.1'
        $result.GatewaySource | Should -Be 'route_table'
    }

    It 'still reports gateway_unreachable when nothing is pingable' {
        (Test-WalledGarden -PrimaryGateway '172.20.20.1').Reason | Should -Be 'gateway_unreachable'
        (Test-WalledGarden -PrimaryGateway '172.20.20.1').IsWalledGarden | Should -BeFalse
    }
}

Describe 'Defect 2 - inconclusive preflight is not "no captive portal"' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:entrySource = Get-Content (Join-Path $root 'main/Main.Entry.ps1') -Raw
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'main/Main.Network.ps1') -Names @('Test-PlausibleLocalNetwork'))
    }

    It 'treats a real IP plus a real gateway as a plausible local network' {
        $r = Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{ IPAddress = '172.20.20.20/24'; DefaultGateway = '172.20.20.1' })
        $r.IsPlausible | Should -BeTrue
        $r.Ip | Should -Be '172.20.20.20'
        $r.Gateway | Should -Be '172.20.20.1'
    }

    It 'rejects APIPA, missing IP, and missing gateway' {
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{ IPAddress = '169.254.10.5'; DefaultGateway = '169.254.10.1' })).Reason | Should -Be 'apipa_ip'
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{ IPAddress = 'N/A'; DefaultGateway = '172.20.20.1' })).Reason | Should -Be 'no_ip'
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{ IPAddress = '172.20.20.20/24'; DefaultGateway = 'N/A' })).Reason | Should -Be 'no_default_gateway'
        (Test-PlausibleLocalNetwork -NetworkInfo $null).IsPlausible | Should -BeFalse
    }

    It 'passes the primary adapter gateway into Test-WalledGarden' {
        $script:entrySource | Should -Match 'Test-WalledGarden -PrimaryGateway \$networkInfo\.DefaultGateway'
    }

    It 'fires Event 778 for a suspected portal in base mode with a plausible local network' {
        $script:entrySource | Should -Match "\`$CapPortalRunnerMode -eq 'base' -and \`$localNet\.IsPlausible"
        $script:entrySource | Should -Match "Send-FlareEvent 'captive_portal_browser_base'"
        $script:entrySource | Should -Match 'SUSPECTED captive portal'
        $script:entrySource | Should -Match 'Set-CprRunExit -Reason ''portal_suspected'' -State ''captive_portal'''
    }

    It 'writes the suspected remediation state file and normalized detection telemetry' {
        $script:entrySource | Should -Match "portal_type = `"suspected`""
        # RC2.1: the artifact is now written through the atomic temp+move
        # writer in Main.CaptivePortal.ps1, which also stamps created_at,
        # run_id, network identity and the effective escalation flag.
        $script:entrySource | Should -Match 'Write-CapPortalRemediationState -State \$suspectPayload'
        $script:entrySource | Should -Match "portal_type = 'suspected'"
        $script:entrySource | Should -Match "status      = 'suspected'"
        $script:entrySource | Should -Match 'preflight_inconclusive'
    }

    It 'does not cancel the Base handoff when the walled-garden test is negative' {
        # The suspected-portal branch lives inside the walled-garden-negative else
        # block and returns before no_net_transient can be set.
        $negative = [regex]::Match($script:entrySource, "WalledGarden test negative[\s\S]*?Invoke-BlackholeAction -Tag 'no_net_transient'").Value
        $negative | Should -Match 'captive_portal_browser_base'
        $negative.IndexOf('captive_portal_browser_base') | Should -BeLessThan $negative.IndexOf("Send-FlareEvent `"no_net_transient`"")
    }

    It 'still falls through to no_net_transient with no plausible local network or outside base mode' {
        $script:entrySource | Should -Match 'Set-CprRunExit -Reason ''nwcheck_unreachable_enroll_no_redirect'' -State ''no_net_transient'''
        $script:entrySource | Should -Match 'Send-FlareEvent "no_net_transient"'
        $script:entrySource | Should -Match "Invoke-BlackholeAction -Tag 'no_net_transient'"
    }

    It 'leaves the ISE_EMPLOYEE posture-rescan path untouched (base-mode regression guard)' {
        # Posture rescan must not be gated on runner mode anywhere.
        $script:entrySource | Should -Match "Send-FlareEvent 'ise_employee_posture_redirect'"
        $script:entrySource | Should -Match 'Invoke-PostureRescan'
        $script:entrySource | Should -Match 'On-prem unpostured: enroll\.cisco\.com'
        ([regex]::Matches($script:entrySource, 'Invoke-PostureRescan')).Count | Should -BeGreaterOrEqual 3

        $iseBranch = [regex]::Match($script:entrySource, 'On-prem unpostured: enroll[\s\S]*?ise_employee_failed_\$complianceResult').Value
        $iseBranch | Should -Not -Match 'CapPortalRunnerMode'
        $iseBranch | Should -Not -Match 'captive_portal_browser_base'
    }
}

Describe 'Defect 3 - Base does its own redirect detection' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:basePath = Join-Path $root 'WW_cap_portal_runner_base.ps1'
        $script:baseSource = Get-Content $script:basePath -Raw
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath -Names @('Get-BaseCapRedirectType', 'Set-BaseCapPreflightStatus', 'Write-BaseCapPreflightFinding'))
        function Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') $script:baseLogs += $Message }
    }

    BeforeEach { $script:baseLogs = @() }

    It 'treats ISE 200-with-Location as a redirect, not just 3xx' {
        $r = Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '200'; redirect_url = 'https://isepsn01.uhc.com/portal'; status = 'unreachable'; reason = '' })
        $r.status | Should -Be 'redirect'
        $r.reason | Should -Be 'http_2xx_with_location'

        $r3 = Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '302'; redirect_url = 'https://cp-webapp.wifi.connected.xfinity.com/'; status = 'unreachable'; reason = '' })
        $r3.status | Should -Be 'redirect'
        $r3.reason | Should -Be 'http_3xx_location'
    }

    It 'keeps 200/404 without a Location header as online' {
        (Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '200'; redirect_url = ''; status = 'unreachable'; reason = '' })).status | Should -Be 'online'
        (Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '404'; redirect_url = ''; status = 'unreachable'; reason = '' })).status | Should -Be 'online'
    }

    It 'classifies ISE_EMPLOYEE / ISE_GUEST / NON_ISE exactly like Main' {
        Get-BaseCapRedirectType -RedirectUrl 'https://isepsn01.uhc.com/portal' | Should -Be 'ISE_EMPLOYEE'
        Get-BaseCapRedirectType -RedirectUrl 'https://isegst01.uhc.com/guest'  | Should -Be 'ISE_GUEST'
        Get-BaseCapRedirectType -RedirectUrl 'https://cp-webapp.wifi.connected.xfinity.com/' | Should -Be 'NON_ISE'
        Get-BaseCapRedirectType -RedirectUrl '' | Should -Be 'UNKNOWN'
    }

    It 'renders the finding in Main-style readable log lines' {
        Write-BaseCapPreflightFinding -Observation ([PSCustomObject]@{ status = 'redirect'; redirect_url = 'https://cp-webapp.wifi.connected.xfinity.com/'; redirect_type = 'NON_ISE'; http_status = '302'; reason = '' })
        ($script:baseLogs -join "`n") | Should -Match 'nwcheck: REDIRECT to https://cp-webapp\.wifi\.connected\.xfinity\.com/'
        ($script:baseLogs -join "`n") | Should -Match 'Redirect classification: NON_ISE'
        ($script:baseLogs -join "`n") | Should -Match 'no browser launch, no process kill, no VPN change, no posture rescan'
    }

    It 'polls the empirical probe instead of probing once' {
        $script:baseSource | Should -Match '\$BasePreflightMaxProbes\s*=\s*\d+'
        $script:baseSource | Should -Match '\$preflightProbes -lt \$BasePreflightMaxProbes'
        $script:baseSource | Should -Match 'Base empirical probe attempt'
    }

    It 'uses a bounded pre-start lookback for Cisco EventID 301 and still dedupes' {
        $script:baseSource | Should -Match '\$CiscoWebHelperLookbackSeconds\s*=\s*\d+'
        $script:baseSource | Should -Match '\$webHelperSince = \$startTime\.AddSeconds\(-\$CiscoWebHelperLookbackSeconds\)'
        $script:baseSource | Should -Match 'Get-CiscoWebHelperNavigationEvent -Since \$webHelperSince[\s\S]{0,200}?-MaxEvents \$BaseWebHelper301MaxRecords[\s\S]{0,200}?-SeenProcessIds \$seenWebHelperPids'
        $script:baseSource | Should -Match '\$seenWebHelperPids\[\$webHelperEvent\.DedupeKey\] = \$true'
    }

    It 'takes no remediation action on its own finding' {
        $script:baseSource | Should -Not -Match 'Start-Process\s+.*msedge'
        $script:baseSource | Should -Not -Match 'Stop-Process'
        $script:baseSource | Should -Not -Match 'Invoke-PostureRescan'
        $script:baseSource | Should -Match 'function Invoke-BaseCapVpnDisconnect \{ return \$false \}'
        $script:baseSource | Should -Match 'AllowAutoRedirect = \$false'
    }

    It 'ships and hands back the classification' {
        $script:baseSource | Should -Match "redirect_type = \[string\]\`$Observation\.redirect_type"
        $script:baseSource | Should -Match 'Base-discovered redirect finding'
        $script:baseSource | Should -Match '-PreflightObservation \$basePreflightObservation'
    }

    It 'renders the Base redirect classification back in white_walker.main.log' {
        $captive = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'main/Main.CaptivePortal.ps1') -Raw
        $captive | Should -Match 'Base nwcheck: REDIRECT to'
        $captive | Should -Match 'Base redirect classification:'
    }
}

Describe 'Defect 4 - FlareGun lifecycle telemetry' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'main/Main.FlareGun.ps1') -Names @('Send-FlareEvent', 'Write-FlareTelemetry', 'Get-FlareTelemetryContext'))

        function Write-Log { param([string]$Message, [string]$Level = 'INFO') }
        function In-Cooldown { param($Tag, $Minutes) return $script:inCooldown }
        function Set-FlareStamp { param($Tag) $script:stamped += $Tag }
        function Invoke-BlackholeAction { param([string]$Tag) $script:blackholed += $Tag }
        function Get-FlareConfig { return $script:flareConfig }
        function Write-TeeLog {
            param([string]$Tag, [hashtable]$Data)
            if ($script:teeThrows) { throw 'tee engine unavailable' }
            $script:teeEvents += [PSCustomObject]@{ Tag = $Tag; Data = $Data }
        }
        function Start-Process {
            [CmdletBinding()]
            param($FilePath, $ArgumentList, $WindowStyle, [switch]$Wait, [switch]$PassThru)
            $script:dispatches += [PSCustomObject]@{ FilePath = $FilePath; ArgumentList = $ArgumentList }
            return [PSCustomObject]@{ ExitCode = $script:exitCode }
        }
    }

    BeforeEach {
        $global:flareHistory = @{}
        $script:teeEvents = @()
        $script:dispatches = @()
        $script:stamped = @()
        $script:blackholed = @()
        $script:inCooldown = $false
        $script:teeThrows = $false
        $script:exitCode = 0
        $script:FlareCooldownMinutes = 15
        $script:flareExe = 'C:\ProgramData\WhiteWalker\flaregun.exe'
        $script:WhatIf = $false
        $script:flareConfig = [PSCustomObject]@{
            flare_events = [PSCustomObject]@{
                captive_portal_browser_base = [PSCustomObject]@{ context = 'USER';   event_id = 778 }
                no_net_transient            = [PSCustomObject]@{ context = 'SYSTEM'; event_id = 790 }
            }
        }
    }

    It 'emits flare_dispatched for a USER-context dispatch without changing dispatch' {
        Send-FlareEvent -Tag 'captive_portal_browser_base'

        $script:dispatches.Count | Should -Be 1
        $script:dispatches[0].FilePath | Should -Be 'eventcreate.exe'
        $script:stamped | Should -Contain 'captive_portal_browser_base'

        $event = $script:teeEvents | Where-Object { $_.Tag -eq 'flare_dispatched' } | Select-Object -First 1
        $event | Should -Not -BeNullOrEmpty
        $event.Data.flare_tag | Should -Be 'captive_portal_browser_base'
        $event.Data.event_id | Should -Be '778'
        $event.Data.context | Should -Be 'USER'
        $event.Data.dispatch_method | Should -Be 'eventcreate'
        $event.Data.status | Should -Be 'dispatched'
        $event.Data.EvtTime | Should -Not -BeNullOrEmpty
    }

    It 'emits flare_dispatched for a SYSTEM-context dispatch' {
        Send-FlareEvent -Tag 'no_net_transient'

        $script:dispatches[0].ArgumentList | Should -Be '/no_net_transient'
        $event = $script:teeEvents | Where-Object { $_.Tag -eq 'flare_dispatched' } | Select-Object -First 1
        $event.Data.context | Should -Be 'SYSTEM'
        $event.Data.dispatch_method | Should -Be 'flare_exe'
    }

    It 'emits flare_dispatched with legacy-direct context when the tag is unknown' {
        Send-FlareEvent -Tag 'some_unconfigured_tag'
        $event = $script:teeEvents | Where-Object { $_.Tag -eq 'flare_dispatched' } | Select-Object -First 1
        $event.Data.context | Should -Be 'legacy-direct'
        $event.Data.event_id | Should -Be ''
    }

    It 'emits flare_suppressed for the per-run de-dupe without re-dispatching' {
        Send-FlareEvent -Tag 'no_net_transient'
        $script:teeEvents = @()
        Send-FlareEvent -Tag 'no_net_transient'

        $script:dispatches.Count | Should -Be 1
        $event = $script:teeEvents | Where-Object { $_.Tag -eq 'flare_suppressed' } | Select-Object -First 1
        $event.Data.reason | Should -Be 'per_run_dedupe'
        $event.Data.status | Should -Be 'suppressed'
    }

    It 'emits flare_suppressed for cooldown and still honours the critical-event bypass' {
        $script:inCooldown = $true

        Send-FlareEvent -Tag 'no_net_transient'
        $script:dispatches.Count | Should -Be 0
        ($script:teeEvents | Where-Object { $_.Tag -eq 'flare_suppressed' }).Data.reason | Should -Be 'cooldown'

        Send-FlareEvent -Tag 'captive_portal_browser_base'
        $script:dispatches.Count | Should -Be 1
        ($script:teeEvents | Where-Object { $_.Tag -eq 'flare_dispatched' }) | Should -Not -BeNullOrEmpty
    }

    It 'emits flare_failed when eventcreate returns a non-zero exit code' {
        $script:exitCode = 1
        Send-FlareEvent -Tag 'captive_portal_browser_base'

        $event = $script:teeEvents | Where-Object { $_.Tag -eq 'flare_failed' } | Select-Object -First 1
        $event | Should -Not -BeNullOrEmpty
        $event.Data.status | Should -Be 'failed'
        $event.Data.reason | Should -Match 'eventcreate_exit_code_1'
    }

    It 'is fail-soft when Write-TeeLog throws' {
        $script:teeThrows = $true
        { Send-FlareEvent -Tag 'no_net_transient' } | Should -Not -Throw
        $script:dispatches.Count | Should -Be 1
        $script:blackholed | Should -Contain 'no_net_transient'
    }

    It 'is fail-soft when Write-TeeLog is unavailable' {
        $saved = ${function:Write-TeeLog}
        Remove-Item function:Write-TeeLog -ErrorAction SilentlyContinue
        try {
            { Send-FlareEvent -Tag 'no_net_transient' } | Should -Not -Throw
            $script:dispatches.Count | Should -Be 1
        } finally {
            Set-Item function:Write-TeeLog $saved
        }
    }

    It 'adds Base runner lifecycle telemetry so a dispatch can be correlated end to end' {
        $base = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'WW_cap_portal_runner_base.ps1') -Raw
        # Lifecycle telemetry now goes through the truthful Write-BaseCapTee
        # wrapper, which calls Write-TeeLog -PassThru and logs the exact reason
        # token (queued | tag_not_in_profile | access_denied | error).
        $base | Should -Match "Write-BaseCapTee -Tag \`$Action -Data @\{"
        $base | Should -Match "Write-TeeLog \`$Tag \`$Data -PassThru"
        $base | Should -Match "-Action 'flare_runner_started'"
        $base | Should -Match "-Action 'flare_runner_completed'"
    }
}

Describe 'Telemetry contract - schema and tee profiles' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:schema = Import-PowerShellDataFile (Join-Path $root 'support_files/haystack_msg_schema.psd1')
        $script:profiles = @{}
        . (Join-Path $root 'WW_set_tee_level.ps1')
        foreach ($level in 1, 3, 4, 5) {
            $script:profiles["level$level"] = Get-CprTeeLevelProfile -Level $level -MasterPath (Join-Path $root 'WW_tee_master.psd1')
        }
    }

    It 'registers every new flare lifecycle tag from level 3 upward and in the active profile' {
        foreach ($key in $script:profiles.Keys) {
            foreach ($tag in 'flare_dispatched', 'flare_suppressed', 'flare_failed', 'flare_runner_started', 'flare_runner_completed') {
                $script:profiles[$key].Events.ContainsKey($tag) | Should -BeTrue -Because "$key must carry $tag"
            }
        }
    }

    It 'promotes the two Base evidence tags out of pilot-only level 5' {
        foreach ($key in $script:profiles.Keys) {
            $script:profiles[$key].Events.ContainsKey('cap_portal_preflight_observation') | Should -BeTrue -Because "$key must carry cap_portal_preflight_observation"
            $script:profiles[$key].Events.ContainsKey('cap_portal_webhelper_navigation') | Should -BeTrue -Because "$key must carry cap_portal_webhelper_navigation"
        }
    }

    It 'carries the new flare fields on the flare tags' {
        $fields = $script:profiles['level5'].Events['flare_dispatched'].fields
        foreach ($f in 'flare_tag', 'event_id', 'context', 'dispatch_method', 'status', 'reason', 'ssid', 'vpn_state') {
            $fields | Should -Contain $f
        }
        $runnerFields = $script:profiles['level5'].Events['flare_runner_started'].fields
        $runnerFields | Should -Contain 'runner'
        $runnerFields | Should -Contain 'duration_sec'
    }

    It 'carries redirect_type and attempt on the Base preflight observation tag' {
        foreach ($key in $script:profiles.Keys) {
            $script:profiles[$key].Events['cap_portal_preflight_observation'].fields | Should -Contain 'redirect_type'
            $script:profiles[$key].Events['cap_portal_preflight_observation'].fields | Should -Contain 'attempt'
        }
    }

    It 'documents every new field in haystack_msg_schema.psd1' {
        foreach ($f in 'flare_tag', 'event_id', 'context', 'dispatch_method', 'runner', 'redirect_type', 'attempt') {
            $script:schema.Optional.ContainsKey($f) | Should -BeTrue -Because "schema must document $f"
            $script:schema.CanonicalCasing          | Should -Contain $f
        }
    }
}
