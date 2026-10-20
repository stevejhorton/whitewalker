# CPR_RC2.CapPortalRecovery.Tests.ps1
#
# RC2.1 recovery coverage for the defects proven by fresh live endpoint
# evidence after the empirical-preflight/WebHelper work:
#
#   A  Base -> Full (Event 777) escalation is OFF by default and fail-safe;
#      only an explicit $true in the dispatch artifact restores it.
#   B  No adapter / radio off / APIPA / missing gateway is NOT a suspected
#      captive portal: no Event 778, no Event 777, fast fail-soft exit.
#   C  The authoritative gateway.optum.com preflight fires immediately after
#      the network is ready, before avoidable slow work, with timing evidence.
#   D  At most ONE vpncli.exe invocation per observe cycle, no pre-probe storm,
#      EventID 301 records are examined once, and the window is deadline bound.
#   E  Base timers mirror Main (drift test) and Main can override them.
#   F  Stale / network-mismatched handoff artifacts are rejected, artifacts are
#      written atomically with identity + lifecycle fields, and the probe URL
#      never becomes the canonical portal URL.
#   G  USER context spools evidence through a narrowly scoped drop directory
#      that SYSTEM ingests - no broad Modify on scripts or configuration.
#   H  The active tee profile can be refreshed without clobbering the operator's
#      selected level, and the new tags exist with their exact schema fields.
#   I  The authoritative preflight / ISE contract is unchanged (ISE_EMPLOYEE
#      still follows Main's rescan flow with no EventID 301 dependency).
#
# AST-extraction style, per repository convention. Everything here is static
# source/contract analysis or pure-function evaluation: no live Windows, Cisco
# or Splunk validation is possible in the Linux sandbox, so Windows-only code
# paths (Get-WinEvent, Get-Acl/Set-Acl, netsh, vpncli.exe, Task Scheduler) are
# asserted at the source-contract level rather than executed.

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

BeforeAll {
    $script:root       = Split-Path $PSScriptRoot -Parent
    $script:basePath   = Join-Path $script:root 'WW_cap_portal_runner_base.ps1'
    $script:baseSource = Get-Content $script:basePath -Raw
    $script:entrySource  = Get-Content (Join-Path $script:root 'main/Main.Entry.ps1') -Raw
    $script:configSource = Get-Content (Join-Path $script:root 'main/Main.Configuration.ps1') -Raw
    $script:capSource    = Get-Content (Join-Path $script:root 'main/Main.CaptivePortal.ps1') -Raw
    $script:teeSource    = Get-Content (Join-Path $script:root 'WW_tee.ps1') -Raw
}

# =============================================================================
# Required A - explicit Base-to-Full escalation flag
# =============================================================================
Describe 'Required A - Base to Full escalation flag' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath -Names @('Resolve-BaseEscalationPolicy'))
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.CaptivePortal.ps1') `
            -Names @('Get-CapPortalBaseEscalationPolicy'))
    }

    It 'declares the config variable and defaults it to $false for Base' {
        $script:configSource | Should -Match '\$CapPortalBaseAllowFullEscalation\s*=\s*\$false'
    }

    It 'resolves to NO escalation when the dispatch artifact is missing entirely' {
        $policy = Resolve-BaseEscalationPolicy -StateData $null
        $policy.Allowed | Should -BeFalse
        $policy.Source  | Should -Be 'default_fail_safe'
    }

    It 'resolves to NO escalation when the property is absent (older Main wrote the artifact)' {
        $state = [PSCustomObject]@{ portal_type = 'suspected'; ssid = 'xfinitywifi' }
        $policy = Resolve-BaseEscalationPolicy -StateData $state
        $policy.Allowed | Should -BeFalse
        $policy.Source  | Should -Be 'default_fail_safe'
    }

    It 'resolves to NO escalation when the property is present but null/blank/garbage' {
        foreach ($value in @($null, '', '   ', 'maybe')) {
            $state = [PSCustomObject]@{ base_allow_full_escalation = $value }
            (Resolve-BaseEscalationPolicy -StateData $state).Allowed | Should -BeFalse
        }
    }

    It 'honours an EXPLICIT true from the dispatch artifact' {
        foreach ($value in @($true, 'True', 'true')) {
            $state = [PSCustomObject]@{ base_allow_full_escalation = $value }
            $policy = Resolve-BaseEscalationPolicy -StateData $state
            $policy.Allowed | Should -BeTrue
            $policy.Source  | Should -Be 'dispatch_artifact'
        }
    }

    It 'honours an EXPLICIT false from the dispatch artifact' {
        $state = [PSCustomObject]@{ base_allow_full_escalation = $false }
        (Resolve-BaseEscalationPolicy -StateData $state).Allowed | Should -BeFalse
    }

    It 'Main resolves the same policy fail-safe when the variable is undefined' {
        Remove-Variable -Name CapPortalBaseAllowFullEscalation -Scope Global -ErrorAction SilentlyContinue
        (Get-CapPortalBaseEscalationPolicy) | Should -BeFalse
    }

    It 'Main carries the effective flag into the dispatch artifact' {
        $script:capSource | Should -Match 'base_allow_full_escalation'
    }

    It 'logs the effective value at Main dispatch and at Base startup' {
        $script:capSource  | Should -Match 'cap_portal_dispatch_settings'
        $script:baseSource | Should -Match 'cap_portal_base_escalation_policy allow_full_escalation='
    }

    It 'only fires Event 777 when escalation is explicitly allowed' {
        # Send-EscalationFlare must be guarded, never called unconditionally.
        $script:baseSource | Should -Match 'if \(\$BaseAllowFullEscalation\) \{\s*\r?\n\s*Send-EscalationFlare'
    }

    It 'writes an observe-only timeout completion and truthful telemetry when escalation is disabled' {
        $script:baseSource | Should -Match 'TIMEOUT_OBSERVE_ONLY'
        $script:baseSource | Should -Match 'native_timeout_observe_only_no_escalation'
        $script:baseSource | Should -Match 'NOT firing Event 777'
    }
}

# =============================================================================
# Required B - strict plausible-local-network gate
# =============================================================================
Describe 'Required B - strict local network gate (Main)' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.Network.ps1') `
            -Names @('Test-PlausibleLocalNetwork'))
    }

    It 'rejects a box with no active adapter at all' {
        $r = Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'N/A'; SSID = ''; IPAddress = ''; DefaultGateway = '' })
        $r.IsPlausible | Should -BeFalse
        $r.Reason      | Should -Be 'no_active_adapter'
    }

    It 'rejects Wi-Fi with the radio off / not associated (no connected SSID)' {
        $r = Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'WiFi'; SSID = ''; IPAddress = '172.20.20.20/24'; DefaultGateway = '172.20.20.1' })
        $r.IsPlausible | Should -BeFalse
        $r.Reason      | Should -Be 'wifi_no_connected_ssid'
    }

    It 'rejects APIPA' {
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'WiFi'; SSID = 'xfinitywifi'; IPAddress = '169.254.10.5'; DefaultGateway = '169.254.10.1' })).Reason |
            Should -Be 'apipa_ip'
    }

    It 'rejects loopback and 0.0.0.0' {
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'Ethernet'; IPAddress = '127.0.0.1'; DefaultGateway = '127.0.0.1' })).Reason | Should -Be 'invalid_ip'
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'Ethernet'; IPAddress = '0.0.0.0'; DefaultGateway = '10.0.0.1' })).Reason | Should -Be 'invalid_ip'
    }

    It 'rejects a missing or zero default gateway' {
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'Ethernet'; IPAddress = '172.20.20.20/24'; DefaultGateway = '' })).Reason | Should -Be 'no_default_gateway'
        (Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'Ethernet'; IPAddress = '172.20.20.20/24'; DefaultGateway = '0.0.0.0' })).Reason | Should -Be 'no_default_gateway'
    }

    It 'accepts a valid WIRED path with no SSID' {
        $r = Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'Ethernet'; SSID = ''; IPAddress = '10.10.69.42/24'; DefaultGateway = '10.10.69.1' })
        $r.IsPlausible    | Should -BeTrue
        $r.Reason         | Should -Be 'valid_ip_and_gateway'
        $r.ConnectionType | Should -Be 'Ethernet'
    }

    It 'accepts a valid Wi-Fi path with a connected SSID' {
        $r = Test-PlausibleLocalNetwork -NetworkInfo ([PSCustomObject]@{
            ConnectionType = 'WiFi'; SSID = 'xfinitywifi'; IPAddress = '172.20.20.20/24'; DefaultGateway = '172.20.20.1' })
        $r.IsPlausible | Should -BeTrue
        $r.Ssid        | Should -Be 'xfinitywifi'
    }

    It 'gates the captive-portal handoff BEFORE the walled-garden test and Event 778' {
        $gateIndex   = $script:entrySource.IndexOf('No usable local network')
        $wgIndex     = $script:entrySource.IndexOf('Test-WalledGarden -PrimaryGateway')
        $gateIndex | Should -BeGreaterThan 0
        $gateIndex | Should -BeLessThan $wgIndex
    }

    It 'falls back to the normal no-network result instead of firing 778/777' {
        $failSoft = [regex]::Match($script:entrySource,
            'No usable local network[\s\S]{0,1200}').Value
        $failSoft | Should -Match 'no_net_transient'
        $failSoft | Should -Not -Match 'captive_portal_browser_base'
        $failSoft | Should -Not -Match 'Invoke-CaptivePortalRemediation'
    }
}

Describe 'Required B - Base re-checks the network and exits fast' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath -Names @('Test-BaseLocalNetworkReady'))
    }

    It 'rejects no IP, APIPA, loopback and a missing gateway' {
        (Test-BaseLocalNetworkReady -NetworkContext @{ ip = ''; gw = '' }).Reason | Should -Be 'no_ip'
        (Test-BaseLocalNetworkReady -NetworkContext @{ ip = '169.254.1.2'; gw = '169.254.1.1' }).Reason | Should -Be 'apipa_ip'
        (Test-BaseLocalNetworkReady -NetworkContext @{ ip = '127.0.0.1'; gw = '127.0.0.1' }).Reason | Should -Be 'invalid_ip'
        (Test-BaseLocalNetworkReady -NetworkContext @{ ip = '172.20.20.20'; gw = '' }).Reason | Should -Be 'no_default_gateway'
    }

    It 'requires a connected SSID on a Wi-Fi path but not on a wired path' {
        (Test-BaseLocalNetworkReady -NetworkContext @{ ip = '172.20.20.20'; gw = '172.20.20.1'; ssid = '' } -ConnectionType 'WiFi').Reason |
            Should -Be 'wifi_no_connected_ssid'
        (Test-BaseLocalNetworkReady -NetworkContext @{ ip = '10.10.69.42'; gw = '10.10.69.1'; ssid = '' }).Ready |
            Should -BeTrue
    }

    It 'accepts a live Wi-Fi context' {
        (Test-BaseLocalNetworkReady -NetworkContext @{ ip = '172.20.20.20'; gw = '172.20.20.1'; ssid = 'xfinitywifi' } -ConnectionType 'WiFi').Ready |
            Should -BeTrue
    }

    It 'records network_unavailable_before_observation and exits without escalating' {
        $script:baseSource | Should -Match 'network_unavailable_before_observation'
        $bail = [regex]::Match($script:baseSource,
            'network_unavailable_before_observation reason[\s\S]{0,1400}').Value
        $bail | Should -Match 'exit 0'
        $bail | Should -Not -Match 'Send-EscalationFlare'
    }

    It 'runs that gate BEFORE the observation loop so the exit is seconds, not the full window' {
        $gateIndex = $script:baseSource.IndexOf('Test-BaseLocalNetworkReady -NetworkContext $netCtx')
        $loopIndex = $script:baseSource.IndexOf('while ((Get-Date) -lt $endTime)')
        $gateIndex | Should -BeGreaterThan 0
        $gateIndex | Should -BeLessThan $loopIndex
    }
}

# =============================================================================
# Required C - immediate authoritative preflight after IP acquisition
# =============================================================================
Describe 'Required C - preflight fires immediately after network-ready' {
    It 'Main probes before the non-routing-critical startup subsystems' {
        $probeIndex    = $script:entrySource.IndexOf('$nwCheck = Get-NwCheckResult')
        $subsystemIdx  = $script:entrySource.IndexOf('Invoke-WhiteWalkerStartupSubsystems', $probeIndex)
        $probeIndex   | Should -BeGreaterThan 0
        $subsystemIdx | Should -BeGreaterThan $probeIndex
    }

    It 'Main defers self-update / blackhole / HayStack reroll / XmlVault into one deferred function' {
        $deferred = [regex]::Match($script:entrySource,
            'function Invoke-WhiteWalkerStartupSubsystems \{[\s\S]*?\n\}').Value
        $deferred | Should -Match 'Invoke-SelfUpdate'
        $deferred | Should -Match 'Sync-BlackholeShutdownTask'
        $deferred | Should -Match 'HaystackScriptPath'
    }

    It 'emits network-ready-to-preflight timing evidence' {
        $script:entrySource | Should -Match 'preflight_timing network_ready_to_preflight_ms='
        $script:baseSource  | Should -Match 'preflight_timing network_ready_to_preflight_ms='
    }

    It 'keeps the required run header, stale-flag and interrupt safety before probing' {
        $probeIndex = $script:entrySource.IndexOf('$nwCheck = Get-NwCheckResult')
        $script:entrySource.IndexOf('Write-RunHeader')     | Should -BeLessThan $probeIndex
        $script:entrySource.IndexOf('Clear-StaleFlagFiles') | Should -BeLessThan $probeIndex
    }

    It 'Base probes immediately after its fast gate, before reading the handoff artifact' {
        # Scope to the MAIN block: helper functions earlier in the file also
        # reference $RemediationStateFile.
        $main = $script:baseSource.Substring($script:baseSource.IndexOf('# ================================ MAIN'))
        $gateIndex   = $main.IndexOf('Local network gate passed')
        $probeIndex  = $main.IndexOf('$basePreflightObservation = Test-BaseCapPreflight')
        $handoffIdx  = $main.IndexOf('if (Test-Path $RemediationStateFile)')
        $gateIndex   | Should -BeGreaterThan 0
        $handoffIdx  | Should -BeGreaterThan 0
        $gateIndex  | Should -BeLessThan $probeIndex
        $probeIndex | Should -BeLessThan $handoffIdx
    }
}

# =============================================================================
# Required D - performance: no vpncli / EventID 301 storms, deadline bounded
# =============================================================================
Describe 'Required D - no process storms, deadline bounded' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath `
            -Names @('Get-BaseCapVpnState', 'Reset-BaseCapVpnStateCache'))
    }

    It 'caches VPN state so one observe cycle costs at most one vpncli call' {
        $script:vpnCalls = 0
        function global:Get-VpnStateQuick { $script:vpnCalls++; return 'Disconnected' }

        Reset-BaseCapVpnStateCache
        $a = Get-BaseCapVpnState
        $b = Get-BaseCapVpnState
        $c = Get-BaseCapVpnState

        $script:vpnCalls | Should -Be 1
        $a | Should -Be 'Disconnected'
        $b | Should -Be 'Disconnected'
        $c | Should -Be 'Disconnected'
    }

    It 'refreshes once per cycle when the cache is reset' {
        $script:vpnCalls = 0
        function global:Get-VpnStateQuick { $script:vpnCalls++; return 'Disconnected' }

        Reset-BaseCapVpnStateCache; $null = Get-BaseCapVpnState; $null = Get-BaseCapVpnState
        Reset-BaseCapVpnStateCache; $null = Get-BaseCapVpnState; $null = Get-BaseCapVpnState

        $script:vpnCalls | Should -Be 2
    }

    It 'never shells vpncli before the first empirical probe' {
        $probeIndex = $script:baseSource.IndexOf('$basePreflightObservation = Test-BaseCapPreflight')
        $preProbe = $script:baseSource.Substring($script:baseSource.IndexOf('# ================================ MAIN'),
            $probeIndex - $script:baseSource.IndexOf('# ================================ MAIN'))
        $preProbe | Should -Not -Match 'Get-VpnStateQuick'
        $preProbe | Should -Not -Match 'Get-BaseCapVpnState'
    }

    It 'passes the cached value into telemetry instead of re-reading it inline' {
        $loop = [regex]::Match($script:baseSource,
            'while \(\(Get-Date\) -lt \$endTime\) \{[\s\S]*?\n    \}').Value
        $loop | Should -Not -Match '-VpnState \(Get-VpnStateQuick\)'
        $loop | Should -Match '-VpnState \$vpnState'
    }

    It 'tracks already-examined EventID 301 records so they are never reparsed' {
        $script:baseSource | Should -Match '\$seenWebHelperRecordIds = @\{\}'
        $script:baseSource | Should -Match '-SeenRecordIds \$seenWebHelperRecordIds'
        $reader = Get-CprFunctionSource -Path $script:basePath -Names @('Get-CiscoWebHelperNavigationEvent')
        $reader | Should -Match '\$SeenRecordIds\.ContainsKey\(\$recordIdentity\)'
    }

    It 'replaces per-record no-navigation spam with a concise per-cycle DEBUG count' {
        $parser = Get-CprFunctionSource -Path $script:basePath -Names @('ConvertFrom-CiscoWebHelperNavigationBody')
        $parser | Should -Not -Match 'did not contain a navigation URL'
        $script:baseSource | Should -Match 'cisco_webhelper_scan cycle=\$iteration'
        $script:baseSource | Should -Match 'without_navigation_url='
    }

    It 'preserves distinct navigation stages and the real-Xfinity field mapping' {
        $script:baseSource | Should -Match '\$webHelperNavigationStages \+='
        $parser = Get-CprFunctionSource -Path $script:basePath -Names @('ConvertFrom-CiscoWebHelperNavigationBody')
        $parser | Should -Match "@\('ap_mac', 'cm'\)"
        $parser | Should -Match 'cp_da_osname'
    }

    It 'never sleeps past the observation deadline' {
        $script:baseSource | Should -Match '\$remainingMs = \[math\]::Max\(0, \[math\]::Floor\(\(\$endTime - \$cycleFinishedAt\)\.TotalMilliseconds\)\)'
        $script:baseSource | Should -Match '\$sleepMs = \[math\]::Min\(\$targetSleepMs, \$remainingMs\)'
        $script:baseSource | Should -Not -Match 'Start-Sleep -Seconds \$CheckIntervalSec'
    }
}

# =============================================================================
# Required E - timer parity between Main and Base
# =============================================================================
Describe 'Required E - Base/Main timer parity' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath -Names @('Get-BaseTimerFromHandoff'))

        function script:Get-Literal {
            param([string]$Source, [string]$Name)
            $m = [regex]::Match($Source, "\`$$Name\s*=\s*(\d+)")
            if (-not $m.Success) { throw "literal $Name not found" }
            return [int]$m.Groups[1].Value
        }
    }

    It 'Base observation window matches Main $CapPortalBaseTimeoutSeconds (drift test)' {
        $mainValue = Get-Literal -Source $script:configSource -Name 'CapPortalBaseTimeoutSeconds'
        $baseValue = Get-Literal -Source $script:baseSource   -Name 'ObserveTimeoutSeconds'
        $baseValue | Should -Be $mainValue
    }

    It 'Base poll interval matches Main $CapPortalBaseCheckIntervalSec (drift test)' {
        $mainValue = Get-Literal -Source $script:configSource -Name 'CapPortalBaseCheckIntervalSec'
        $baseValue = Get-Literal -Source $script:baseSource   -Name 'CheckIntervalSec'
        $baseValue | Should -Be $mainValue
    }

    It 'the Base observation window also matches Main $CaptivePortalTimeout' {
        (Get-Literal -Source $script:configSource -Name 'CaptivePortalTimeout') |
            Should -Be (Get-Literal -Source $script:baseSource -Name 'ObserveTimeoutSeconds')
    }

    It 'documents which full-runner waits are deliberately NOT mirrored into Base' {
        $script:baseSource | Should -Match 'InitialWaitSeconds'
        $script:baseSource | Should -Match 'have no Base equivalent'
    }

    It 'Main is the source of truth: a sane artifact value wins over the local literal' {
        $state = [PSCustomObject]@{ base_observe_timeout_sec = '90' }
        Get-BaseTimerFromHandoff -StateData $state -Property 'base_observe_timeout_sec' -Fallback 120 | Should -Be 90
    }

    It 'falls back to the mirrored literal for a missing, zero, negative or absurd value' {
        Get-BaseTimerFromHandoff -StateData $null -Property 'base_observe_timeout_sec' -Fallback 120 | Should -Be 120
        foreach ($value in @('0', '-5', 'abc', '999999')) {
            $state = [PSCustomObject]@{ base_observe_timeout_sec = $value }
            Get-BaseTimerFromHandoff -StateData $state -Property 'base_observe_timeout_sec' -Fallback 120 | Should -Be 120
        }
    }

    It 'Main carries both timers through the dispatch artifact' {
        $script:capSource | Should -Match 'base_observe_timeout_sec'
        $script:capSource | Should -Match 'base_check_interval_sec'
    }
}

# =============================================================================
# Required F - stale artifacts and actual-state matching
# =============================================================================
Describe 'Required F - handoff freshness and network identity' {
    BeforeAll {
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') }
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath `
            -Names @('Test-BaseHandoffArtifact'))
    }

    It 'accepts a fresh artifact whose SSID matches the live context' {
        $state = [PSCustomObject]@{
            created_at = (Get-Date).AddSeconds(-20).ToString('o'); ssid = 'xfinitywifi'
            ip = '172.20.20.20'; gw = '172.20.20.1' }
        $r = Test-BaseHandoffArtifact -StateData $state -NetworkContext @{ ssid = 'xfinitywifi'; ip = '172.20.20.20'; gw = '172.20.20.1' }
        $r.Accepted | Should -BeTrue
        $r.Reason   | Should -Be 'accepted'
    }

    It 'rejects an artifact that is too old as stale_handoff' {
        $state = [PSCustomObject]@{ created_at = (Get-Date).AddHours(-3).ToString('o'); ssid = 'xfinitywifi' }
        $r = Test-BaseHandoffArtifact -StateData $state -NetworkContext @{ ssid = 'xfinitywifi' } -MaxAgeSeconds 900
        $r.Accepted   | Should -BeFalse
        $r.Reason     | Should -Be 'stale_handoff'
        $r.AgeSeconds | Should -BeGreaterThan 900
    }

    It 'rejects the exact live mismatch the endpoint produced (cia_van vs xfinitywifi)' {
        $state = [PSCustomObject]@{
            created_at = (Get-Date).AddSeconds(-30).ToString('o')
            ssid = 'cia_van'; gateway_ip = '10.10.69.1'; portal_type = 'suspected' }
        $r = Test-BaseHandoffArtifact -StateData $state -NetworkContext @{ ssid = 'xfinitywifi'; ip = '172.20.20.20'; gw = '172.20.20.1' }
        $r.Accepted | Should -BeFalse
        $r.Reason   | Should -Be 'network_context_mismatch'
    }

    It 'uses adapter/IP/gateway identity when there is no SSID (wired path)' {
        $state = [PSCustomObject]@{
            created_at = (Get-Date).AddSeconds(-30).ToString('o'); ssid = ''
            ip = '10.10.69.42'; gw = '10.10.69.1' }
        (Test-BaseHandoffArtifact -StateData $state -NetworkContext @{ ssid = ''; ip = '192.168.1.5'; gw = '192.168.1.1' }).Reason |
            Should -Be 'network_context_mismatch'
        (Test-BaseHandoffArtifact -StateData $state -NetworkContext @{ ssid = ''; ip = '10.10.69.42'; gw = '10.10.69.1' }).Accepted |
            Should -BeTrue
    }

    It 'does not invent a conflict from missing fields' {
        $state = [PSCustomObject]@{ created_at = (Get-Date).ToString('o'); ssid = ''; ip = ''; gw = '' }
        (Test-BaseHandoffArtifact -StateData $state -NetworkContext @{ ssid = 'xfinitywifi'; ip = '172.20.20.20'; gw = '172.20.20.1' }).Accepted |
            Should -BeTrue
    }

    It 'reports no_handoff_artifact rather than throwing when there is nothing to read' {
        (Test-BaseHandoffArtifact -StateData $null -NetworkContext @{}).Reason | Should -Be 'no_handoff_artifact'
    }

    It 'logs BOTH contexts when it rejects a handoff' {
        $script:baseSource | Should -Match 'handoff_context: ssid='
        $script:baseSource | Should -Match 'live_context: ssid='
    }
}

Describe 'Required F - artifact identity, atomicity and lifecycle' {
    It 'stamps creation time, correlation, network identity, mode and the escalation flag' {
        $writer = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.CaptivePortal.ps1') `
            -Names @('Write-CapPortalRemediationState')
        foreach ($field in @('created_at', 'run_id', 'correlation_id', 'ssid', 'ip', 'gw',
                             'runner_mode', 'base_allow_full_escalation')) {
            $writer | Should -Match $field
        }
    }

    It 'writes the artifact atomically (temp + move), never in place' {
        $writer = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.CaptivePortal.ps1') `
            -Names @('Write-CapPortalRemediationState')
        $writer | Should -Match '\.tmp'
        $writer | Should -Match 'Move-Item'
    }

    It 'Base also writes its handback atomically' {
        $atomic = Get-CprFunctionSource -Path $script:basePath -Names @('Write-BaseCapAtomicFile')
        $atomic | Should -Match '\.tmp'
        $atomic | Should -Match 'Move-Item'
    }

    It 'never clears an artifact belonging to the current correlated run' {
        $clear = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.CaptivePortal.ps1') `
            -Names @('Clear-CapPortalRemediationState')
        $clear | Should -Match 'run_id'
    }

    It 'clears the artifact on Base exit, timeout and network loss' {
        $script:baseSource | Should -Match "Clear-BaseRemediationState -Reason 'network_unavailable_before_observation'"
        $script:baseSource | Should -Match "base_observe_only_timeout"
        $script:baseSource | Should -Match "base_observed_resolution"
    }

    It 'NEVER lets the gateway.optum.com probe URL become the canonical portal URL' {
        $suspect = [regex]::Match($script:entrySource,
            'portal_type = "suspected"[\s\S]{0,1200}').Value
        $suspect | Should -Match 'probe_url'
        $suspect | Should -Match "url_source\s*=\s*[`"']none_no_redirect_observed"
        $suspect | Should -Not -Match 'url\s*=\s*\$NewPreflightURL'
    }

    It 'does not claim remediation merely because EventID 301 / WebView2 navigated' {
        # The only cap_portal_remediation_passed in Base sits inside the
        # Test-SiteReachability (connectivity verification) branch.
        $main = $script:baseSource.Substring($script:baseSource.IndexOf('# ================================ MAIN'))
        $passedIndex  = $main.IndexOf("cap_portal_remediation_passed")
        $verifyIndex  = $main.IndexOf('if (Test-SiteReachability')
        $verifyIndex | Should -BeGreaterThan 0
        $passedIndex | Should -BeGreaterThan $verifyIndex

        # Navigation evidence is explicitly labelled as corroboration only.
        $script:baseSource | Should -Match 'EventID 301 is optional corroboration only'
    }
}

# =============================================================================
# Required G - safe USER-context telemetry channel
# =============================================================================
Describe 'Required G - USER spool / SYSTEM ingestion' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $script:root 'WW_tee.ps1') `
            -Names @('Add-TeeSpoolEntry', 'Initialize-TeeSpoolDirectory', 'Test-TeeSpoolRequired', 'Test-TeeRunningAsSystem'))
    }

    It 'writes one atomic file per event so concurrent JSONL corruption is impossible' {
        $spool = Join-Path $TestDrive 'spool'
        $entryA = '{"ts":"2026-10-16T02:00:00.0000000Z","payload":"action=flare_runner_started","extraInfo":""}'
        $entryB = '{"ts":"2026-10-16T02:00:01.0000000Z","payload":"action=flare_runner_completed","extraInfo":""}'

        $a = Add-TeeSpoolEntry -Entry $entryA -Path $spool
        $b = Add-TeeSpoolEntry -Entry $entryB -Path $spool

        $a.Queued | Should -BeTrue
        $a.Reason | Should -Be 'spooled'
        $b.Queued | Should -BeTrue

        $files = @(Get-ChildItem -Path $spool -Filter 'evt_*.json' -File)
        $files.Count | Should -Be 2
        @(Get-ChildItem -Path $spool -Filter '*.tmp' -File).Count | Should -Be 0
        (Get-Content -Path $a.File -Raw).Trim() | Should -Be $entryA
    }

    It 'keeps the payload byte-identical to a canonical queue line' {
        $spool = Join-Path $TestDrive 'spool_fmt'
        $entry = '{"ts":"2026-10-16T02:00:00.0000000Z","payload":"action=cap_portal_preflight_observation status=redirect","extraInfo":""}'
        $r = Add-TeeSpoolEntry -Entry $entry -Path $spool
        $line = (Get-Content -Path $r.File -Raw).Trim()
        $line | Should -Be $entry
        { $line | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'reports a truthful reason instead of throwing when the spool cannot be written' {
        $r = Add-TeeSpoolEntry -Entry '{}' -Path ([System.IO.Path]::Combine($TestDrive, 'a_file_not_a_dir', 'x'))
        # On any failure it must report, never throw.
        $r.Queued | Should -BeOfType [bool]
    }

    It 'only diverts to the spool on Windows in a non-SYSTEM context' {
        # Sandbox is Linux: the direct append path (and every existing
        # queue-format test) must behave exactly as before.
        Test-TeeSpoolRequired | Should -BeFalse
        Test-TeeRunningAsSystem | Should -BeFalse
    }

    It 'routes non-SYSTEM writes through the spool inside Add-TeeQueueEntry' {
        $writer = Get-CprFunctionSource -Path (Join-Path $script:root 'WW_tee.ps1') -Names @('Add-TeeQueueEntry')
        $writer | Should -Match 'Test-TeeSpoolRequired'
        $writer | Should -Match 'Add-TeeSpoolEntry -Entry \$Entry'
    }

    It 'reports spooled truthfully rather than pretending the event reached the queue' {
        $script:teeSource | Should -Match "if \(\`$queueWrite\.Reason -eq 'spooled'\) \{ 'spooled' \}"
    }

    It 'does NOT grant Users Modify on the queue any more - append/write/read only' {
        $repair = Get-CprFunctionSource -Path (Join-Path $script:root 'WW_tee.ps1') -Names @('Repair-TeeQueueAccess')
        $repair | Should -Not -Match "FileSystemAccessRule\([\s\S]{0,120}'Modify'"
        $repair | Should -Match 'FileSystemRights\]::AppendData'
        $repair | Should -Not -Match 'FileSystemRights\]::Delete'
        $repair | Should -Not -Match 'FileSystemRights\]::ChangePermissions'
    }

    It 'grants nothing on the script or configuration directories' {
        $installSource = Get-Content (Join-Path $script:root 'install.ps1') -Raw
        $aclFunc = Get-CprFunctionSource -Path (Join-Path $script:root 'install.ps1') -Names @('Initialize-TelemetrySpool')
        $aclFunc | Should -Match '\$TelemetrySpoolDir'
        $aclFunc | Should -Not -Match 'MainScriptDeployDir'
        $aclFunc | Should -Not -Match 'ConfigDeployDir'
        $aclFunc | Should -Not -Match "FileSystemAccessRule\([\s\S]{0,120}'Modify'"
        $aclFunc | Should -Not -Match 'FileSystemRights\]::FullControl'
        # Nothing anywhere in the installer may widen rights on the scripts.
        $installSource | Should -Not -Match 'FileSystemAccessRule\([^\)]*MainScriptDeployDir'
    }

    It 'creates and repairs the spool directory idempotently at install/upgrade' {
        $installSource = Get-Content (Join-Path $script:root 'install.ps1') -Raw
        $installSource | Should -Match 'Initialize-TelemetrySpool'
        $aclFunc = Get-CprFunctionSource -Path (Join-Path $script:root 'install.ps1') -Names @('Initialize-TelemetrySpool')
        # Must detect an existing correct ACE and do nothing (idempotent).
        $aclFunc | Should -Match 'ACL already correct'
    }

    It 'SYSTEM ingests spool drops into the canonical queue, preserving format and drain semantics' {
        $haystack = Get-Content (Join-Path $script:root 'haystack_action.ps1') -Raw
        $ingest = Get-CprFunctionSource -Path (Join-Path $script:root 'haystack_action.ps1') -Names @('Import-SyslogSpool')
        $ingest   | Should -Match "Filter 'evt_\*\.json'"
        $ingest   | Should -Match 'Add-Content -Path \$SyslogQueueFile'
        $ingest   | Should -Match 'ConvertFrom-Json'
        # Ingestion must run at the top of the drain, before the empty check.
        $haystack.IndexOf('Import-SyslogSpool', $haystack.IndexOf('function Drain-SyslogQueue')) |
            Should -BeLessThan $haystack.IndexOf('if (-not (Test-Path $SyslogQueueFile)) { return }')
    }

    It 'uses a separate user handback artifact instead of weakening the SYSTEM control state' {
        $handback = Get-CprFunctionSource -Path $script:basePath -Names @('Write-BaseCapPreflightHandback')
        $handback | Should -Match 'Write-BaseCapAtomicFile -Path \$BaseHandbackFile'
        $handback | Should -Match 'not writable from user context \(expected\)'
        $script:baseSource | Should -Match '\$BaseHandbackFile\s*=\s*Join-Path \$LogDir'
    }

    It 'Main consumes and clears the handback artifact' {
        $consumer = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.CaptivePortal.ps1') `
            -Names @('Import-CapPortalUserHandback')
        $consumer | Should -Match 'cap_portal_base_handback consumed'
        $consumer | Should -Match 'Remove-Item'
        $script:entrySource | Should -Match 'Import-CapPortalUserHandback'
    }
}

# =============================================================================
# Required H - profile activation without clobbering tech choice
# =============================================================================
Describe 'Required H - tee profile staleness and level-preserving repair' {
    BeforeAll {
        $script:profilesDir = Join-Path $script:root 'tee_profiles'
        $script:adminSource = Get-Content (Join-Path $script:root 'admin/Invoke-WhiteWalkerAction.ps1') -Raw
    }

    It 'every reference profile carries an explicit Level and ProfileVersion marker' {
        foreach ($file in Get-ChildItem -Path $script:profilesDir -Filter 'tee_level_*.psd1') {
            $data = Import-PowerShellDataFile -Path $file.FullName
            $expected = [int]($file.BaseName -replace '^tee_level_', '')
            $data.Level          | Should -Be $expected
            $data.ProfileVersion | Should -Not -BeNullOrEmpty
        }
    }

    It 'the deployed active profile also carries a marker' {
        $active = Import-PowerShellDataFile -Path (Join-Path $script:root 'WW_tee_events.psd1')
        $active.Level          | Should -Not -BeNullOrEmpty
        $active.ProfileVersion | Should -Not -BeNullOrEmpty
    }

    It 'identifies the active level from the marker, not only a SHA256 match' {
        $detect = Get-CprFunctionSource -Path (Join-Path $script:root 'admin/Invoke-WhiteWalkerAction.ps1') `
            -Names @('Get-WWActiveTeeProfileName')
        $detect | Should -Match 'Import-PowerShellDataFile'
        $detect | Should -Match '\$active\.Level'
    }

    It 'refuses to guess the level and leaves the profile unchanged when it is unknown' {
        $refresh = Get-CprFunctionSource -Path (Join-Path $script:root 'admin/Invoke-WhiteWalkerAction.ps1') `
            -Names @('Invoke-WWTeeProfileRefresh')
        $refresh | Should -Match 'leaving the active profile UNCHANGED'
        $refresh | Should -Match 'Write-WWAdminLog "Tee profile refresh skipped'
    }

    It 'refreshes from the operator-selected level, preserving the choice' {
        $refresh = Get-CprFunctionSource -Path (Join-Path $script:root 'admin/Invoke-WhiteWalkerAction.ps1') `
            -Names @('Invoke-WWTeeProfileRefresh')
        $refresh | Should -Match 'Copy-Item -LiteralPath \$status\.ReferencePath'
        $refresh | Should -Match 'selected level preserved'
    }

    It 'exposes a one-step repair action in the admin menu' {
        $script:adminSource | Should -Match 'Refresh Active Tee Profile'
        $script:adminSource | Should -Match "Invoke-WWAction -Name 'TeeProfileRefresh'"
    }

    It 'the level picker always copies the latest deployed reference file' {
        $picker = Get-CprFunctionSource -Path (Join-Path $script:root 'admin/Invoke-WhiteWalkerAction.ps1') `
            -Names @('Invoke-WWTeeLevelPicker')
        $picker | Should -Match 'Copy-Item -LiteralPath \$chosen\.Path -Destination \$script:ActiveTeeProfile -Force'
    }

    It 'makes stale-profile status obvious in diagnostics' {
        $diag = Get-Content (Join-Path $script:root 'WW_diagnostics.ps1') -Raw
        $diag | Should -Match 'STALE ACTIVE TEE PROFILE'
        $diag | Should -Match 'Test-TeeProfileHealth'
    }

    It 'level 5 contains every new tag with its exact schema fields' {
        $schema  = Import-PowerShellDataFile (Join-Path $script:root 'support_files/haystack_msg_schema.psd1')
        $known   = @($schema.Mandatory.Keys) + @($schema.Optional.Keys)
        $level5  = Import-PowerShellDataFile (Join-Path $script:profilesDir 'tee_level_5.psd1')

        foreach ($tag in @('flare_runner_started', 'flare_runner_completed', 'flare_dispatched',
                           'cap_portal_preflight_observation', 'cap_portal_webhelper_navigation')) {
            $level5.Events.ContainsKey($tag) | Should -BeTrue -Because "$tag must exist in level 5"
            $level5.Events[$tag].action | Should -Be $tag
            @($level5.Events[$tag].fields).Count | Should -BeGreaterThan 0
            foreach ($field in $level5.Events[$tag].fields) {
                $known | Should -Contain $field -Because "$tag field '$field' must be a known schema field"
            }
        }
    }

    It 'levels 3 and 4 also expose the new captive-portal and flare lifecycle tags' {
        foreach ($name in @('tee_level_3', 'tee_level_4')) {
            $data = Import-PowerShellDataFile (Join-Path $script:profilesDir "$name.psd1")
            foreach ($tag in @('flare_runner_started', 'flare_runner_completed', 'flare_dispatched',
                               'cap_portal_preflight_observation', 'cap_portal_webhelper_navigation')) {
                $data.Events.ContainsKey($tag) | Should -BeTrue -Because "$name must expose $tag"
            }
        }
    }

    It 'the deployed active profile exposes the same new tags' {
        $active = Import-PowerShellDataFile -Path (Join-Path $script:root 'WW_tee_events.psd1')
        foreach ($tag in @('flare_runner_started', 'flare_runner_completed', 'flare_dispatched',
                           'cap_portal_preflight_observation', 'cap_portal_webhelper_navigation')) {
            $active.Events.ContainsKey($tag) | Should -BeTrue -Because "$tag must be available on the endpoint"
        }
    }
}

# =============================================================================
# Required I - authoritative preflight / ISE contract is unchanged
# =============================================================================
Describe 'Required I - preflight and ISE contract preserved' {
    BeforeAll {
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') }
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath `
            -Names @('Set-BaseCapPreflightStatus', 'Get-BaseCapRedirectType'))
    }

    It 'keeps 200/404 without Location as online and 2xx/3xx with Location as redirect' {
        (Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '200'; redirect_url = ''; status = 'unreachable'; reason = '' })).status | Should -Be 'online'
        (Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '404'; redirect_url = ''; status = 'unreachable'; reason = '' })).status | Should -Be 'online'
        (Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '200'; redirect_url = 'https://isepsn01.uhc.com/portal'; status = 'unreachable'; reason = '' })).status | Should -Be 'redirect'
        (Set-BaseCapPreflightStatus -Result ([ordered]@{ http_status = '302'; redirect_url = 'https://cp-webapp.wifi.connected.xfinity.com/'; status = 'unreachable'; reason = '' })).status | Should -Be 'redirect'
    }

    It 'classifies isepsn / isegst / other exactly as before' {
        Get-BaseCapRedirectType -RedirectUrl 'https://isepsn01.uhc.com/portal' | Should -Be 'ISE_EMPLOYEE'
        Get-BaseCapRedirectType -RedirectUrl 'https://isegst01.uhc.com/guest'  | Should -Be 'ISE_GUEST'
        Get-BaseCapRedirectType -RedirectUrl 'https://cp-webapp.wifi.connected.xfinity.com/' | Should -Be 'NON_ISE'
    }

    It 'ISE_EMPLOYEE still routes to Main posture rescan with no EventID 301 dependency' {
        $iseBranch = [regex]::Match($script:entrySource, 'ISE_EMPLOYEE[\s\S]{0,2500}').Value
        $iseBranch | Should -Match 'Invoke-PostureRescan|posture'
        $iseBranch | Should -Not -Match 'EventID 301'
        $iseBranch | Should -Not -Match 'captive_portal_browser_base'
    }

    It 'Base never performs the posture rescan itself' {
        $script:baseSource | Should -Match 'Base performs NO posture rescan'
    }

    It 'the walled garden remains fallback evidence only' {
        $wg = [regex]::Match($script:entrySource, 'Test-WalledGarden -PrimaryGateway[\s\S]{0,600}').Value
        $wg | Should -Not -Match 'Resolve-CapPreflightClassification'
    }
}
