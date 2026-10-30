# CPR_RC2.CapPortalConfigContract.Tests.ps1
#
# RC2.2 Required D + Required E.
#
#   D  bounded network-settle readiness gate before the authoritative preflight
#      (satisfied-fast, satisfied-slow, never-confirmed cap, evidence fields).
#   E  ONE captive-portal timing/behavior contract in Main.Configuration.ps1:
#      config is the source of truth, Main writes the effective values into the
#      dispatch artifact before firing 777/778, BASE and FULL consume it, their
#      literals are fail-safe defaults used only when the artifact is missing,
#      and no orphaned duplicate literal remains.

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
    $script:configPath = Join-Path $script:root 'main/Main.Configuration.ps1'
    $script:networkPath = Join-Path $script:root 'main/Main.Network.ps1'
    $script:entryPath  = Join-Path $script:root 'main/Main.Entry.ps1'
    $script:capPath    = Join-Path $script:root 'main/Main.CaptivePortal.ps1'
    $script:basePath   = Join-Path $script:root 'WW_cap_portal_runner_base.ps1'
    $script:fullPath   = Join-Path $script:root 'WW_cap_portal_runner.ps1'

    $script:configSource = Get-Content $script:configPath -Raw
    $script:entrySource  = Get-Content $script:entryPath  -Raw
    $script:capSource    = Get-Content $script:capPath    -Raw
    $script:baseSource   = Get-Content $script:basePath   -Raw
    $script:fullSource   = Get-Content $script:fullPath   -Raw

    # Every key the contract must carry end to end.
    $script:contractKeys = @(
        'main_captive_portal_timeout_sec', 'main_flag_poll_interval_sec', 'main_initial_sleep_sec',
        'main_captive_event_cooldown_min', 'main_captive_event_limit',
        'network_ready_enabled', 'network_ready_max_wait_ms', 'network_ready_poll_interval_ms',
        'network_ready_gateway_timeout_ms', 'network_ready_dns_timeout_ms',
        'base_observe_timeout_sec', 'base_check_interval_sec', 'base_preflight_timeout_ms',
        'base_preflight_max_probes', 'base_webhelper_lookback_sec',
        'webhelper_301_first_enabled', 'webhelper_301_log_name', 'webhelper_301_provider_name',
        'webhelper_301_event_id', 'webhelper_301_lookback_sec', 'webhelper_301_wait_sec',
        'webhelper_301_poll_interval_ms', 'webhelper_301_max_age_sec',
        'webhelper_301_no_url_immediate_preflight', 'webhelper_301_suppress_preflight',
        'webhelper_301_haystack_fallback_enabled', 'webhelper_301_haystack_lookback_sec',
        'handoff_max_age_sec', 'validation_site', 'site_reachability_timeout_sec',
        'full_initial_wait_sec', 'full_final_wait_sec', 'full_check_interval_sec',
        'preflight_url'
    )
}

# =============================================================================
# Required D - bounded network-settle readiness gate
# =============================================================================
Describe 'Required D - Wait-CprNetworkReady' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path $script:networkPath -Names @(
            'Wait-CprNetworkReady', 'ConvertTo-CprReadyAddress', 'ConvertTo-CprReadyHost'
        ))
    }

    BeforeEach {
        $global:CprGatewayCalls = 0
        $global:CprDnsCalls     = 0
        function global:Test-CprGatewayReachable { param($Address, $TimeoutMs) $global:CprGatewayCalls++; return $global:CprGatewayReady }
        function global:Test-CprDnsResolvable    { param($HostName, $TimeoutMs) $global:CprDnsCalls++;     return (& $global:CprDnsReady) }
        $global:CprGatewayReady = $false
        $global:CprDnsReady = { return $false }
    }

    It 'satisfied-fast: returns on the first poll when the gateway answers' {
        $global:CprGatewayReady = $true
        $r = Wait-CprNetworkReady -GatewayAddress '172.20.20.1' -ProbeHost 'https://gateway.optum.com' `
            -MaxWaitMs 5000 -PollIntervalMs 500
        $r.Ready    | Should -BeTrue
        $r.Signal   | Should -Be 'gateway_reachable'
        $r.Attempts | Should -Be 1
        $r.WaitedMs | Should -BeLessThan 500
        $global:CprDnsCalls | Should -Be 0          # cheapest signal first, no extra work
    }

    It 'satisfied-slow: keeps polling and fires the MOMENT DNS resolves' {
        $global:CprDnsReady = { if ($global:CprDnsCalls -ge 3) { return $true } else { return $false } }
        $r = Wait-CprNetworkReady -GatewayAddress '172.20.20.1' -ProbeHost 'https://gateway.optum.com' `
            -MaxWaitMs 5000 -PollIntervalMs 100
        $r.Ready    | Should -BeTrue
        $r.Signal   | Should -Be 'dns_resolved'
        $r.Attempts | Should -Be 3
        $r.WaitedMs | Should -BeGreaterThan 100     # it genuinely waited
        $r.WaitedMs | Should -BeLessThan 5000       # but far short of the cap
    }

    It 'never-confirmed: caps the total wait and reports not_confirmed so the caller probes anyway' {
        $r = Wait-CprNetworkReady -GatewayAddress '172.20.20.1' -ProbeHost 'https://gateway.optum.com' `
            -MaxWaitMs 600 -PollIntervalMs 100
        $r.Ready    | Should -BeFalse
        $r.Signal   | Should -Be 'not_confirmed'
        $r.WaitedMs | Should -BeLessThan 2000       # hard-capped, no multi-minute latency
        $r.Attempts | Should -BeGreaterThan 1
    }

    It 'is a no-op when disabled, and when no signal is available' {
        $disabled = Wait-CprNetworkReady -GatewayAddress '172.20.20.1' -ProbeHost 'x' -Disabled
        $disabled.Ready  | Should -BeFalse
        $disabled.Signal | Should -Be 'disabled'
        $disabled.WaitedMs | Should -Be 0

        $none = Wait-CprNetworkReady -GatewayAddress '0.0.0.0' -ProbeHost '' -MaxWaitMs 500
        $none.Signal | Should -Be 'no_signals_available'
        $none.WaitedMs | Should -Be 0
    }

    It 'normalizes placeholder gateways and URL probe hosts' {
        ConvertTo-CprReadyAddress 'N/A'    | Should -Be ''
        ConvertTo-CprReadyAddress ' None ' | Should -Be ''
        ConvertTo-CprReadyAddress '172.20.20.1' | Should -Be '172.20.20.1'
        ConvertTo-CprReadyHost 'https://gateway.optum.com/x?y=1' | Should -Be 'gateway.optum.com'
        ConvertTo-CprReadyHost 'gateway.optum.com' | Should -Be 'gateway.optum.com'
    }

    It 'never throws when the underlying probes blow up' {
        function global:Test-CprGatewayReachable { param($Address, $TimeoutMs) throw 'icmp exploded' }
        function global:Test-CprDnsResolvable    { param($HostName, $TimeoutMs) throw 'dns exploded' }
        { Wait-CprNetworkReady -GatewayAddress '172.20.20.1' -ProbeHost 'gateway.optum.com' `
            -MaxWaitMs 300 -PollIntervalMs 100 } | Should -Not -Throw
    }
}

Describe 'Required D - gate is wired in front of the authoritative preflight' {
    It 'MAIN runs the gate between network-ready and Get-NwCheckResult, and keeps preflight_timing' {
        $gateIndex     = $script:entrySource.IndexOf('Wait-CprNetworkReady')
        $nwCheckIndex  = $script:entrySource.IndexOf('$nwCheck = Invoke-GatedNwCheck')
        $gateIndex     | Should -BeGreaterThan 0
        $nwCheckIndex  | Should -BeGreaterThan $gateIndex
        $script:entrySource | Should -Match 'network_ready_gate network_ready_wait_ms=\{0\} signal='
        $script:entrySource | Should -Match 'preflight_timing network_ready_to_preflight_ms'
    }

    It 'BASE runs the gate after its fast network gate and before the first preflight' {
        $networkGate = $script:baseSource.IndexOf('Local network gate passed')
        $readyGate   = $script:baseSource.IndexOf('Wait-BaseNetworkReady -GatewayAddress')
        $preflight   = $script:baseSource.IndexOf('$basePreflightObservation = Test-BaseCapPreflight')
        $readyGate   | Should -BeGreaterThan $networkGate
        $preflight   | Should -BeGreaterThan $readyGate
        $script:baseSource | Should -Match 'network_ready_gate network_ready_wait_ms=\{0\} signal='
    }

    It 'uses configured thresholds, never literals, at the MAIN call site' {
        $script:entrySource | Should -Match 'Wait-CprNetworkReady -GatewayAddress \$networkInfo\.DefaultGateway'
        $script:entrySource | Should -Match '-Disabled:\(\(-not \$NetworkReadyEnabled\)'
        $script:entrySource | Should -Not -Match 'Wait-CprNetworkReady[^\r\n]*-MaxWaitMs \d'
    }

    It 'does not delay the ISE posture rescan path with a fixed sleep' {
        # The gate must be the ONLY new wait, and it must be a poll loop.
        $gate = Get-CprFunctionSource -Path $script:networkPath -Names @('Wait-CprNetworkReady')
        $gate | Should -Match 'Start-Sleep -Milliseconds \$PollIntervalMs'
        $gate | Should -Not -Match 'Start-Sleep -Seconds'
    }
}

# =============================================================================
# Required E - one configuration contract
# =============================================================================
Describe 'Required E - Main.Configuration.ps1 is the source of truth' {
    BeforeAll {
        # Load only the contract function and the values it reads.
        $script:contract = & {
            $CaptivePortalTimeout = 120
            $MainPortalFlagPollIntervalSec = 3
            $initial_sleep = 5
            $CaptiveEventCooldown = 60
            $CaptiveEventLimit = 3
            $CapPortalBaseTimeoutSeconds = 120
            $CapPortalBaseCheckIntervalSec = 10
            $NewPreflightURL = 'https://gateway.optum.com'
            # Everything else comes from the real file.
            Invoke-Expression (
                [regex]::Match((Get-Content $script:configPath -Raw),
                    '(?s)# ---- Required D: bounded network-settle readiness gate.*?^\}',
                    'Multiline').Value)
            Get-CprCapPortalTimingContract
        }
    }

    It 'declares every tunable the owner listed' {
        foreach ($name in @(
            'NetworkReadyMaxWaitMs', 'NetworkReadyPollIntervalMs', 'NetworkReadyGatewayTimeoutMs',
            'NetworkReadyDnsTimeoutMs', 'NetworkReadyEnabled',
            'CapPortalBasePreflightTimeoutMs', 'CapPortalBasePreflightMaxProbes',
            'CapPortalBaseWebHelperLookbackSec', 'CapPortalHandoffMaxAgeSec',
            'CapPortalWebHelper301FirstEnabled', 'CapPortalWebHelper301LogName',
            'CapPortalWebHelper301ProviderName', 'CapPortalWebHelper301EventId',
            'CapPortalWebHelper301LookbackSec', 'CapPortalWebHelper301WaitSec',
            'CapPortalWebHelper301PollIntervalMs', 'CapPortalWebHelper301MaxAgeSec',
            'CapPortalWebHelper301NoUrlImmediatePreflight', 'CapPortalWebHelper301SuppressPreflight',
            'CapPortalWebHelper301HaystackFallbackEnabled', 'CapPortalWebHelper301HaystackLookbackSec',
            'CapPortalValidationSite', 'CapPortalSiteTimeoutSec',
            'CapPortalFullInitialWaitSec', 'CapPortalFullFinalWaitSec', 'CapPortalFullCheckIntervalSec',
            'CaptivePortalTimeout', 'MainPortalFlagPollIntervalSec', 'initial_sleep',
            'CapPortalBaseTimeoutSeconds', 'CapPortalBaseCheckIntervalSec',
            'CaptiveEventCooldown', 'CaptiveEventLimit')) {
            $script:configSource | Should -Match ('\$' + $name + '\s*=')
        }
    }

    It 'documents unit and consumer for the consolidated values' {
        $script:configSource | Should -Match 'consumer: MAIN'
        $script:configSource | Should -Match 'consumer: BASE'
        $script:configSource | Should -Match 'consumer: FULL'
    }

    It 'preserves the owner-stated values that must not drift' {
        $script:configSource | Should -Match '\$CapPortalFullInitialWaitSec\s*=\s*150'
        $script:configSource | Should -Match '\$CapPortalFullFinalWaitSec\s*=\s*30'
        # Owner set Base cap-portal timers to match Main's.
        $script:contract.base_observe_timeout_sec | Should -Be 120
    }

    It 'renames the ambiguous poll interval and documents the kept alias' {
        # MAIN polls portal_complete.flag; BASE polls connectivity. Distinct.
        $script:configSource | Should -Match '\$MainPortalFlagPollIntervalSec\s*='
        $script:configSource | Should -Match '\$FlagPollInterval\s*=\s*\$MainPortalFlagPollIntervalSec'
        $script:configSource | Should -Match '(?i)deprecated alias'
        $script:capSource    | Should -Not -Match 'Start-Sleep -Seconds \$FlagPollInterval'
    }

    It 'exposes the full contract through Get-CprCapPortalTimingContract' {
        foreach ($key in $script:contractKeys) {
            $script:contract.Keys | Should -Contain $key
        }
        $script:contract.GetType().FullName | Should -Be 'System.Collections.Specialized.OrderedDictionary'
    }
}

Describe 'Required E - MAIN writes the effective values into the artifact before 777/778' {
    It 'stamps timing_contract in the remediation artifact writer' {
        $writer = Get-CprFunctionSource -Path $script:capPath -Names @('Write-CapPortalRemediationState')
        $writer | Should -Match 'Get-CprCapPortalTimingContract'
        $writer | Should -Match "timing_contract"
        $writer | Should -Match 'cap_portal_timing_contract'
    }

    It 'writes the artifact BEFORE Send-FlareEvent fires 777/778' {
        $remediation = Get-CprFunctionSource -Path $script:capPath -Names @('Invoke-CaptivePortalRemediation')
        $write = $remediation.IndexOf('Write-CapPortalRemediationState')
        $fire  = $remediation.IndexOf("Send-FlareEvent 'captive_portal_browser_base'")
        $write | Should -BeGreaterThan 0
        $fire  | Should -BeGreaterThan $write
    }
}

Describe 'Required E - BASE and FULL consume the artifact, literals are fail-safe only' {
    BeforeAll {
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath -Names @('Get-CprTimingValue'))
    }

    It 'BASE resolves its timers from the artifact when present' {
        $resolver = Get-CprFunctionSource -Path $script:basePath -Names @('Resolve-BaseTimingContract')
        foreach ($key in @('base_observe_timeout_sec', 'base_check_interval_sec', 'base_preflight_timeout_ms',
                'base_preflight_max_probes', 'base_webhelper_lookback_sec', 'handoff_max_age_sec',
                'validation_site', 'site_reachability_timeout_sec', 'preflight_url',
                'network_ready_max_wait_ms', 'network_ready_poll_interval_ms',
                'webhelper_301_suppress_preflight', 'webhelper_301_max_age_sec')) {
            $resolver | Should -Match ([regex]::Escape($key))
        }
        $resolver | Should -Match "'dispatch_artifact'"
        $resolver | Should -Match "'fallback_defaults'"
    }

    It 'FULL resolves its timers from the artifact when present' {
        $resolver = Get-CprFunctionSource -Path $script:fullPath -Names @('Resolve-FullTimingContract')
        foreach ($key in @('full_initial_wait_sec', 'full_final_wait_sec', 'full_check_interval_sec',
                'validation_site', 'site_reachability_timeout_sec')) {
            $resolver | Should -Match ([regex]::Escape($key))
        }
    }

    It 'both runners document their literals as fail-safe defaults' {
        $script:baseSource | Should -Match '(?i)FAIL-SAFE DEFAULT'
        $script:fullSource | Should -Match '(?i)FAIL-SAFE DEFAULT'
    }

    It 'the fallback only engages when the key is absent, unreadable or out of range' {
        $contract = [ordered]@{ base_check_interval_sec = 10; validation_site = 'https://www.optum.com'; bad = 'xyz' }
        Get-CprTimingValue -Contract $contract -Key 'base_check_interval_sec' -Fallback 99 | Should -Be 10
        Get-CprTimingValue -Contract $contract -Key 'validation_site' -Fallback 'https://fallback' | Should -Be 'https://www.optum.com'
        Get-CprTimingValue -Contract $contract -Key 'missing' -Fallback 42 | Should -Be 42
        Get-CprTimingValue -Contract $null -Key 'base_check_interval_sec' -Fallback 42 | Should -Be 42
        Get-CprTimingValue -Contract $contract -Key 'bad' -Fallback 42 | Should -Be 42
        # Range guard: an absurd artifact value cannot hang a runner.
        Get-CprTimingValue -Contract ([ordered]@{ base_check_interval_sec = 99999 }) `
            -Key 'base_check_interval_sec' -Fallback 10 -Maximum 300 | Should -Be 10
    }

    It 'handles both hashtable and ordered-dictionary contracts identically' {
        $ordered = [ordered]@{ full_final_wait_sec = 30 }
        $hash    = @{ full_final_wait_sec = 30 }
        Get-CprTimingValue -Contract $ordered -Key 'full_final_wait_sec' -Fallback 1 | Should -Be 30
        Get-CprTimingValue -Contract $hash    -Key 'full_final_wait_sec' -Fallback 1 | Should -Be 30
    }

    It 'logs the effective contract at MAIN dispatch and at each runner startup' {
        $script:capSource  | Should -Match 'cap_portal_timing_contract source='
        $script:baseSource | Should -Match 'cap_portal_timing_contract source='
        $script:fullSource | Should -Match 'cap_portal_timing_contract source='
    }
}

Describe 'Required E - no orphaned duplicate literals' {
    It 'BASE no longer hardcodes its timers at the use sites' {
        $script:baseSource | Should -Not -Match 'Start-Sleep -Seconds 10\b'
        $script:baseSource | Should -Match '\$baseTiming\.CheckIntervalSec'
        $script:baseSource | Should -Match '\$baseTiming\.ObserveTimeoutSeconds'
    }

    It 'FULL no longer hardcodes 150/30 at the use sites' {
        $script:fullSource | Should -Match '\$InitialWaitSeconds'
        $script:fullSource | Should -Not -Match 'Start-Sleep -Seconds 150'
        $script:fullSource | Should -Not -Match 'Start-Sleep -Seconds 30\b'
    }

    It 'the validation site is declared once per script and sourced from the contract' {
        @([regex]::Matches($script:baseSource, '"https://www\.optum\.com"')).Count | Should -BeLessOrEqual 1
        @([regex]::Matches($script:fullSource, '"https://www\.optum\.com"')).Count | Should -BeLessOrEqual 1
    }
}
