# CPR RC2 orchestration entry point.
# Depends on: every preceding Main.* library in the documented dot-sourcing order.


# RC2.1 stages: (1) critical path = classify network, flare, remediate;
# (2) Maintenance stage (Invoke-MaintenanceStage) = task sync, HayStack reroll,
# self-update, XmlVault sync. Maintenance runs once, last, after the flare, and
# skips share-dependent work when offline / not on-prem / VPN not Connected.
function Write-MaintStep {
    # Timing marker between startup-maintenance steps. If a run stalls, the last
    # marker in the log names the step that finished; the stall is in the next one.
    param([string]$Name)
    $now = Get-Date
    $ms = 0
    if ($script:maintStepAt) { $ms = [math]::Round(($now - $script:maintStepAt).TotalMilliseconds) }
    Write-Log "maintenance_step name='$Name' elapsed_ms=$ms" "DEBUG"
    $script:maintStepAt = $now
}

function Invoke-WhiteWalkerStartupSubsystems {
    # Cheap local essentials only: drain the cap-portal handback and clear stale
    # blackhole hosts entries. Everything else is the Maintenance stage below.
    if ($script:startupSubsystemsRan) { return }
    $script:startupSubsystemsRan = $true
    $script:maintStepAt = Get-Date

    $null = Import-CapPortalUserHandback
    Write-MaintStep 'handback'

    # Safety: run blackhole -rm at every startup regardless of state, so hosts
    # entries are never left in place after a prior state snafu.
    Invoke-BlackholeAction -Tag 'startup'
    Write-MaintStep 'blackhole_startup'
}

function Invoke-HaystackDrainKick {
    param([bool]$CorpReachable = $false)
    # End-of-run: if telemetry is queued and the state can ship, start the
    # HayStack_Monitor task now instead of waiting for its next wake, so an
    # install/update result reaches Splunk right away. The task drains the
    # queue itself (claim-by-rename, IgnoreNew), so this never double-sends.
    # Gated on THIS run's verdict ($CorpReachable = on-prem or VPN really Connected),
    # never on state.json, which can be stale (e.g. user_tun left over while the
    # client is still posturing). WW_syslog.ps1 is UDP and exits 0 once the packet
    # leaves the box, so a drain on a dead path would DELETE rows as "sent".
    # Fail-soft: never throws, never delays the run.
    if (-not $HaystackEnabled -or -not $HaystackDrainKick) { return }
    try {
        $queued = $false
        if ((Test-Path $HaystackDrainQueueFile) -and ((Get-Item $HaystackDrainQueueFile -ErrorAction SilentlyContinue).Length -gt 0)) { $queued = $true }
        if (-not $queued -and (Test-Path $HaystackDrainPendingDir)) {
            if (@(Get-ChildItem $HaystackDrainPendingDir -File -ErrorAction SilentlyContinue).Count -gt 0) { $queued = $true }
        }
        if (-not $queued) { Write-Log "haystack_drain_kick skipped reason='queue_empty'" "DEBUG"; return }

        if (-not $CorpReachable) {
            Write-Log "haystack_drain_kick skipped reason='corp_not_reachable_this_run'" "INFO"
            return
        }
        $cur = ''
        try { $cur = [string](Get-Content $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json).currentState } catch { }
        if ($WhatIf) { Write-Log "WHATIF: Would start task $HaystackDrainTaskName (drain kick)" "INFO"; return }
        # Find the task by name wherever it is registered (the reroll may be
        # re-registering it, or an older install left it in another folder).
        $t = @(Get-ScheduledTask -TaskName $HaystackDrainTaskName -ErrorAction SilentlyContinue) | Select-Object -First 1
        $started = $false
        if ($t) {
            try {
                Start-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop
                Write-Log "haystack_drain_kick started task='$($t.TaskPath)$($t.TaskName)' state='$cur'" "INFO"
                $started = $true
            } catch {
                Write-Log "haystack_drain_kick task start failed ($($_.Exception.Message)) - trying direct" "WARN"
            }
        } else {
            Write-Log "haystack_drain_kick task '$HaystackDrainTaskName' not found in any folder - trying direct" "WARN"
        }
        if (-not $started) {
            if (Test-Path $HaystackActionScriptPath) {
                Start-Process "powershell.exe" -WindowStyle Hidden `
                    -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$HaystackActionScriptPath`""
                Write-Log "haystack_drain_kick started direct script='$HaystackActionScriptPath' state='$cur'" "INFO"
            } else {
                Write-Log "haystack_drain_kick failed: no task and script not found: $HaystackActionScriptPath" "WARN"
            }
        }
    } catch {
        Write-Log "haystack_drain_kick failed: $($_.Exception.Message)" "WARN"
    }
}

function Invoke-MaintenanceStage {
    # RC2.1 Maintenance stage: everything that is not on the critical path
    # (classify network -> flare -> remediate). Runs ONCE at the very end of the
    # run, after the exit reason and flare are settled, so a slow or hung step
    # can never delay a VPN disconnect, a rescan or a portal browser.
    # Steps that need the corp share are skipped when it is unreachable.
    param([string]$ExitReason = '', [bool]$Skip = $false)
    if ($script:maintenanceRan) { return }
    $script:maintenanceRan = $true

    if ($Skip) {
        Write-Log "maintenance_stage skipped reason='online_fast_path_policy'" "INFO"
        return
    }
    # exit_reason is <reason>:<state>; offline = no usable network state, or a run that never settled (error/unknown).
    $offline = ((Get-CprExitState $ExitReason) -eq 'no_net_transient') -or (@('error_exception', 'state_unknown') -contains (Get-CprExitReasonPart $ExitReason))
    $maintStartedAt = Get-Date
    $script:maintStepAt = $maintStartedAt
    Write-Log "maintenance_stage begin exit_reason='$ExitReason' offline=$offline" "DEBUG"

    # Local-only work: runs even when offline.
    Sync-BlackholeShutdownTask
    Write-MaintStep 'blackhole_task_sync'

    if ($HaystackEnabled) {
        if (Test-Path $HaystackScriptPath) {
            Write-Log "HayStack: enabled - invoking reroll check" "INFO"
            if (-not $WhatIf) {
                Start-Process "powershell.exe" `
                    -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$HaystackScriptPath`" -reroll" `
                    -WindowStyle Hidden
            } else {
                Write-Log "WHATIF: Would invoke haystack.ps1 -reroll" "INFO"
            }
        } else {
            Write-Log "HayStack: enabled but script not found: $HaystackScriptPath" "WARN"
        }
    } else {
        Write-Log "HayStack: disabled - skipping" "DEBUG"
    }
    Write-MaintStep 'haystack'

    Sync-XmlVaultTask
    Write-MaintStep 'xmlvault_task_sync'

    # Share-dependent work: needs on-prem or a Connected VPN, and a live network.
    $shareOk = (-not $offline) -and (Test-XmlVaultSyncAllowed)
    if (-not $shareOk) {
        Write-Log "maintenance_stage: self-update and XmlVault sync skipped - share unreachable (offline=$offline, not on-prem and VPN not Connected)" "INFO"
    } else {
        # Synchronous so download/extract/install status is reliable and concurrent
        # installs are impossible. Last thing in the run, so replacing files is safe.
        Invoke-SelfUpdate
        Write-MaintStep 'self_update'

        if ($XmlVaultEnabled) {
            if (Test-Path $XmlVaultScriptPath) {
                Write-Log "XmlVault: enabled - invoking startup sync" "INFO"
                if (-not $WhatIf) {
                    Start-Process "powershell.exe" `
                        -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$XmlVaultScriptPath`"" `
                        -WindowStyle Hidden
                } else {
                    Write-Log "WHATIF: Would invoke WW_xml_vault.ps1 (sync mode)" "INFO"
                }
            } else {
                Write-Log "XmlVault: enabled but script not found: $XmlVaultScriptPath" "WARN"
            }
        } else {
            Write-Log "XmlVault: disabled - skipping" "DEBUG"
        }
        Write-MaintStep 'xmlvault'
    }
    # After self-update so its result rows are already queued.
    Invoke-HaystackDrainKick -CorpReachable ([bool]$shareOk)
    Write-MaintStep 'haystack_drain_kick'
    Write-Log ("phase_timing phase='maintenance_stage' elapsed_ms={0}" -f `
        [math]::Round(((Get-Date) - $maintStartedAt).TotalMilliseconds)) "INFO"
}

function Invoke-WhiteWalkerMain {

    $mainStartedAt = Get-Date
    $script:LastWebHelper301Evidence = $null
    $ciscoPath = Get-CiscoInstallPath

    Initialize-Logger
    Write-RunHeader
    Write-Log ("phase_timing phase='startup_bootstrap' elapsed_ms={0} startup_elapsed_ms={0}" -f `
        [math]::Round(((Get-Date) - $mainStartedAt).TotalMilliseconds)) "INFO"

    if (-not $ciscoPath) { 
        Write-Log "Error: Cisco Secure Client install path not found."
        Set-CprRunExit -Reason 'error_no_cisco' -State 'cpr_error'
        Send-CprExitFlare $script:exitReason
    } else {
        $ise_cmd = Join-Path $ciscoPath "posturecli.exe"
        $vpn_cmd = Join-Path $ciscoPath "vpncli.exe"

        Write-Log ("CiscoPath={0}" -f $ciscoPath)
        Write-Log ("vpncli={0}"    -f $vpn_cmd)
        Write-Log ("posturecli={0}"-f $ise_cmd)

        if (-not (Test-Path $vpn_cmd)) { 
            Write-Log "Error: vpncli.exe not found."
            Set-CprRunExit -Reason 'error_no_vpncli' -State 'cpr_error'
            Send-CprExitFlare $script:exitReason
        } elseif (-not (Test-Path $ise_cmd)) { 
            Write-Log "Error: posturecli.exe not found."
            Set-CprRunExit -Reason 'error_no_posturecli' -State 'cpr_error'
            Send-CprExitFlare $script:exitReason
        } else {
            Set-CprRunExit -Reason 'state_unknown' -State 'cpr_error'
            $script:currentSsid = $null
            try {
                Write-Log "CPR+ v$ver starting..."

                # ER6: Clean stale flag files before anything else
                Clear-StaleFlagFiles -StaleThresholdMinutes 15
                
                # Set interrupt flag for active instances
                try {
                    Set-Content -Path $InterruptFile -Value (Get-Date).ToString('o') -Encoding UTF8
                    Write-Log "Network interrupt flag set for any active instances" "DEBUG"
                } catch {
                    Write-Log "Could not set interrupt flag: $_" "DEBUG"
                }
                
                # Gather network info with retry logic
                # Handles "Connect Automatically" unchecked scenario where adapter exists but not connected
                $networkInfo = Get-NetworkInfo
                $script:currentSsid = $networkInfo.SSID  # captured for Write-RunEnd SSID cache update
                $script:runAdapterSet = Get-CprActivePhysicalSet

                # RC2.1 early VPN gate: FIRST decision of every run, ahead of every
                # wait, sleep and probe. Secure Client fires a reconnect on any network
                # state change and blocks all traffic while Connecting/Reconnecting.
                $earlyGate = Invoke-EarlyVpnGate -NetworkInfo $networkInfo

                # If no active connection, retry a few times before giving up
                if ($networkInfo.IPAddress -eq "N/A" -or $networkInfo.ConnectionType -eq "Unknown") {
                    Write-Log "No active network connection detected (IP: $($networkInfo.IPAddress), Type: $($networkInfo.ConnectionType))" "WARN"
                    Write-Log "This may be 'Connect Automatically' unchecked - waiting for user to connect..." "INFO"
                    
                    for ($retry = 1; $retry -le $NetworkConnectionRetries; $retry++) {
                        Write-Log "Waiting ${NetworkConnectionWait}s for network connection (attempt $retry/$NetworkConnectionRetries)..." "INFO"
                        Start-Sleep -Seconds $NetworkConnectionWait
                        
                        $networkInfo = Get-NetworkInfo
                        
                        if ($networkInfo.IPAddress -ne "N/A" -and $networkInfo.ConnectionType -ne "Unknown") {
                            Write-Log "Network connection established after $retry retry(ies)" "INFO"
                            break
                        }
                    }
                    
                    # Final check - if still no connection, exit gracefully
                    if ($networkInfo.IPAddress -eq "N/A" -or $networkInfo.ConnectionType -eq "Unknown") {
                        Write-Log "No network connection after $NetworkConnectionRetries retries (total wait: $($NetworkConnectionRetries * $NetworkConnectionWait)s)" "WARN"
                        Write-Log "User needs to manually connect to network (check 'Connect Automatically' setting)" "WARN"
                        Set-CprRunExit -Reason 'no_network_connection' -State 'no_net_transient'
                        Write-NetworkInfoToLog -NetworkInfo $networkInfo
                        Invoke-WhiteWalkerStartupSubsystems
                        Invoke-BlackholeAction -Tag 'no_network_connection'
                        return
                    }
                }
                
                Write-NetworkInfoToLog -NetworkInfo $networkInfo

                # Cache current SSID for Write-RunEnd to persist at run completion
                $script:currentSsid = $networkInfo.SSID
                $script:runAdapterSet = Get-CprActivePhysicalSet

                # WLANi03 awareness: always on-prem corp wireless, ISE likely mid-posture scan.
                # If we have no valid IP yet, wait longer than normal before proceeding.
                # Once we have a valid IP, let the normal preflight flow run - gateway.optum.com
                # will redirect when unpostured, same as enroll.cisco.com.
                if ($networkInfo.SSID -eq 'WLANi03' -and 
                    ($networkInfo.IPAddress -eq 'N/A' -or $networkInfo.IPAddress -match '^169\.254\.')) {
                    Write-Log "WLANi03 detected but no valid IP yet - waiting for ISE to complete initial scan..." "INFO"
                    $wlaniRetries = 6   # up to 18s extra wait (6 x 3s)
                    for ($w = 1; $w -le $wlaniRetries; $w++) {
                        Start-Sleep -Seconds 3
                        $networkInfo = Get-NetworkInfo
                        Write-Log "WLANi03 IP wait attempt $w/$wlaniRetries : $($networkInfo.IPAddress)" "DEBUG"
                        if ($networkInfo.IPAddress -ne 'N/A' -and $networkInfo.IPAddress -notmatch '^169\.254\.') {
                            Write-Log "WLANi03 valid IP obtained: $($networkInfo.IPAddress)" "INFO"
                            break
                        }
                    }
                    # Refresh log with updated network info
                    Write-NetworkInfoToLog -NetworkInfo $networkInfo
                }
                
                # Check for user prompt flag
                if (Test-UserPromptedFlag) {
                    Set-CprRunExit -Reason 'waiting_user_response' -State 'captive_portal'
                    Invoke-WhiteWalkerStartupSubsystems
                    Invoke-BlackholeAction -Tag 'waiting_user_response'
                    return
                }
                
                # Cisco browser killer fires only in captive portal branch
                # (Invoke-CaptivePortalRemediation / walled garden). Init null for finally safety net.
                $ciscoBrowserKillerJob = $null

                # =====================================================================
                # RC2.1 Connected short-circuit: the early gate left VPN fully Connected,
                # so the network is demonstrably up and there is no portal or ISE redirect
                # to find - skip the gateway preflight and every cap-portal branch. A
                # Connected VPN is never disconnected here (BlackHole owns on-prem policy).
                # VPN Disconnected always takes the normal path.
                # =====================================================================
                if ($VpnConnectedShortCircuit -and $earlyGate.VpnState -eq 'Connected' -and -not $earlyGate.Acted) {
                    if (($earlyGate.Wake -or $earlyGate.Jump) -and -not $VpnConnectedTrustOnWakeJump) {
                        # Optional paranoia (pivot off by default): Secure Client can report Connected for
                        # seconds after a hop. Default is to trust Connected - when it goes stale it flips to
                        # Reconnecting and its 2072/2037/2044 events start a new run.
                        Write-Log "VPN reports Connected but a wake/SSID jump just happened (wake=$($earlyGate.Wake) jump=$($earlyGate.Jump)) - not short-circuiting" "WARN"
                    } else {
                        $scFlavor = Get-VpnTunnelFlavor
                        if ($scFlavor -eq 'mgmt_tun' -or $scFlavor -eq 'user_tun') {
                            Write-Log "VPN Connected at run start (flavor=$scFlavor wake=$($earlyGate.Wake) jump=$($earlyGate.Jump)) - skipping preflight and captive-portal checks" "INFO"
                            Invoke-WhiteWalkerStartupSubsystems
                            $scTelemetry = Get-CprConnectionTelemetry -NetworkInfo $networkInfo
                            Write-TeeLog 'network_state' @{
                                ip        = $networkInfo.IPAddress
                                gw        = $networkInfo.DefaultGateway
                                dns       = ($networkInfo.DNSServers -join ',')
                                ssid      = $scTelemetry.ssid
                                connection_type = $scTelemetry.connection_type
                                vpn_state = 'Connected'
                                lease_sec = $(if ($null -ne $networkInfo.LeaseDurationSeconds) { $networkInfo.LeaseDurationSeconds } else { -1 })
                            }
                            Send-FlareEvent $scFlavor
                            Clear-CaptiveEventHistory "VPN connected"
                            Set-CprRunExit -Reason 'vpn_connected' -State $scFlavor
                            return
                        }
                        Write-Log "VPN reported Connected but tunnel flavor is '$scFlavor' - continuing with normal preflight" "WARN"
                    }
                }

                # (Moved below the Connected short-circuit: a Connected VPN needs no DHCP settle.)
                # Only the DHCP settling delay survives here - it is the one wait
                # that is genuinely required before probing a freshly acquired
                # lease. Nothing else is allowed between network-ready and the
                # authoritative preflight.
                Write-Log "Sleeping $initial_sleep seconds post-DHCP (DHCP settling - required before probing a fresh lease)..."
                Start-Sleep -Seconds $initial_sleep

                # APIPA check: 169.254.x.x + no gateway = no real network connection yet.
                # No point hitting nwcheck or anything else - just bail.
                if ($networkInfo.IPAddress -match '^169\.254\.' -and 
                    ($networkInfo.DefaultGateway -eq 'N/A' -or [string]::IsNullOrEmpty($networkInfo.DefaultGateway))) {
                    Write-Log "APIPA address ($($networkInfo.IPAddress)) with no gateway - not connected to network yet" "WARN"
                    Set-CprRunExit -Reason 'apipa_no_gateway' -State 'no_net_transient'
                    Invoke-WhiteWalkerStartupSubsystems
                    Invoke-BlackholeAction -Tag 'no_net_transient'
                    return
                }

                # =====================================================================
                # RC2.3 evidence precedence: a fresh direct EventID 301
                # navigated_url wins only while Cisco WebHelper actively owns the
                # captive-portal path. Otherwise nwcheck remains the authoritative
                # online / redirect / unreachable classifier.
                #
                # RC2.1 (Required C): this authoritative preflight is now fired
                # IMMEDIATELY once a usable IP/default gateway exists. Self-update,
                # HayStack reroll, XmlVault sync, the network_state tee (vpncli),
                # SSID-change handling and MAC-randomization checks all run AFTER
                # it, so the probe no longer waits minutes behind them.
                # =====================================================================
                $networkReadyAt = Get-Date
                Write-Log "Network ready (ip=$($networkInfo.IPAddress) gw=$($networkInfo.DefaultGateway)) - selecting captive-portal evidence source" "INFO"

                $nwCheck = $null
                $webHelperEvidence = $null
                $webHelperActive = $false
                if ($CapPortalWebHelper301FirstEnabled) {
                    # This is the credibility gate: do not query EventID 301 on
                    # every normal run. Cisco's active captive-portal WebHelper
                    # means WebView2 currently owns the path and a fresh direct
                    # event can avoid a predictably blocked PowerShell request.
                    $webHelperActive = Test-CprCiscoWebHelperActive
                    if ($webHelperActive) {
                        Write-Log "Cisco WebHelper is active - checking direct EventID 301 evidence before gateway preflight" "INFO"
                        $first301LookupStartedAt = Get-Date
                        $webHelperEvidence = Wait-CprCiscoWebHelper301Evidence `
                            -CorrelationStart $networkReadyAt `
                            -LookbackSeconds $CapPortalWebHelper301LookbackSec `
                            -MaxRecords $CapPortalWebHelper301MaxRecords `
                            -WaitSeconds $CapPortalWebHelper301WaitSec `
                            -PollIntervalMs $CapPortalWebHelper301PollIntervalMs `
                            -MaximumAgeSeconds $CapPortalWebHelper301MaxAgeSec `
                            -LogName $CapPortalWebHelper301LogName `
                            -ProviderName $CapPortalWebHelper301ProviderName `
                            -EventId $CapPortalWebHelper301EventId `
                            -CurrentSsid $networkInfo.SSID `
                            -NoUrlImmediatePreflight $CapPortalWebHelper301NoUrlImmediatePreflight `
                            -HaystackFallbackEnabled $CapPortalWebHelper301HaystackFallbackEnabled `
                            -HaystackLookbackSeconds $CapPortalWebHelper301HaystackLookbackSec
                        Write-Log ("phase_timing phase='first_webhelper_301_lookup' elapsed_ms={0} startup_elapsed_ms={1}" -f `
                            [math]::Round(((Get-Date) - $first301LookupStartedAt).TotalMilliseconds), `
                            [math]::Round(((Get-Date) - $mainStartedAt).TotalMilliseconds)) "INFO"
                        if ($webHelperEvidence.Found -or $webHelperEvidence.ReadFailed) {
                            $webHelperNetCtx = Get-CaptivePortalNetworkContext
                            Write-CprCiscoWebHelper301Evidence -Evidence $webHelperEvidence -NetworkContext $webHelperNetCtx
                        }
                        if (Test-CprWebHelperCanSuppressPreflight -Evidence $webHelperEvidence `
                            -SuppressEnabled $CapPortalWebHelper301SuppressPreflight) {
                            $nwCheck = New-CprWebHelperPreflightResult -Evidence $webHelperEvidence
                            $global:LastCapPreflightResult = $nwCheck
                            $script:LastWebHelper301Evidence = $webHelperEvidence
                            Write-Log ("detection_source=cisco_webhelper_301 selected_record_id='{0}' selected_event_time='{1}' navigated_url='{2}' - blocked gateway preflight suppressed" -f `
                                $webHelperEvidence.EventRecordId, $webHelperEvidence.EventTime, $webHelperEvidence.NavigatedUrl) "WARN"
                        } elseif ($webHelperEvidence.Source -eq 'haystack_log_fallback') {
                            Write-Log "detection_source=haystack_log_fallback is supporting diagnostic only - gateway_preflight remains required" "INFO"
                        } elseif ($webHelperEvidence.UsableNavigation) {
                            Write-Log "EventID 301 classification='$($webHelperEvidence.Classification)' is not eligible to suppress gateway_preflight; Main posture routing remains authoritative" "INFO"
                        } elseif ($webHelperEvidence.Found) {
                            Write-Log "detection_source=cisco_webhelper_301 status=navigation_unavailable reason=$($webHelperEvidence.Reason) - falling back to gateway_preflight" "INFO"
                        } elseif ($webHelperEvidence.ReadFailed) {
                            Write-Log "Direct EventID 301 read failed softly: $($webHelperEvidence.Error) - falling back to gateway_preflight" "WARN"
                        }
                    }
                }

                if ($null -eq $nwCheck) {
                    # RC2.2 (Required D): bounded network-settle gate. Polls cheap
                    # readiness signals and fires the preflight the MOMENT one is
                    # observed; on cap expiry it probes anyway and records
                    # signal='not_confirmed'. Never a fixed sleep, so a healthy
                    # corporate-wireless path (WLANi03 posture) is not delayed.
                    # RC2.1: settle VPN state BEFORE the readiness poll - in Connecting/
                    # Reconnecting every readiness probe fails and burns the full cap.
                    $preSettleVpnState = 'Disconnected'
                    if ($PreflightRequiresSettledVpn) {
                        $preSettleVpnState = Get-VpnStateStable -TimeoutSec $VpnStateMaxWaitSeconds
                    }
                    # HostScan posture in progress: the client already reached the headend and is not blocked behind a
                    # portal. Do not probe, classify or cut - end the run; the next trigger re-checks.
                    if ($script:VpnHostscanHoldActive -and $preSettleVpnState -in @('Connecting', 'Reconnecting')) {
                        Write-Log "vpn_hostscan_posturing_hold exit - HostScan scan in progress, ending run without probing or disconnecting" "WARN"
                        Set-CprRunExit -Reason 'hostscan_in_progress' -State 'vpn_connecting'
                        Write-RunEnd $script:exitReason
                        return
                    }
                    $vpnSettledForProbe = ($preSettleVpnState -in @('Connected', 'Disconnected'))
                    $readiness = Wait-CprNetworkReady -GatewayAddress $networkInfo.DefaultGateway `
                        -ProbeHost $NewPreflightURL -Disabled:((-not $NetworkReadyEnabled) -or (-not $vpnSettledForProbe))
                    Write-Log ("network_ready_gate network_ready_wait_ms={0} signal='{1}' attempts={2} max_wait_ms={3} poll_interval_ms={4}" -f `
                        $readiness.WaitedMs, $readiness.Signal, $readiness.Attempts, `
                        $NetworkReadyMaxWaitMs, $NetworkReadyPollIntervalMs) $(if ($readiness.Ready) { 'INFO' } else { 'WARN' })

                    $preflightStartedAt = Get-Date
                    $networkReadyToPreflightMs = [math]::Round(($preflightStartedAt - $networkReadyAt).TotalMilliseconds)
                    Write-Log "detection_source=gateway_preflight - running authoritative gateway.optum.com classification" "INFO"
                    $nwCheck = Invoke-GatedNwCheck -KnownVpnState $preSettleVpnState
                    $preflightFinishedAt = Get-Date
                    Write-Log ("preflight_timing network_ready_to_preflight_ms={0} network_ready_to_preflight_sec={1} startup_to_preflight_ms={2} preflight_duration_ms={3} status='{4}'" -f `
                        $networkReadyToPreflightMs, [math]::Round($networkReadyToPreflightMs / 1000, 2), `
                        [math]::Round(($preflightStartedAt - $mainStartedAt).TotalMilliseconds), `
                        [math]::Round(($preflightFinishedAt - $preflightStartedAt).TotalMilliseconds), $nwCheck.Status) "INFO"
                } else {
                    Write-Log ("preflight_timing network_ready_to_preflight_ms=-1 network_ready_to_preflight_sec=-1 startup_to_preflight_ms=-1 preflight_duration_ms=0 status='suppressed' gateway_preflight_ran=false") "INFO"
                }

                # RC2.1: remember which network this preflight result belongs to.
                $preflightFingerprint = Get-CprNetworkFingerprint -NetworkInfo $networkInfo
                $reprobedOnNetworkChange = $false

                $onlineFastPathSelected = ($OnlineFastPathEnabled -and $nwCheck.Status -eq 'online')
                if ($onlineFastPathSelected) {
                    $onlineFastPathStartedAt = Get-Date
                    Write-Log ("online_fast_path ran=true evidence='gateway_preflight_online' maintenance='{0}' skipped='webhelper_301_lookup,redirect_tests,walled_garden,base_full_dispatch,remediation_state,portal_polling,secondary_preflight'" -f `
                        $(if ($OnlineFastPathRunMaintenance) { 'synchronous' } else { 'deferred' })) "INFO"
                } else {
                    Write-Log "online_fast_path ran=false reason='preflight_not_online_or_policy_disabled' skipped='none'" "INFO"
                }

                # Deferred, non-routing-critical subsystem work now that the
                # authoritative probe is already in hand.
                Invoke-WhiteWalkerStartupSubsystems

                # A synchronous self-update is a long blocking operation and may
                # replace network cmdlets or span DHCP/reconnect transitions. Never
                # trust the pre-install snapshot afterward without a cheap check.
                $networkInfo = Get-CprCurrentNetworkSnapshot -Snapshot $networkInfo `
                    -Force:([bool]$script:NetworkSnapshotInvalidated)
                $script:NetworkSnapshotInvalidated = $false
                $script:currentSsid = $networkInfo.SSID
                $script:runAdapterSet = Get-CprActivePhysicalSet
                $connectionTelemetry = Get-CprConnectionTelemetry -NetworkInfo $networkInfo

                Write-TeeLog 'network_state' @{
                    ip        = $networkInfo.IPAddress
                    gw        = $networkInfo.DefaultGateway
                    dns       = ($networkInfo.DNSServers -join ',')
                    ssid      = $connectionTelemetry.ssid
                    connection_type = $connectionTelemetry.connection_type
                    vpn_state = (Get-VpnState)
                    lease_sec = $(if ($null -ne $networkInfo.LeaseDurationSeconds) { $networkInfo.LeaseDurationSeconds } else { -1 })
                }

                # SSID change detection: if SSID changed and VPN active/stuck,
                # give it a grace window then force disconnect if needed.
                # Prevents VPN reconnect attempts blocking captive portal / ISE.
                Invoke-SsidChangeCheck -CurrentSsid $networkInfo.SSID

                # Check for MAC randomization on this SSID (hotel portals auth by MAC)
                if ($networkInfo.ConnectionType -eq "WiFi" -and $networkInfo.SSID -ne "N/A") {
                    Test-MacRandomization -CurrentSsid $networkInfo.SSID -CurrentMac $networkInfo.MACAddress
                }

                # RC2.1: a preflight result belongs to the network it was taken on. If the
                # adapter/IP/gateway/SSID fingerprint changed during this run (user hopped
                # networks while startup maintenance or SSID-change handling ran), the
                # result is stale - e.g. 'online' from home must not classify a captive
                # portal network. Discard it and probe the new network. A new network with
                # no usable IP yet ends the run: its DHCP event starts a fresh one.
                $currentFingerprint = Get-CprNetworkFingerprint -NetworkInfo $networkInfo
                if ($preflightFingerprint -and ($currentFingerprint -ne $preflightFingerprint)) {
                    Write-Log "Network changed since preflight - discarding stale '$($nwCheck.Status)' result (was '$preflightFingerprint', now '$currentFingerprint')" "WARN"
                    $global:LastCapPreflightResult = $null
                    $script:LastWebHelper301Evidence = $null
                    if (-not (Test-AnyUsableIp -NetworkInfo $networkInfo)) {
                        Write-Log "New network has no usable IP yet - ending run; its DHCP event starts a fresh run" "WARN"
                        Set-CprRunExit -Reason 'network_changed_no_ip' -State 'no_net_transient'
                        return
                    }
                    $nwCheck = Invoke-GatedNwCheck
                    $reprobedOnNetworkChange = $true
                    Write-Log "Preflight on new network: $($nwCheck.Status)" "INFO"
                }

                # The early probe can be INCONCLUSIVE because a still-negotiating
                # Cisco tunnel was holding the stack when it fired. SSID-change
                # handling above may have cleared that, so re-probe once - a
                # usable (online/redirect) early result is kept as-is.
                # RC2.1: nothing was done to a VPN that stayed Connected, so a second probe cannot differ.
                $vpnStayedConnected = ($earlyGate.VpnState -eq 'Connected' -and -not $earlyGate.Acted)
                if ($nwCheck.Status -eq 'unreachable' -and -not $reprobedOnNetworkChange -and -not $vpnStayedConnected) {
                    Write-Log "Early preflight was inconclusive - re-probing once after VPN/SSID handling settled" "INFO"
                    $nwCheck = Invoke-GatedNwCheck
                    Write-Log "Re-probe result after settling: $($nwCheck.Status)" "INFO"
                }
                
                switch ($nwCheck.Status) {
                
                    "online" {
                        # nwcheck returned gateway signature - we have clean internet.
                        # Use Get-VpnTunnelFlavor directly - it parses Management Connection State
                        # which is the ONLY reliable way to detect mgmt tunnels.
                        # Get-VpnState reads basic State: which shows Disconnected on mgmt tunnels.
                        Write-Log "nwcheck: ONLINE - classifying connection type..." "INFO"
                        $flavor = Get-VpnTunnelFlavor
                        Write-Log "VPN tunnel flavor: $flavor" "INFO"
                        
                        if ($flavor -eq 'mgmt_tun' -or $flavor -eq 'user_tun') {
                            Write-Log "VPN connected; flavor=$flavor"
                            
                            # FLARE EVENT: user_tun OR mgmt_tun
                            # Context: USER | Reason: VPN tunnel confirmed active
                            # Ivanti Use: Session-specific automations requiring user identity
                            Send-FlareEvent $flavor
                            
                            Clear-CaptiveEventHistory "VPN connected"
                            Set-CprRunExit -Reason 'vpn_connected' -State $flavor
                            return
                        }
                        
                        # No VPN tunnel - on-prem or off-prem
                        $dcOK = Test-DC -hostname $DC_FQDN
                        Write-Log ("Connectivity: VPN=None  DC={0}  preflight=online" -f $dcOK)
                        
                        if ($dcOK) {
                            # DC reachable - verify on-prem with SSID trust check.
                            # Wired = always trusted. WiFi = must be in hardcoded list or trusted_ssids.cfg.
                            # Protects against: off-prem VPN + ISP hands out no suffix
                            # (VPN pushes corp-only suffixes making DC check look on-prem).
                            $ssidTrusted = Test-SsidTrusted -NetworkInfo $networkInfo
                            if ($ssidTrusted) {
                                # FLARE EVENT: on_prem
                                # Context: SYSTEM (Event ID 793) | Reason: DC reachable, no VPN, SSID trusted
                                # Ivanti Use: Telemetry for on-prem presence / campus automations
                                Send-FlareEvent 'on_prem'
                                Clear-CaptiveEventHistory "on-premises connection"
                                Set-CprRunExit -Reason 'no_action_dc_reachable' -State 'on_prem'
                            } else {
                                # DC reachable but SSID not trusted - off-prem on VPN with no ISP suffix.
                                # Do NOT disconnect VPN. Let normal VPN flare fire on next run.
                                Write-Log "DC reachable but SSID '$($networkInfo.SSID)' not trusted - treating as off-prem, leaving VPN alone" "WARN"
                                Send-FlareEvent 'off_prem_no_vpn'
                                Clear-CaptiveEventHistory "off-premises - untrusted SSID"
                                Set-CprRunExit -Reason 'untrusted' -State 'off_prem_no_vpn'
                            }
                        } else {
                            # FLARE EVENT: off_prem_no_vpn
                            # Context: USER (Event ID 782) | Reason: Internet up, DC not reachable, no VPN
                            # Ivanti Use: Prompt user to connect VPN
                            Send-FlareEvent 'off_prem_no_vpn'
                            Clear-CaptiveEventHistory "off-premises connection"
                            Set-CprRunExit -Reason 'untrusted' -State 'off_prem_no_vpn'
                        }
                        return
                    }
                    
                    "redirect" {
                        # nwcheck was redirected - device is not postured or is behind a captive portal.
                        # The redirect URL tells us exactly which workflow to invoke.
                        $redirectUrl = $nwCheck.RedirectUrl
                        Write-Log "nwcheck: REDIRECT to $redirectUrl - routing to correct workflow" "INFO"
                        $redirectType = Get-RedirectType -RedirectUrl $redirectUrl
                        Write-Log "Redirect classification: $redirectType"
                        
                        # Disconnect VPN if it's blocking local network auth
                        $currentVPNState = Get-VpnState
                        if (Test-VPNBlockingNetwork -VPNState $currentVPNState -RedirectDetected $true) {
                            Write-Log "VPN blocking network auth - forcing disconnect" "WARN"
                            try {
                                Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null
                                Start-Sleep -Seconds 2
                                Write-Log "VPN disconnected to allow network authentication" "INFO"
                            } catch {
                                Write-Log "Error disconnecting VPN: $_" "WARN"
                            }
                        }
                        
                        switch ($redirectType) {
                            "ISE_EMPLOYEE" {
                                # On-prem ISE posture redirect (PSN) -> rescan
                                Write-Log "ISE Employee PSN redirect -> triggering posture rescan" "INFO"
                                
                                # FLARE EVENT: ise_employee_posture_redirect
                                # Context: SYSTEM | Reason: On-prem ISE posture redirect detected via nwcheck
                                # Ivanti Use: Telemetry for ISE posture remediation events
                                Send-FlareEvent 'ise_employee_posture_redirect'
                                Write-TeeLog 'ise_posture_redirect' @{ psn_url = $redirectUrl; ssid = $networkInfo.SSID }
                                
                                $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
                                if (-not $svc) {
                                    Write-Log "ISE redirect but posture service unavailable - cannot rescan" "ERROR"
                                    
                                    # FLARE EVENT: ise_posture_service_unavailable
                                    # Context: SYSTEM | Reason: ISE redirect present but posture service missing
                                    # Ivanti Use: Alert for broken Cisco Secure Client installations
                                    Send-FlareEvent 'ise_posture_service_unavailable'
                                    
                                    Set-CprRunExit -Reason 'ise_redirect_no_posture_service' -NetworkInfo $networkInfo
                                    return
                                }
                                
                                Write-Log "Posture service available: $($svc.Name) ($($svc.Status))" "INFO"
                                Invoke-PostureRescan
                                
                                Write-Log "Monitoring for ISE compliance (up to $PostureComplianceTimeout seconds)..." "INFO"
                                $postureCheckStart = Get-Date
                                $complianceResult = Test-ISEPostureCompliance -TimeoutSec $PostureComplianceTimeout
                                $postureCheckDurationSec = [math]::Round(((Get-Date) - $postureCheckStart).TotalSeconds)
                                
                                if ($complianceResult -eq "Compliant") {
                                    Write-Log "ISE posture check SUCCESSFUL - device is now compliant" "INFO"
                                    
                                    # Verify nwcheck.optum.com is now accessible (ACL lifted)
                                    $nwCheckVerified = Test-NwCheckAfterCompliance -TimeoutSec 30 -PollIntervalSec 3
                                    
                                    if ($nwCheckVerified) {
                                        Write-Log "Post-compliance verification: nwcheck accessible, ACL confirmed lifted" "INFO"
                                    } else {
                                        Write-Log "Post-compliance verification: nwcheck still blocked (ISE/WLC propagation delay)" "WARN"
                                    }
                                    
                                    # FLARE EVENT: ise_posture_compliant
                                    # Context: SYSTEM (Event ID 791) | Reason: Posture check passed
                                    # Ivanti Use: Success telemetry for compliance monitoring
                                    Send-FlareEvent 'ise_posture_compliant'
                                    Write-TeeLog 'ise_posture_compliant' @{ duration_sec = $postureCheckDurationSec }
                                    
                                    Clear-CaptiveEventHistory "ISE posture compliant"
                                    Set-CprRunExit -Reason 'ise_employee_compliant' -NetworkInfo $networkInfo
                                } else {
                                    Write-Log "ISE posture check FAILED - result: $complianceResult" "ERROR"
                                    
                                    # FLARE EVENT: ise_posture_failed
                                    # Context: SYSTEM (Event ID 792) | Reason: Posture check failed after rescan
                                    # Ivanti Use: Alert for non-compliant devices requiring intervention
                                    Send-FlareEvent 'ise_posture_failed'
                                    Write-TeeLog 'ise_posture_failed' @{ reason = $complianceResult }
                                    
                                    Set-CprRunExit -Reason "ise_employee_failed_$complianceResult" -NetworkInfo $networkInfo
                                }
                                return
                            }
                            "ISE_GUEST" {
                                # ISE guest portal -> browser. cap_portal_runner polls nwcheck until clear.
                                Write-Log "ISE Guest portal redirect -> browser remediation" "INFO"
                                Invoke-CaptivePortalRemediation -PortalType "ISE_GUEST" -RedirectUrl $redirectUrl
                                Set-CprRunExit -Reason 'ise_guest_browser_remediated' -NetworkInfo $networkInfo
                                return
                            }
                            default {
                                # Non-ISE captive portal (hotel, coffee shop, airport, etc.)
                                # browser. cap_portal_runner polls nwcheck until clear.
                                Write-Log "Non-ISE/Unknown captive portal redirect -> browser remediation" "INFO"
                                
                                # FLARE EVENT: unknown_captive_portal (for UNKNOWN type only)
                                if ($redirectType -eq "UNKNOWN") {
                                    # Context: SYSTEM | Reason: Redirect detected but type unclassified
                                    # Ivanti Use: Alert for unexpected network configurations
                                    Send-FlareEvent 'unknown_captive_portal'
                                }
                                
                                Invoke-CaptivePortalRemediation -PortalType "NON_ISE" -RedirectUrl $redirectUrl
                                Set-CprRunExit -Reason 'non_ise_browser_remediated' -NetworkInfo $networkInfo
                                return
                            }
                        }
                    }
                    
                    "unreachable" {
                        # nwcheck got no response - two possible causes:
                        #   A) Genuine network problem (no connectivity)
                        #   B) On-prem unpostured: ISE BLOCKS nwcheck but only REDIRECTS enroll.cisco.com
                        # CRITICAL: Test enroll.cisco.com IMMEDIATELY before DHCP lease expires
                        # RC2.1: a Connected VPN settles it. enroll.cisco.com only means something when
                        # there is no VPN (it redirects to an ISE PSN only for an unpostured endpoint), so
                        # with the VPN up there is nothing to learn from it or from any captive-portal
                        # test. A stale Connected after a hop turns into Reconnecting by itself, and that
                        # event starts a fresh run that handles it. Saves ~12s of timeouts per hop.
                        $vpnBeforeEnroll = Get-VpnState
                        if ($vpnBeforeEnroll -eq "Connected") {
                            $triage = Invoke-ConnectedUnreachableTriage
                            Write-Log ("connected_triage outcome='{0}' dc_reachable={1} preflight='{2}' vpn_state='{3}' waited_ms={4} wake={5} jump={6}" -f `
                                $triage.Outcome, $triage.DcReachable, $triage.Preflight, $triage.VpnState, $triage.WaitedMs, $earlyGate.Wake, $earlyGate.Jump) "INFO"
                            Write-TeeLog 'vpn_connected_triage' @{
                                outcome = $triage.Outcome; dc_reachable = [string]$triage.DcReachable; preflight = $triage.Preflight
                                vpn_state = $triage.VpnState; waited_ms = [string]$triage.WaitedMs
                                wake = [string][bool]$earlyGate.Wake; jump = [string][bool]$earlyGate.Jump }
                            if ($triage.Outcome -eq 'state_left_connected') {
                                # The stale Connected resolved: treat it like any not-Connected VPN and
                                # carry on into the normal enroll / captive-portal checks below.
                                if ($triage.VpnState -ne 'Disconnected') {
                                    $null = Invoke-EarlyVpnDisconnect -Reason 'stale_connected_blocking' -VpnStateWas $triage.VpnState
                                }
                                Write-Log "Stale Connected resolved to '$($triage.VpnState)' - continuing with normal checks" "INFO"
                            } else {
                                $flavor = Get-VpnTunnelFlavor
                                Send-FlareEvent $flavor
                                Set-CprRunExit -Reason $(if ($triage.Preflight -eq 'online') { 'vpn_connected' } else { 'vpn_connected_nwcheck_unreachable' }) -State $flavor
                                Invoke-BlackholeAction -Tag $flavor
                                return
                            }
                        }

                        Write-Log "nwcheck: UNREACHABLE - immediately testing enroll.cisco.com before network drops" "WARN"
                        
                        $enrollResult = Test-Redirect -Url $ISERedirectTestURL
                        
                        if ($enrollResult.IsRedirect) {
                            $enrollRedirectType = Get-RedirectType -RedirectUrl $enrollResult.RedirectUrl
                            Write-Log "enroll.cisco.com redirected: type=$enrollRedirectType url=$($enrollResult.RedirectUrl)" "INFO"
                            
                            if ($enrollRedirectType -eq "ISE_EMPLOYEE") {
                                # On-prem unpostured confirmed -> rescan immediately
                                Write-Log "On-prem unpostured: enroll.cisco.com → PSN, triggering rescan" "INFO"
                                Send-FlareEvent 'ise_employee_posture_redirect'
                                Write-TeeLog 'ise_posture_redirect' @{ psn_url = $enrollResult.RedirectUrl; ssid = $networkInfo.SSID }
                                
                                $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
                                if (-not $svc) {
                                    Write-Log "ISE redirect confirmed but posture service unavailable - cannot rescan" "ERROR"
                                    Send-FlareEvent 'ise_posture_service_unavailable'
                                    Set-CprRunExit -Reason 'ise_redirect_no_posture_service' -NetworkInfo $networkInfo
                                    return
                                }
                                
                                Write-Log "Posture service available: $($svc.Name) ($($svc.Status))" "INFO"
                                Invoke-PostureRescan
                                
                                Write-Log "Monitoring for ISE compliance (up to $PostureComplianceTimeout seconds)..." "INFO"
                                $postureCheckStart = Get-Date
                                $complianceResult = Test-ISEPostureCompliance -TimeoutSec $PostureComplianceTimeout
                                $postureCheckDurationSec = [math]::Round(((Get-Date) - $postureCheckStart).TotalSeconds)
                                
                                if ($complianceResult -eq "Compliant") {
                                    Write-Log "ISE posture check SUCCESSFUL - device is now compliant" "INFO"
                                    
                                    # Verify nwcheck.optum.com is now accessible (ACL lifted)
                                    $nwCheckVerified = Test-NwCheckAfterCompliance -TimeoutSec 30 -PollIntervalSec 3
                                    
                                    if ($nwCheckVerified) {
                                        Write-Log "Post-compliance verification: nwcheck accessible, ACL confirmed lifted" "INFO"
                                    } else {
                                        Write-Log "Post-compliance verification: nwcheck still blocked (ISE/WLC propagation delay)" "WARN"
                                    }
                                    
                                    Send-FlareEvent 'ise_posture_compliant'
                                    Write-TeeLog 'ise_posture_compliant' @{ duration_sec = $postureCheckDurationSec }
                                    Clear-CaptiveEventHistory "ISE posture compliant"
                                    Set-CprRunExit -Reason 'ise_employee_compliant' -NetworkInfo $networkInfo
                                } else {
                                    Write-Log "ISE posture check FAILED - result: $complianceResult" "ERROR"
                                    Send-FlareEvent 'ise_posture_failed'
                                    Write-TeeLog 'ise_posture_failed' @{ reason = $complianceResult }
                                    Set-CprRunExit -Reason "ise_employee_failed_$complianceResult" -NetworkInfo $networkInfo
                                }
                                return
                            } else {
                                # enroll.cisco.com redirected but not to PSN - treat as captive portal
                                Write-Log "enroll.cisco.com redirected to non-PSN URL ($enrollRedirectType) - treating as captive portal" "WARN"
                                $portalRedirectUrl = $enrollResult.RedirectUrl
                                if ($CapPortalWebHelper301FirstEnabled -and
                                    ($null -eq $webHelperEvidence -or -not $webHelperEvidence.UsableNavigation)) {
                                    $webHelperEvidence = Wait-CprCiscoWebHelper301Evidence `
                                        -CorrelationStart $networkReadyAt `
                                        -LookbackSeconds $CapPortalWebHelper301LookbackSec `
                                        -MaxRecords $CapPortalWebHelper301MaxRecords `
                                        -WaitSeconds $CapPortalWebHelper301WaitSec `
                                        -PollIntervalMs $CapPortalWebHelper301PollIntervalMs `
                                        -MaximumAgeSeconds $CapPortalWebHelper301MaxAgeSec `
                                        -LogName $CapPortalWebHelper301LogName `
                                        -ProviderName $CapPortalWebHelper301ProviderName `
                                        -EventId $CapPortalWebHelper301EventId `
                                        -CurrentSsid $networkInfo.SSID `
                                        -NoUrlImmediatePreflight $CapPortalWebHelper301NoUrlImmediatePreflight `
                                        -HaystackFallbackEnabled $CapPortalWebHelper301HaystackFallbackEnabled `
                                        -HaystackLookbackSeconds $CapPortalWebHelper301HaystackLookbackSec
                                    if ($webHelperEvidence.Found -or $webHelperEvidence.ReadFailed) {
                                        Write-CprCiscoWebHelper301Evidence -Evidence $webHelperEvidence `
                                            -NetworkContext (Get-CaptivePortalNetworkContext)
                                    }
                                    if (Test-CprWebHelperCanSuppressPreflight -Evidence $webHelperEvidence `
                                        -SuppressEnabled $true) {
                                        $portalRedirectUrl = $webHelperEvidence.NavigatedUrl
                                        $script:LastWebHelper301Evidence = $webHelperEvidence
                                        $global:LastCapPreflightResult = New-CprWebHelperPreflightResult -Evidence $webHelperEvidence
                                        Write-Log ("detection_source=cisco_webhelper_301 selected_record_id='{0}' selected_event_time='{1}' navigated_url='{2}' selected after enroll.cisco.com entered NON_ISE remediation" -f `
                                            $webHelperEvidence.EventRecordId, $webHelperEvidence.EventTime, $portalRedirectUrl) "WARN"
                                    }
                                }
                                Invoke-CaptivePortalRemediation -PortalType "NON_ISE" -RedirectUrl $portalRedirectUrl
                                Set-CprRunExit -Reason 'non_ise_browser_remediated_via_enroll' -NetworkInfo $networkInfo
                                return
                            }
                        }
                        
                        # enroll.cisco.com didn't redirect - now check VPN state for other causes
                        Write-Log "enroll.cisco.com no redirect - checking VPN state to determine cause" "INFO"
                        $currentVPNState = Get-VpnState
                        
                        if ($currentVPNState -eq "Connected") {
                            # VPN is up but nwcheck unreachable - log anomaly and exit
                            Write-Log "nwcheck unreachable with VPN connected - unexpected state, exiting" "WARN"
                            $flavor = Get-VpnTunnelFlavor
                            Send-FlareEvent $flavor
                            Set-CprRunExit -Reason 'vpn_connected_nwcheck_unreachable' -State $flavor
                            Invoke-BlackholeAction -Tag $flavor
                            return
                        }
                        
                        # VPN in intermediate state (Connecting/Reconnecting/Unknown) blocks ALL traffic.
                        # Force disconnect so we can probe cleanly.
                        if ($currentVPNState -notin @("Disconnected", "Connected")) {
                            Write-Log "VPN in intermediate state: $currentVPNState (blocks all traffic) - forcing disconnect" "WARN"
                            try {
                                Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null
                                Start-Sleep -Seconds 3
                                Write-Log "VPN disconnect issued - waiting for state to settle" "INFO"
                                $currentVPNState = Get-VpnState
                                Write-Log "VPN state after disconnect: $currentVPNState" "INFO"
                            } catch {
                                Write-Log "Error disconnecting VPN: $_" "WARN"
                            }
                            
                            # Re-probe nwcheck now that VPN is out of the way.
                            # Disconnecting may be all that was needed (e.g. user drove in from home).
                            Write-Log "Re-probing nwcheck after VPN disconnect..." "INFO"
                            $nwCheck2 = Get-NwCheckResult
                            
                            if ($nwCheck2.Status -eq "online") {
                                # Online now - classify and exit, no need to touch enroll.cisco.com
                                Write-Log "nwcheck: 200 after VPN disconnect - classifying connection type" "INFO"
                                $vpnState2 = Get-VpnState
                                if ($vpnState2 -eq "Connected") {
                                    $flavor = Get-VpnTunnelFlavor
                                    Send-FlareEvent $flavor
                                    Clear-CaptiveEventHistory "VPN connected post-disconnect"
                                    Set-CprRunExit -Reason 'vpn_connected' -State $flavor
                                } else {
                                    $dcOK = Test-DC -hostname $DC_FQDN
                                    if ($dcOK) {
                                        Send-FlareEvent 'on_prem'
                                        Clear-CaptiveEventHistory "on-premises connection"
                                        Set-CprRunExit -Reason 'no_action_dc_reachable' -State 'on_prem'
                                    } else {
                                        Send-FlareEvent 'off_prem_no_vpn'
                                        Clear-CaptiveEventHistory "off-premises connection"
                                        Set-CprRunExit -Reason 'untrusted' -State 'off_prem_no_vpn'
                                    }
                                }
                                return
                            } elseif ($nwCheck2.Status -eq "redirect") {
                                # Redirect after disconnect - route same as main redirect branch
                                Write-Log "nwcheck: redirect after VPN disconnect to $($nwCheck2.RedirectUrl) - routing" "INFO"
                                $redirectType2 = Get-RedirectType -RedirectUrl $nwCheck2.RedirectUrl
                                switch ($redirectType2) {
                                    "ISE_EMPLOYEE" {
                                        Send-FlareEvent 'ise_employee_posture_redirect'
                                        Write-TeeLog 'ise_posture_redirect' @{ psn_url = $nwCheck2.RedirectUrl; ssid = $networkInfo.SSID }
                                        $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
                                        if (-not $svc) {
                                            Send-FlareEvent 'ise_posture_service_unavailable'
                                            Set-CprRunExit -Reason 'ise_redirect_no_posture_service' -NetworkInfo $networkInfo
                                            return
                                        }
                                        Invoke-PostureRescan
                                        $postureCheckStart = Get-Date
                                        $complianceResult = Test-ISEPostureCompliance -TimeoutSec $PostureComplianceTimeout
                                        $postureCheckDurationSec = [math]::Round(((Get-Date) - $postureCheckStart).TotalSeconds)
                                        if ($complianceResult -eq "Compliant") {
                                            Send-FlareEvent 'ise_posture_compliant'
                                            Write-TeeLog 'ise_posture_compliant' @{ duration_sec = $postureCheckDurationSec }
                                            Clear-CaptiveEventHistory "ISE posture compliant"
                                            Set-CprRunExit -Reason 'ise_employee_compliant' -NetworkInfo $networkInfo
                                        } else {
                                            Send-FlareEvent 'ise_posture_failed'
                                            Write-TeeLog 'ise_posture_failed' @{ reason = $complianceResult }
                                            Set-CprRunExit -Reason "ise_employee_failed_$complianceResult" -NetworkInfo $networkInfo
                                        }
                                        return
                                    }
                                    "ISE_GUEST" {
                                        Invoke-CaptivePortalRemediation -PortalType "ISE_GUEST" -RedirectUrl $nwCheck2.RedirectUrl
                                        Set-CprRunExit -Reason 'ise_guest_browser_remediated' -NetworkInfo $networkInfo
                                        return
                                    }
                                    default {
                                        if ($redirectType2 -eq "UNKNOWN") { Send-FlareEvent 'unknown_captive_portal' }
                                        Invoke-CaptivePortalRemediation -PortalType "NON_ISE" -RedirectUrl $nwCheck2.RedirectUrl
                                        Set-CprRunExit -Reason 'non_ise_browser_remediated' -NetworkInfo $networkInfo
                                        return
                                    }
                                }
                            }
                            # nwcheck still unreachable after VPN disconnect and enroll didn't redirect
                            # (we tested enroll immediately at top of unreachable block)
                            Write-Log "nwcheck still unreachable after VPN disconnect - genuine network problem" "WARN"
                            Set-CprRunExit -Reason 'nwcheck_unreachable_after_vpn_disconnect' -State 'no_net_transient'
                            Invoke-BlackholeAction -Tag 'no_net_transient'
                            return
                        }
                        
                        # If we reach here: enroll didn't redirect, VPN not intermediate.
                        # Before declaring no_net_transient, check for walled-garden portal pattern.
                        # Walled gardens (Wyndham, Marriott, etc.) block DNS entirely - no redirect ever comes.
                        # Signature: gateway pingable (L3 works) + DNS fails = walled garden confirmed.
                        Write-Log "enroll.cisco.com no redirect, VPN disconnected - testing for walled-garden captive portal..." "INFO"

                        # Re-check VPN state immediately before Walled Garden testing. The Get-VpnState read
                        # above is a point-in-time snapshot - Cisco Secure Client (AlwaysOn) can still be
                        # mid-negotiation on the adapter, holding local L3/DNS hostage. A still-blocking VPN
                        # would make the gateway-ping/DNS walled-garden test unreliable and get misclassified
                        # as a genuine no_net_transient outage. This check is NOT gated on $BlackholeEnabled -
                        # it is a client-blocking-network safety action, unrelated to the Blackhole feature.
                        $vpnStateForBlockCheck = Get-VpnState
                        if (Test-VPNBlockingNetwork -VPNState $vpnStateForBlockCheck -RedirectDetected $false) {
                            Write-Log "VPN client is blocking network access (state: $vpnStateForBlockCheck) - force-disconnecting before walled-garden test" "WARN"
                            try {
                                Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null
                                Start-Sleep -Seconds 2
                                $vpnStateForBlockCheck = Get-VpnState
                                Write-Log "VPN state after forced disconnect: $vpnStateForBlockCheck" "INFO"
                            } catch {
                                Write-Log "Error disconnecting blocking VPN before walled-garden test: $_" "WARN"
                            }
                        }

                        # STRICT local-network gate (RC2.1). No usable adapter/IP/gateway
                        # (or Wi-Fi with no connected SSID) can never be a captive portal,
                        # so it must never fire Event 778/777 or hand off to a runner.
                        $localNet = Test-PlausibleLocalNetwork -NetworkInfo $networkInfo
                        Write-Log "Local network plausibility: plausible=$($localNet.IsPlausible) type='$($localNet.ConnectionType)' ssid='$($localNet.Ssid)' ip='$($localNet.Ip)' gw='$($localNet.Gateway)' reason=$($localNet.Reason)" "INFO"

                        if (-not $localNet.IsPlausible) {
                            Write-Log "No usable local network (reason=$($localNet.Reason)) - captive-portal handoff suppressed: no Event 778, no Event 777, no runner launch" "WARN"
                            Set-CprRunExit -Reason 'no_plausible_local_network' -State 'no_net_transient'
                            Send-FlareEvent "no_net_transient"
                            Invoke-BlackholeAction -Tag 'no_net_transient'
                            Clear-CapPortalRemediationState -Reason 'no_usable_local_network' | Out-Null
                            if ($CapPortalRunnerMode -ne 'base' -and $ciscoBrowserKillerJob) {
                                Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob
                            }
                            Write-RunEnd $script:exitReason
                            return
                        }

                        # Prefer the gateway Get-NetworkInfo already resolved for the primary
                        # adapter in THIS run. Test-WalledGarden's own route-table lookup can
                        # return a stale/virtual/Cisco default route (xfinitywifi evidence:
                        # 10.10.69.1 instead of the live 172.20.20.1).
                        $walledGarden = Test-WalledGarden -PrimaryGateway $networkInfo.DefaultGateway

                        if ($walledGarden.IsWalledGarden) {
                            Write-Log "WALLED GARDEN CAPTIVE PORTAL DETECTED (gateway=$($walledGarden.GatewayIP))" "WARN"
                            Write-Log "Portal type: DNS-blocking - handing off to cap_portal_runner for remediation" "INFO"

                            # Write portal context into the remediation state file.
                            # cap_portal_runner reads this at init and branches on portal_type.
                            # Runner is responsible for clearing this file on exit.
                            try {
                                # RC1.25: carry full network + URL context so the
                                # separate-process base runner can emit normalized
                                # telemetry without re-deriving (or guessing) any of it.
                                $wgStateNetCtx = Get-CaptivePortalNetworkContext
                                $wgDispatchContext = Get-CapPortalDispatchContext `
                                    -FlareTag $(if ($CapPortalRunnerMode -eq 'base') { 'captive_portal_browser_base' } else { 'captive_portal_browser' }) `
                                    -Status 'detected' `
                                    -Reason "walled_garden_$($walledGarden.Reason)" `
                                    -VpnState $vpnStateForBlockCheck `
                                    -NetworkContext $wgStateNetCtx `
                                    -Ssid $networkInfo.SSID
                                $statePayload = @{
                                    dispatch_context = $wgDispatchContext
                                    timestamp   = (Get-Date).ToString('o')
                                    portal_type = "walled_garden"
                                    gateway_ip  = $walledGarden.GatewayIP
                                    ssid        = $networkInfo.SSID
                                    reason      = $walledGarden.Reason
                                    ip          = $wgStateNetCtx.ip
                                    gw          = $(if ([string]::IsNullOrEmpty($wgStateNetCtx.gw)) { (ConvertTo-TelemetryValue $walledGarden.GatewayIP) } else { $wgStateNetCtx.gw })
                                    dns         = $wgStateNetCtx.dns
                                    vpn_state   = (ConvertTo-TelemetryValue $vpnStateForBlockCheck)
                                    protocol    = "http"
                                    fqdn        = (ConvertTo-TelemetryValue $walledGarden.GatewayIP)
                                    port        = "80"
                                    url         = "http://$($walledGarden.GatewayIP)"
                                }
                                if (Write-CapPortalRemediationState -State $statePayload -NetworkContext $wgStateNetCtx -Ssid $networkInfo.SSID) {
                                    Write-Log "Remediation state file written: portal_type=walled_garden gateway=$($walledGarden.GatewayIP)" "INFO"
                                }
                            } catch {
                                Write-Log "Could not write remediation state file: $_" "WARN"
                            }

                            # Telemetry flare - SYSTEM context, fires immediately
                            Set-CprRunExit -Reason 'captive_walled_garden' -State 'captive_portal'
                            Send-FlareEvent -Tag "captive_walled_garden"
                            Write-TeeLog 'captive_walled_garden' @{ gateway_ip = $walledGarden.GatewayIP; ssid = $networkInfo.SSID }

                            # Trigger the runner in USER context. Base must leave Cisco
                            # WebHelper alive so its EventID 301 evidence remains observable.
                            if (Test-MainSkipCiscoBrowserKill) {
                                if ($CapPortalRunnerMode -eq 'base') {
                                    Write-Log "Cisco browser killing skipped: Base observer mode preserves Cisco native browser/WebHelper evidence" "INFO"
                                } else {
                                    Write-Log "Cisco browser killing skipped: CapPortalSkipBrowserKill is true or undefined" "INFO"
                                }
                                $script:ciscoBrowserKillerJob = $null
                            } else {
                                $script:ciscoBrowserKillerJob = Start-CiscoBrowserKiller
                            }
                            # Cap portal runner pivot - route to base observer or full runner based on $CapPortalRunnerMode
                            if ($CapPortalRunnerMode -eq "base") {
                                # Base mode has no WW_cap_portal_runner.ps1 wrapper to fire
                                # cap_portal_redirect via Invoke-CaptivePortalRemediation (walled
                                # garden detection never goes through that function - no
                                # RedirectUrl exists for a DNS-blocking portal). Ship it here,
                                # mirroring the exact pattern Invoke-CaptivePortalRemediation uses,
                                # so Splunk sees cap_portal_redirect regardless of runner mode.
                                $wgRedirectUrl = "http://$($walledGarden.GatewayIP)"
                                $wgRedirectTelemetry = Get-CaptivePortalRedirectTelemetry -RedirectUrl $wgRedirectUrl
                                $wgVpnState = $null
                                try {
                                    $wgVpnState = Get-VpnState
                                } catch {
                                    Write-Log "Error getting VPN state for walled-garden captive portal telemetry: $_" "DEBUG"
                                }
                                $wgNetCtx = Get-CaptivePortalNetworkContext
                                Write-TeeLog 'cap_portal_redirect' @{
                                    EvtTime     = (Get-Date -Format 'o')
                                    url         = ConvertTo-TelemetryValue $wgRedirectTelemetry.url
                                    port        = ConvertTo-TelemetryValue $wgRedirectTelemetry.port
                                    ssid        = (ConvertTo-TelemetryValue $networkInfo.SSID)
                                    vpn_state   = ConvertTo-TelemetryValue $wgVpnState
                                    ip          = $wgNetCtx.ip
                                    gw          = $wgNetCtx.gw
                                    dns         = $wgNetCtx.dns
                                    portal_type = 'walled_garden'
                                    status      = 'detected'
                                    reason      = (ConvertTo-TelemetryValue $walledGarden.Reason)
                                }

                                Write-Log "CapPortalRunner: mode=base - firing captive_portal_browser_base (Event 778)" "INFO"
                                Send-FlareEvent 'captive_portal_browser_base'
                            } else {
                                Write-Log "CapPortalRunner: mode=full - firing captive_portal_browser (Event 777)" "INFO"
                                Send-FlareEvent 'captive_portal_browser'
                            }

                            if ($CapPortalRunnerMode -ne 'base' -and $ciscoBrowserKillerJob) {
                                Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob
                            }
                            Write-RunEnd $script:exitReason
                            return

                        } else {
                            # WalledGarden is FALLBACK evidence only. The authoritative probe
                            # (gateway.optum.com) was INCONCLUSIVE - timeout/unreachable/DNS
                            # failure means "we do not know yet", not "the network is broken".
                            Write-Log "WalledGarden test negative (reason: $($walledGarden.Reason)) - fallback heuristic only, not conclusive" "WARN"

                            $localNet = Test-PlausibleLocalNetwork -NetworkInfo $networkInfo
                            Write-Log "Local network plausibility re-check: plausible=$($localNet.IsPlausible) reason=$($localNet.Reason)" "DEBUG"

                            if ($CapPortalRunnerMode -eq 'base' -and $localNet.IsPlausible) {
                                # SUSPECTED captive portal. Main runs as SYSTEM and its probe
                                # timed out; Cisco Secure Client's WebView2 runs in USER context
                                # and has been observed getting the portal redirect in the same
                                # conditions. Hand off to Base so it can run its own empirical
                                # probe rather than declaring a transient outage here.
                                Write-Log "Preflight inconclusive with a plausible local network - classifying as SUSPECTED captive portal (base mode)" "WARN"
                                Write-Log "Main runs as SYSTEM; a USER-context retry may still see the redirect - handing off to Base observer" "INFO"

                                $suspectVpnState = $vpnStateForBlockCheck
                                $suspectNetCtx = Get-CaptivePortalNetworkContext
                                # The probe URL is NOT the portal URL. No redirect was observed,
                                # so the canonical portal url/protocol/fqdn/port stay empty and
                                # gateway.optum.com is recorded only as probe_url.
                                $suspectProbeUrl = $NewPreflightURL

                                try {
                                    $suspectPayload = @{
                                        dispatch_context = (Get-CapPortalDispatchContext `
                                            -FlareTag 'captive_portal_browser_base' `
                                            -Status 'suspected' `
                                            -Reason "preflight_inconclusive_walled_garden_$($walledGarden.Reason)" `
                                            -VpnState $suspectVpnState `
                                            -NetworkContext $suspectNetCtx `
                                            -Ssid $networkInfo.SSID)
                                        timestamp   = (Get-Date).ToString('o')
                                        portal_type = "suspected"
                                        gateway_ip  = (ConvertTo-TelemetryValue $localNet.Gateway)
                                        ssid        = $networkInfo.SSID
                                        reason      = "preflight_inconclusive"
                                        ip          = $suspectNetCtx.ip
                                        gw          = $(if ([string]::IsNullOrEmpty($suspectNetCtx.gw)) { (ConvertTo-TelemetryValue $localNet.Gateway) } else { $suspectNetCtx.gw })
                                        dns         = $suspectNetCtx.dns
                                        vpn_state   = (ConvertTo-TelemetryValue $suspectVpnState)
                                        probe_url   = $suspectProbeUrl
                                        protocol    = ""
                                        fqdn        = ""
                                        port        = ""
                                        url         = ""
                                        url_source  = "none_no_redirect_observed"
                                    }
                                    if (Write-CapPortalRemediationState -State $suspectPayload -NetworkContext $suspectNetCtx -Ssid $networkInfo.SSID) {
                                        Write-Log "Remediation state file written: portal_type=suspected reason=preflight_inconclusive url='' (probe_url='$suspectProbeUrl' is never the portal URL)" "INFO"
                                    }
                                } catch {
                                    Write-Log "Could not write remediation state file: $_" "WARN"
                                }

                                Write-TeeLog 'cap_portal_redirect' @{
                                    EvtTime     = (Get-Date -Format 'o')
                                    url         = ''
                                    port        = ''
                                    ssid        = (ConvertTo-TelemetryValue $networkInfo.SSID)
                                    vpn_state   = ConvertTo-TelemetryValue $suspectVpnState
                                    ip          = $suspectNetCtx.ip
                                    gw          = $suspectNetCtx.gw
                                    dns         = $suspectNetCtx.dns
                                    portal_type = 'suspected'
                                    status      = 'suspected'
                                    reason      = "preflight_inconclusive_walled_garden_$($walledGarden.Reason)"
                                }

                                Set-CprRunExit -Reason 'portal_suspected' -State 'captive_portal'
                                Write-Log "CapPortalRunner: mode=base - firing captive_portal_browser_base (Event 778) for suspected captive portal" "INFO"
                                Send-FlareEvent 'captive_portal_browser_base'
                                Write-RunEnd $script:exitReason
                                return
                            }

                            # Genuinely no plausible local network, or not base mode - preserve
                            # the existing full-mode behavior exactly.
                            Write-Log "enroll.cisco.com no redirect, VPN state OK - genuine network connectivity problem" "WARN"
                            Set-CprRunExit -Reason 'nwcheck_unreachable_enroll_no_redirect' -State 'no_net_transient'
                            Send-FlareEvent "no_net_transient"
                            Invoke-BlackholeAction -Tag 'no_net_transient'
                            if ($CapPortalRunnerMode -ne 'base' -and $ciscoBrowserKillerJob) {
                                Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob
                            }
                            Write-RunEnd $script:exitReason
                            return
                        }
                    }
                }
                
            } catch {
                Write-Log "Error in main execution: $_" "ERROR"
                Set-CprRunExit -Reason 'error_exception' -State 'cpr_error'
            } finally {
                # Exit state flare: exactly one per run, the <state> half of exit_reason (Ivanti reads this).
                Send-CprExitFlare $script:exitReason
                if ((Test-Path variable:onlineFastPathSelected) -and $onlineFastPathSelected) {
                    Write-Log ("phase_timing phase='online_fast_path' elapsed_ms={0} exit_reason='{1}'" -f `
                        [math]::Round(((Get-Date) - $onlineFastPathStartedAt).TotalMilliseconds), $script:exitReason) "INFO"
                }
                # Stop Cisco browser killer job if it's still running
                if ($ciscoBrowserKillerJob) {
                    Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob
                }
                
                # Maintenance stage: last, after the flare and any remediation.
                $maintSkip = (-not $OnlineFastPathRunMaintenance) -and `
                    (((Test-Path variable:onlineFastPathSelected) -and $onlineFastPathSelected) -or "$($script:exitReason)" -like 'vpn_connected:*')
                try { Invoke-MaintenanceStage -ExitReason "$($script:exitReason)" -Skip $maintSkip }
                catch { Write-Log "Maintenance stage error: $_" "WARN" }

                # Tee level flag (user-touchable cpr_tee_<N>.flag) + revert timer: cheap, always runs.
                try { Invoke-TeeLevelFlagCheck } catch { Write-Log "TeeFlag error: $_" "WARN" }

                # End-of-run network re-check: last step before exit - did the network flip while we worked?
                $recheck = $null
                if (Test-Path variable:networkInfo) {
                    try { $recheck = Invoke-EndRunNetworkRecheck -Baseline $networkInfo }
                    catch { Write-Log "End-of-run re-check error: $_" "WARN" }
                }
                if ($recheck -and $recheck.Now -and $recheck.Changed) {
                    $script:endNetworkSsid = $recheck.Now.SSID
                }

                Write-RunEnd $script:exitReason
            }
        }
    }
}
