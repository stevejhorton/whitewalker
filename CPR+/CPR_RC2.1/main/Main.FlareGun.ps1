# CPR RC2 FlareGun, Cisco path, blackhole, and task-synchronization helpers.
# Depends on: Main.Logging.ps1, Main.State.ps1, and Main.Configuration.ps1.

# ------------------------- FlareGun Framework --------------------------------
function Get-FlareConfig {
  # Cache config in memory for performance
  if (-not $global:_flareConfig) {
    try {
      if (Test-Path $FlareGunConfigPath) {
        $configJson = Get-Content -Path $FlareGunConfigPath -Raw -ErrorAction Stop
        $global:_flareConfig = $configJson | ConvertFrom-Json
        Write-Log "FlareGun config loaded: $FlareGunConfigPath" "DEBUG"
      } else {
        Write-Log "FlareGun config not found: $FlareGunConfigPath - using direct flares" "WARN"
        $global:_flareConfig = $null
      }
    } catch {
      Write-Log "Error loading FlareGun config: $_" "ERROR"
      $global:_flareConfig = $null
    }
  }
  return $global:_flareConfig
}

function Start-CiscoBrowserKiller {
    <#
    .SYNOPSIS
    Kill interfering Cisco browser processes in background job
    
    .DESCRIPTION
    Cisco Secure Client may launch browser processes (acwebhelper, CiscoCollabHost, etc.)
    that interfere with network connectivity checks and captive portal workflows.
    This function starts a background job that continuously kills these processes
    for 10 seconds to ensure they don't interfere.
    
    Called proactively on every WhiteWalker run to clean up orphaned Cisco browsers,
    especially useful when:
    - Guest network sessions are still valid (no redirect, but Cisco browser opened)
    - Previous captive portal sessions left browsers running
    - Cisco client launches browsers during posture checks
    #>
    
    try {
        Write-Log "Starting Cisco browser killer background job..." "DEBUG"
        
        $ciscoBrowserProcesses = @(
            "acwebhelper",
            "CiscoCollabHost", 
            "CiscoAnyConnectWebView",
            "CiscoWebLaunchHelper",
            "CiscoWebHelper"
        )
        
        $killerJob = Start-Job -ScriptBlock {
            param($ProcessNames)
            
            $endTime = (Get-Date).AddSeconds(120)  # Run for 120 seconds - covers full WW execution window
            $killCount = 0
            
            while ((Get-Date) -lt $endTime) {
                foreach ($processName in $ProcessNames) {
                    try {
                        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
                        if ($processes) {
                            foreach ($proc in $processes) {
                                try {
                                    $proc.Kill()
                                    $killCount++
                                    Start-Sleep -Milliseconds 100
                                } catch { }
                            }
                        }
                    } catch { }
                }
                Start-Sleep -Milliseconds 500
            }
            
            return $killCount
        } -ArgumentList (,[string[]]$ciscoBrowserProcesses)
        
        Write-Log "Cisco browser killer job started (JobId: $($killerJob.Id)) - will run for 120 seconds" "DEBUG"
        return $killerJob
        
    } catch {
        Write-Log "Failed to start Cisco browser killer: $_" "WARN"
        return $null
    }
}

function Stop-CiscoBrowserKiller {
    <#
    .SYNOPSIS
    Stop Cisco browser killer background job immediately (fire and forget).
    -Wait on Receive-Job was blocking the main thread for the full job duration.
    We don't need the return value - just kill it and move on.
    #>
    param($Job)

    if ($Job) {
        try {
            Stop-Job   -Job $Job -ErrorAction SilentlyContinue
            Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
            Write-Log "Cisco browser killer job stopped" "DEBUG"
        } catch {
            Write-Log "Error stopping Cisco browser killer job: $_" "DEBUG"
        }
    }
}

function Test-TaskRegistered {
    # File test on the task store. Get-ScheduledTask goes through CIM / the Task
    # Scheduler service and was seen blocking 141s during a network hop. Our
    # tasks live at the root folder, so the task file name is the task name.
    param([string]$Name)
    Test-Path -LiteralPath (Join-Path $env:windir "System32\Tasks\$Name")
}

function Sync-BlackholeShutdownTask {
    <#
    .SYNOPSIS
    Ensures WW_blackhole_shutdown TS task exists when BlackholeEnabled=true
    and removes it when BlackholeEnabled=false. Called once at startup.
    Keeps the single $BlackholeEnabled toggle in WW_main.ps1 in full control
    of a task that fires independently (on shutdown event ID 1074).
    #>
    $taskName = $BlackholeShutdownTaskName
    $taskXml  = $BlackholeShutdownTaskXml
    $exists   = Test-TaskRegistered $taskName

    if ($BlackholeEnabled) {
        if ($exists) {
            Write-Log "BlackholeShutdown: task already registered - OK" "DEBUG"
            return
        }
        if (-not (Test-Path $taskXml)) {
            Write-Log "BlackholeShutdown: XML not found at $taskXml - cannot register task" "WARN"
            Write-TeeLog 'subsystem_task_sync_failed' @{ subsystem = 'blackhole_shutdown'; operation = 'register'; reason = 'task_xml_missing' }
            return
        }
        try {
            $xml = Get-Content $taskXml -Raw -ErrorAction Stop
            Register-ScheduledTask -TaskName $taskName -Xml $xml -Force -ErrorAction Stop | Out-Null
            Write-Log "BlackholeShutdown: task registered" "INFO"
        } catch {
            Write-Log "BlackholeShutdown: failed to register task: $_" "WARN"
            Write-TeeLog 'subsystem_task_sync_failed' @{ subsystem = 'blackhole_shutdown'; operation = 'register'; reason = 'register_failed' }
        }
    } else {
        if (-not $exists) {
            Write-Log "BlackholeShutdown: task not present (disabled) - OK" "DEBUG"
            return
        }
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Log "BlackholeShutdown: task unregistered (BlackholeEnabled=false)" "INFO"
        } catch {
            Write-Log "BlackholeShutdown: failed to unregister task: $_" "WARN"
            Write-TeeLog 'subsystem_task_sync_failed' @{ subsystem = 'blackhole_shutdown'; operation = 'unregister'; reason = 'unregister_failed' }
        }
    }
}

function Sync-XmlVaultTask {
    <#
    .SYNOPSIS
    Ensures WW_xml_vault TS task exists when XmlVaultEnabled=true
    and removes it when XmlVaultEnabled=false. Called once at startup.
    Keeps the single $XmlVaultEnabled toggle in WW_main.ps1 in full control
    of a task that fires independently (on event IDs 801/802).
    #>
    $taskName = $XmlVaultTaskName
    $taskXml  = $XmlVaultTaskXml
    $exists   = Test-TaskRegistered $taskName

    if ($XmlVaultEnabled) {
        if ($exists) {
            Write-Log "XmlVault: task already registered - OK" "DEBUG"
            return
        }
        if (-not (Test-Path $taskXml)) {
            Write-Log "XmlVault: XML not found at $taskXml - cannot register task" "WARN"
            Write-TeeLog 'subsystem_task_sync_failed' @{ subsystem = 'xml_vault'; operation = 'register'; reason = 'task_xml_missing' }
            return
        }
        try {
            $xml = Get-Content $taskXml -Raw -ErrorAction Stop
            Register-ScheduledTask -TaskName $taskName -Xml $xml -Force -ErrorAction Stop | Out-Null
            Write-Log "XmlVault: task registered" "INFO"
        } catch {
            Write-Log "XmlVault: failed to register task: $_" "WARN"
            Write-TeeLog 'subsystem_task_sync_failed' @{ subsystem = 'xml_vault'; operation = 'register'; reason = 'register_failed' }
        }
    } else {
        if (-not $exists) {
            Write-Log "XmlVault: task not present (disabled) - OK" "DEBUG"
            return
        }
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Log "XmlVault: task unregistered (XmlVaultEnabled=false)" "INFO"
        } catch {
            Write-Log "XmlVault: failed to unregister task: $_" "WARN"
            Write-TeeLog 'subsystem_task_sync_failed' @{ subsystem = 'xml_vault'; operation = 'unregister'; reason = 'unregister_failed' }
        }
    }
}

function Invoke-BlackholeAction {
    param([string]$Tag)

    # SAFETY: If blackhole is disabled, fire -rm ONCE to clear any stale entries
    # left from a prior enabled session, then mark it cleared so subsequent runs
    # skip the redundant process spawn + Splunk noise. The cleared-marker is
    # removed the moment BlackholeEnabled flips back to $true (see below) and is
    # included in install/upgrade stale-flag cleanup, so a lost marker just
    # costs one extra harmless -rm - never a skipped cleanup.
    if (-not $BlackholeEnabled) {
        if (Test-Path $BlackholeClearedFlagFile) {
            Write-Log "Blackhole: disabled - already cleared (marker present) - skipping -rm" "DEBUG"
            return
        }
        if (Test-Path $BlackholeScriptPath) {
            Write-Log "Blackhole: disabled - firing -rm to clear any stale sinkhole entries" "INFO"
            if (-not $WhatIf) {
                Start-Process "powershell.exe" `
                    -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BlackholeScriptPath`" -rm" `
                    -WindowStyle Hidden
                Remove-Item $BlackholeFlagFile -Force -ErrorAction SilentlyContinue
                Set-Content -Path $BlackholeClearedFlagFile -Value (Get-Date).ToString('o') -Encoding UTF8 -Force
                Write-Log "Blackhole: -rm fired (disabled mode), flag cleared, cleared-marker written" "INFO"
                Write-TeeLog 'vpn_blackhole_remove' @{ reason = "disabled" }
            } else {
                Write-Log "Blackhole: [WhatIf] would fire -rm (disabled mode) and write cleared-marker" "INFO"
            }
        }
        return
    }

    # Clear the disabled-mode marker the instant Blackhole is re-enabled, so if it
    # is ever disabled again later, the safety -rm fires fresh rather than trusting
    # a marker from a completely different enabled/disabled cycle.
    Remove-Item $BlackholeClearedFlagFile -Force -ErrorAction SilentlyContinue

    # --- $BlackholeEnabled = $true path (unchanged) ---

    # Tags that confirm device is on corporate premises -> -add
    $onPremTags = @(
        'on_prem',
        'ise_employee_posture_redirect',
        'ise_posture_compliant',
        'ise_posture_failed',
        'ise_posture_service_unavailable'
    )
    
    if ($onPremTags -contains $Tag) {
        # On-prem confirmed - block VPN headends to prevent hairpinning
        if (-not (Test-Path $BlackholeScriptPath)) {
            Write-Log "Blackhole enabled but script not found: $BlackholeScriptPath" "WARN"
            return
        }
        Write-Log "Blackhole: on-prem state ($Tag) - firing -add (synchronous)" "INFO"
        if (-not $WhatIf) {
            # Synchronous so sinkhole is applied before VPN disconnect check below
            Start-Process "powershell.exe" `
                -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BlackholeScriptPath`" -add" `
                -WindowStyle Hidden -Wait
            Set-Content -Path $BlackholeFlagFile -Value (Get-Date).ToString('o') -Encoding UTF8 -Force
            Write-Log "Blackhole: -add complete, flag created" "INFO"
            Write-TeeLog 'vpn_blackhole_add' @{ ssid = $networkInfo.SSID; dc_reachable = $true }

            # VPN disconnect - only fires here ($BlackholeEnabled=true, on-prem confirmed).
            # Sinkhole is now applied. If VPN is still active, take it down cleanly.
            $postBhVpnState = Get-VpnState
            if ($postBhVpnState -ne 'Disconnected') {
                Write-Log "Blackhole -add complete - VPN still active ($postBhVpnState) - disconnecting" "INFO"
                try {
                    & $vpn_cmd disconnect | Out-Null
                    Start-Sleep -Seconds 2
                    $finalVpnState = Get-VpnState
                    Write-Log "VPN disconnected - on-prem sinkhole enforced (final state: $finalVpnState)" "INFO"
                } catch {
                    Write-Log "Error disconnecting VPN after blackhole -add: $_" "WARN"
                }
            } else {
                Write-Log "Blackhole -add complete - VPN already Disconnected" "DEBUG"
            }
        } else {
            Write-Log "WHATIF: Would run blackhole.ps1 -add, create flag, and disconnect VPN if active" "INFO"
        }
    } else {
        # Any other state - always fire -rm unconditionally.
        # CRITICAL: Do NOT gate on flag file existence.
        # Flag can be lost during install/upgrade/cleanup leaving orphaned hosts entries.
        # Remove-ManagedBlock handles "nothing there" gracefully - safe to always run.
        if (-not (Test-Path $BlackholeScriptPath)) {
            Write-Log "Blackhole enabled but script not found: $BlackholeScriptPath" "WARN"
            return
        }
        Write-Log "Blackhole: non-on-prem state ($Tag) - firing -rm unconditionally" "INFO"
        if (-not $WhatIf) {
            Start-Process "powershell.exe" `
                -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BlackholeScriptPath`" -rm" `
                -WindowStyle Hidden
            # Clean up flag if present - best effort
            if (Test-Path $BlackholeFlagFile) {
                Remove-Item $BlackholeFlagFile -Force -ErrorAction SilentlyContinue
                Write-Log "Blackhole: flag removed" "INFO"
            }
            Write-Log "Blackhole: -rm fired" "INFO"
            Write-TeeLog 'vpn_blackhole_remove' @{ reason = $Tag }
        } else {
            Write-Log "WHATIF: Would run Set-VpnHostsEntry.ps1 -rm and remove flag if present" "INFO"
        }
    }
}

function Get-FlareTelemetryContext {
    <#
    .SYNOPSIS
    Cheap, fail-soft ssid/vpn_state lookup for flare lifecycle telemetry.

    .DESCRIPTION
    PowerShell variable lookup walks the caller's scope chain, so the values
    WW_main.ps1's run already gathered ($networkInfo, and whichever VPN-state
    local the current branch populated) are readable here without re-probing
    netsh or vpncli. Anything not already known stays an explicit empty string -
    this helper never spawns a process and never fabricates a value.
    #>
    $ctx = @{ ssid = ''; vpn_state = '' }

    try {
        $ni = Get-Variable -Name 'networkInfo' -ValueOnly -ErrorAction SilentlyContinue
        if ($ni -and $ni.SSID) { $ctx.ssid = [string]$ni.SSID }
    } catch { }

    foreach ($name in @('vpnStateForBlockCheck', 'currentVPNState', 'vpnState')) {
        try {
            $value = Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue
            if ($value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $ctx.vpn_state = [string]$value
                break
            }
        } catch { }
    }

    if (Get-Command ConvertTo-TelemetryValue -ErrorAction SilentlyContinue) {
        $ctx.ssid      = ConvertTo-TelemetryValue $ctx.ssid
        $ctx.vpn_state = ConvertTo-TelemetryValue $ctx.vpn_state
    }

    return $ctx
}

function Write-FlareTelemetry {
    <#
    .SYNOPSIS
    Normalized flare lifecycle telemetry (flare_dispatched / flare_suppressed /
    flare_failed) shipped through Write-TeeLog.

    .DESCRIPTION
    Send-FlareEvent is a dispatcher: it writes a Windows event (USER tags) or
    runs the flare exe (SYSTEM tags). Until now none of that reached Splunk
    directly - it only showed up if a HayStack needle happened to exist for the
    Event ID. This helper adds the missing visibility WITHOUT touching dispatch,
    de-dupe, cooldown, or event IDs. It is strictly fail-soft: any telemetry
    error is swallowed so a flare is never broken or delayed by logging.
    #>
    param(
        [string]$Tag = "",
        [string]$EventId = "",
        [string]$Context = "",
        [string]$DispatchMethod = "",
        [string]$Status = "",
        [string]$Reason = "",
        [string]$Action = "flare_dispatched"
    )

    try {
        if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) { return }

        $ctx = Get-FlareTelemetryContext

        # -PassThru so a dropped/denied dispatch event is reported truthfully
        # (queued | tag_not_in_profile | haystack_disabled | tee_disabled |
        # access_denied | error) instead of vanishing. Still fail-soft: a
        # telemetry problem never breaks or delays the flare itself.
        $teeResult = Write-TeeLog $Action @{
            EvtTime         = (Get-Date -Format 'o')
            flare_tag       = $Tag
            event_id        = $EventId
            context         = $Context
            dispatch_method = $DispatchMethod
            status          = $Status
            reason          = $Reason
            ssid            = $ctx.ssid
            vpn_state       = $ctx.vpn_state
        } -PassThru

        if ($teeResult -and (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
            $level = if ($teeResult.Queued) { 'DEBUG' } elseif ($teeResult.Reason -in @('access_denied', 'error')) { 'WARN' } else { 'DEBUG' }
            Write-Log "FlareTelemetry: tee '$Action' for '$Tag' queued=$($teeResult.Queued) reason=$($teeResult.Reason)" $level
        }
    } catch {
        # Telemetry must never break or delay a flare.
    }
}

function Send-FlareEvent {
  param([Parameter(Mandatory=$true)][string]$Tag)
  
  # Per-run de-dupe
  if (-not ($global:flareHistory -is [hashtable])) { $global:flareHistory = @{} }
  if ($global:flareHistory.ContainsKey($Tag)) { 
    Write-Log "FlareEvent de-duped (already sent this run): $Tag" "DEBUG"
    Write-FlareTelemetry -Action 'flare_suppressed' -Tag $Tag -Status 'suppressed' -Reason 'per_run_dedupe'
    return 
  }
  
  # Cooldown check - BUT BYPASS for critical captive portal runner events
  # This ensures the runner ALWAYS launches when captive portal is detected
  $bypassCooldown = ($Tag -eq "captive_portal_browser" -or $Tag -eq "captive_portal_browser_base")
  
  if (-not $bypassCooldown -and (In-Cooldown $Tag $FlareCooldownMinutes)) {
    Write-Log "FlareEvent suppressed (cooldown ${FlareCooldownMinutes}m): $Tag" "WARN"
    Write-FlareTelemetry -Action 'flare_suppressed' -Tag $Tag -Status 'suppressed' -Reason 'cooldown'
    return
  }
  
  if ($bypassCooldown) {
    Write-Log "FlareEvent bypassing cooldown (critical event): $Tag" "INFO"
  }
  
  try {
    # Load config to determine execution context
    $config = Get-FlareConfig
    
    if ($config -and $config.flare_events.$Tag) {
      $flareInfo = $config.flare_events.$Tag
      
      if ($flareInfo.context -eq "USER") {
        # USER CONTEXT FLARE: Write event log message for Task Scheduler pickup
        # Task Scheduler job (running as USER) will parse message and send flare
        Write-Log "FlareEvent queued for USER context: $Tag (Event ID $($flareInfo.event_id))" "INFO"
        
        if (-not $WhatIf) {
          # Use Start-Process with -WindowStyle Hidden to prevent window flash
          $eventArgs = @(
            "/T", "INFORMATION",
            "/ID", $flareInfo.event_id,
            "/L", "APPLICATION", 
            "/SO", "WhiteWalkerFlareGun",
            "/D", "FLARE:$Tag"
          )
          
          # ER5: Enhanced error checking for event creation
          try {
            $proc = Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
            if ($proc.ExitCode -eq 0) {
              Write-Log "Event log message written successfully: FLARE:$Tag (Event ID: $($flareInfo.event_id))" "INFO"
              Write-FlareTelemetry -Tag $Tag -EventId ([string]$flareInfo.event_id) -Context 'USER' -DispatchMethod 'eventcreate' -Status 'dispatched' -Reason 'event_written'
            } else {
              Write-Log "Event log message MAY have failed (ExitCode: $($proc.ExitCode)) for FLARE:$Tag" "WARN"
              Write-FlareTelemetry -Action 'flare_failed' -Tag $Tag -EventId ([string]$flareInfo.event_id) -Context 'USER' -DispatchMethod 'eventcreate' -Status 'failed' -Reason "eventcreate_exit_code_$($proc.ExitCode)"
            }
          } catch {
            Write-Log "ERROR writing event log for FLARE:$Tag : $_" "ERROR"
            Write-FlareTelemetry -Action 'flare_failed' -Tag $Tag -EventId ([string]$flareInfo.event_id) -Context 'USER' -DispatchMethod 'eventcreate' -Status 'failed' -Reason 'eventcreate_exception'
          }
        } else {
          Write-Log "WHATIF: Would queue USER flare event: $Tag" "INFO"
        }
      } else {
        # SYSTEM CONTEXT FLARE: Send directly (we're already running as SYSTEM)
        $args = "/$Tag"
        Write-Log "FlareEvent sent directly as SYSTEM: $args" "INFO"
        
        if (-not $WhatIf) {
          Start-Process -FilePath $flareExe -ArgumentList $args -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
          Write-FlareTelemetry -Tag $Tag -EventId ([string]$flareInfo.event_id) -Context 'SYSTEM' -DispatchMethod 'flare_exe' -Status 'dispatched' -Reason 'direct_system'
        } else {
          Write-Log "WHATIF: Would send SYSTEM flare: $args" "INFO"
        }
      }
    } else {
      # FALLBACK: Config missing or tag not found - send directly as SYSTEM (legacy behavior)
      $args = "/$Tag"
      Write-Log "FlareEvent (legacy/direct): $args" "INFO"
      
      if (-not $WhatIf) {
        Start-Process -FilePath $flareExe -ArgumentList $args -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        Write-FlareTelemetry -Tag $Tag -Context 'legacy-direct' -DispatchMethod 'flare_exe' -Status 'dispatched' -Reason 'config_missing_or_tag_unknown'
      } else {
        Write-Log "WHATIF: Would send legacy flare: $args" "INFO"
      }
    }
    
    # Record in history and state
    $global:flareHistory[$Tag] = (Get-Date)
    Set-FlareStamp $Tag
    
    # Blackhole integration - fires after flare is recorded
    Invoke-BlackholeAction -Tag $Tag
    
  } catch {
    Write-Log "FlareEvent failed for $Tag : $_" "ERROR"
    Write-FlareTelemetry -Action 'flare_failed' -Tag $Tag -Status 'failed' -Reason 'dispatch_exception'
  }
}

# LEGACY: Keep old function for backward compatibility (calls new function)
function Send-SignalFlare {
  param([Parameter(Mandatory=$true)][string]$Tag)
  Send-FlareEvent -Tag $Tag
}

# ----------------------------- Cisco Paths -----------------------------------
function Get-CiscoInstallPath {
  $cands = @('HKLM:\SOFTWARE\Cisco\Cisco Secure Client','HKLM:\SOFTWARE\WOW6432Node\Cisco\Cisco Secure Client')
  foreach ($key in $cands) {
    try {
      $val = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue)
      if ($val -and $val.InstallPathWithSlash) {
        $p = $val.InstallPathWithSlash.TrimEnd('\')
        if (Test-Path $p) { return $p }
      }
    } catch { }
  }
  foreach ($p in @('C:\Program Files\Cisco\Cisco Secure Client','C:\Program Files (x86)\Cisco\Cisco Secure Client')) {
    if (Test-Path $p) { return $p }
  }
  return $null
}

# -------------------------- Ivanti Signal Flares -----------------------------
function Send-SignalFlare {
  param([Parameter(Mandatory=$true)][string]$Tag)
  if (-not ($global:flareHistory -is [hashtable])) { $global:flareHistory = @{} }

  if ($global:flareHistory.ContainsKey($Tag)) { return } # per-run de-dupe
  if (In-Cooldown $Tag $FlareCooldownMinutes) {
    Write-Log "SignalFlare suppressed (cooldown ${FlareCooldownMinutes}m): /$Tag" "WARN"
    return
  }
  try {
    $args = "/$Tag"
    Write-Log "SignalFlare: $flareExe $args"
    if (-not $WhatIf) {
      Start-Process -FilePath $flareExe -ArgumentList $args -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    } else {
      Write-Log "WHATIF: Would send signal flare: $args" "INFO"
    }
    $global:flareHistory[$Tag] = (Get-Date)
    Set-FlareStamp $Tag
  } catch {
    Write-Log "SignalFlare failed: $_" "ERROR"
  }
}

