# CPR RC2 posture-service, ISE compliance, and VPN state/gatekeeper helpers.
# Depends on: Main.Network.ps1, Main.Logging.ps1, and Main.Configuration.ps1.

# ----------------------------- Posture Service Wait --------------------------
function Get-PostureService {
  try {
    # Known Cisco posture service names (varies by version/installation)
    $knownServices = @(
      "csc_iseagent",      # Cisco Secure Client - ISE Posture Agent
      "ciscod.exe",        # Cisco Secure Client - Posture Agent
      "csc_posture",       # Legacy name (older versions)
      "csc_vpn_posture"    # Alternative legacy name
    )
    
    foreach ($serviceName in $knownServices) {
      $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
      if ($svc) { 
        Write-Log "Found posture service: $serviceName ($($svc.DisplayName))" "DEBUG"
        return $svc 
      }
    }
    
    # Fallback: Search by display name pattern
    $candidates = Get-Service -ErrorAction SilentlyContinue | Where-Object {
      ($_.Name -match '(?i)posture') -or ($_.DisplayName -match '(?i)posture')
    } | Where-Object {
      $_.DisplayName -match '(?i)Cisco|Secure Client|AnyConnect|Secure Firewall|ISE'
    }
    if ($candidates) { 
      $svc = $candidates | Select-Object -First 1
      Write-Log "Found posture service via pattern match: $($svc.Name) ($($svc.DisplayName))" "DEBUG"
      return $svc
    }
  } catch { }
  return $null
}
function Wait-ForPostureService {
  param([int]$TimeoutSec = $PostureWaitSeconds)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $svc = $null
  do {
    $svc = Get-PostureService
    if ($svc) {
      if ($svc.Status -eq 'Running') { return $svc }
      if ($svc.Status -eq 'Stopped') {
        try { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue } catch { }
      }
      Start-Sleep -Milliseconds 750
    } else {
      Start-Sleep -Milliseconds 750
    }
  } while ((Get-Date) -lt $deadline)
  return $null
}

function Test-ISEPostureCompliance {
  param([int]$TimeoutSec = 30, [int]$PollIntervalSec = 3)
  
  Write-Log "Monitoring ISE posture compliance (up to $TimeoutSec seconds)..." "INFO"
  
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $attempt = 0
  
  while ((Get-Date) -lt $deadline) {
    $attempt++
    
    try {
      # Query posture status
      $postureOutput = & $ise_cmd status 2>$null | Out-String
      
      if ($WWDebug) {
        Write-Log "DEBUG: Posture status check attempt $attempt" "DEBUG"
      }
      Write-DebugBlock -Label "posturecli status" -Text $postureOutput
      
      # Check for "Compliant" status (exact string TBD - will refine tomorrow)
      if ($postureOutput -match '(?i)compliant') {
        Write-Log "ISE posture is now COMPLIANT" "INFO"
        return "Compliant"
      }
      
      # Check for transitioning states (will add more patterns tomorrow)
      if ($postureOutput -match '(?i)checking|scanning|evaluating|in progress') {
        Write-Log "ISE posture check in progress (attempt $attempt)..." "DEBUG"
      } else {
        Write-Log "ISE posture status unclear (attempt $attempt)" "DEBUG"
      }
      
    } catch {
      Write-Log "Error checking posture status: $_" "WARN"
    }
    
    # Calculate remaining time
    $remaining = ($deadline - (Get-Date)).TotalSeconds
    if ($remaining -gt 0) {
      $sleepTime = [Math]::Min($PollIntervalSec, $remaining)
      Write-Log "Waiting ${sleepTime}s before next posture check..." "DEBUG"
      Start-Sleep -Seconds $sleepTime
    }
  }
  
  Write-Log "ISE posture compliance check TIMEOUT after $TimeoutSec seconds" "WARN"
  return "Timeout"
}

function Test-NwCheckAfterCompliance {
    param([int]$TimeoutSec = 30, [int]$PollIntervalSec = 3)
    
    Write-Log "Verifying nwcheck accessibility after ISE compliance (up to $TimeoutSec seconds)..." "INFO"
    
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $attempt = 0
    
    while ((Get-Date) -lt $deadline) {
        $attempt++
        
        try {
            $nwCheck = Get-NwCheckResult
            
            if ($nwCheck.Status -eq "online") {
                Write-Log "nwcheck verification SUCCESS - ACL lifted, network access confirmed (attempt $attempt)" "INFO"
                return $true
            }
            
            Write-Log "nwcheck still unreachable after compliance (attempt $attempt) - ACL not yet lifted" "DEBUG"
            
        } catch {
            Write-Log "Error verifying nwcheck: $_" "WARN"
        }
        
        # Calculate remaining time
        $remaining = ($deadline - (Get-Date)).TotalSeconds
        if ($remaining -gt 0) {
            $sleepTime = [Math]::Min($PollIntervalSec, $remaining)
            Start-Sleep -Seconds $sleepTime
        }
    }
    
    Write-Log "nwcheck verification TIMEOUT - ISE reports compliant but ACL not lifted after $TimeoutSec seconds" "WARN"
    Write-Log "This may indicate ISE/WLC propagation delay - device should have access despite timeout" "INFO"
    return $false
}

# -------------------------- VPN State & Flavor -------------------------------
function Test-RecentWakeFromSleep {
  param([int]$TimeWindowSeconds = $VpnWakeTimeWindow)
  
  try {
    # Check Windows Event Log for recent Kernel-Power wake events
    # Event ID 566 = System wake (Reason FullWake)
    # Event ID 507 = System exiting Modern Standby
    # These are the actual events visible in corporate GPO environments
    $wakeEvents = Get-WinEvent -FilterHashtable @{
      LogName = 'System'
      ProviderName = 'Microsoft-Windows-Kernel-Power'
      Id = 566, 507
      StartTime = (Get-Date).AddSeconds(-$TimeWindowSeconds)
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    
    if ($wakeEvents) {
      $timeSinceWake = ((Get-Date) - $wakeEvents[0].TimeCreated).TotalSeconds
      Write-Log "Recent wake from sleep detected: $([math]::Round($timeSinceWake))s ago (Event ID $($wakeEvents[0].Id))" "INFO"
      return $true
    }
    
    Write-Log "No recent wake from sleep detected in last ${TimeWindowSeconds}s" "DEBUG"
    return $false
    
  } catch {
    Write-Log "Could not check wake from sleep status: $_" "DEBUG"
    return $false
  }
}

function Get-VpnState {
  try {
    $statsText = ""
    $stateText = ""
    
    try { $statsText = (& $vpn_cmd stats 2>$null | Out-String) } catch { }
    try { $stateText = (& $vpn_cmd state 2>$null | Out-String) } catch { }
    
    $combined = "$statsText`n$stateText"
    
    if ($WWDebug) { Write-Log "DEBUG: polled vpncli state and stats." }
    Write-DebugBlock -Label 'vpncli combined' -Text $combined
    
    if ($combined.Length -gt 10000) {
      $combined = $combined.Substring(0, 10000)
      Write-Log "Truncated very long vpncli output for parsing" "DEBUG"
    }
    
    # Check >> state: lines first
    $stateMatches = [regex]::Matches($stateText, '(?im)^\s*>>\s*state:\s*(\w+)\s*$')
    if ($stateMatches.Count -gt 0) {
      $lastState = $stateMatches[$stateMatches.Count - 1].Groups[1].Value
      Write-Log "VPN state from >> state: line: $lastState" "DEBUG"
      
      $intermediateStates = @('Reconnecting', 'Connecting', 'Unknown', 'Disconnecting')
      if ($intermediateStates -contains $lastState) {
        Write-Log "VPN in intermediate state: $lastState (blocks all traffic)" "WARN"
        return $lastState
      }
      
      if ($lastState -eq 'Connected') {
        if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Connected\b') {
          Write-Log "Management tunnel confirmed Connected" "DEBUG"
          return "Connected"
        }
        if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Disconnected.*user\s+tunnel\s+active') {
          Write-Log "User tunnel active (management disconnected)" "DEBUG"
          return "Connected"
        }
      }
      
      return $lastState
    }
    
    if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Connected\b') {
      Write-Log "Management tunnel active - returning Connected" "DEBUG"
      return "Connected"
    }
    
    if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Disconnected.*user\s+tunnel\s+active') {
      Write-Log "User tunnel active - returning Connected" "DEBUG"  
      return "Connected"
    }
    
    if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Disconnected\s*') {
      Write-Log "Management shows Disconnected, no user tunnel" "DEBUG"
      return "Disconnected"
    }
    
  } catch { 
    Write-Log "Get-VpnState error: $_" "DEBUG"
  }
  return "Unknown"
}

function Get-VpnStateStable {
  param([int]$TimeoutSec = $VpnStateMaxWaitSeconds)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $intermediateStart = $null
  $state = "Unknown"
  
  Write-Log ("Stabilizing VPN state for up to {0}s..." -f $TimeoutSec)
  
  do {
    $state = Get-VpnState
    
    if ($state -eq 'Connected' -or $state -eq 'Disconnected') { 
      Write-Log "vpncli state (stable): $state" "INFO"
      return $state
    }
    
    $intermediateStates = @('Reconnecting', 'Connecting', 'Unknown', 'Disconnecting')
    if ($intermediateStates -contains $state) {
      if ($null -eq $intermediateStart) {
        $intermediateStart = Get-Date
        
        # SMART VPN DISCONNECT: Use wake detection to determine context
        # 
        # KEY INSIGHT: ALL traffic is blocked during VPN intermediate states
        # (cannot do redirect checks - they will always fail/timeout)
        #
        # Scenario 1 (DISCONNECT): Laptop wake from sleep
        #   - User closed laptop at home with VPN  ->  opens at office
        #   - VPN wakes in "Reconnecting" trying to reach wrong headend
        #   - Blocks 802.1x/captive portal authentication
        #   - SOLUTION: Detect wake event, force disconnect immediately
        #
        # Scenario 2 (ALLOW): Normal network change
        #   - User at home on real WiFi, AlwaysOn VPN legitimately connecting
        #   - No wake event (or wake was >2 minutes ago)
        #   - SOLUTION: Let VPN attempt connection normally
        #
        if ($VpnWakeDetection) {
          $isRecentWake = Test-RecentWakeFromSleep -TimeWindowSeconds $VpnWakeTimeWindow
          
          if ($isRecentWake) {
            Write-Log "VPN in intermediate state ($state) + recent wake from sleep = BLOCKING SCENARIO" "WARN"
            Write-Log "Laptop wake detected - VPN likely trying to reconnect to wrong headend" "WARN"
            Write-Log "This blocks ALL traffic including 802.1x and captive portals - forcing disconnect" "WARN"
            try {
              & $vpn_cmd disconnect | Out-Null
              Write-Log "Wake-based VPN disconnect completed - local network auth can now proceed" "INFO"
              Start-Sleep -Seconds 2
              Write-Log "vpncli state (stable after wake-based disconnect): Disconnected" "INFO"
              return "Disconnected"
            } catch {
              Write-Log "Error during wake-based VPN disconnect: $_" "ERROR"
              # Fall through to normal timeout logic
            }
          } else {
            Write-Log "VPN in intermediate state ($state) but NO recent wake detected" "INFO"
            Write-Log "Likely legitimate VPN connection attempt - allowing ${VpnIntermediateMaxWait}s to complete" "INFO"
          }
        }
        
        Write-Log "VPN in intermediate state: $state (will force disconnect after ${VpnIntermediateMaxWait}s if still stuck)" "WARN"
      }
      
      $intermediateElapsed = ((Get-Date) - $intermediateStart).TotalSeconds
      if ($intermediateElapsed -ge $VpnIntermediateMaxWait) {
        Write-Log "VPN stuck in intermediate state ($state) for ${intermediateElapsed}s - forcing timeout disconnect" "WARN"
        try {
          & $vpn_cmd disconnect | Out-Null
          Write-Log "Timeout-based VPN disconnect completed" "INFO"
          Start-Sleep -Seconds 2
          Write-Log "vpncli state (stable after timeout disconnect): Disconnected" "INFO"
          return "Disconnected"
        } catch {
          Write-Log "Error forcing VPN disconnect: $_" "ERROR"
        }
      }
    } else {
      $intermediateStart = $null
    }
    
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  
  Write-Log "vpncli state (stable after timeout): $state" "INFO"
  return $state
}

function Get-VpnTunnelFlavor {
  $statsText  = ""
  $statusText = ""
  try { $statsText  = (& $vpn_cmd stats  2>$null | Out-String) }  catch { Write-Log "Get-VpnTunnelFlavor: stats error: $_" }
  try { $statusText = (& $vpn_cmd status 2>$null | Out-String) }  catch { Write-Log "Get-VpnTunnelFlavor: status error: $_" }

  if ($WWDebug) { Write-Log "DEBUG: classifying tunnel flavor from vpncli stats/status." }
  Write-DebugBlock -Label 'vpncli stats'  -Text $statsText
  Write-DebugBlock -Label 'vpncli status' -Text $statusText

  $combined = "$statsText`n$statusText"

  if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Connected\b') {
    Write-Log "Management tunnel detected via 'Management Connection State: Connected'" "DEBUG"
    return 'mgmt_tun'
  }
  
  if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Disconnected.*user\s+tunnel\s+active') {
    Write-Log "User tunnel detected via 'Management Connection State: Disconnected (user tunnel active)'" "DEBUG"
    return 'user_tun'
  }
  
  if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Disconnected\s*') {
    Write-Log "No VPN detected via 'Management Connection State: Disconnected (no tunnel active)'" "DEBUG"
    return 'no_vpn'
  }
  
  if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*(.+)') {
    $mgmtState = $matches[1].Trim()
    Write-Log "Unknown Management Connection State pattern: '$mgmtState'" "WARN"
    return 'vpn_connected'
  }

  Write-Log "No 'Management Connection State:' line found, using fallback detection" "DEBUG"
  
  $userIndicators = @(
    '(?im)^\s*State\s*:\s*Connected\b',
    '(?im)^\s*Client\s+Address\s*:\s*\S+',
    '(?im)^\s*User(Name)?\s*:\s*\S+',
    '(?im)^\s*Bytes\s+(?:Sent|Received)\s*:\s*\d',
    '(?im)^\s*Duration\s*:\s*\d'
  )
  foreach ($pat in $userIndicators) { 
    if ($combined -match $pat) { 
      Write-Log "Fallback user tunnel detection via pattern: $pat" "DEBUG"
      return 'user_tun' 
    } 
  }

  return 'vpn_connected'
}

function Is-CiscoAdapterUp {
  try {
    $adp = Get-NetAdapter -Physical:$false -ErrorAction SilentlyContinue |
           Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Cisco (AnyConnect|Secure) Client') } |
           Select-Object -First 1
    return ($null -ne $adp)
  } catch { return $false }
}

# NEW: Smart VPN blocking detection
function Test-VPNBlockingNetwork {
    param(
        [string]$VPNState,
        [bool]$RedirectDetected = $false
    )
    
    # Intermediate states ALWAYS block all traffic (802.1x, captive portals, everything)
    $blockingStates = @('Connecting', 'Reconnecting', 'Unknown', 'Disconnecting')
    if ($blockingStates -contains $VPNState) {
        Write-Log "VPN state '$VPNState' blocks all network traffic including 802.1x and captive portals" "DEBUG"
        return $true
    }
    
    # Connected VPN + redirect detected = VPN is blocking network authentication
    # User needs to auth to LOCAL network first, then reconnect VPN after
    if ($VPNState -eq 'Connected' -and $RedirectDetected) {
        Write-Log "VPN is Connected but redirect detected - VPN blocking local network authentication" "DEBUG"
        return $true
    }
    
    Write-Log "VPN state '$VPNState' not blocking network access" "DEBUG"
    return $false
}

function VPN-Gatekeeper-AndMaybeExit {
  Write-Log "Checking VPN status (VPN-first gatekeeper)..."
  $state = Get-VpnStateStable -TimeoutSec $VpnStateMaxWaitSeconds

  if ($UseAdapterFallback -and $state -eq 'Unknown' -and (Is-CiscoAdapterUp)) {
    Write-Log "vpncli state ambiguous; Cisco virtual adapter is Up -> treating as Connected (fallback)"
    $state = "Connected"
  }

  if ($state -eq "Connected") {
    $flavor = Get-VpnTunnelFlavor
    Write-Log "VPN connected; flavor = $flavor"
    
    # FLARE EVENT: user_tun OR mgmt_tun
    # Context: USER (Event ID 780/781) | Reason: VPN connection detected
    # Expected Flow: WW_main (SYSTEM) ???EUR ?EUR(TM) Event Log ???EUR ?EUR(TM) Task Scheduler ???EUR ?EUR(TM) WW_flaregun_user.ps1 (USER) ???EUR ?EUR(TM) Flare
    # Ivanti Use: Trigger USER session automations (can launch GUI, user-context tools)
    # Why USER context: Ivanti needs logged-in user identity for session-specific actions
    Send-FlareEvent $flavor
    
    Clear-CaptiveEventHistory "VPN connected"
    $script:exitReason = "vpn_connected:$flavor"
    return
  }

  if ($state -eq "Disconnected") {
    Write-Log "VPN is Disconnected after stabilization; proceeding with redirect detection."
    return
  }

  Write-Log ("VPN state remained Unknown after {0}s; proceeding as not connected." -f $VpnStateMaxWaitSeconds)
}


# ------------------------- RC2.1 early VPN gate ------------------------------
# Secure Client fires a reconnect to its cached headend on ANY network state
# change. In Connecting/Reconnecting it blocks ALL traffic (802.1x, ISE posture,
# captive portals). This gate runs first, before any wait/sleep/preflight.
function Test-AnyUsableIp {
    # True if ANY physical WiFi/Ethernet adapter holds a non-APIPA IPv4 address.
    # Uses the per-adapter records Get-NetworkInfo already gathered (.Adapters).
    param([object]$NetworkInfo)
    try {
        $adapters = @($NetworkInfo.Adapters | Where-Object { $_ })
        if ($adapters.Count -eq 0) { $adapters = @($NetworkInfo) }
        foreach ($a in $adapters) {
            $ip = [string]$a.IPAddress
            if ($ip -and $ip -ne 'N/A' -and $ip -notmatch '^169\.254\.') { return $true }
        }
    } catch { Write-Log "Test-AnyUsableIp error: $_" "DEBUG" }
    return $false
}

function Test-EarlyTrustedNetwork {
    # Test-SsidTrusted returns $true for ANY wired link, which is too loose for a
    # disconnect-the-VPN decision (a docked laptop at home would count as trusted).
    # For wired, require corp-only DNS suffixes instead.
    param([object]$NetworkInfo)
    if ($NetworkInfo.ConnectionType -eq 'Ethernet') { return (Test-OnPremBySuffix) }
    return (Test-SsidTrusted -NetworkInfo $NetworkInfo)
}

function Invoke-EarlyVpnDisconnect {
    param([string]$Reason, [string]$VpnStateWas)
    Write-Log "Early VPN gate: disconnecting VPN now (reason=$Reason, state=$VpnStateWas)" "WARN"
    if ($WhatIf) { Write-Log "WHATIF: Would run vpncli disconnect" "INFO"; return $false }
    try {
        & $vpn_cmd disconnect | Out-Null
        $deadline = (Get-Date).AddSeconds($EarlyGateDisconnectWaitSec)
        do {
            Start-Sleep -Milliseconds 500
            $s = Get-VpnState
        } while ($s -ne 'Disconnected' -and (Get-Date) -lt $deadline)
        Write-Log "Early VPN gate: state after disconnect = $s" "INFO"
        $script:LastVpnState = $s; $script:LastVpnStateAt = Get-Date
        Write-TeeLog 'vpn_disconnect_forced' @{ reason = "early_gate:$Reason"; vpn_state_was = $VpnStateWas }
        return ($s -eq 'Disconnected')
    } catch {
        Write-Log "Early VPN gate: disconnect error: $_" "WARN"
        return $false
    }
}

function Invoke-EarlyVpnGate {
    # Rules (VPN already Disconnected = nothing to do):
    #   no IP on any adapter + Connecting/Reconnecting -> disconnect (attempt cannot succeed)
    #   recent wake  OR SSID jump + Connecting/Reconnecting -> disconnect
    #   recent wake  OR SSID jump + Connected + trusted network -> disconnect
    #   Connected + untrusted network -> leave alone (a working off-prem tunnel is not in the way)
    param([object]$NetworkInfo)
    $r = [pscustomobject]@{ VpnState = 'Unknown'; HasIp = $false; Acted = $false; Reason = 'none' }
    if (-not $EarlyVpnGateEnabled) { $r.Reason = 'disabled'; return $r }
    try {
        $r.HasIp = Test-AnyUsableIp -NetworkInfo $NetworkInfo
        $state = Get-VpnState
        $r.VpnState = $state
        $script:LastVpnState = $state; $script:LastVpnStateAt = Get-Date
        if ($state -eq 'Disconnected') { $r.Reason = 'already_disconnected'; return $r }

        $blocking  = @('Connecting', 'Reconnecting') -contains $state
        $connected = ($state -eq 'Connected')
        $reason = $null

        if (-not $r.HasIp) {
            if ($blocking) { $reason = 'no_ip' }
        } else {
            $wake = $false
            if ($VpnWakeDetection) { $wake = Test-RecentWakeFromSleep -TimeWindowSeconds $VpnWakeTimeWindow }
            $jump = Test-SsidJump -CurrentSsid $NetworkInfo.SSID
            if ($wake -or $jump) {
                $why = if ($wake) { 'wake' } else { 'ssid_jump' }
                if ($blocking) { $reason = "${why}_blocking" }
                elseif ($connected -and (Test-EarlyTrustedNetwork -NetworkInfo $NetworkInfo)) { $reason = "${why}_trusted" }
            }
        }

        if ($reason) {
            $r.Acted = $true
            $r.Reason = $reason
            [void](Invoke-EarlyVpnDisconnect -Reason $reason -VpnStateWas $state)
        } else {
            $r.Reason = 'no_action'
        }
        Write-Log ("early_vpn_gate state='{0}' has_ip={1} acted={2} reason='{3}'" -f $state, $r.HasIp, $r.Acted, $r.Reason) "INFO"
    } catch {
        Write-Log "Early VPN gate error: $_" "WARN"
    }
    return $r
}

function Invoke-GatedNwCheck {
    # Gateway preflight only runs when the Cisco client is Disconnected or Connected.
    # Any intermediate state blocks all traffic, so the probe is guaranteed to fail
    # (and burns its full timeout). Get-VpnStateStable keeps the original "give the
    # client n secs to settle" window before we give up on the probe.
    param([string]$Url = $NewPreflightURL, [string]$KnownVpnState = '')
    if ($PreflightRequiresSettledVpn) {
        $vpnState = $KnownVpnState
        if ([string]::IsNullOrEmpty($vpnState)) { $vpnState = Get-VpnStateStable -TimeoutSec $VpnStateMaxWaitSeconds }
        $script:LastVpnState = $vpnState; $script:LastVpnStateAt = Get-Date
        if ($vpnState -notin @('Connected', 'Disconnected')) {
            Write-Log "Preflight skipped: VPN state '$vpnState' blocks all traffic - probe would always fail" "WARN"
            $skip = [PSCustomObject]@{
                Status = 'unreachable'; Classification = 'INCONCLUSIVE'; RedirectUrl = $null
                RedirectType = ''; HttpStatus = ''; Protocol = ''; Fqdn = ''; Port = ''
                DurationMs = 0; Attempt = 1; ProbeUrl = $Url
                ObservationTime = (Get-Date).ToString('o')
                Reason = 'vpn_state_not_settled'; ErrorMessage = "vpn_state=$vpnState"
            }
            try { $global:LastCapPreflightResult = $skip } catch { }
            return $skip
        }
    }
    return (Get-NwCheckResult -Url $Url)
}

function Test-XmlVaultSyncAllowed {
    # The XmlVault share is only reachable on-prem or through the VPN tunnel.
    # On-prem = corp-only DNS suffixes (no I/O). VPN state is reused from this run's
    # own checks when fresh (a vpncli call costs several seconds), else queried.
    $maxAgeSec = 30
    if (Test-OnPremBySuffix) { return $true }
    $state = $null
    if ($script:LastVpnStateAt -and (((Get-Date) - $script:LastVpnStateAt).TotalSeconds -lt $maxAgeSec)) {
        $state = $script:LastVpnState
    } else {
        $state = Get-VpnState
    }
    return ($state -eq 'Connected')
}
