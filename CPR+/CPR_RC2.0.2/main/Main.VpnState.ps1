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

# Every vpncli call goes through here so a busy Secure Client agent (it blocks vpncli for minutes while it
# retries a failed connect, e.g. DNS failure on a guest network) can never hang the run. Returns the stdout
# text. On timeout the child process is killed, a WARN is logged and '' is returned, which callers already
# treat as "state unknown". A launch failure is NOT swallowed, so existing try/catch blocks still see it.
function Invoke-VpnCliBounded {
  param(
    [Parameter(Mandatory = $true)][string]$Arguments,
    [int]$TimeoutSec = 0
  )
  if ($Arguments -match '^\s*disconnect\b') {
    # Safety net for every disconnect path: never cut a client that is mid HostScan scan.
    if ((Get-Command Test-VpnHostscanHold -ErrorAction SilentlyContinue) -and (Test-VpnHostscanHold -Where 'disconnect')) { return '' }
    $script:VpnDisconnectsThisRun = [int]$script:VpnDisconnectsThisRun + 1
  }
  if ($TimeoutSec -le 0) {
    $TimeoutSec = if ($Arguments -match '^\s*disconnect\b') { [int]$VpnCliDisconnectTimeoutSec } else { [int]$VpnCliTimeoutSec }
    if ($TimeoutSec -le 0) { $TimeoutSec = 8 }
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName               = $vpn_cmd
  $psi.Arguments              = $Arguments
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow         = $true
  $proc = $null
  $startedAt = Get-Date
  try {
    $proc = [System.Diagnostics.Process]::Start($psi)
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $null    = $proc.StandardError.ReadToEndAsync()
    if ($proc.WaitForExit($TimeoutSec * 1000)) {
      $proc.WaitForExit()   # flush the async readers
      return [string]$outTask.Result
    }
    Write-Log ("vpncli_timeout cmd='{0}' waited_ms={1} - child killed, treating output as empty" -f `
      $Arguments, [math]::Round(((Get-Date) - $startedAt).TotalMilliseconds)) "WARN"
    try { $proc.Kill() } catch { }
    return ''
  } finally {
    if ($proc) { try { $proc.Dispose() } catch { } }
  }
}

function Test-VpnHostscanHold {
  <#
  True while a real HostScan scan (scanner provider csc_cscan) is running and the episode is under the
  ceiling. HostScan runs only after the client has reached the headend, so the network works and the
  client is NOT blocked behind a captive portal: cutting it would kill a legitimate connect. The episode
  start is persisted so the ceiling holds across runs; the episode ends (file removed) once the scanner
  has been silent for $VpnHostscanSilentSec. Fail-soft: any error returns $false (normal behavior).
  #>
  param([string]$Where = '')
  if (-not $VpnPostureDetection -or -not $VpnHostscanHold) { return $false }
  try {
    $silent = [int]$VpnHostscanSilentSec; if ($silent -le 0) { $silent = 30 }
    $ceil = [int]$VpnHostscanMaxWaitSec;  if ($ceil -le 0) { $ceil = 300 }
    $scan = Get-WinEvent -FilterHashtable @{ LogName = $VpnPostureLogName; ProviderName = $VpnPostureScanProvider; StartTime = (Get-Date).AddSeconds(-$silent) } -MaxEvents 1 -ErrorAction SilentlyContinue
    if (-not $scan) {
      if ($VpnHostscanEpisodeFile -and (Test-Path -LiteralPath $VpnHostscanEpisodeFile)) { Remove-Item -LiteralPath $VpnHostscanEpisodeFile -Force -ErrorAction SilentlyContinue }
      return $false
    }
    $start = Get-Date
    if ($VpnHostscanEpisodeFile) {
      $parsed = [datetime]::MinValue
      if ((Test-Path -LiteralPath $VpnHostscanEpisodeFile) -and [datetime]::TryParse((Get-Content -LiteralPath $VpnHostscanEpisodeFile -Raw -ErrorAction SilentlyContinue), [ref]$parsed)) { $start = $parsed }
      else { Set-Content -LiteralPath $VpnHostscanEpisodeFile -Value (Get-Date).ToString('o') -Force -ErrorAction SilentlyContinue }
    }
    $age = [int]((Get-Date) - $start).TotalSeconds
    if ($age -gt $ceil) {
      Write-Log ("vpn_hostscan_posture_ceiling episode_age_sec={0} max_wait_sec={1} where='{2}' - scan has run too long, normal VPN handling resumes" -f $age, $ceil, $Where) "WARN"
      return $false
    }
    $script:VpnHostscanHoldActive = $true
    Write-Log ("vpn_hostscan_posturing_hold episode_age_sec={0} max_wait_sec={1} last_event='{2}' where='{3}' - HostScan scan in progress, not disconnecting" -f $age, $ceil, $scan.TimeCreated.ToString('HH:mm:ss'), $Where) "WARN"
    return $true
  } catch { Write-Log "Test-VpnHostscanHold error: $_" "DEBUG" }
  return $false
}

function Test-VpnPostureActive {
  <#
  Secure Firewall Posture (HostScan/OPSWAT) is invisible to vpncli: the client can sit in a posture
  scan for minutes while 'vpncli state' still reads Disconnected. That Windows event log is silent when
  the client is idle (observed), so any event inside a short window means posture is in progress.
  One bounded Get-WinEvent (MaxEvents 1). Fail-soft: any error or missing log returns $false.
  #>
  param([int]$WindowSec = 0)
  if (-not $VpnPostureDetection) { return $false }
  if ($WindowSec -le 0) { $WindowSec = [int]$VpnPostureActiveWindowSec }
  if ($WindowSec -le 0) { $WindowSec = 15 }
  try {
    $since = (Get-Date).AddSeconds(-$WindowSec)
    # Scanner process (csc_cscan) = a real HostScan/OPSWAT scan. Any other provider in this log
    # (csc_ciscod connection callbacks) is just the client working on a connect attempt.
    $scan = Get-WinEvent -FilterHashtable @{ LogName = $VpnPostureLogName; ProviderName = $VpnPostureScanProvider; StartTime = $since } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($scan) {
      Write-Log ("vpn_hostscan_posture_active log='{0}' last_event='{1}' provider='{2}' window_sec={3} - reporting Connecting instead of Disconnected" -f `
        $VpnPostureLogName, $scan.TimeCreated.ToString('HH:mm:ss'), $scan.ProviderName, $WindowSec) "WARN"
      return $true
    }
    $ev = Get-WinEvent -FilterHashtable @{ LogName = $VpnPostureLogName; StartTime = $since } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($ev) {
      Write-Log ("vpn_client_connect_activity log='{0}' last_event='{1}' provider='{2}' window_sec={3} - no HostScan scan seen, client is working on a connect attempt; reporting Connecting instead of Disconnected" -f `
        $VpnPostureLogName, $ev.TimeCreated.ToString('HH:mm:ss'), $ev.ProviderName, $WindowSec) "WARN"
      return $true
    }
  } catch { Write-Log "Test-VpnPostureActive error: $_" "DEBUG" }
  return $false
}

function Get-VpnState {
  try {
    $statsText = ""
    $stateText = ""
    
    try { $statsText = (Invoke-VpnCliBounded -Arguments 'stats') } catch { }
    try { $stateText = (Invoke-VpnCliBounded -Arguments 'state') } catch { }
    
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
      
      if ($lastState -eq 'Disconnected' -and (Test-VpnPostureActive)) { return 'Connecting' }
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
      # 'vpncli state' returned nothing (timed out or blank) while 'stats' answered. The management
      # line says nothing about the user tunnel (non-Always-On profiles have no management tunnel), so
      # it cannot prove Disconnected - the client may be mid-connect. Report Unknown (an intermediate
      # state) instead of a false Disconnected.
      if ([string]::IsNullOrWhiteSpace($stateText)) {
        Write-Log "vpn_state_untrusted: 'vpncli state' returned no output; management line alone cannot prove Disconnected - returning Unknown" "WARN"
        return "Unknown"
      }
      Write-Log "Management shows Disconnected, no user tunnel" "DEBUG"
      if (Test-VpnPostureActive) { return "Connecting" }
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
      # Secure Client re-fires a connect attempt right after our disconnect (it retries a cached headend, and on a
      # guest network that fails with DNS errors). If WW already cut the VPN this run and it re-entered
      # Connecting/Reconnecting, cut it again - capped, so a client that never stops retrying cannot trap the run.
      if (@('Connecting', 'Reconnecting') -contains $state -and (Test-VpnHostscanHold -Where 'stabilize')) {
        Write-Log "vpncli state (stable): $state - HostScan scan in progress; not waiting or cutting this run" "INFO"
        return $state
      }
      if (@('Connecting', 'Reconnecting') -contains $state -and [int]$script:VpnDisconnectsThisRun -gt 0 -and
          [int]$script:VpnPostDisconnectRetries -lt [int]$VpnPostDisconnectRetryMax) {
        $script:VpnPostDisconnectRetries = [int]$script:VpnPostDisconnectRetries + 1
        Write-Log ("VPN re-entered {0} after our disconnect (retry {1} of {2}) - disconnecting again" -f `
          $state, $script:VpnPostDisconnectRetries, $VpnPostDisconnectRetryMax) "WARN"
        try { Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null } catch { Write-Log "Retry disconnect error: $_" "WARN" }
        Start-Sleep -Seconds 2
        continue
      }
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
              Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null
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
          Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null
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
  try { $statsText  = (Invoke-VpnCliBounded -Arguments 'stats') }  catch { Write-Log "Get-VpnTunnelFlavor: stats error: $_" }
  try { $statusText = (Invoke-VpnCliBounded -Arguments 'status') }  catch { Write-Log "Get-VpnTunnelFlavor: status error: $_" }

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
    Set-CprRunExit -Reason 'vpn_connected' -State $flavor
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

function Invoke-EarlyVpnDisconnect {
    param([string]$Reason, [string]$VpnStateWas)
    Write-Log "Early VPN gate: disconnecting VPN now (reason=$Reason, state=$VpnStateWas)" "WARN"
    if ($WhatIf) { Write-Log "WHATIF: Would run vpncli disconnect" "INFO"; return $false }
    try {
        Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null
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
    # Rules (only NOT-yet-connected VPN states are ever cut; Disconnected = nothing to do):
    #   no IP on any adapter + Connecting/Reconnecting -> disconnect (attempt cannot succeed)
    #   recent wake  OR SSID jump + Connecting/Reconnecting -> disconnect
    #   Connected -> NEVER disconnected here, on-prem or not. Users may legitimately VPN
    #   from on-prem; the BlackHole subsystem owns that policy.
    param([object]$NetworkInfo)
    $r = [pscustomobject]@{ VpnState = 'Unknown'; HasIp = $false; Acted = $false; Reason = 'none'; Wake = $false; Jump = $false }
    if (-not $EarlyVpnGateEnabled) { $r.Reason = 'disabled'; return $r }
    try {
        $r.HasIp = Test-AnyUsableIp -NetworkInfo $NetworkInfo
        $state = Get-VpnState
        $r.VpnState = $state
        $script:LastVpnState = $state; $script:LastVpnStateAt = Get-Date
        if ($state -eq 'Disconnected') { $r.Reason = 'already_disconnected'; return $r }

        $blocking = @('Connecting', 'Reconnecting') -contains $state
        $reason = $null

        if (-not $r.HasIp) {
            if ($blocking) { $reason = 'no_ip' }
        } else {
            $wake = $false
            if ($VpnWakeDetection) { $wake = Test-RecentWakeFromSleep -TimeWindowSeconds $VpnWakeTimeWindow }
            $jump = Test-SsidJump -CurrentSsid $NetworkInfo.SSID
            $r.Wake = [bool]$wake; $r.Jump = [bool]$jump
            if ($wake -or $jump) {
                $why = if ($wake) { 'wake' } else { 'ssid_jump' }
                if ($blocking) { $reason = "${why}_blocking" }
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

# RC2.1: raw reachability of the DC FQDN (NOT Test-DC, which answers "on-prem?" using DNS
# suffixes and says False on a healthy home VPN). Quiet and fast-failing.
function Test-DcPing {
    try { return [bool](Test-Connection -ComputerName $DC_FQDN -Count 1 -Quiet -ErrorAction Stop) } catch { return $false }
}

function Invoke-ConnectedUnreachableTriage {
    # VPN reports Connected but the gateway preflight failed. Decide quickly whether the tunnel
    # is real, using a cheap DC ping and, when that fails, a bounded poll of the VPN state
    # (stale Connected after a hop usually flips to Reconnecting within seconds).
    #   Outcome: dc_reachable | dc_recovered | state_left_connected | timeout
    param([string]$Url = $NewPreflightURL)
    $started = Get-Date
    $r = [pscustomobject]@{ Outcome = 'timeout'; DcReachable = $false; Preflight = 'not_run'; VpnState = 'Connected'; WaitedMs = 0 }

    if (Test-DcPing) {
        $r.DcReachable = $true; $r.Outcome = 'dc_reachable'
        $r.Preflight = [string](Invoke-GatedNwCheck -Url $Url -KnownVpnState 'Connected').Status
    } else {
        $deadline = $started.AddSeconds($StaleConnectedMaxWaitSec)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $StaleConnectedPollSec
            if (Test-DcPing) {
                $r.DcReachable = $true; $r.Outcome = 'dc_recovered'
                $r.Preflight = [string](Invoke-GatedNwCheck -Url $Url -KnownVpnState 'Connected').Status
                break
            }
            $st = Get-VpnState
            $r.VpnState = $st
            if ($st -ne 'Connected') { $r.Outcome = 'state_left_connected'; break }
        }
    }
    $r.WaitedMs = [int]((Get-Date) - $started).TotalMilliseconds
    return $r
}
