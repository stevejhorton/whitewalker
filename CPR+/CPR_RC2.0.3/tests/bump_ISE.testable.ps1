#Requires -RunAsAdministrator
param(
  [switch]$WWDebug,        # Light debug: decision breadcrumbs only
  [switch]$WWTrace,        # Heavy debug: raw vpncli stats/status dumps
  [switch]$WhatIf          # Show what would be done without executing
)

<#
  White Walker (ISE Auto Rescan Tool)
  Version: 3.3.0
  Author: steve.horton@optum.com (with AI assist)
  Date: 18-Sep-2025

  Behavior changes in 3.3.0:
    - Removed Zscaler polling bottleneck - redirect detection is sufficient
    - Simplified browser launch for better user context execution
    - Removed CaptivePortalOnly mode (no longer needed)
    - Streamlined captive portal handling based on redirect analysis
    - Faster execution by eliminating redundant status checks

  Usage Examples:
    WhiteWalker.ps1                          # Normal DHCP-triggered operation
    WhiteWalker.ps1 -WWDebug                 # Normal run with debug logging
    WhiteWalker.ps1 -WWTrace                 # Full debug with CLI output dumps
#>

# ------------------------------- Config ---------------------------------------
$ver                    = "3.3.0"
$initial_sleep          = 7     # seconds after DHCP before checks
$LogPath                = "C:\Windows\UHGLogs\white_walker.log"

# VPN stabilization
$VpnStateMaxWaitSeconds = 12     # how long to wait for vpncli to settle to Connected/Disconnected

# Rescan & flare behavior
$RescanOnlyOnRedirect   = $true
$FlareCooldownMinutes   = 10     # per-flare tag cooldown
$RescanCooldownMinutes  = 3      # rescan cooldown
$PostureWaitSeconds     = 12     # wait for posture service to appear on redirect
$StateRoot              = 'C:\Windows\UHGLogs'
$StateFile              = Join-Path $StateRoot 'state.json'

# Ivanti flare exe (receives "/<tag>")
$flareExe               = "$env:SystemRoot\System32\rundll32.exe"

# Optional adapter fallback: if vpncli is ambiguous, treat an "Up" Cisco virtual adapter as connected
$UseAdapterFallback     = $false

# Target domain/DC name for on-prem check
$DC_FQDN = "ms.ds.uhc.com"

# Browser launch configuration
$CaptivePortalURL = "http://gateway.zscalertwo.net/zcc_conn_test"
$CiscoBrowserKillDelay = 3  # seconds to monitor for Cisco browser popup

# Cisco browser process names to terminate
$CiscoBrowserProcesses = @(
    "csc_ui_skip",
    "csc_vpnui_skip",
    "vpnui_skip",
    "acwebhelper",
    "CiscoCollabHost",
    "CiscoAnyConnectWebView"
)

function Start-CiscoBrowserKiller {
    try {
        # Start background job to monitor and kill Cisco browser processes
        $killerScript = {
            param($ProcessNames, $DelaySeconds, $LogPath)
            
            function Add-KillerLog($message) {
                $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
                try {
                    Add-Content -Path $LogPath -Value "$ts [CiscoBrowserKiller] $message" -ErrorAction SilentlyContinue
                } catch { }
            }
            
            $endTime = (Get-Date).AddSeconds($DelaySeconds)
            Add-KillerLog "Starting Cisco browser monitoring for $DelaySeconds seconds"
            
            while ((Get-Date) -lt $endTime) {
                foreach ($processName in $ProcessNames) {
                    try {
                        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
                        foreach ($proc in $processes) {
                            Add-KillerLog "Terminating Cisco browser process: $($proc.Name) (PID: $($proc.Id))"
                            $proc.Kill()
                            $proc.WaitForExit(2000)
                        }
                    } catch {
                        Add-KillerLog "Error killing process $processName : $_"
                    }
                }
                Start-Sleep -Milliseconds 500
            }
            Add-KillerLog "Cisco browser monitoring completed"
        }
        
        Write-Log "Starting Cisco browser killer background job" "INFO"
        $job = Start-Job -ScriptBlock $killerScript -ArgumentList $CiscoBrowserProcesses, $CiscoBrowserKillDelay, $LogPath
        
        # Don't wait for the job - let it run in background
        return $job
        
    } catch {
        Write-Log "Failed to start Cisco browser killer: $_" "WARN"
        return $null
    }
}

function Stop-CiscoBrowserKiller {
    param($Job)
    
    if ($Job) {
        try {
            Stop-Job -Job $Job -ErrorAction SilentlyContinue
            Remove-Job -Job $Job -ErrorAction SilentlyContinue
            Write-Log "Cisco browser killer job stopped" "DEBUG"
        } catch {
            Write-Log "Error stopping Cisco browser killer job: $_" "DEBUG"
        }
    }
}

# --------------------- Utility: Reliable Append Logging -----------------------
function Initialize-Logger {
  $dir = Split-Path -Parent $LogPath
  if (-not (Test-Path $dir))  { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType File -Force | Out-Null }
}
function Add-LogLine([string]$line) {
  for ($i=1; $i -le 3; $i++) {
    try   { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop; break }
    catch { Start-Sleep -Milliseconds (50 * $i); if ($i -eq 3) { Write-Host "LOG WRITE FAILED: $($_.Exception.Message)" } }
  }
}
function Write-Log { param([Parameter(Mandatory=$true)][string]$Message, [string]$Level = "INFO")
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
  $logLine = "$ts [WW] [$Level] $Message"
  Add-LogLine $logLine
}
function Write-DebugBlock {
  param([Parameter(Mandatory=$true)][string]$Label,[Parameter(Mandatory=$true)][string]$Text)
  if (-not $WWTrace) { return }
  $flat = $Text.Replace("`r","").Replace("`n","⎘")
  Write-Log ("DEBUG {0}:`n{1}" -f $Label, $flat)
}

# Run header/trailer
$RunId  = "{0}-{1}" -f (Get-Date -Format "yyyyMMddHHmmssfff"), $PID
$HostNm = $env:COMPUTERNAME
$UserNm = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
function Write-RunHeader {
  $utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'")
  $loc = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
  $bar = ('=' * 80)
  Add-LogLine $bar
  Add-LogLine ("RUN START  White Walker v{0}" -f $ver)
  Add-LogLine ("run_id={0} host={1} user={2}" -f $RunId, $HostNm, $UserNm)
  Add-LogLine ("ts_local={0}  ts_utc={1}" -f $loc, $utc)
  Add-LogLine ("log_path={0}" -f $LogPath)
  Add-LogLine $bar
}
function Write-RunEnd([string]$Reason='') {
  $bar = ('-' * 80)
  Add-LogLine $bar
  Add-LogLine ("RUN END    run_id={0} exit_reason=""{1}""" -f $RunId, $Reason)
  Add-LogLine ""
}

# ----------------------- Utility: State & Cooldowns ---------------------------
if (-not (Test-Path $StateRoot)) { New-Item -Path $StateRoot -ItemType Directory -Force | Out-Null }

function Rescan-InCooldown {
    return In-Cooldown 'rescan' $RescanCooldownMinutes
}

function To-Hashtable($obj) {
  if ($null -eq $obj) { return $null }
  if ($obj -is [System.Collections.IDictionary]) { return $obj }
  if ($obj -is [System.Management.Automation.PSCustomObject]) {
    $ht = @{}
    foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = To-Hashtable $p.Value }
    return $ht
  }
  if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
    $arr = @()
    foreach ($i in $obj) { $arr += ,(To-Hashtable $i) }
    return $arr
  }
  return $obj
}

function Get-State {
  if (Test-Path $StateFile) {
    try {
      $s = Get-Content $StateFile -Raw | ConvertFrom-Json
      if ($s.lastFlare) { $s.lastFlare = To-Hashtable $s.lastFlare }
      return $s
    } catch { }
  }
  [PSCustomObject]@{ lastFlare = @{}; lastRescan = '' }
}
function Save-State($obj) {
  try { $obj | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8 } catch { }
}
$global:_state = Get-State

# per-run de-dupe (ensure hashtable)
if (-not ($global:flareHistory -is [hashtable])) { $global:flareHistory = @{} } else { $global:flareHistory.Clear() }

function In-Cooldown([string]$key, [int]$minutes) {
  try {
    if (-not $global:_state.lastFlare) { return $false }
    if (-not ($global:_state.lastFlare -is [hashtable])) { $global:_state.lastFlare = To-Hashtable $global:_state.lastFlare }
    $stamp = $global:_state.lastFlare[$key]
    if (-not $stamp) { return $false }
    $when = [datetime]::Parse($stamp)
    return ((Get-Date) -lt $when.AddMinutes($minutes))
  } catch { return $false }
}
function Set-FlareStamp([string]$key) {
  if (-not $global:_state.lastFlare) {
    $global:_state | Add-Member -NotePropertyName lastFlare -NotePropertyValue @{} -Force
  } elseif (-not ($global:_state.lastFlare -is [hashtable])) {
    $global:_state.lastFlare = To-Hashtable $global:_state.lastFlare
  }
  $global:_state.lastFlare[$key] = (Get-Date).ToString('o')
  Save-State $global:_state
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

# ---------------------- Connectivity & Redirect Checks -----------------------
function Test-DefaultGateway {
  try {
    $gateways = Get-NetIPConfiguration |
      Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } |
      ForEach-Object { $_.IPv4DefaultGateway.NextHop } |
      Select-Object -Unique
    foreach ($gw in $gateways) {
      if (Test-Connection -ComputerName $gw -Count 1 -Quiet) { return $true }
    }
  } catch { }
  return $false
}
function Test-DC { param([string]$hostname = $DC_FQDN)
  try { return (Test-Connection -ComputerName $hostname -Count 1 -Quiet) } catch { return $false }
}
function Test-Redirect { 
    param([string]$Url = "http://enroll.cisco.com")
    
    Write-Log "Testing for redirect: trying $Url"
  
  $redirectInfo = @{
    IsRedirect = $false
    RedirectUrl = $null
    Method = $null
  }
  
  try {
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 4000
    $response = $request.GetResponse()
    $statusCode = [int]$response.StatusCode
    $location = $response.Headers['Location']
    $response.Close()
    
    if ($statusCode -ge 300 -and $statusCode -lt 400) { 
      Write-Log "REDIRECT DETECTED: HTTP $statusCode - $Url redirected to: $location"
      $redirectInfo.IsRedirect = $true
      $redirectInfo.RedirectUrl = $location
      $redirectInfo.Method = "HTTP"
      return $redirectInfo
    } else {
      Write-Log "No HTTP redirect: $Url returned status $statusCode"
    }
  } catch { 
    Write-Log "HTTP redirect check error for $Url (may be captive or blocked): $_" 
  }
  
  try {
    Write-Log "Attempting fallback content check for meta refresh on $Url"
    $resp = Invoke-WebRequest -Uri $Url -TimeoutSec 5
    if ($resp.StatusCode -eq 200) {
      $content = $resp.Content
      
      # Try multiple meta refresh patterns
      $metaPatterns = @(
        '<meta\s+http-equiv\s*=\s*["'']refresh["'']\s+content\s*=\s*["''][^"'']*?url\s*=\s*([^"''\s>]+)[^>]*>',
        '<meta\s+http-equiv\s*=\s*["'']refresh["'']\s+content\s*=\s*["''][^"'']*?url\s*=\s*["'']([^"'']+)["''][^>]*>',
        '<meta\s+content\s*=\s*["''][^"'']*?url\s*=\s*([^"''\s>;]+)[^>]*?\s+http-equiv\s*=\s*["'']refresh["''][^>]*>',
        '<meta\s+content\s*=\s*["''][^"'']*?url\s*=\s*["'']([^"'']+)["''][^>]*?\s+http-equiv\s*=\s*["'']refresh["''][^>]*>'
      )
      
      $metaRedirectUrl = $null
      foreach ($pattern in $metaPatterns) {
        if ($content -match $pattern) {
          $metaRedirectUrl = $matches[1]
          Write-Log "META REFRESH PATTERN MATCHED: $pattern"
          break
        }
      }
      
      if ($metaRedirectUrl) {
        Write-Log "REDIRECT DETECTED: Meta refresh - $Url redirected to: $metaRedirectUrl"
        $redirectInfo.IsRedirect = $true
        $redirectInfo.RedirectUrl = $metaRedirectUrl
        $redirectInfo.Method = "META"
        return $redirectInfo
      }
      
      # Fallback: just look for any meta refresh tag and log the full tag for analysis
      if ($content -match '(<meta[^>]*http-equiv\s*=\s*["'']refresh["''][^>]*>)') {
        $fullMetaTag = $matches[1]
        Write-Log "REDIRECT DETECTED: Meta refresh found but couldn't extract URL. Full tag: $fullMetaTag"
        $redirectInfo.IsRedirect = $true
        $redirectInfo.RedirectUrl = "UNKNOWN"
        $redirectInfo.Method = "META_UNKNOWN"
        return $redirectInfo
      }
      
      Write-Log "No meta refresh redirect found in $Url content"
    }
  } catch { 
    Write-Log "Fallback content check failed for ${Url}: $_" 
  }
  
  Write-Log "No redirect detected from $Url"
  return $redirectInfo
}

function Get-RedirectType {
    param([string]$RedirectUrl)
    
    if (-not $RedirectUrl -or $RedirectUrl -eq "UNKNOWN") {
        return "UNKNOWN"
    }
    
    $url = $RedirectUrl.ToLower()
    
    if ($url -match "isepsn") {
        Write-Log "ISE Employee Network detected in redirect URL: $RedirectUrl"
        return "ISE_EMPLOYEE"
    }
    elseif ($url -match "isegst") {
        Write-Log "ISE Guest Network detected in redirect URL: $RedirectUrl"
        return "ISE_GUEST"
    }
    else {
        Write-Log "Non-ISE captive portal detected in redirect URL: $RedirectUrl"
        return "NON_ISE"
    }
}

function Open-CaptivePortalBrowser {
    param([string]$URL)
    
    if ($WhatIf) {
        Write-Log "WHATIF: Would open browser to: $URL" "INFO"
        return $true
    }

    Write-Log "Opening browser for captive portal authentication..." "INFO"
    Write-Log "Target URL: $URL" "DEBUG"
    
    try {
        Write-Log "Launching browser via scheduled task method..." "DEBUG"
        $taskName = "WW_CaptivePortal_$((Get-Date).Ticks)"
        
        # Use exact same approach as working test script (Method 5)
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c start `"CaptivePortal`" `"$URL`""
        $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Write-Log "Registering scheduled task: $taskName" "DEBUG"
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        
        Write-Log "Starting scheduled task: $taskName" "DEBUG"
        Start-ScheduledTask -TaskName $taskName
        
        # Clean up task after brief delay
        Start-Sleep -Seconds 3
        Write-Log "Cleaning up scheduled task: $taskName" "DEBUG"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        
        Write-Log "Browser launched successfully via scheduled task method" "INFO"
        return $true
        
    } catch {
        Write-Log "Failed to launch browser: $($_.Exception.Message)" "ERROR"
        Write-Log "User will need to manually navigate to: $URL" "ERROR"
        return $false
    }
}

function Invoke-CaptivePortalRemediation {
    param([string]$PortalType)
    
    Write-Log "Starting captive portal remediation for $PortalType" "INFO"
    Send-SignalFlare "captive_portal_$($PortalType.ToLower())"
    
    # Start Cisco browser killer to prevent interference
    $killerJob = Start-CiscoBrowserKiller
    
    # Open browser for user authentication
    $browserResult = Open-CaptivePortalBrowser -URL $CaptivePortalURL
    
    if ($browserResult) {
        Write-Log "Browser opened successfully. User can complete authentication." "INFO"
        # Give time for the Cisco browser killer to do its work
        Start-Sleep -Seconds 3
    }
    
    # Stop the browser killer job
    Stop-CiscoBrowserKiller -Job $killerJob
    
    return $browserResult
}

# ----------------------------- Posture Service Wait --------------------------
function Get-PostureService {
  try {
    $known = Get-Service -Name "csc_posture","csc_vpn_posture" -ErrorAction SilentlyContinue
    if ($known) { return ($known | Select-Object -First 1) }
    $candidates = Get-Service -ErrorAction SilentlyContinue | Where-Object {
      ($_.Name -match '(?i)posture') -or ($_.DisplayName -match '(?i)posture')
    } | Where-Object {
      $_.DisplayName -match '(?i)Cisco|Secure Client|AnyConnect|Secure Firewall'
    }
    if ($candidates) { return ($candidates | Select-Object -First 1) }
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

# -------------------------- VPN State & Flavor -------------------------------
function Get-VpnState {
  try {
    $statsText = ""
    $stateText = ""
    
    # Get both stats and state output
    try { $statsText = (& $vpn_cmd stats 2>$null | Out-String) } catch { }
    try { $stateText = (& $vpn_cmd state 2>$null | Out-String) } catch { }
    
    $combined = "$statsText`n$stateText"
    
    if ($WWDebug) { Write-Log "DEBUG: polled vpncli state and stats." }
    Write-DebugBlock -Label 'vpncli combined' -Text $combined
    
    # Check Management Connection State first - if management tunnel is active, we're connected
    if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Connected\b') {
      Write-Log "Management tunnel active - returning Connected" "DEBUG"
      return "Connected"
    }
    
    # Check for user tunnel active (Management disconnected but user tunnel active)
    if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Disconnected.*user\s+tunnel\s+active') {
      Write-Log "User tunnel active - returning Connected" "DEBUG"  
      return "Connected"
    }
    
    # If Management Connection State shows just "Disconnected" (no user tunnel), check traditional state
    if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*Disconnected\s*') {
      Write-Log "Management shows Disconnected, checking traditional state" "DEBUG"
      # Fall through to traditional state check below
    }
    
    # Traditional state parsing (fallback and primary for non-management scenarios)
    $m = [regex]::Matches($stateText, '(?im)^\s*(?:>>\s*)?state:\s*(\w+)\s*')
    if ($m.Count -gt 0) { 
      $state = $m[$m.Count - 1].Groups[1].Value
      Write-Log "Traditional state detection: $state" "DEBUG"
      return $state
    }
    
  } catch { 
    Write-Log "Get-VpnState error: $_" "DEBUG"
  }
  return "Unknown"
}
function Get-VpnStateStable {
  param([int]$TimeoutSec = $VpnStateMaxWaitSeconds)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $state = "Unknown"
  Write-Log ("Stabilizing VPN state for up to {0}s..." -f $TimeoutSec)
  do {
    $state = Get-VpnState
    if ($state -in @('Connected','Disconnected')) { break }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
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

  # Primary detection: Use "Management Connection State:" line as single source of truth
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
  
  # If Management Connection State line exists but doesn't match above patterns, log it for analysis
  if ($combined -match '(?im)^\s*Management\s+Connection\s+State\s*:\s*(.+)') {
    $mgmtState = $matches[1].Trim()
    Write-Log "Unknown Management Connection State pattern: '$mgmtState'" "WARN"
    return 'vpn_connected'  # Generic connected state
  }

  # Fallback: if no Management Connection State line found, use legacy detection
  Write-Log "No 'Management Connection State:' line found, using fallback detection" "DEBUG"
  
  # Standard user tunnel indicators (fallback only)
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

function VPN-Gatekeeper-AndMaybeExit {
  # Stabilize first, then act decisively
  Write-Log "Checking VPN status (VPN-first gatekeeper)..."
  $state = Get-VpnStateStable -TimeoutSec $VpnStateMaxWaitSeconds

  # Optional adapter fallback if still Unknown
  if ($UseAdapterFallback -and $state -eq 'Unknown' -and (Is-CiscoAdapterUp)) {
    Write-Log "vpncli state ambiguous; Cisco virtual adapter is Up -> treating as Connected (fallback)"
    $state = "Connected"
  }

  Write-Log "vpncli state (stable): $state"
  if ($state -eq "Connected") {
    $flavor = Get-VpnTunnelFlavor
    Write-Log "VPN connected; flavor = $flavor"
    Send-SignalFlare $flavor
    Write-RunEnd "vpn_connected:$flavor"
    exit 0
  }

  if ($state -eq "Disconnected") {
    Write-Log "VPN is Disconnected after stabilization; proceeding with redirect/DC/GW classification."
    return
  }

  # Still Unknown after wait: proceed as Disconnected but call it out
  Write-Log ("VPN state remained Unknown after {0}s; proceeding as not connected." -f $VpnStateMaxWaitSeconds)
}

# ------------------------------- ISE Rescan ----------------------------------
function Set-RescanStamp {
    $global:_state.lastRescan = (Get-Date).ToString('o')
    Save-State $global:_state
}

function Invoke-PostureRescan {
  if (Rescan-InCooldown) { Write-Log "Rescan suppressed (cooldown ${RescanCooldownMinutes}m)"; return }

  # Wait for posture service to appear and be startable
  $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
  if (-not $svc) {
    Write-Log "Posture service not available within ${PostureWaitSeconds}s; skipping rescan."
    return
  }

  if ($svc.Status -ne "Running") {
    Write-Log ("Posture service {0} not running -> starting..." -f $svc.Name)
    try { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue; Start-Sleep -Seconds 6 } catch { Write-Log "Failed to start posture service: $_" }
  }

  # Try direct CLI
  try {
    Write-Log "Rescan (direct): & '$ise_cmd' rescan"
    if (-not $WhatIf) {
      $null = & $ise_cmd rescan
    } else {
      Write-Log "WHATIF: Would execute ISE rescan" "INFO"
    }
    Set-RescanStamp
    return
  } catch {
    Write-Log "Direct rescan error: $_"
  }

  # Fallback: interactive tiny session
  if (-not $WhatIf) {
    try {
      Write-Log "Rescan (interactive fallback)"
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName               = $ise_cmd
      $psi.RedirectStandardInput  = $true
      $psi.RedirectStandardOutput = $true
      $psi.UseShellExecute        = $false
      $p = New-Object System.Diagnostics.Process
      $p.StartInfo = $psi
      $p.Start() | Out-Null
      $p.StandardInput.WriteLine("rescan")
      $p.StandardInput.WriteLine("exit")
      $p.WaitForExit(20000) | Out-Null
      Set-RescanStamp
    } catch {
      Write-Log "Interactive rescan failed: $_"
    }
  }
}
    
# --------------------------------- MAIN --------------------------------------
# Only execute main logic when script is run directly, not when dot-sourced for testing
if ($MyInvocation.InvocationName -ne '.') {
    # Normal WhiteWalker operation
    $ciscoPath = Get-CiscoInstallPath

    Initialize-Logger
    Write-RunHeader

    if (-not $ciscoPath) { Write-Log "Error: Cisco Secure Client install path not found."; Write-RunEnd "error_no_cisco"; exit 1 }
    $ise_cmd = Join-Path $ciscoPath "posturecli.exe"
    $vpn_cmd = Join-Path $ciscoPath "vpncli.exe"

    Write-Log ("CiscoPath={0}" -f $ciscoPath)
    Write-Log ("vpncli={0}"    -f $vpn_cmd)
    Write-Log ("posturecli={0}"-f $ise_cmd)

    if (-not (Test-Path $vpn_cmd)) { Write-Log "Error: vpncli.exe not found.";     Write-RunEnd "error_no_vpncli";     exit 1 }
    if (-not (Test-Path $ise_cmd)) { Write-Log "Error: posturecli.exe not found."; Write-RunEnd "error_no_posturecli"; exit 1 }

    try {
      Write-Log "White Walker v$ver starting..."
      Write-Log "Sleeping $initial_sleep seconds post-DHCP..."
      Start-Sleep -Seconds $initial_sleep

      # >>> VPN-FIRST GATEKEEPER <<<
      VPN-Gatekeeper-AndMaybeExit

      # ISE/Captive Portal Detection and Routing
      $redirectResult = Test-Redirect
      if ($redirectResult.IsRedirect) {
        $redirectType = Get-RedirectType -RedirectUrl $redirectResult.RedirectUrl
        Write-Log "Redirect classification: Type=$redirectType, URL=$($redirectResult.RedirectUrl), Method=$($redirectResult.Method)"
        
        switch ($redirectType) {
          "ISE_EMPLOYEE" {
            Write-Log "ISE Employee Network detected -> forcing ISE posture rescan"
            Send-SignalFlare 'ise_employee_captive_portal'
            $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
            if (-not $svc) {
              Write-Log "ISE redirect detected, but no posture service available within ${PostureWaitSeconds}s; skipping rescan."
              Write-RunEnd "ise_redirect_no_posture"
              exit 0
            }
            Write-Log ("ISE employee redirect detected -> forcing ISE rescan (service: {0}, status: {1})" -f $svc.Name, $svc.Status)
            Invoke-PostureRescan
            Write-RunEnd "ise_employee_rescan"
            exit 0
          }
          "ISE_GUEST" {
            Write-Log "ISE Guest Network detected -> browser remediation (no rescan)"
            Invoke-CaptivePortalRemediation -PortalType "ISE_GUEST"
            Write-RunEnd "ise_guest_browser_remediated"
            exit 0
          }
          "NON_ISE" {
            Write-Log "Non-ISE captive portal detected -> browser remediation"
            Invoke-CaptivePortalRemediation -PortalType "NON_ISE"
            Write-RunEnd "non_ise_browser_remediated"
            exit 0
          }
          "UNKNOWN" {
            Write-Log "Unknown redirect type - defaulting to ISE rescan for safety"
            Send-SignalFlare 'unknown_captive_portal'
            $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
            if (-not $svc) {
              Write-Log "Unknown redirect detected, but no posture service available within ${PostureWaitSeconds}s; skipping rescan."
              Write-RunEnd "unknown_redirect_no_posture"
              exit 0
            }
            Write-Log ("Unknown redirect detected -> defaulting to ISE rescan (service: {0}, status: {1})" -f $svc.Name, $svc.Status)
            Invoke-PostureRescan
            Write-RunEnd "unknown_redirect_rescan"
            exit 0
          }
        }
      } else {
        Write-Log "No redirect detected"
        
        # No redirect -> classify connectivity and exit
        $dcOK = Test-DC -hostname $DC_FQDN
        $gwOK = Test-DefaultGateway
        Write-Log ("Connectivity: Gateway={0}  DC={1}  Redirect=False" -f $gwOK, $dcOK)

        if ($dcOK) {
          Send-SignalFlare 'on_prem'
          Write-RunEnd "on_prem"
        }
        elseif ($gwOK) {
          Send-SignalFlare 'off_prem_no_vpn'
          Write-RunEnd "off_prem_no_vpn"
        }
        else {
          Write-RunEnd "no_net_transient"
        }
        exit 0
      }
    } catch {
      Write-Log "Error in main execution: $_" "ERROR"
      Write-RunEnd "error_exception"
      exit 1
    }
}
