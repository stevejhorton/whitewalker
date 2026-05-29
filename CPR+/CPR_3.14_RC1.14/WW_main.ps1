#Requires -RunAsAdministrator
param(
  [switch]$WWDebug,        # Light debug: decision breadcrumbs only
  [switch]$WWTrace,        # Heavy debug: raw vpncli stats/status dumps
  [switch]$WhatIf          # Show what would be done without executing
)

<#
  White Walker (ISE Auto Rescan Tool)
  Version: 3.14.0_RC1.17
  Author: steve.horton@optum.com (with AI assist)
  Date: 22-May-2026

  Major changes in 3.14.0_RC1.17:
    - ARCH: Walled-garden remediation moved fully into WW_cap_portal_runner (correct owner)
    - WW_main now writes portal_type + gateway_ip into cap_portal_remediation_active.flag
    - Removed inline browser launch from WW_main walled-garden path (was duplicating runner)
    - captive_walled_garden flare now registered in WW_flaregun_config.json (SYSTEM context)
    - no_net_transient flare now registered in WW_flaregun_config.json (SYSTEM context)
    - WW_main walled-garden path: write state → fire captive_walled_garden → fire captive_portal_browser → exit
    - All browser/toast/VPN-wait logic lives exclusively in cap_portal_runner

  Major changes in 3.14.0_RC1.16:
    - NEW: Get-MacRandomizationState function - reads Windows 11 MAC randomization registry setting
    - Reports randomization mode (disabled/per_network/daily/per_connection) on every WiFi run
    - Modes 2 (daily) and 3 (per_connection) logged as WARN - these break captive portal re-auth
    - Mode 1 (per_network) logged as INFO - same MAC per SSID, generally portal-safe
    - Mode 0 (disabled) logged as DEBUG - permanent MAC, fully portal-safe
    - Called from Write-NetworkInfoToLog on WiFi connections - zero overhead on Ethernet/VPN runs
    - Complements RC1.15 Test-MacRandomization (reactive) with proactive registry-based detection

  Major changes in 3.14.0_RC1.15:
    - NEW: Walled-garden captive portal detection (Test-WalledGarden function)
    - Detects DNS-blocking portals (Wyndham, Marriott, etc.) that don't redirect
    - Signature: gateway reachable via ping + DNS fails on enroll.cisco.com (instant NXDOMAIN)
    - These portals kill HTTPS with SSL MITM or timeout instead of redirecting
    - New exit reason: captive_walled_garden (distinct from no_net_transient)
    - New flare: captive_walled_garden -> triggers browser to gateway IP for user auth
    - MAC randomization warning: logs alert when MAC differs from last seen on same SSID
    - Prevents false no_net_transient exits at hotel/venue walled-garden WiFi

  Major changes in 3.14.0_RC1.14:
    - NEW: HayStack event monitor subsystem integration
    - HayStack runs as a fully standalone script (haystack.ps1)
    - WW_main calls haystack.ps1 -reroll via Start-Process (same pattern as Set-VpnHostsEntry.ps1)
    - $HaystackEnabled toggle (default $false) - zero impact when disabled
    - $HaystackScriptPath points to deployed haystack.ps1
    - Run header now logs haystack_enabled state

  Major changes in 3.14.0_RC1.11-13:
    - BUGFIX: SSID cache was never written - $script:currentSsid was never set
    - Invoke-SsidChangeCheck always hit "first run" path and returned silently
    - Fix: $script:currentSsid set from $networkInfo.SSID after Get-NetworkInfo
    - Fix: $script:currentSsid initialized to $null at top of main block
    - Write-RunEnd now correctly persists SSID cache on every run exit
    - Updated Test-DC function to be more strict and flipped the logic to use cmdlts rather than regex

  Major changes in 3.14.0_RC1.10:
    - NEW: SSID change detection - Invoke-SsidChangeCheck fires after Get-NetworkInfo
    - If SSID changes and VPN active, grace window (VpnSsidChangeGraceSec=15s) lets VPN progress
    - VPN still stuck after grace window -> force vpncli disconnect
    - CRITICAL FIX: SSID cache written at END of every run (any exit reason)
    - Previously only written after nwcheck 200 - VPN-connected runs never wrote cache
    - First run at new location now correctly detects SSID and writes cache
    - New config vars: SsidCacheFile, SsidChangedFlag, VpnSsidChangeGraceSec, VpnSsidChangePollSec
    - NEW: Send-WwNotification helper - any script can trigger toast via Event ID 800

  Major changes in 3.14.0_RC1.9:
    - SAFETY: Blackhole -rm now fires unconditionally on all non-on-prem states
    - Removed flag file gate on -rm path - flag can be lost during install/upgrade
    - Orphaned hosts entries (flag deleted but entries still present) now always cleaned
    - Flag file is now informational only - not a safety gate for -rm
    - Set-VpnHostsEntry.ps1 -rm was already unconditional - no change needed there

  Major changes in 3.14.0_RC1.8:
    - PERF: $initial_sleep reduced from 5s to 3s
    - SAFETY: Blackhole -rm fires at every startup before anything else (clears any stale state)
    - WLANi03 awareness: if on WLANi03 with no valid IP, wait up to 18s for ISE to finish initial scan
    - WLANi03 does NOT bypass preflight - gateway.optum.com redirect is still the signal
    - Prevents no_net_transient misfire when ISE is mid-posture and hasn't assigned IP yet

  Major changes in 3.14.0_RC1.7:
    - NEW: Size-based log rotation (Invoke-LogRotation) - 1MB threshold, keeps last 5 logs as .1-.5
    - NEW: VPN Blackhole integration (Invoke-BlackholeAction) - prevents on-prem hairpinning
    - Blackhole fires blackhole.ps1 -add on on_prem flare (creates vpn_blocked.flag)
    - Blackhole fires blackhole.ps1 -rm on any other flare if flag present (removes flag)
    - Blackhole is independent - all AD group logic lives inside blackhole.ps1
    - $BlackholeEnabled toggle (default false) - zero impact when disabled
    - Run header now logs blackhole_enabled state and flag presence

  Major changes in 3.14.0_RC1.6 (Release Candidate 1.6):
    - Preflight URL changed from nwcheck.optum.com to gateway.optum.com
    - gateway.optum.com returns HTTP 404 (not 200) on clean reachable connection
    - Get-NwCheckResult now treats both 200 and 404 as "online" signal
    - 404 = "no route matched" from gateway API = proof of internet life

  Major changes in 3.14.0_RC1.5 (Release Candidate 1.5):
    - NEW: Post-compliance nwcheck verification - confirms ACL lifted after ISE reports compliant
    - Polls nwcheck.optum.com for up to 30s after posture compliance to verify network access
    - Prevents false success when ISE agent reports compliant but WLC hasn't propagated ACL change
    - Logs warning if nwcheck still blocked but exits success (trusts ISE compliance report)

  Major changes in 3.14.0_RC1.3 (Release Candidate 1.3):
    - CRITICAL FIX: Detect redirects on ANY 2xx/3xx with Location header (not just 3xx)
    - ISE returning non-standard 200+Location instead of proper 302/307 redirects
    - Makes redirect detection resilient to ISE config variations across PSNs
    - Handles both standard redirects (3xx) and ISE quirks (200+Location)

  Major changes in 3.14.0_RC1.2 (Release Candidate 1.2):
    - CRITICAL FIX: Race condition fix - test enroll.cisco.com IMMEDIATELY when nwcheck fails
    - Prevents DHCP lease expiration before enroll test completes
    - Resolves ISE rescan failure loop when on-prem unpostured
    - Removed duplicate enroll test (now happens upfront before any VPN logic)

  Major changes in 3.14.0_RC1.1 (Release Candidate 1.1):
    - CRITICAL FIX: Test-Redirect catch block now properly detects HTTP redirects
    - AllowAutoRedirect=false throws exceptions on redirect - must inspect exception response
    - Fixes enroll.cisco.com redirect detection (was being caught and discarded)
    - Resolves ISE rescan loop when on-prem unpostured

  Major changes in 3.14.0_RC1 (Release Candidate 1):
    - RC1: $UseNewPreflight set to $true - nwcheck.optum.com is live and in posture redirect ACL
    - RC1: $NewPreflightURL updated to https://nwcheck.optum.com (was http)
    - RC1: Test-InternetAccess-New now checks for HTTP 200 (nwcheck returns 200, not 204)
    - Network preflight is now the primary gate: 200=G2G/exit, redirect=route to correct workflow
    - nwcheck.optum.com is blocked in ISE/WLC posture redirect ACL until device is postured or captive portal accepted

  Major changes in 3.13.1_ER6 (Engineering Release 6):
    - CRITICAL FIX: user_prompted.flag now included in stale flag cleanup (was blocking execution)
    - CRITICAL FIX: DC=True on captive portals no longer misclassifies as on_prem
    - Enhanced DC test with SSID awareness (detects stale VPN routes on public WiFi)
    - DC reachability now checks for non-corporate SSIDs (Starbucks, xfinitywifi, etc.)
    - Prevents false positive "on_prem" classification when DC ping succeeds via stale routes
    - user_prompted.flag added to 15-minute staleness cleanup (prevents lock-out scenarios)

  Major changes in 3.13.1_ER5 (Engineering Release 5):
    - CRITICAL FIX: Captive portal browser event now bypasses cooldown (was getting suppressed)
    - ENHANCED: Added detailed logging around captive portal browser trigger
    - ENHANCED: Event log creation now verified with error checking
    - DEBUG: Added flare history dump when captive portal triggers
    - Ensures captive_portal_browser flare ALWAYS fires when needed (no cooldown suppression)

  Major changes in 3.13.1_ER4 (Engineering Release 4):
    - NEW: Proactive Cisco browser killer runs on EVERY WhiteWalker execution
    - Kills interfering Cisco browsers (acwebhelper, CiscoCollabHost, etc.) in background for 10 seconds
    - Fixes issue where valid guest network sessions leave orphaned Cisco browsers
    - Scenario: User reconnects to guest network with valid session -> no redirect detected -> 
      Cisco browser opened but never cleaned up -> user must manually kill browser
    - Now runs after post-DHCP sleep, before any connectivity checks
    - Also updated WW_cap_portal_runner.ps1 to v1.7.0_ER3 with timeout fixes and RETRY/EXIT notification

  Major changes in 3.13.1_ER3 (Engineering Release 3):
    - CRITICAL FIX: Captive portal was triggering on the string "login" being in the HTML response, which was giving false positives on almost any home router. Removed that string from the array of checks.
    - Knocked all cooldowns to 1 min. 
    - Made all task schdlr jobs run in background via 'conhost.exe --headless powershell.exe' so they no longer flash.
  Major changes in 3.13.1_ER2 (Engineering Release 2):
    - CRITICAL FIX: Captive portal Event 777 now routed through FlareGun (was broken)
    - FIXED: Event 777 source changed from "WhiteWalkerTrigger" to FlareGun framework
    - NEW: Remediation state file created when captive portal detected
    - NEW: Cap portal runner checks state file, waits for VPN stable if needed
    - VPN stabilization (60s max, 5s polls) and validation browser handled by cap_portal_runner in USER context
    - Captive portal workflow: detect ?+' Event 777 ?+' cap_portal_runner handles everything
    - Captive portal remediation fully functional (was completely broken in ER1)

  Major changes in 3.13.1_ER1 (Engineering Release 1):
    - FIXED: Wake from sleep detection now uses Event ID 566 + 507 (correct events for corporate GPO)
    - FIXED: Network connection polling - waits for active connection before proceeding
    - NEW: $NetworkConnectionRetries config var (default: 2 retries x 5 seconds = 10s total)
    - Handles "Connect Automatically" unchecked scenario gracefully

  Major changes in 3.13.1:
    - FIXED: PowerShell window flashing during flare events (all eventcreate calls now hidden)
    - Changed all cmd.exe /c eventcreate to Start-Process -WindowStyle Hidden
    - Smooth, silent operation - no more clunky window flashes!

  Major changes in 3.13.0:
    - NEW: FlareGun framework integration for context-aware Ivanti signaling
    - SYSTEM flares fire directly (immediate response for monitoring/logging)
    - USER flares route through event log ???EUR ?EUR(TM) Task Scheduler ???EUR ?EUR(TM) USER context
    - Config-driven flare routing (WW_flaregun_config.json)
    - Detailed comments at every flare call site for debugging
    - All existing functionality preserved (surgical integration)

  Major changes in 3.12.0_ER8.1:
    - NEW: Wake-from-sleep detection for smart VPN disconnect
    - FIXED: Posture service detection (now finds csc_iseagent, ciscod.exe, etc.)
    - EDGE CASE FIX: Laptop wake with VPN in intermediate state
       ->  Uses Windows Event Log (Kernel-Power ID 1/107) to detect recent wake
       ->  IF wake within 2 minutes + VPN intermediate: Force disconnect (blocking scenario)
       ->  IF no recent wake + VPN intermediate: Allow connection (legitimate AlwaysOn)
    - Config: $VpnWakeDetection = $true, $VpnWakeTimeWindow = 120 seconds
    - WHY NOT REDIRECT CHECK: ALL traffic blocked during VPN intermediate states
    - PREVENTS: Accidentally killing legitimate AlwaysOn VPN connections at home
    - FIXES: VPN blocking 802.1x/captive portal authentication after laptop wake
    - VERIFIED: ISE rescan implementation uses battle-tested approach (no brittleness)
    - Service status check before CLI operations prevents IPC errors
    - 30-second post-rescan recovery period ensures ISE stability

  Previous changes in 3.12.0_ER7:
    - NEW: ISE enroll.cisco.com redirect test (runs FIRST before captive portal)
    - NEW: Posture compliance monitoring after rescan (polls up to 30s)
    - NEW: Test-ISEPostureCompliance function for automated compliance verification
    - IMPROVED: Workflow now detects on-prem ISE redirect and auto-remediates
    - Exit reasons: ise_employee_compliant, ise_employee_failed_*, ise_redirect_no_posture_service

  Hotfix changes in 3.12.0_ER6.1:
    - FIXED: Gateway HTTP -> HTTPS redirect false positive (home routers)
    - FIXED: SSID detection using netsh wlan instead of Get-NetConnectionProfile
    - Now validates redirect is to DIFFERENT host before flagging as captive portal

  Behavior changes in 3.12.0_ER6:
    - DUAL PREFLIGHT: Added new nwcheck.optum.com check with $UseNewPreflight toggle
    - WORKFLOW REORDER: Legacy preflight now checks VPN  ->  Redirect  ->  Internet (moved later)
    - SMART VPN DISCONNECT: Force disconnect VPN when it blocks 802.1x or captive portal
    - FIXED SSID BUG: Exclude VPN interface IP addresses from SSID detection
    - ENHANCED LOGGING: More device/user context without performance impact
    - New Test-VPNBlockingNetwork function for intelligent VPN management

  Previous changes in 3.11.1:
    - Internet connectivity check ran BEFORE captive portal detection
    - Prevented false positives from HTTP -> HTTPS router redirects
    - Fixed duplicate Write-RunEnd calls

  Usage Examples:
    WhiteWalker.ps1                          # Normal DHCP-triggered operation
    WhiteWalker.ps1 -WWDebug                 # Normal run with debug logging
    WhiteWalker.ps1 -WWTrace                 # Full debug with CLI output dumps
    
  Task Scheduler Configuration:
    Program: powershell.exe
    Arguments: -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_main.ps1"
#>

# ------------------------------- Config ---------------------------------------
$ver                    = "3.14.0_RC1.17"
$initial_sleep          = 3     # seconds after DHCP before checks
$LogPath                = "C:\ProgramData\WhiteWalker\white_walker.main.log"

# Network connection polling (for "Connect Automatically" unchecked scenarios)
$NetworkConnectionRetries = 2   # number of retries to wait for active connection
$NetworkConnectionWait    = 3   # seconds between retries

# NEW: Preflight check toggle
$UseNewPreflight        = $true   # RC1: nwcheck.optum.com is live and in posture redirect ACL
$NewPreflightURL        = "https://gateway.optum.com"
$LegacyPreflightURL     = "http://clients3.google.com/generate_204"

# ISE-specific redirect test
$ISERedirectTestURL     = "http://enroll.cisco.com"  # On-prem ISE posture redirect detection
$PostureComplianceTimeout = 20   # seconds to wait for posture compliance after rescan

# VPN stabilization
$VpnStateMaxWaitSeconds = 12     # how long to wait for vpncli to settle to Connected/Disconnected
$VpnIntermediateMaxWait = 30     # force disconnect if stuck in Reconnecting/Connecting/Unknown >30s
$VpnWakeDetection = $true        # detect wake from sleep and disconnect blocking VPN (smart disconnect)
$VpnWakeTimeWindow = 120         # seconds - if wake event within this window, consider it a wake scenario

# Rescan & flare behavior
$RescanOnlyOnRedirect   = $true
$FlareCooldownMinutes   = 1      # per-flare tag cooldown
$RescanCooldownMinutes  = 1      # rescan cooldown
$PostureWaitSeconds     = 12     # wait for posture service to appear on redirect
$StateRoot              = 'C:\Windows\UHGLogs'
$StateFile              = Join-Path $StateRoot 'state.json'

# Captive Portal Integration
$FlagFile               = "C:\ProgramData\WhiteWalker\portal_complete.flag"
$InterruptFile          = "C:\ProgramData\WhiteWalker\network_interrupt.flag"
$RemediationStateFile   = "C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag"  # NEW ER2: Track VPN stabilization need
$CaptivePortalTimeout   = 120    # seconds to wait for user to complete auth (3 minutes + 15s buffer)
$FlagPollInterval       = 3      # seconds between flag file checks
$CaptiveEventCooldown   = 1      # minutes between captive portal event triggers
$CaptiveEventLimit      = 3      # max events before showing user alert
$CaptiveFailureFlag     = "C:\ProgramData\WhiteWalker\captive_failure.flag"
$UserPromptedFlag       = "C:\ProgramData\WhiteWalker\user_prompted.flag"

# Ivanti flare exe (receives "/<tag>")
$flareExe               = "$env:SystemRoot\System32\rundll32.exe"

# FlareGun configuration (context-aware flare routing)
$FlareGunConfigPath     = "C:\ProgramData\WhiteWalker\WW_flaregun_config.json"

# Log rotation
$LogRotationMaxBytes    = 1MB     # rotate when log exceeds this size
$LogRotationKeep        = 5       # number of rotated logs to keep

# VPN Blackhole (on_prem hairpin prevention)
$BlackholeEnabled       = $false  # set to $true to enable VPN blackhole on on_prem flare
$BlackholeScriptPath    = "C:\ProgramData\WhiteWalker\Set-VpnHostsEntry.ps1"
$BlackholeFlagFile      = "C:\ProgramData\WhiteWalker\vpn_blocked.flag"

# HayStack Event Monitor (event log needle watcher)
$HaystackEnabled            = $false  # set to $true to enable HayStack event monitoring
$HaystackScriptPath         = "C:\ProgramData\WhiteWalker\haystack.ps1"
$HaystackRerollCooldownMinutes = 60   # passed to haystack.ps1 -reroll as override if needed

# SSID change detection - disconnects VPN when network changes to prevent captive portal blocking
$SsidCacheFile          = "C:\ProgramData\WhiteWalker\ssid_last_known.flag"
$SsidChangedFlag        = "C:\ProgramData\WhiteWalker\ssid_changed.flag"
$VpnSsidChangeGraceSec  = 15    # seconds to wait for VPN to progress before force disconnect
$VpnSsidChangePollSec   = 3     # poll interval during grace window

# Walled-garden captive portal detection
$WalledGardenFlare      = "captive_walled_garden"  # flare tag for DNS-blocking portals
$MacCacheFile           = "C:\ProgramData\WhiteWalker\mac_last_known.flag"  # per-SSID MAC cache for randomization detection

# Optional adapter fallback: if vpncli is ambiguous, treat an "Up" Cisco virtual adapter as connected
$UseAdapterFallback     = $false

# Target domain/DC name for on-prem check
$DC_FQDN = "ms.ds.uhc.com"

# --------------------- Utility: Reliable Append Logging -----------------------
function Invoke-LogRotation {
    # Size-based rotation. Runs before logger opens the file.
    # Keeps last $LogRotationKeep files as .1 .2 ... .5
    if (-not (Test-Path $LogPath)) { return }
    
    $size = (Get-Item $LogPath -ErrorAction SilentlyContinue).Length
    if ($size -lt $LogRotationMaxBytes) { return }
    
    Write-Host "Log rotation triggered: $LogPath ($([math]::Round($size/1KB))KB)"
    
    # Drop oldest if already at limit
    $oldest = "$LogPath.$LogRotationKeep"
    if (Test-Path $oldest) { Remove-Item $oldest -Force -ErrorAction SilentlyContinue }
    
    # Shift .1-.4 down to .2-.5
    for ($i = ($LogRotationKeep - 1); $i -ge 1; $i--) {
        $src = "$LogPath.$i"
        $dst = "$LogPath.$($i + 1)"
        if (Test-Path $src) { Rename-Item $src $dst -Force -ErrorAction SilentlyContinue }
    }
    
    # Rotate current log to .1
    Rename-Item $LogPath "$LogPath.1" -Force -ErrorAction SilentlyContinue
}

function Initialize-Logger {
  Invoke-LogRotation
  $dir = Split-Path -Parent $LogPath
  if (-not (Test-Path $dir)) { 
    try {
      New-Item -Path $dir -ItemType Directory -Force | Out-Null 
    } catch {
      Write-Host "WARNING: Cannot create log directory $dir - $_"
    }
  }
  if (-not (Test-Path $LogPath)) { 
    try {
      New-Item -Path $LogPath -ItemType File -Force | Out-Null 
    } catch {
      Write-Host "WARNING: Cannot create log file $LogPath - $_"
    }
  }
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
  $flat = $Text.Replace("`r","").Replace("`n","[NL]")
  Write-Log ("DEBUG {0}:`n{1}" -f $Label, $flat)
}

# Run header/trailer with enhanced context
$RunId  = "{0}-{1}" -f (Get-Date -Format "yyyyMMddHHmmssfff"), $PID
$HostNm = $env:COMPUTERNAME
$UserNm = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

function Get-SystemContext {
    # Gather system info without slowing down execution
    $ctx = @{
        OS = "Unknown"
        Model = "Unknown"
        SerialNumber = "Unknown"
        LastBootTime = "Unknown"
    }
    
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) {
            $ctx.Model = "$($cs.Manufacturer) $($cs.Model)"
        }
        
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $ctx.OS = "$($os.Caption) $($os.Version)"
            $ctx.LastBootTime = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        if ($bios) {
            $ctx.SerialNumber = $bios.SerialNumber
        }
    } catch {
        Write-Log "Could not gather full system context: $_" "DEBUG"
    }
    
    return $ctx
}

function Write-RunHeader {
  $utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'")
  $loc = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
  $bar = ('=' * 80)
  Add-LogLine $bar
  Add-LogLine ("RUN START  White Walker v{0}" -f $ver)
  Add-LogLine ("run_id={0} host={1} user={2}" -f $RunId, $HostNm, $UserNm)
  Add-LogLine ("ts_local={0}  ts_utc={1}" -f $loc, $utc)
  Add-LogLine ("log_path={0}" -f $LogPath)
  
  # Add system context
  $sysCtx = Get-SystemContext
  Add-LogLine ("system={0}" -f $sysCtx.OS)
  Add-LogLine ("model={0}" -f $sysCtx.Model)
  Add-LogLine ("serial={0}" -f $sysCtx.SerialNumber)
  Add-LogLine ("last_boot={0}" -f $sysCtx.LastBootTime)
  Add-LogLine ("preflight_mode=RC1.6 gateway.optum.com (https, 200/404=online, 3xx=route-to-workflow)")
  Add-LogLine ("blackhole_enabled={0}  script={1}" -f $BlackholeEnabled, $BlackholeScriptPath)
  Add-LogLine ("blackhole_flag_present={0}" -f (Test-Path $BlackholeFlagFile))
  Add-LogLine ("haystack_enabled={0}  script={1}" -f $HaystackEnabled, $HaystackScriptPath)
  $vpnProfile = (Get-ItemProperty -Path "HKLM:\SYSTEM\UHG\DSM" -ErrorAction SilentlyContinue).VPN
  if ($vpnProfile) { Add-LogLine ("vpn_profile={0}" -f $vpnProfile) } else { Add-LogLine "vpn_profile=NOT_SET ***ALERT***" }

  Add-LogLine $bar
}

function Write-RunEnd([string]$Reason='') {
  # Update SSID cache on every run regardless of exit reason.
  # CRITICAL: must happen here not just on nwcheck 200 - VPN-connected runs
  # would never write the cache otherwise, breaking SSID change detection.
  if ($script:currentSsid) {
      Update-SsidCache -Ssid $script:currentSsid
  }
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
            
            $endTime = (Get-Date).AddSeconds(10)  # Run for 10 seconds
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
        
        Write-Log "Cisco browser killer job started (JobId: $($killerJob.Id)) - will run for 10 seconds" "DEBUG"
        return $killerJob
        
    } catch {
        Write-Log "Failed to start Cisco browser killer: $_" "WARN"
        return $null
    }
}

function Stop-CiscoBrowserKiller {
    <#
    .SYNOPSIS
    Stop Cisco browser killer background job and report results
    #>
    param($Job)
    
    if ($Job) {
        try {
            $result = Receive-Job -Job $Job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue
            if ($result -and $result -gt 0) {
                Write-Log "Cisco browser killer terminated $result process(es)" "INFO"
            } else {
                Write-Log "Cisco browser killer found no processes to terminate" "DEBUG"
            }
        } catch {
            Write-Log "Error stopping Cisco browser killer job: $_" "DEBUG"
        }
    }
}

function Invoke-BlackholeAction {
    param([string]$Tag)

    # SAFETY: If blackhole is disabled, always fire -rm to clear any stale entries
    # left from a prior enabled session. Never leave hosts file poisoned.
    if (-not $BlackholeEnabled) {
        if (Test-Path $BlackholeScriptPath) {
            Write-Log "Blackhole: disabled - firing -rm to clear any stale sinkhole entries" "INFO"
            if (-not $WhatIf) {
                Start-Process "powershell.exe" `
                    -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BlackholeScriptPath`" -rm" `
                    -WindowStyle Hidden
                Remove-Item $BlackholeFlagFile -Force -ErrorAction SilentlyContinue
                Write-Log "Blackhole: -rm fired (disabled mode), flag cleared" "INFO"
            } else {
                Write-Log "Blackhole: [WhatIf] would fire -rm (disabled mode)" "INFO"
            }
        }
        return
    }

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
        Write-Log "Blackhole: on-prem state ($Tag) - firing -add in background" "INFO"
        if (-not $WhatIf) {
            Start-Process "powershell.exe" `
                -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BlackholeScriptPath`" -add" `
                -WindowStyle Hidden
            Set-Content -Path $BlackholeFlagFile -Value (Get-Date).ToString('o') -Encoding UTF8 -Force
            Write-Log "Blackhole: -add fired, flag created" "INFO"
        } else {
            Write-Log "WHATIF: Would run blackhole.ps1 -add and create $BlackholeFlagFile" "INFO"
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
        } else {
            Write-Log "WHATIF: Would run Set-VpnHostsEntry.ps1 -rm and remove flag if present" "INFO"
        }
    }
}

function Send-FlareEvent {
  param([Parameter(Mandatory=$true)][string]$Tag)
  
  # Per-run de-dupe
  if (-not ($global:flareHistory -is [hashtable])) { $global:flareHistory = @{} }
  if ($global:flareHistory.ContainsKey($Tag)) { 
    Write-Log "FlareEvent de-duped (already sent this run): $Tag" "DEBUG"
    return 
  }
  
  # Cooldown check - BUT BYPASS for critical captive_portal_browser event
  # This ensures the browser ALWAYS launches when captive portal is detected
  $bypassCooldown = ($Tag -eq "captive_portal_browser")
  
  if (-not $bypassCooldown -and (In-Cooldown $Tag $FlareCooldownMinutes)) {
    Write-Log "FlareEvent suppressed (cooldown ${FlareCooldownMinutes}m): $Tag" "WARN"
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
            } else {
              Write-Log "Event log message MAY have failed (ExitCode: $($proc.ExitCode)) for FLARE:$Tag" "WARN"
            }
          } catch {
            Write-Log "ERROR writing event log for FLARE:$Tag : $_" "ERROR"
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

# ---------------------- Connectivity & Redirect Checks -----------------------
function Get-NetworkInfo {
    # FIXED: Exclude VPN interface IPs from SSID detection
    $netInfo = @{
        SSID = "N/A"
        InterfaceName = "N/A"
        IPAddress = "N/A"
        SubnetMask = "N/A"
        DefaultGateway = "N/A"
        DNSServers = @()
        MACAddress = "N/A"
        ConnectionType = "Unknown"
    }
    
    try {
        # Get active PHYSICAL network adapter only (exclude VPN virtual adapters)
        $activeAdapter = Get-NetAdapter | Where-Object { 
            $_.Status -eq 'Up' -and 
            $_.Virtual -eq $false -and
            $_.InterfaceDescription -notmatch 'Cisco|VPN|TAP|Virtual|Tunnel|WAN Miniport|AnyConnect'
        } | Select-Object -First 1
        
        if ($activeAdapter) {
            $netInfo.InterfaceName = $activeAdapter.Name
            $netInfo.MACAddress = $activeAdapter.MacAddress
            
            # Determine connection type
            if ($activeAdapter.Name -match "Wi-Fi|Wireless|802\.11") {
                $netInfo.ConnectionType = "WiFi"
                
                # Get SSID for WiFi connections using netsh (more reliable than Get-NetConnectionProfile)
                try {
                    $netshOutput = netsh wlan show interfaces 2>$null | Out-String
                    
                    if ($netshOutput -and ($netshOutput -match '(?m)^\s*State\s*:\s*connected')) {
                        # Extract SSID from netsh output - match entire line to get SSID value
                        if ($netshOutput -match '(?m)^\s*SSID\s*:\s*(.+)$') {
                            $ssidCandidate = $matches[1].Trim()
                            
                            # Validate SSID is not an IP address (VPN interface bug)
                            if ($ssidCandidate -and 
                                $ssidCandidate -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and 
                                $ssidCandidate -ne "Identifying..." -and
                                $ssidCandidate.Length -gt 0) {
                                $netInfo.SSID = $ssidCandidate
                                Write-Log "WiFi SSID detected: $ssidCandidate" "DEBUG"
                            } else {
                                Write-Log "SSID validation failed: '$ssidCandidate' - may be transient state or VPN interface" "DEBUG"
                            }
                        } else {
                            Write-Log "WiFi connected but could not extract SSID from netsh output" "DEBUG"
                        }
                    } else {
                        Write-Log "WiFi adapter present but not connected (State != connected)" "DEBUG"
                    }
                } catch {
                    Write-Log "Could not retrieve SSID via netsh wlan: $_" "DEBUG"
                }
            } elseif ($activeAdapter.Name -match "Ethernet|LAN") {
                $netInfo.ConnectionType = "Ethernet"
            }
            
            # Get IP configuration
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $activeAdapter.InterfaceIndex -ErrorAction SilentlyContinue
            
            if ($ipConfig) {
                # IP Address
                $ipv4 = $ipConfig.IPv4Address | Select-Object -First 1
                if ($ipv4) {
                    $netInfo.IPAddress = $ipv4.IPAddress
                    $netInfo.SubnetMask = $ipv4.PrefixLength
                }
                
                # Default Gateway
                $gw = $ipConfig.IPv4DefaultGateway | Select-Object -First 1
                if ($gw) {
                    $netInfo.DefaultGateway = $gw.NextHop
                }
                
                # DNS Servers
                $dns = Get-DnsClientServerAddress -InterfaceIndex $activeAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                if ($dns -and $dns.ServerAddresses) {
                    $netInfo.DNSServers = $dns.ServerAddresses
                }
            }
        }
    } catch {
        Write-Log "Error gathering network info: $_" "WARN"
    }
    
    return $netInfo
}

function Write-NetworkInfoToLog {
    param($NetworkInfo)
    
    Write-Log "=== Network Information ===" "INFO"
    Write-Log "  Connection Type: $($NetworkInfo.ConnectionType)" "INFO"
    Write-Log "  Interface: $($NetworkInfo.InterfaceName)" "INFO"
    if ($NetworkInfo.SSID -ne "N/A") {
        Write-Log "  SSID: $($NetworkInfo.SSID)" "INFO"
    }
    Write-Log "  IP Address: $($NetworkInfo.IPAddress)/$($NetworkInfo.SubnetMask)" "INFO"
    Write-Log "  Default Gateway: $($NetworkInfo.DefaultGateway)" "INFO"
    Write-Log "  MAC Address: $($NetworkInfo.MACAddress)" "INFO"
    if ($NetworkInfo.DNSServers.Count -gt 0) {
        Write-Log "  DNS Servers: $($NetworkInfo.DNSServers -join ', ')" "INFO"
    }
    Write-Log "===========================" "INFO"

    # RC1.16: Report MAC randomization mode for WiFi adapters
    # Modes 2 (daily) and 3 (per_connection) break captive portal re-auth - log as WARN
    if ($NetworkInfo.ConnectionType -eq "WiFi") {
        $macRand = Get-MacRandomizationState -InterfaceName $NetworkInfo.InterfaceName
        if ($macRand.ModeValue -ge 0) {
            $randMsg = "  MAC randomization: mode=$($macRand.RandomizationMode) (value=$($macRand.ModeValue))"
            if ($macRand.IsRisky) {
                Write-Log "$randMsg - RISKY: MAC changes between connections, captive portal re-auth will fail" "WARN"
            } elseif ($macRand.IsRandomized) {
                Write-Log "$randMsg - same MAC per SSID, portal-safe" "INFO"
            } else {
                Write-Log "$randMsg - permanent MAC, portal-safe" "DEBUG"
            }
        }
    }
}

function Get-MacRandomizationState {
    <#
    .SYNOPSIS
    Read Windows 11 MAC randomization setting for the active WiFi adapter from registry.

    .DESCRIPTION
    Windows 11 stores per-adapter MAC randomization state in:
      HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces\{AdapterGUID}\RandomizationEnabled

    Values:
      0 = Disabled (permanent MAC)           - portal-safe
      1 = Random per network (same per SSID) - generally portal-safe
      2 = Random daily (changes every 24h)   - RISKY: breaks portal sessions after midnight
      3 = Random per connection              - CRITICAL: breaks portal re-auth on every reconnect

    This function is called proactively on every WiFi run to surface the risk level
    BEFORE a failure occurs, rather than detecting MAC changes reactively after the fact.

    Returns a hashtable with:
      ModeValue        - raw registry integer (-1 if not found)
      RandomizationMode - human-readable string
      IsRandomized     - $true if any randomization is active (value > 0)
      IsRisky          - $true if mode is daily or per-connection (value >= 2)
    #>
    param(
        [string]$InterfaceName = "Wi-Fi"
    )

    $result = @{
        ModeValue         = -1
        RandomizationMode = "unknown"
        IsRandomized      = $false
        IsRisky           = $false
    }

    try {
        # Resolve the active WiFi adapter
        $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
        if (-not $adapter) {
            $adapter = Get-NetAdapter | Where-Object {
                $_.Status -eq 'Up' -and
                $_.Virtual -eq $false -and
                $_.Name -match 'Wi-Fi|Wireless'
            } | Select-Object -First 1
        }
        if (-not $adapter) {
            Write-Log "MacRandState: no active WiFi adapter found" "DEBUG"
            return $result
        }

        # Build the expected registry key path using the adapter's InterfaceGuid
        $wlanKey = "HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces"
        if (-not (Test-Path $wlanKey)) {
            Write-Log "MacRandState: WlanSvc Interfaces key not present" "DEBUG"
            return $result
        }

        # Try direct GUID path first (most common)
        $guidStr      = $adapter.InterfaceGuid.ToString("B").ToUpper()   # {XXXXXXXX-...} format (with braces)
        $guidStrPlain = $adapter.InterfaceGuid.ToString().ToUpper()       # default format (no braces)
        $guidStrNoBraces = $guidStrPlain -replace '[{}]',''               # strip braces for fallback compare

        $ifaceKeyPath = $null
        foreach ($candidate in @($guidStr, $guidStrPlain)) {
            $tryPath = Join-Path $wlanKey $candidate
            if (Test-Path $tryPath) {
                $ifaceKeyPath = $tryPath
                break
            }
        }

        # Fallback: iterate all sub-keys and match case-insensitively
        if (-not $ifaceKeyPath) {
            foreach ($subKey in Get-ChildItem $wlanKey -ErrorAction SilentlyContinue) {
                if ($subKey.PSChildName -replace '[{}]','' -ieq $guidStrNoBraces) {
                    $ifaceKeyPath = $subKey.PSPath
                    break
                }
            }
        }

        if (-not $ifaceKeyPath) {
            Write-Log "MacRandState: no WlanSvc registry key found for adapter '$($adapter.Name)' ($guidStr)" "DEBUG"
            return $result
        }

        $randVal = (Get-ItemProperty -Path $ifaceKeyPath -Name "RandomizationEnabled" -ErrorAction SilentlyContinue).RandomizationEnabled

        if ($null -eq $randVal) {
            Write-Log "MacRandState: RandomizationEnabled value not present in registry key" "DEBUG"
            return $result
        }

        $result.ModeValue    = [int]$randVal
        $result.IsRandomized = ($randVal -gt 0)
        $result.IsRisky      = ($randVal -ge 2)
        $result.RandomizationMode = switch ([int]$randVal) {
            0       { "disabled" }
            1       { "random_per_network" }
            2       { "random_daily" }
            3       { "random_per_connection" }
            default { "unknown_$randVal" }
        }

    } catch {
        Write-Log "MacRandState: registry read error: $_" "DEBUG"
    }

    return $result
}

function Test-DefaultGateway {
    try {
        $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Select-Object -First 1).NextHop
        if ($gw -and (Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return $true
        }
    } catch { }
    return $false
}

function Clear-StaleFlagFiles {
    <#
    .SYNOPSIS
    Remove stale flag files that might block execution
    
    .DESCRIPTION
    ER6: Flag files can become stale if cap_portal_runner crashes or system reboots
    while remediation is in progress. This function checks file age and removes
    flags older than threshold (default 15 minutes).
    
    Prevents scenario where stale flags block WhiteWalker from running until manual cleanup.
    #>
    param([int]$StaleThresholdMinutes = 15)
    
    $flagFiles = @(
        $FlagFile,                # portal_complete.flag
        $InterruptFile,           # network_interrupt.flag
        $RemediationStateFile,    # cap_portal_remediation_active.flag
        $CaptiveFailureFlag,      # captive_failure.flag
        $UserPromptedFlag,        # user_prompted.flag (ER6: was blocking execution)
        "C:\ProgramData\WhiteWalker\dns_chicken_egg_issue.flag"
    )
    
    $now = Get-Date
    $removedCount = 0
    
    foreach ($flagPath in $flagFiles) {
        if (Test-Path $flagPath) {
            try {
                $fileInfo = Get-Item $flagPath -ErrorAction Stop
                $age = ($now - $fileInfo.LastWriteTime).TotalMinutes
                
                if ($age -gt $StaleThresholdMinutes) {
                    Remove-Item $flagPath -Force -ErrorAction Stop
                    Write-Log "Removed stale flag file (age: $([math]::Round($age))min): $(Split-Path $flagPath -Leaf)" "INFO"
                    $removedCount++
                } else {
                    Write-Log "Flag file present but fresh (age: $([math]::Round($age))min): $(Split-Path $flagPath -Leaf)" "DEBUG"
                }
            } catch {
                Write-Log "Error checking/removing flag file $flagPath : $_" "WARN"
            }
        }
    }
    
    if ($removedCount -gt 0) {
        Write-Log "Cleaned up $removedCount stale flag file(s)" "INFO"
    } else {
        Write-Log "No stale flag files found" "DEBUG"
    }
}

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

function Test-WalledGarden {
    <#
    .SYNOPSIS
    Detect DNS-blocking walled-garden captive portals.
    
    .DESCRIPTION
    Walled-garden portals (Wyndham, Marriott, etc.) block ALL DNS before user authenticates.
    Unlike redirect-based portals, they never return a Location header.
    
    Signature:
      1. Device has a valid IP and default gateway (not APIPA)
      2. Default gateway is reachable via ping (local L3 works)
      3. DNS resolution fails (not timeout - instant NXDOMAIN/unreachable)
    
    This is distinct from a genuinely broken network because the gateway IS pingable.
    A broken network has no gateway or an unreachable gateway.
    
    Called when: gateway.optum.com unreachable AND enroll.cisco.com DNS fails AND VPN disconnected.
    #>
    
    $result = @{
        IsWalledGarden = $false
        GatewayIP      = $null
        Reason         = "unknown"
    }
    
    try {
        # Step 1: Get default gateway
        $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | 
               Sort-Object RouteMetric | 
               Select-Object -First 1).NextHop
        
        if (-not $gw -or $gw -eq '0.0.0.0') {
            $result.Reason = "no_default_gateway"
            Write-Log "WalledGarden: no default gateway found - not a walled garden" "DEBUG"
            return $result
        }
        
        $result.GatewayIP = $gw
        Write-Log "WalledGarden: default gateway is $gw - testing reachability..." "DEBUG"
        
        # Step 2: Ping the gateway - if reachable, local L3 is working
        $gwPing = Test-Connection -ComputerName $gw -Count 2 -Quiet -ErrorAction SilentlyContinue
        if (-not $gwPing) {
            $result.Reason = "gateway_unreachable"
            Write-Log "WalledGarden: gateway $gw not pingable - genuine connectivity problem, not walled garden" "DEBUG"
            return $result
        }
        
        Write-Log "WalledGarden: gateway $gw IS reachable - local L3 works" "DEBUG"
        
        # Step 3: Test DNS resolution - walled gardens block DNS entirely
        # Use .NET directly for speed and to capture the specific failure mode
        $dnsBlocked = $false
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses("enroll.cisco.com")
            # DNS worked - not a walled garden (or portal is transparent to DNS)
            Write-Log "WalledGarden: DNS resolution succeeded for enroll.cisco.com - not a walled garden" "DEBUG"
            $result.Reason = "dns_works"
            return $result
        } catch {
            $dnsErr = $_.Exception.Message
            Write-Log "WalledGarden: DNS resolution failed for enroll.cisco.com: $dnsErr" "DEBUG"
            $dnsBlocked = $true
        }
        
        if ($dnsBlocked) {
            # Gateway reachable + DNS blocked = walled garden
            $result.IsWalledGarden = $true
            $result.Reason = "gateway_up_dns_blocked"
            Write-Log "WalledGarden: CONFIRMED - gateway $gw reachable but DNS blocked = walled-garden captive portal" "WARN"
        }
        
    } catch {
        Write-Log "WalledGarden: detection error: $_" "DEBUG"
        $result.Reason = "detection_error"
    }
    
    return $result
}

function Test-MacRandomization {
    <#
    .SYNOPSIS
    Detect Windows 11 MAC randomization on reconnect to same SSID.
    
    .DESCRIPTION
    Windows 11 uses random hardware addresses per-network by default.
    On reconnect, the MAC may change. Hotel portals authenticate by MAC,
    so a MAC change = portal treats device as new unauthenticated client.
    This is a silent failure mode - user thinks they authenticated but
    the portal doesn't recognize them on reconnect.
    
    Logs a WARNING when MAC differs from last seen on this SSID.
    Does not block execution - informational only.
    #>
    param(
        [string]$CurrentSsid,
        [string]$CurrentMac
    )
    
    if (-not $CurrentSsid -or $CurrentSsid -eq "N/A") { return }
    if (-not $CurrentMac -or $CurrentMac -eq "N/A") { return }
    
    try {
        # Cache file stores JSON: { "SSID": "MAC" }
        $macCache = @{}
        if (Test-Path $MacCacheFile) {
            try {
                $raw = Get-Content $MacCacheFile -Raw -ErrorAction Stop
                $loaded = $raw | ConvertFrom-Json
                foreach ($prop in $loaded.PSObject.Properties) {
                    $macCache[$prop.Name] = $prop.Value
                }
            } catch {
                Write-Log "MacRandomization: could not read MAC cache: $_" "DEBUG"
            }
        }
        
        $normalizedSsid = $CurrentSsid.Trim()
        $normalizedMac  = $CurrentMac.ToUpper().Trim()
        
        if ($macCache.ContainsKey($normalizedSsid)) {
            $lastMac = $macCache[$normalizedSsid].ToUpper().Trim()
            if ($lastMac -ne $normalizedMac) {
                Write-Log "MAC RANDOMIZATION DETECTED on SSID '$normalizedSsid': was $lastMac now $normalizedMac" "WARN"
                Write-Log "MAC change may invalidate captive portal session - portal authenticates by MAC" "WARN"
                Write-Log "Recommendation: Disable random hardware addresses for this SSID in Windows WiFi settings" "WARN"
            } else {
                Write-Log "MacRandomization: MAC unchanged for SSID '$normalizedSsid' ($normalizedMac)" "DEBUG"
            }
        } else {
            Write-Log "MacRandomization: first seen MAC for SSID '$normalizedSsid': $normalizedMac" "DEBUG"
        }
        
        # Update cache
        $macCache[$normalizedSsid] = $normalizedMac
        $macCache | ConvertTo-Json -Depth 2 | Set-Content -Path $MacCacheFile -Encoding UTF8 -Force
        
    } catch {
        Write-Log "MacRandomization: check failed: $_" "DEBUG"
    }
}

function Test-DC { 
    param([string]$hostname = $DC_FQDN)
    
    # Ping the DC, then confirm via DNS suffix.
    # Stale VPN routes can make DC pingable from any network - suffixes don't lie.
    # If ANY non-corporate suffix is found, we're off-prem.
    try {
        $pingResult = Test-Connection -ComputerName $hostname -Count 1 -Quiet -ErrorAction Stop
        if (-not $pingResult) { return $false }
        
        try {
            $corpSuffixes = @('ms.ds.uhc.com', 'ds.uhc.com', 'uhc.com')
            $foundSuffixes = @()

            # Method 1: Get DNS suffix search list (the clean way - no regex!)
            try {
                $dnsGlobal = Get-DnsClientGlobalSetting -ErrorAction Stop
                if ($dnsGlobal.SuffixSearchList) {
                    $foundSuffixes += $dnsGlobal.SuffixSearchList | ForEach-Object { $_.ToLower().Trim() }
                }
            } catch {
                Write-Log "Could not get DNS suffix search list via Get-DnsClientGlobalSetting: $_" "DEBUG"
            }

            # Method 2: Get primary DNS suffix (computer's domain membership)
            try {
                $primarySuffix = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
                if (-not [string]::IsNullOrWhiteSpace($primarySuffix)) {
                    $foundSuffixes += $primarySuffix.ToLower().Trim()
                }
            } catch {
                Write-Log "Could not get primary DNS suffix: $_" "DEBUG"
            }

            # Remove duplicates and blanks
            $foundSuffixes = $foundSuffixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            
            Write-Log "DNS suffixes detected: $($foundSuffixes -join ', ')" "DEBUG"

            if (-not $foundSuffixes) {
                Write-Log "DC ping succeeded but no DNS suffixes found - cannot confirm on-prem" "WARN"
                return $false
            }

            # Check if we have ONLY corporate suffixes (no ISP/public WiFi suffixes)
            # On-prem: only corp suffixes present
            # VPN from home: corp suffixes + ISP suffix (comcast.net, att.net, etc.)
            $corpSuffixCount = 0
            $nonCorpSuffixes = @()
            
            foreach ($found in $foundSuffixes) {
                $isCorp = $false
                foreach ($corp in $corpSuffixes) {
                    # Exact match or subdomain (e.g., "foo.uhc.com" matches "uhc.com")
                    if ($found -eq $corp -or $found -like "*.$corp") {
                        $isCorp = $true
                        $corpSuffixCount++
                        break
                    }
                }
                if (-not $isCorp) {
                    $nonCorpSuffixes += $found
                }
            }

            # Must have at least one corporate suffix
            if ($corpSuffixCount -eq 0) {
                Write-Log "DC ping succeeded but NO corporate DNS suffixes found (found: $($foundSuffixes -join ', ')) - off-prem" "WARN"
                return $false
            }

            # Must have ONLY corporate suffixes (no ISP/public suffixes)
            if ($nonCorpSuffixes.Count -gt 0) {
                Write-Log "DC ping succeeded with corporate suffixes, but also non-corporate suffixes present ($($nonCorpSuffixes -join ', ')) - VPN from off-prem" "WARN"
                return $false
            }

            Write-Log "DC reachable with ONLY corporate DNS suffixes ($($foundSuffixes -join ', ')) - on-prem confirmed" "DEBUG"
            return $true
            
        } catch {
            # Suffix check failed - fall through and trust the ping
            Write-Log "Could not validate DNS suffixes: $_" "DEBUG"
            return $true
        }
        
    } catch { 
        return $false 
    }
}

# RC1: Primary network gate function
function Get-NwCheckResult {
    # Hits nwcheck.optum.com (blocked in ISE/WLC posture redirect ACL).
    # Returns structured object so main block can route in one shot:
    #   Status = "online"      -> 200 received, network is clean
    #   Status = "redirect"    -> 3xx received, RedirectUrl tells us which workflow
    #   Status = "unreachable" -> exception or unexpected status, treat as no_net_transient
    param([string]$Url = $NewPreflightURL)
    
    Write-Log "RC1 nwcheck preflight: GET $Url" "INFO"
    
    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 8000
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $location = $response.Headers['Location']
        $response.Close()
        
        if ($statusCode -eq 200 -or $statusCode -eq 404) {
            Write-Log "preflight: HTTP $statusCode from $Url - network is online" "INFO"
            return [PSCustomObject]@{ Status = "online"; RedirectUrl = $null }
        } elseif ($statusCode -ge 300 -and $statusCode -lt 400) {
            Write-Log "preflight: $statusCode redirect to $location - restricted access (captive/ISE)" "WARN"
            return [PSCustomObject]@{ Status = "redirect"; RedirectUrl = $location }
        } else {
            Write-Log "preflight: Unexpected status $statusCode" "WARN"
            return [PSCustomObject]@{ Status = "unreachable"; RedirectUrl = $null }
        }
    } catch [System.Net.WebException] {
        # HttpWebRequest throws WebException for non-2xx responses (including 404).
        # Must inspect the exception's response object to get the real status code.
        $exResponse = $_.Exception.Response
        if ($exResponse) {
            $statusCode = [int]$exResponse.StatusCode
            $location = $exResponse.Headers['Location']

            if ($statusCode -eq 404) {
                # Read response body to confirm this is gateway.optum.com's known 404
                # and not a captive portal or DNS hijack also returning 404
                try {
                    $stream = $exResponse.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $body = $reader.ReadToEnd()
                    $reader.Close()
                } catch {
                    $body = ""
                }
                $exResponse.Close()

                if ($body -match '"no Route matched with those values"') {
                    Write-Log "preflight: HTTP 404 from $Url - gateway signature confirmed, network is online" "INFO"
                    return [PSCustomObject]@{ Status = "online"; RedirectUrl = $null }
                } else {
                    Write-Log "preflight: HTTP 404 from $Url but body does not match gateway signature - treating as unreachable" "WARN"
                    Write-Log "preflight: body=$body" "DEBUG"
                    return [PSCustomObject]@{ Status = "unreachable"; RedirectUrl = $null }
                }
            } elseif ($statusCode -ge 300 -and $statusCode -lt 400) {
                $exResponse.Close()
                Write-Log "preflight: $statusCode redirect to $location (via exception) - restricted access" "WARN"
                return [PSCustomObject]@{ Status = "redirect"; RedirectUrl = $location }
            } else {
                $exResponse.Close()
                Write-Log "preflight: Unexpected status $statusCode (via exception)" "WARN"
                return [PSCustomObject]@{ Status = "unreachable"; RedirectUrl = $null }
            }
        }
        Write-Log "preflight: Unreachable - $($_.Exception.Message)" "WARN"
        return [PSCustomObject]@{ Status = "unreachable"; ErrorMessage = $_.Exception.Message; RedirectUrl = $null }
    } catch {
        Write-Log "preflight: Unreachable - $_" "WARN"
        return [PSCustomObject]@{ Status = "unreachable"; ErrorMessage = $_.Exception.Message; RedirectUrl = $null }
    }
}

function Test-InternetAccess-Legacy {
    # LEGACY: Google 204 check (currently passes even with ISE redirect due to blank ACL)
    param([string]$Url = $LegacyPreflightURL)
    
    Write-Log "Pre-flight check (LEGACY): Testing $Url" "INFO"
    
    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 3000
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $response.Close()
        
        if ($statusCode -eq 204) {
            Write-Log "Pre-flight PASSED (LEGACY): Received 204 from Google" "INFO"
            return $true
        }
        
        Write-Log "Pre-flight FAILED (LEGACY): Status $statusCode" "WARN"
        return $false
        
    } catch {
        Write-Log "Pre-flight FAILED (LEGACY): $_" "WARN"
        return $false
    }
}

function Test-CaptivePortalCleared {
    # Used by cap_portal_runner poll loop to confirm portal has been accepted
    if ($UseNewPreflight) {
        $result = Get-NwCheckResult
        return ($result.Status -eq "online")
    } else {
        return Test-InternetAccess-Legacy
    }
}

function Test-Redirect { 
    param([string]$Url = "http://captive.apple.com/hotspot-detect.html")
    
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
    
    # ISE can return 200 with Location header OR standard 3xx redirects
    # Check for Location header on any 2xx or 3xx response
    if ($statusCode -ge 200 -and $statusCode -lt 400 -and $location) {
      Write-Log "REDIRECT DETECTED: HTTP $statusCode with Location header - $Url redirected to: $location"
      $redirectInfo.IsRedirect = $true
      $redirectInfo.RedirectUrl = $location
      $redirectInfo.Method = "HTTP"
      return $redirectInfo
    } else {
      Write-Log "No HTTP redirect: $Url returned status $statusCode (Location: $location)"
    }
  } catch { 
    # When AllowAutoRedirect=false, redirects throw exceptions - check if exception contains redirect
    if ($_.Exception.Response) {
      $statusCode = [int]$_.Exception.Response.StatusCode
      $location = $_.Exception.Response.Headers['Location']
      
      # Check for Location header on any 2xx or 3xx response in exception
      if ($statusCode -ge 200 -and $statusCode -lt 400 -and $location) {
        Write-Log "REDIRECT DETECTED (via exception): HTTP $statusCode with Location - $Url redirected to: $location"
        $redirectInfo.IsRedirect = $true
        $redirectInfo.RedirectUrl = $location
        $redirectInfo.Method = "HTTP"
        return $redirectInfo
      }
    }
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

function Test-RedirectToGateway {
    # Gateway redirect test (fallback method)
    Write-Log "Attempting gateway redirect test (fallback method)"
    
    try {
        $gateways = Get-NetIPConfiguration |
            Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } |
            ForEach-Object { $_.IPv4DefaultGateway.NextHop } |
            Select-Object -Unique
        
        foreach ($gw in $gateways) {
            Write-Log "Testing redirect via gateway: http://$gw"
            
            try {
                $request = [System.Net.HttpWebRequest]::Create("http://$gw")
                $request.AllowAutoRedirect = $false
                $request.Timeout = 4000
                
                $response = $request.GetResponse()
                $statusCode = [int]$response.StatusCode
                $location = $response.Headers['Location']
                $response.Close()
                
                if ($statusCode -ge 300 -and $statusCode -lt 400 -and $location) {
                    # Check if this is just HTTP -> HTTPS upgrade on same IP (not a captive portal)
                    try {
                        $redirectUri = [System.Uri]$location
                        $redirectHost = $redirectUri.Host.Trim('[]')  # Remove IPv6 brackets if present
                        
                        if ($redirectHost -eq $gw) {
                            Write-Log "Gateway redirect is HTTP -> HTTPS upgrade on same IP ($gw) - not a captive portal" "DEBUG"
                            continue  # Try next gateway or exit loop
                        }
                    } catch {
                        Write-Log "Could not parse redirect URL $location - treating as captive portal" "DEBUG"
                    }
                    
                    # Redirect to different host = likely captive portal
                    Write-Log "REDIRECT DETECTED via gateway: HTTP $statusCode - http://$gw redirected to: $location"
                    return @{
                        IsRedirect = $true
                        RedirectUrl = $location
                        Method = "GATEWAY_HTTP"
                    }
                } elseif ($statusCode -eq 200) {
                    try {
                        $resp = Invoke-WebRequest -Uri "http://$gw" -TimeoutSec 5
                        $content = $resp.Content.ToLower()
                        
                        #if ($content -match "login|captive|portal|authentication|accept.*terms|click.*continue") {
                        if ($content -match "captive|portal|authentication|accept.*terms|click.*continue") {
                            Write-Log "REDIRECT DETECTED: Gateway returned captive portal page"
                            return @{
                                IsRedirect = $true
                                RedirectUrl = "http://$gw"
                                Method = "GATEWAY_CAPTIVE_PAGE"
                            }
                        }
                    } catch {
                        Write-Log "Gateway page content check failed: $_" "DEBUG"
                    }
                }
                
                Write-Log "Gateway $gw returned status $statusCode with no redirect or captive indicators"
                
            } catch {
                Write-Log "Gateway redirect test failed for $gw : $_" "DEBUG"
            }
        }
    } catch {
        Write-Log "Gateway redirect test error: $_" "DEBUG"
    }
    
    Write-Log "No redirect detected via gateway method"
    return @{
        IsRedirect = $false
        RedirectUrl = $null
        Method = $null
    }
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

# ------------------------ Captive Portal Integration -------------------------
function Clear-CaptivePortalFlag {
    if (Test-Path $FlagFile) {
        try {
            Remove-Item -Path $FlagFile -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared captive portal flag file" "DEBUG"
        } catch {
            Write-Log "Failed to clear captive portal flag file: $_" "WARN"
        }
    }
}

function Get-CaptiveEventCount {
    try {
        if (-not $global:_state.captiveEvents) {
            $global:_state | Add-Member -NotePropertyName captiveEvents -NotePropertyValue @() -Force
        }
        
        $now = Get-Date
        $recentEvents = @()
        
        foreach ($eventTime in $global:_state.captiveEvents) {
            try {
                $when = [datetime]::Parse($eventTime)
                if (($now - $when).TotalMinutes -lt $CaptiveEventCooldown) {
                    $recentEvents += $eventTime
                }
            } catch { }
        }
        
        $global:_state.captiveEvents = $recentEvents
        Save-State $global:_state
        
        return $recentEvents.Count
    } catch {
        Write-Log "Error checking captive event count: $_" "DEBUG"
        return 0
    }
}

function Add-CaptiveEvent {
    try {
        if (-not $global:_state.captiveEvents) {
            $global:_state | Add-Member -NotePropertyName captiveEvents -NotePropertyValue @() -Force
        }
        
        $global:_state.captiveEvents += (Get-Date).ToString('o')
        Save-State $global:_state
    } catch {
        Write-Log "Error recording captive event: $_" "DEBUG"
    }
}

function Clear-CaptiveEventHistory {
    param([string]$Reason = "successful connection")
    try {
        if ($global:_state.captiveEvents -and $global:_state.captiveEvents.Count -gt 0) {
            Write-Log "Clearing captive event history due to: $Reason (was: $($global:_state.captiveEvents.Count) events)" "DEBUG"
            $global:_state.captiveEvents = @()
            Save-State $global:_state
            
            try {
                $eventArgs = @("/T", "INFORMATION", "/ID", "0", "/L", "APPLICATION", "/SO", "WhiteWalker", "/D", "Network Connection Established")
                Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Network connection success event logged (ID 0)" "DEBUG"
            } catch {
                Write-Log "Failed to log success event: $_" "DEBUG"
            }
        }
        
        if (Test-Path $CaptiveFailureFlag) {
            Remove-Item $CaptiveFailureFlag -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared captive portal failure flag due to: $Reason" "DEBUG"
        }
    } catch {
        Write-Log "Error clearing captive event history: $_" "DEBUG"
    }
}

function Show-CaptivePortalAlert {
    param([int]$EventCount)
    
    Write-Log "Showing BLOCKING user alert for repeated captive portal failures (count: $EventCount)" "WARN"
    
    $currentSSID = $null
    $isWiFiConnected = $false
    
    try {
        $wifiAdapter = Get-NetAdapter | Where-Object { 
            $_.Status -eq 'Up' -and 
            $_.Name -match "Wi-Fi|Wireless|802\.11" 
        } | Select-Object -First 1
        
        if ($wifiAdapter) {
            $netshOutput = netsh wlan show interfaces 2>$null
            if ($netshOutput -and ($netshOutput -match 'State\s+:\s+connected')) {
                $isWiFiConnected = $true
                if ($netshOutput -match 'SSID\s+:\s+(.+)') {
                    $currentSSID = $matches[1].Trim()
                    Write-Log "WiFi connected to SSID: $currentSSID" "INFO"
                }
            } else {
                Write-Log "WiFi adapter exists but not connected to any network" "WARN"
            }
        } else {
            Write-Log "No active WiFi adapter found - may be on Ethernet" "INFO"
        }
    } catch {
        Write-Log "Could not detect WiFi status: $_" "DEBUG"
    }
    
    try {
        $eventArgs = @("/T", "WARNING", "/ID", "1", "/L", "APPLICATION", "/SO", "WhiteWalker", "/D", "Maximum ($EventCount) Connection Attempts Reached. Prompted user to exit browsers and disconnect/reconnect to the network, to reattempt")
        Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Captive portal failure event logged (ID 1) with count: $EventCount" "INFO"
    } catch {
        Write-Log "Failed to log failure event: $_" "WARN"
    }
    
    try {
        $promptContent = @{
            timestamp = (Get-Date).ToString('o')
            event_count = $EventCount
            message = "User prompted for captive portal connection failure"
        } | ConvertTo-Json -Compress
        
        Set-Content -Path $UserPromptedFlag -Value $promptContent -Encoding UTF8
        Write-Log "User prompted flag created - all future script executions will be blocked" "INFO"
    } catch {
        Write-Log "Failed to create user prompted flag: $_" "WARN"
    }
}

function Show-CaptivePortalAlert {
    param([int]$EventCount)
    
    Write-Log "Showing BLOCKING user alert for repeated captive portal failures (count: $EventCount)" "WARN"
    
    $currentSSID = $null
    $isWiFiConnected = $false
    
    try {
        $wifiAdapter = Get-NetAdapter | Where-Object { 
            $_.Status -eq 'Up' -and 
            $_.Name -match "Wi-Fi|Wireless|802\.11" 
        } | Select-Object -First 1
        
        if ($wifiAdapter) {
            $netshOutput = netsh wlan show interfaces 2>$null
            if ($netshOutput -and ($netshOutput -match 'State\s+:\s+connected')) {
                $isWiFiConnected = $true
                if ($netshOutput -match 'SSID\s+:\s+(.+)') {
                    $currentSSID = $matches[1].Trim()
                    Write-Log "WiFi connected to SSID: $currentSSID" "INFO"
                }
            } else {
                Write-Log "WiFi adapter exists but not connected to any network" "WARN"
            }
        } else {
            Write-Log "No active WiFi adapter found - may be on Ethernet" "INFO"
        }
    } catch {
        Write-Log "Could not detect WiFi status: $_" "DEBUG"
    }
    
    try {
        $eventArgs = @("/T", "WARNING", "/ID", "1", "/L", "APPLICATION", "/SO", "WhiteWalker", "/D", "Maximum ($EventCount) Connection Attempts Reached. Prompted user to exit browsers and disconnect/reconnect to the network, to reattempt")
        Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Captive portal failure event logged (ID 1) with count: $EventCount" "INFO"
    } catch {
        Write-Log "Failed to log failure event: $_" "WARN"
    }
    
    try {
        $promptContent = @{
            timestamp = (Get-Date).ToString('o')
            event_count = $EventCount
            message = "User prompted for captive portal connection failure"
        } | ConvertTo-Json -Compress
        
        Set-Content -Path $UserPromptedFlag -Value $promptContent -Encoding UTF8
        Write-Log "User prompted flag created - all future script executions will be blocked" "INFO"
    } catch {
        Write-Log "Failed to create user prompted flag: $_" "WARN"
    }
    
    $alertTitle = "Optum Employee Connectivity"
    $alertMessage = ""
    
    if ($isWiFiConnected -and $currentSSID) {
        $alertMessage = @"
There seems to be an issue connecting to this Captive Portal Network.

Network: $currentSSID

WhiteWalker will now disconnect and reconnect you to the network automatically.

Please wait while we attempt to reconnect...

- Optum Employee Connectivity
"@
    } elseif ($isWiFiConnected) {
        $alertMessage = @"
There seems to be an issue connecting to this Captive Portal Network.

Network: Unknown WiFi Network

WhiteWalker will now disconnect and reconnect you to the network automatically.

Please wait while we attempt to reconnect...

- Optum Employee Connectivity
"@
    } else {
        $alertMessage = @"
There seems to be an issue connecting to this Captive Portal Network.

Connection Type: Wired/Ethernet or WiFi Disconnected

Please disconnect from the network and reconnect manually to try again.

- Optum Employee Connectivity
"@
    }

    $userClickedOK = $false
    try {
        if (-not $WhatIf) {
            Add-Type -AssemblyName System.Windows.Forms
            
            $form = New-Object System.Windows.Forms.Form
            $form.Text = $alertTitle
            $form.Size = New-Object System.Drawing.Size(450,280)
            $form.StartPosition = "CenterScreen"
            $form.TopMost = $true
            
            $label = New-Object System.Windows.Forms.Label
            $label.Location = New-Object System.Drawing.Point(10,20)
            $label.Size = New-Object System.Drawing.Size(420,140)
            $label.Text = $alertMessage
            $form.Controls.Add($label)
            
            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Location = New-Object System.Drawing.Point(175,190)
            $okButton.Size = New-Object System.Drawing.Size(100,30)
            $okButton.Text = "OK"
            $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Controls.Add($okButton)
            $form.AcceptButton = $okButton
            
            $timer = New-Object System.Windows.Forms.Timer
            $timer.Interval = 5000
            $timer.Add_Tick({
                $form.Close()
            })
            $timer.Start()
            
            $result = $form.ShowDialog()
            $timer.Stop()
            
            Write-Log "User alert shown (WiFi: $isWiFiConnected, SSID: $currentSSID) - auto-proceeds after 5s or user clicks OK" "INFO"
            $userClickedOK = $true
            
        } else {
            Write-Log "WHATIF: Would show user alert with auto-reconnect for WiFi: $isWiFiConnected, SSID: $currentSSID" "INFO"
            $userClickedOK = $true
        }
    } catch {
        Write-Log "Failed to show user alert: $_" "ERROR"
        $userClickedOK = $true
    }
    
    if ($userClickedOK -and $isWiFiConnected) {
        try {
            Write-Log "Attempting automatic WiFi reconnection..." "INFO"
            
            if ($currentSSID) {
                Write-Log "Disconnecting from WiFi..." "INFO"
                & netsh wlan disconnect | Out-Null
                Start-Sleep -Seconds 3
                
                Write-Log "Reconnecting to SSID: $currentSSID" "INFO"
                & netsh wlan connect name="$currentSSID" | Out-Null
                Start-Sleep -Seconds 5
                
                Write-Log "WiFi reconnection completed" "INFO"
            } else {
                Write-Log "WiFi connected but SSID unknown - attempting disconnect/reconnect anyway" "WARN"
                & netsh wlan disconnect | Out-Null
                Start-Sleep -Seconds 3
                Write-Log "Waiting for Windows to auto-reconnect to preferred network..." "INFO"
                Start-Sleep -Seconds 3
            }
            
        } catch {
            Write-Log "Error during WiFi reconnection: $_" "ERROR"
            Write-Log "User will need to manually reconnect" "WARN"
        }
    } elseif ($userClickedOK -and -not $isWiFiConnected) {
        Write-Log "Not on WiFi - skipping auto-reconnect, user must reconnect manually" "INFO"
    }
    
    try {
        Remove-Item $UserPromptedFlag -Force -ErrorAction SilentlyContinue
        Write-Log "User prompted flag cleared - script executions can resume" "INFO"
        
        Clear-CaptiveEventHistory "user alert acknowledged"
        
    } catch {
        Write-Log "Error clearing flags: $_" "WARN"
    }
}

function Test-UserPromptedFlag {
    if (Test-Path $UserPromptedFlag) {
        try {
            $promptContent = Get-Content $UserPromptedFlag -Raw | ConvertFrom-Json
            $promptTime = [datetime]::Parse($promptContent.timestamp)
            $promptAge = (Get-Date) - $promptTime
            
            Write-Log "User prompted flag exists - script execution blocked (age: $([math]::Round($promptAge.TotalMinutes, 1)) minutes)" "INFO"
            Write-Log "Exited. Waiting on user response" "INFO"
            
            return $true
        } catch {
            Write-Log "Error reading user prompted flag, removing: $_" "WARN"
            Remove-Item $UserPromptedFlag -Force -ErrorAction SilentlyContinue
            return $false
        }
    }
    return $false
}

function Get-CaptivePortalResult {
    param([int]$TimeoutSeconds = $CaptivePortalTimeout)
    
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($TimeoutSeconds)
    
    $initialNetworkInfo = Get-NetworkInfo
    $initialFingerprint = "$($initialNetworkInfo.IPAddress)|$($initialNetworkInfo.DefaultGateway)|$($initialNetworkInfo.SSID)"
    Write-Log "Initial network fingerprint: $initialFingerprint" "DEBUG"
    
    Write-Log "Waiting for captive portal remediation - Start: $($startTime.ToString('HH:mm:ss'))" "INFO"
    Write-Log "Will wait until: $($endTime.ToString('HH:mm:ss')) (up to $TimeoutSeconds seconds)" "INFO"
    
    $lastLogTime = $startTime
    $lastNetworkCheckTime = $startTime
    $lastPortalCheckTime = $startTime
    $lastInterruptCheckTime = $startTime
    $logInterval = 10
    $networkCheckInterval = 5
    $portalCheckInterval = 15
    $interruptCheckInterval = 2
    
    while ((Get-Date) -lt $endTime) {
        $now = Get-Date
        
        if (($now - $lastInterruptCheckTime).TotalSeconds -ge $interruptCheckInterval) {
            if (Test-Path $InterruptFile) {
                Write-Log "Network interrupt detected - aborting captive portal wait" "WARN"
                try {
                    Remove-Item $InterruptFile -Force -ErrorAction SilentlyContinue
                } catch { }
                return @{
                    status = "INTERRUPTED"
                    details = "Network change detected during wait"
                    user = "SYSTEM"
                    captive_browser_pid = 0
                }
            }
            $lastInterruptCheckTime = $now
        }
        
        if (($now - $lastPortalCheckTime).TotalSeconds -ge $portalCheckInterval) {
            if (Test-CaptivePortalCleared) {
                $elapsed = ($now - $startTime).TotalSeconds
                Write-Log "Portal cleared during wait after $([math]::Round($elapsed))s - exiting early!" "INFO"
                return @{
                    status = "SUCCESS"
                    details = "Portal cleared early during wait (detected at ${elapsed}s)"
                    user = "SYSTEM"
                    captive_browser_pid = 0
                }
            }
            $lastPortalCheckTime = $now
        }
        
        if (($now - $lastNetworkCheckTime).TotalSeconds -ge $networkCheckInterval) {
            $currentNetworkInfo = Get-NetworkInfo
            $currentFingerprint = "$($currentNetworkInfo.IPAddress)|$($currentNetworkInfo.DefaultGateway)|$($currentNetworkInfo.SSID)"
            
            if ($currentFingerprint -ne $initialFingerprint) {
                Write-Log "Network change detected during wait!" "WARN"
                Write-Log "  Initial: $initialFingerprint" "WARN"
                Write-Log "  Current: $currentFingerprint" "WARN"
                return @{
                    status = "NETWORK_CHANGED"
                    details = "Network switched during captive portal authentication"
                    user = "SYSTEM"
                    captive_browser_pid = 0
                }
            }
            $lastNetworkCheckTime = $now
        }
        
        if (Test-Path $FlagFile) {
            try {
                $flagContent = Get-Content -Path $FlagFile -Raw -ErrorAction Stop
                $result = $flagContent | ConvertFrom-Json -ErrorAction Stop
                
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                Write-Log "Captive portal flag found after $([math]::Round($elapsed))s: Status=$($result.status), User=$($result.user)" "INFO"
                if ($result.details) {
                    Write-Log "Details: $($result.details)" "DEBUG"
                }
                
                return $result
                
            } catch {
                Write-Log "Error reading captive portal flag file: $_" "WARN"
                Start-Sleep -Seconds $FlagPollInterval
                continue
            }
        }
        
        if (($now - $lastLogTime).TotalSeconds -ge $logInterval) {
            $elapsed = ($now - $startTime).TotalSeconds
            $remaining = ($endTime - $now).TotalSeconds
            Write-Log "Still waiting for remediation... Elapsed: $([math]::Round($elapsed))s, Remaining: $([math]::Round($remaining))s" "DEBUG"
            $lastLogTime = $now
        }
        
        Start-Sleep -Seconds $FlagPollInterval
    }
    
    $totalElapsed = ((Get-Date) - $startTime).TotalSeconds
    Write-Log "Captive portal polling timeout reached after $([math]::Round($totalElapsed))s" "WARN"
    return $null
}

function Test-CaptivePortalCompatibility {
    <#
    .SYNOPSIS
    Analyze captive portal redirect URL for known compatibility issues
    
    .DESCRIPTION
    Checks redirect URL for patterns known to cause issues with corporate security policies:
    - Non-HTTPS (blocked by browser policy)
    - Non-standard ports (blocked by Defender firewall)
    - IP-based redirects (may not work)
    - Certificate issues (name mismatch, expired, self-signed)
    
    Only runs AFTER captive portal is detected, doesn't impact normal workflow.
    #>
    param([string]$RedirectUrl)
    
    $issues = @{
        HasIssues = $false
        IssueType = "NONE"
        Description = ""
        UserMessage = ""
        AllowRetry = $true
    }
    
    if ([string]::IsNullOrEmpty($RedirectUrl)) {
        return $issues
    }
    
    try {
        $uri = [System.Uri]$RedirectUrl
        
        # Check 1: Non-HTTPS redirect (blocked by browser security policy)
        if ($uri.Scheme -eq "http") {
            $issues.HasIssues = $true
            $issues.IssueType = "NON_HTTPS"
            $issues.Description = "Captive portal uses insecure HTTP (blocked by browser policy)"
            $issues.UserMessage = "This network uses an insecure captive portal that is blocked by corporate security policy. Connection may not be possible."
            $issues.AllowRetry = $false  # Retrying won't help
            Write-Log "CAPTIVE PORTAL ISSUE: Non-HTTPS redirect detected: $RedirectUrl" "WARN"
            return $issues
        }
        
        # Check 2: Non-standard port (may be blocked by Defender)
        if ($uri.Port -ne 80 -and $uri.Port -ne 443 -and $uri.Port -ne -1) {
            $issues.HasIssues = $true
            $issues.IssueType = "NON_STANDARD_PORT"
            $issues.Description = "Captive portal uses non-standard port $($uri.Port) (may be blocked by firewall)"
            $issues.UserMessage = "This network uses port $($uri.Port) which may be blocked by corporate firewall. Connection may fail."
            $issues.AllowRetry = $true  # Might work, let user try
            Write-Log "CAPTIVE PORTAL ISSUE: Non-standard port detected: $($uri.Port) in $RedirectUrl" "WARN"
            return $issues
        }
        
        # Check 3: IP-based redirect (no FQDN)
        $ipPattern = '^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if ($RedirectUrl -match $ipPattern) {
            $issues.HasIssues = $true
            $issues.IssueType = "IP_BASED_REDIRECT"
            $issues.Description = "Captive portal redirects to IP address instead of FQDN"
            $issues.UserMessage = "This network redirects to an IP address which may cause certificate errors. Connection may work but could be unreliable."
            $issues.AllowRetry = $true
            Write-Log "CAPTIVE PORTAL ISSUE: IP-based redirect detected: $RedirectUrl" "INFO"
            return $issues
        }
        
        # Check 4: Test if DNS resolution works for the redirect URL
        # This is the chicken/egg problem: DNS blocked until captive portal accepted,
        # but can't accept terms without DNS to reach the portal
        if ($uri.Scheme -eq "https" -or $uri.Scheme -eq "http") {
            try {
                $dnsTest = [System.Net.Dns]::GetHostEntry($uri.Host)
                Write-Log "DNS resolution successful for $($uri.Host)" "DEBUG"
            } catch {
                $issues.HasIssues = $true
                $issues.IssueType = "DNS_BLOCKED"
                $issues.Description = "DNS resolution blocked until captive portal accepted (chicken/egg problem)"
                $issues.UserMessage = "This network blocks DNS resolution until you accept terms, but the captive portal URL requires DNS to load. This is a network misconfiguration - contact the network administrator."
                $issues.AllowRetry = $false  # Retrying won't fix DNS
                Write-Log "CAPTIVE PORTAL ISSUE: DNS resolution failed for $($uri.Host) - chicken/egg problem detected" "WARN"
                return $issues
            }
        }
        
        # Check 5: Certificate validation (HTTPS only)
        if ($uri.Scheme -eq "https") {
            try {
                $certCheck = [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $req = [System.Net.HttpWebRequest]::Create($RedirectUrl)
                $req.Timeout = 5000
                $req.AllowAutoRedirect = $false
                
                try {
                    $response = $req.GetResponse()
                    $response.Close()
                } catch [System.Net.WebException] {
                    $webEx = $_.Exception
                    
                    # Check for certificate errors in exception
                    if ($webEx.Message -match "certificate|SSL|TLS") {
                        $issues.HasIssues = $true
                        $issues.IssueType = "CERTIFICATE_ERROR"
                        $issues.Description = "Captive portal has certificate validation errors"
                        $issues.UserMessage = "This network has SSL certificate problems (expired, self-signed, or name mismatch). Connection may fail due to security policy."
                        $issues.AllowRetry = $false
                        Write-Log "CAPTIVE PORTAL ISSUE: Certificate error detected for $RedirectUrl : $($webEx.Message)" "WARN"
                        return $issues
                    }
                }
                
            } catch {
                # Don't fail the whole check if cert validation fails
                Write-Log "Could not validate certificate for $RedirectUrl : $_" "DEBUG"
            } finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }
        }
        
        # No issues detected
        Write-Log "Captive portal compatibility check passed for $RedirectUrl" "DEBUG"
        return $issues
        
    } catch {
        Write-Log "Error analyzing captive portal URL $RedirectUrl : $_" "WARN"
        return $issues  # Return no issues if we can't parse
    }
}

function Invoke-CaptivePortalRemediation {
    param(
        [string]$PortalType,
        [string]$RedirectUrl = ""
    )
    
    Write-Log "Starting captive portal remediation for $PortalType" "INFO"
    
    if (Test-CaptivePortalCleared) {
        Write-Log "Captive portal already cleared - no remediation needed" "INFO"
        Clear-CaptiveEventHistory "captive portal pre-check passed"
        return $true
    }
    Write-Log "Captive portal still active - proceeding with remediation" "DEBUG"
    
    # ER5: Check for known captive portal compatibility issues
    $portalIssues = $null
    if (-not [string]::IsNullOrEmpty($RedirectUrl)) {
        Write-Log "Analyzing captive portal compatibility for: $RedirectUrl" "DEBUG"
        $portalIssues = Test-CaptivePortalCompatibility -RedirectUrl $RedirectUrl
        
        if ($portalIssues.HasIssues) {
            Write-Log "NON-STANDARD CAPTIVE PORTAL CONFIG DETECTED: $($portalIssues.IssueType)" "WARN"
            Write-Log "  Issue: $($portalIssues.Description)" "WARN"
            Write-Log "  User Impact: $($portalIssues.UserMessage)" "WARN"
            Write-Log "  Retry Recommended: $($portalIssues.AllowRetry)" "INFO"
        }
    }
    
    # NEW: Force disconnect VPN if blocking traffic
    try {
        $vpnState = Get-VpnState
        if (Test-VPNBlockingNetwork -VPNState $vpnState -RedirectDetected $true) {
            Write-Log "VPN in blocking state ($vpnState) - forcing disconnect to allow captive portal/ISE traffic" "WARN"
            & $vpn_cmd disconnect | Out-Null
            Start-Sleep -Seconds 2
            Write-Log "VPN disconnected to allow network authentication" "INFO"
        }
    } catch {
        Write-Log "Error checking/disconnecting VPN: $_" "DEBUG"
    }
    
    $eventCount = Get-CaptiveEventCount
    Write-Log "Recent captive portal events in last $CaptiveEventCooldown minutes: $eventCount" "DEBUG"
    
    if ($eventCount -ge $CaptiveEventLimit) {
        Write-Log "Captive portal event limit reached ($eventCount >= $CaptiveEventLimit) - showing BLOCKING user alert" "WARN"
        Show-CaptivePortalAlert -EventCount $eventCount
        return $false
    }
    
    # FLARE EVENT: captive_portal_ise_employee / captive_portal_ise_guest / captive_portal_non_ise
    # Context: SYSTEM | Reason: Captive portal detected, browser remediation initiated
    # Expected Flow: WW_main (SYSTEM) ???EUR ?EUR(TM) Direct flare to Ivanti EM
    # Ivanti Use: Monitoring/telemetry for captive portal encounters across fleet
    Send-FlareEvent "captive_portal_$($PortalType.ToLower())"
    
    Clear-CaptivePortalFlag
    
    try {
        if (Test-Path $InterruptFile) {
            Remove-Item $InterruptFile -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared stale interrupt flag before starting wait" "DEBUG"
        }
    } catch { }
    
    Add-CaptiveEvent
    
    # NEW ER2: Create remediation state file to track VPN stabilization need
    try {
        $remediationState = @{
            timestamp = (Get-Date).ToString('o')
            portal_type = $PortalType
            attempt_count = ($eventCount + 1)
        }
        
        # ER5: Add portal compatibility issues if detected
        if ($portalIssues -and $portalIssues.HasIssues) {
            $remediationState.portal_issues = @{
                issue_type = $portalIssues.IssueType
                description = $portalIssues.Description
                user_message = $portalIssues.UserMessage
                allow_retry = $portalIssues.AllowRetry
            }
        }
        
        $remediationStateJson = $remediationState | ConvertTo-Json -Compress
        
        Set-Content -Path $RemediationStateFile -Value $remediationStateJson -Encoding UTF8 -Force
        Write-Log "Created remediation state file for VPN stabilization tracking" "DEBUG"
    } catch {
        Write-Log "Failed to create remediation state file: $_" "WARN"
    }
    
    try {
        Write-Log "Triggering captive portal browser (attempt $($eventCount + 1)/$CaptiveEventLimit)" "INFO"
        
        if (-not $WhatIf) {
            # ER5: Dump flare history for debugging
            Write-Log "=== Flare History Debug Dump ===" "DEBUG"
            if ($global:flareHistory -and $global:flareHistory.Count -gt 0) {
                foreach ($key in $global:flareHistory.Keys) {
                    Write-Log "  FlareHistory[$key] = $($global:flareHistory[$key])" "DEBUG"
            Write-Log "Send-FlareEvent completed for captive_portal_browser" "DEBUG"
            
            # ER5: Give event log a moment to propagate
            Start-Sleep -Milliseconds 500
            Write-Log "Event log propagation wait complete" "DEBUG"
                }
            } else {
                Write-Log "  FlareHistory is empty (good - no de-dupe issues)" "DEBUG"
            }
            Write-Log "===========================" "DEBUG"
            
            # ER5: Check cooldown status before sending
            $inCooldown = In-Cooldown "captive_portal_browser" $FlareCooldownMinutes
            Write-Log "Cooldown check for captive_portal_browser: $inCooldown (will be bypassed anyway)" "DEBUG"
            
            Write-Log "Calling Send-FlareEvent for captive_portal_browser..." "DEBUG"
            # FLARE EVENT: captive_portal_browser
            # Context: USER | Reason: Launch browser for captive portal authentication
            # Expected Flow: WW_main (SYSTEM) ?+' Event 777 ?+' FlareGun ?+' USER context browser launch
            # FlareGun routes this to WW_flaregun_user.ps1 ?+' WW_cap_portal_runner.ps1
            Send-FlareEvent "captive_portal_browser"
            
            Write-Log "Captive portal browser launch triggered via FlareGun (Event 777)" "INFO"
        } else {
            Write-Log "WHATIF: Would trigger captive portal browser via FlareGun" "INFO"
            return $true
        }
        
        $result = Get-CaptivePortalResult -TimeoutSeconds $CaptivePortalTimeout
        
        if ($result) {
            if ($result.status -eq "INTERRUPTED" -or $result.status -eq "NETWORK_CHANGED") {
                Write-Log "Captive portal wait was interrupted: $($result.status) - $($result.details)" "WARN"
                Clear-CaptivePortalFlag
                
                # Clean up remediation state file on interrupt
                if (Test-Path $RemediationStateFile) {
                    Remove-Item $RemediationStateFile -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleaned up remediation state file (interrupted)" "DEBUG"
                }
                return $false
            }
            
            # Cap portal runner handles VPN stabilization and validation browser
            # We just clean up the captive browser here
            if ($result.captive_browser_pid -and $result.captive_browser_pid -gt 0) {
                try {
                    $captivePID = $result.captive_browser_pid
                    Write-Log "Attempting to clean up captive portal browser (PID: $captivePID)" "DEBUG"
                    
                    $captiveProcess = Get-Process -Id $captivePID -ErrorAction SilentlyContinue
                    if ($captiveProcess) {
                        Write-Log "Terminating captive portal browser process: $($captiveProcess.Name) (PID: $captivePID)" "INFO"
                        $captiveProcess.Kill()
                        $captiveProcess.WaitForExit(3000) | Out-Null
                        Write-Log "Captive portal browser terminated successfully" "INFO"
                    } else {
                        Write-Log "Captive portal browser process (PID: $captivePID) no longer running" "DEBUG"
                    }
                } catch {
                    Write-Log "Error cleaning up captive portal browser (PID: $captivePID): $_" "WARN"
                }
            }
            
            Clear-CaptivePortalFlag
            
            if ($result.status -eq "SUCCESS" -or $result.status -eq "PARTIAL") {
                Write-Log "Runner reported: $($result.status) - verifying portal clearance..." "INFO"
                
                Start-Sleep -Seconds 2
                
                if (Test-CaptivePortalCleared) {
                    Write-Log "Captive portal authentication VERIFIED - portal cleared" "INFO"
                    Clear-CaptiveEventHistory "captive portal verified cleared"
                    return $true
                } else {
                    Write-Log "Runner reported success but portal still present - user may not have completed auth" "WARN"
                    return $false
                }
            } else {
                Write-Log "Captive portal authentication failed: $($result.details)" "WARN"
                return $false
            }
        } else {
            Write-Log "Captive portal authentication timed out or no response" "WARN"
            Clear-CaptivePortalFlag
            return $false
        }
        
    } catch {
        Write-Log "Failed to trigger captive portal event: $_" "ERROR"
        Clear-CaptivePortalFlag
        return $false
    }
}

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
    
    Write-Log "Verifying nwcheck.optum.com accessibility after ISE compliance (up to $TimeoutSec seconds)..." "INFO"
    
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

# ------------------------------- ISE Rescan ----------------------------------
function Set-RescanStamp {
    $global:_state.lastRescan = (Get-Date).ToString('o')
    Save-State $global:_state
}

function Invoke-PostureRescan {
  if (Rescan-InCooldown) { Write-Log "Rescan suppressed (cooldown ${RescanCooldownMinutes}m)"; return }

  # CRITICAL: Check posture service state BEFORE attempting CLI operations
  # This prevents IPC errors and service crashes
  $postureService = Get-PostureService
  if (-not $postureService) {
    Write-Log "Posture service not found; skipping rescan."
    Write-Log "Searched for: csc_iseagent, ciscod.exe, csc_posture, csc_vpn_posture" "DEBUG"
    return
  }
  
  Write-Log "Using posture service: $($postureService.Name) ($($postureService.DisplayName))" "INFO"
  
  if ($postureService.Status -ne "Running") {
    Write-Log "Posture service not running (Status: $($postureService.Status)). Attempting to start..."
    try {
      Start-Service -Name $postureService.Name -ErrorAction Stop
      Write-Log "Posture service started. Waiting 10 seconds for stabilization..."
      Start-Sleep -Seconds 10
    } catch {
      Write-Log "Failed to start posture service: $_"
      return
    }
  } else {
    Write-Log "Posture service already running (Status: $($postureService.Status))"
  }

  # Execute direct rescan using variable path
  # Steve's proven method: simple, direct, no fancy redirection
  try {
    Write-Log "Executing ISE rescan: & '$ise_cmd' rescan"
    if (-not $WhatIf) {
      $output = & $ise_cmd rescan 2>&1
      Write-Log "ISE rescan command executed. Output: $output"
    } else {
      Write-Log "WHATIF: Would execute ISE rescan" "INFO"
    }
    Set-RescanStamp
    
    # CRITICAL: Allow 30 seconds for posture module recovery
    # ISE client is brittle and needs time to stabilize after rescan
    Write-Log "Sleeping 30 seconds post-rescan to allow posture module recovery..."
    if (-not $WhatIf) {
      Start-Sleep -Seconds 30
    }
    
    Write-Log "ISE rescan completed successfully"
  } catch {
    Write-Log "Error executing ISE rescan: $_"
    # Don't try fallback methods - they're more likely to break things
    # If direct method fails, log it and move on
  }
}
    
function Send-WwNotification {
    param([string]$Title, [string]$Body, [int]$Duration = 10, [string]$Type = "toast")
    $payload = "NOTIFY:$Type|title=$Title|body=$Body|duration=$Duration"
    Write-Log "Queuing user notification: $payload" "INFO"
    if (-not $WhatIf) {
        try {
            $proc = Start-Process -FilePath "eventcreate.exe" `
                -ArgumentList "/T INFORMATION /ID 800 /L APPLICATION /SO WhiteWalkerFlareGun /D `"$payload`"" `
                -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
            if ($proc.ExitCode -eq 0) {
                Write-Log "Notification event written successfully (ID 800)" "INFO"
            } else {
                Write-Log "Notification event FAILED (ExitCode: $($proc.ExitCode)) - payload: $payload" "WARN"
            }
        } catch {
            Write-Log "Failed to write notification event: $_" "WARN"
        }
    } else {
        Write-Log "WHATIF: Would send notification - $payload" "INFO"
    }
}
function Update-SsidCache {
    # Written at end of EVERY run - not just after nwcheck 200.
    # Critical: VPN-connected runs must write cache or SSID change detection
    # silently skips on the next network change (no cache = no comparison).
    param([string]$Ssid)
    if ([string]::IsNullOrEmpty($Ssid) -or $Ssid -eq 'N/A') { return }
    try {
        Set-Content -Path $SsidCacheFile -Value $Ssid -Encoding UTF8 -Force
        Write-Log "SSID cache updated: $Ssid" "DEBUG"
        if (Test-Path $SsidChangedFlag) {
            Remove-Item $SsidChangedFlag -Force -ErrorAction SilentlyContinue
            Write-Log "SSID changed flag cleared" "DEBUG"
        }
    } catch { Write-Log "Could not update SSID cache: $_" "WARN" }
}

function Invoke-SsidChangeCheck {
    param([string]$CurrentSsid)
    if ([string]::IsNullOrEmpty($CurrentSsid) -or $CurrentSsid -eq 'N/A') { return }

    $cachedSsid = $null
    if (Test-Path $SsidCacheFile) {
        try { $cachedSsid = (Get-Content $SsidCacheFile -Raw -ErrorAction Stop).Trim() } catch { }
    }

    if ([string]::IsNullOrEmpty($cachedSsid)) {
        Write-Log "No cached SSID - first run, writing cache now" "DEBUG"
        Update-SsidCache -Ssid $CurrentSsid
        return
    }

    if ($CurrentSsid -eq $cachedSsid) { Write-Log "SSID unchanged: $CurrentSsid" "DEBUG"; return }

    Write-Log "SSID CHANGED: '$cachedSsid' -> '$CurrentSsid'" "INFO"
    $vpnState = Get-VpnState
    Write-Log "VPN state on SSID change: $vpnState" "INFO"

    if ($vpnState -eq "Disconnected") {
        Write-Log "VPN already disconnected on SSID change - no intervention" "INFO"
        return
    }

    Write-Log "VPN is '$vpnState' on SSID change - grace window ${VpnSsidChangeGraceSec}s" "INFO"
    $elapsed = 0; $resolved = $false

    while ($elapsed -lt $VpnSsidChangeGraceSec) {
        Start-Sleep -Seconds $VpnSsidChangePollSec
        $elapsed += $VpnSsidChangePollSec
        $vpnState = Get-VpnState
        Write-Log "SSID change grace: ${elapsed}s/${VpnSsidChangeGraceSec}s - VPN: $vpnState" "DEBUG"
        if ($vpnState -eq "Connected" -or $vpnState -eq "Disconnected") {
            Write-Log "VPN resolved to '$vpnState' within grace window - no force disconnect" "INFO"
            $resolved = $true; break
        }
    }

    if (-not $resolved) {
        Write-Log "VPN stuck in '$vpnState' after ${VpnSsidChangeGraceSec}s - forcing disconnect" "WARN"
        try {
            & $vpn_cmd disconnect | Out-Null
            Start-Sleep -Seconds 2
            Write-Log "VPN force disconnected due to SSID change" "INFO"
        } catch { Write-Log "Error disconnecting VPN on SSID change: $_" "WARN" }
        
        # Notify user why VPN dropped
        Send-WwNotification -Title "VPN Disconnected" `
            -Body "A network change was detected. VPN has been disconnected to allow connection to the new network. It will reconnect automatically." `
            -Duration 10
        
        try {
            Set-Content -Path $SsidChangedFlag -Value (Get-Date).ToString('o') -Encoding UTF8 -Force
        } catch { }
    }
}

# --------------------------------- MAIN --------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $ciscoPath = Get-CiscoInstallPath

    Initialize-Logger
    Write-RunHeader

    if (-not $ciscoPath) { 
        Write-Log "Error: Cisco Secure Client install path not found."
        $script:exitReason = "error_no_cisco"
    } else {
        $ise_cmd = Join-Path $ciscoPath "posturecli.exe"
        $vpn_cmd = Join-Path $ciscoPath "vpncli.exe"

        Write-Log ("CiscoPath={0}" -f $ciscoPath)
        Write-Log ("vpncli={0}"    -f $vpn_cmd)
        Write-Log ("posturecli={0}"-f $ise_cmd)

        if (-not (Test-Path $vpn_cmd)) { 
            Write-Log "Error: vpncli.exe not found."
            $script:exitReason = "error_no_vpncli"
        } elseif (-not (Test-Path $ise_cmd)) { 
            Write-Log "Error: posturecli.exe not found."
            $script:exitReason = "error_no_posturecli"
        } else {
            $script:exitReason = "unknown"
            $script:currentSsid = $null
            try {
                Write-Log "White Walker v$ver starting..."
                
                # Safety: run blackhole -rm at every startup regardless of state.
                # Ensures hosts entries are never left in place due to a prior state snafu.
                # When $BlackholeEnabled = $false, still fires -rm to clear any stale entries.
                Invoke-BlackholeAction -Tag 'startup'

                # HayStack - event monitor subsystem reroll check
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
                        $script:exitReason = "no_network_connection"
                        Write-NetworkInfoToLog -NetworkInfo $networkInfo
                        Invoke-BlackholeAction -Tag 'no_network_connection'
                        return
                    }
                }
                
                Write-NetworkInfoToLog -NetworkInfo $networkInfo

                # Cache current SSID for Write-RunEnd to persist at run completion
                $script:currentSsid = $networkInfo.SSID

                # SSID change detection: if SSID changed and VPN active/stuck,
                # give it a grace window then force disconnect if needed.
                # Prevents VPN reconnect attempts blocking captive portal / ISE.
                Invoke-SsidChangeCheck -CurrentSsid $networkInfo.SSID

                # Check for MAC randomization on this SSID (hotel portals auth by MAC)
                if ($networkInfo.ConnectionType -eq "WiFi" -and $networkInfo.SSID -ne "N/A") {
                    Test-MacRandomization -CurrentSsid $networkInfo.SSID -CurrentMac $networkInfo.MACAddress
                }

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
                    $script:exitReason = "waiting_user_response"
                    Invoke-BlackholeAction -Tag 'waiting_user_response'
                    return
                }
                
                Write-Log "Sleeping $initial_sleep seconds post-DHCP..."
                Start-Sleep -Seconds $initial_sleep

                # Start Cisco browser killer to clean up any interfering processes
                # This runs on EVERY WhiteWalker execution to handle scenarios like:
                # - Guest network with valid session (no redirect, but Cisco browser opened)
                # - Orphaned browsers from previous captive portal sessions
                # - Cisco client launching browsers during posture checks
                $ciscoBrowserKillerJob = Start-CiscoBrowserKiller

                # APIPA check: 169.254.x.x + no gateway = no real network connection yet.
                # No point hitting nwcheck or anything else - just bail.
                if ($networkInfo.IPAddress -match '^169\.254\.' -and 
                    ($networkInfo.DefaultGateway -eq 'N/A' -or [string]::IsNullOrEmpty($networkInfo.DefaultGateway))) {
                    Write-Log "APIPA address ($($networkInfo.IPAddress)) with no gateway - not connected to network yet" "WARN"
                    $script:exitReason = "no_net_transient"
                    Invoke-BlackholeAction -Tag 'no_net_transient'
                    return
                }

                # =====================================================================
                # RC1: nwcheck.optum.com IS THE PRIMARY GATE
                # One call tells us everything: online / redirect / unreachable.
                # No multi-step probing - redirect URL routes us directly to the
                # correct workflow without additional checks.
                # =====================================================================
                Write-Log "RC1: nwcheck preflight - single call determines all workflow routing" "INFO"
                $nwCheck = Get-NwCheckResult
                
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
                            $script:exitReason = "vpn_connected:$flavor"
                            return
                        }
                        
                        # No VPN tunnel - on-prem or off-prem
                        $dcOK = Test-DC -hostname $DC_FQDN
                        Write-Log ("Connectivity: VPN=None  DC={0}  preflight=online" -f $dcOK)
                        
                        if ($dcOK) {
                            # FLARE EVENT: on_prem
                            # Context: SYSTEM (Event ID 793) | Reason: DC reachable, no VPN, clean internet
                            # Ivanti Use: Telemetry for on-prem presence / campus automations
                            Send-FlareEvent 'on_prem'
                            Clear-CaptiveEventHistory "on-premises connection"
                            $script:exitReason = "on_prem"
                        } else {
                            # FLARE EVENT: off_prem_no_vpn
                            # Context: USER (Event ID 782) | Reason: Internet up, DC not reachable, no VPN
                            # Ivanti Use: Prompt user to connect VPN
                            Send-FlareEvent 'off_prem_no_vpn'
                            Clear-CaptiveEventHistory "off-premises connection"
                            $script:exitReason = "off_prem_no_vpn"
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
                                & $vpn_cmd disconnect | Out-Null
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
                                
                                $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
                                if (-not $svc) {
                                    Write-Log "ISE redirect but posture service unavailable - cannot rescan" "ERROR"
                                    
                                    # FLARE EVENT: ise_posture_service_unavailable
                                    # Context: SYSTEM | Reason: ISE redirect present but posture service missing
                                    # Ivanti Use: Alert for broken Cisco Secure Client installations
                                    Send-FlareEvent 'ise_posture_service_unavailable'
                                    
                                    $script:exitReason = "ise_redirect_no_posture_service"
                                    return
                                }
                                
                                Write-Log "Posture service available: $($svc.Name) ($($svc.Status))" "INFO"
                                Invoke-PostureRescan
                                
                                Write-Log "Monitoring for ISE compliance (up to $PostureComplianceTimeout seconds)..." "INFO"
                                $complianceResult = Test-ISEPostureCompliance -TimeoutSec $PostureComplianceTimeout
                                
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
                                    
                                    Clear-CaptiveEventHistory "ISE posture compliant"
                                    $script:exitReason = "ise_employee_compliant"
                                } else {
                                    Write-Log "ISE posture check FAILED - result: $complianceResult" "ERROR"
                                    
                                    # FLARE EVENT: ise_posture_failed
                                    # Context: SYSTEM (Event ID 792) | Reason: Posture check failed after rescan
                                    # Ivanti Use: Alert for non-compliant devices requiring intervention
                                    Send-FlareEvent 'ise_posture_failed'
                                    
                                    $script:exitReason = "ise_employee_failed_$complianceResult"
                                }
                                return
                            }
                            "ISE_GUEST" {
                                # ISE guest portal -> browser. cap_portal_runner polls nwcheck until clear.
                                Write-Log "ISE Guest portal redirect -> browser remediation" "INFO"
                                Invoke-CaptivePortalRemediation -PortalType "ISE_GUEST" -RedirectUrl $redirectUrl
                                $script:exitReason = "ise_guest_browser_remediated"
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
                                $script:exitReason = "non_ise_browser_remediated"
                                return
                            }
                        }
                    }
                    
                    "unreachable" {
                        # nwcheck got no response - two possible causes:
                        #   A) Genuine network problem (no connectivity)
                        #   B) On-prem unpostured: ISE BLOCKS nwcheck but only REDIRECTS enroll.cisco.com
                        # CRITICAL: Test enroll.cisco.com IMMEDIATELY before DHCP lease expires
                        Write-Log "nwcheck: UNREACHABLE - immediately testing enroll.cisco.com before network drops" "WARN"
                        
                        $enrollResult = Test-Redirect -Url $ISERedirectTestURL
                        
                        if ($enrollResult.IsRedirect) {
                            $enrollRedirectType = Get-RedirectType -RedirectUrl $enrollResult.RedirectUrl
                            Write-Log "enroll.cisco.com redirected: type=$enrollRedirectType url=$($enrollResult.RedirectUrl)" "INFO"
                            
                            if ($enrollRedirectType -eq "ISE_EMPLOYEE") {
                                # On-prem unpostured confirmed -> rescan immediately
                                Write-Log "On-prem unpostured: enroll.cisco.com → PSN, triggering rescan" "INFO"
                                Send-FlareEvent 'ise_employee_posture_redirect'
                                
                                $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
                                if (-not $svc) {
                                    Write-Log "ISE redirect confirmed but posture service unavailable - cannot rescan" "ERROR"
                                    Send-FlareEvent 'ise_posture_service_unavailable'
                                    $script:exitReason = "ise_redirect_no_posture_service"
                                    return
                                }
                                
                                Write-Log "Posture service available: $($svc.Name) ($($svc.Status))" "INFO"
                                Invoke-PostureRescan
                                
                                Write-Log "Monitoring for ISE compliance (up to $PostureComplianceTimeout seconds)..." "INFO"
                                $complianceResult = Test-ISEPostureCompliance -TimeoutSec $PostureComplianceTimeout
                                
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
                                    Clear-CaptiveEventHistory "ISE posture compliant"
                                    $script:exitReason = "ise_employee_compliant"
                                } else {
                                    Write-Log "ISE posture check FAILED - result: $complianceResult" "ERROR"
                                    Send-FlareEvent 'ise_posture_failed'
                                    $script:exitReason = "ise_employee_failed_$complianceResult"
                                }
                                return
                            } else {
                                # enroll.cisco.com redirected but not to PSN - treat as captive portal
                                Write-Log "enroll.cisco.com redirected to non-PSN URL ($enrollRedirectType) - treating as captive portal" "WARN"
                                Invoke-CaptivePortalRemediation -PortalType "NON_ISE" -RedirectUrl $enrollResult.RedirectUrl
                                $script:exitReason = "non_ise_browser_remediated_via_enroll"
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
                            $script:exitReason = "vpn_connected_nwcheck_unreachable:$flavor"
                            Invoke-BlackholeAction -Tag $flavor
                            return
                        }
                        
                        # VPN in intermediate state (Connecting/Reconnecting/Unknown) blocks ALL traffic.
                        # Force disconnect so we can probe cleanly.
                        if ($currentVPNState -notin @("Disconnected", "Connected")) {
                            Write-Log "VPN in intermediate state: $currentVPNState (blocks all traffic) - forcing disconnect" "WARN"
                            try {
                                & $vpn_cmd disconnect | Out-Null
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
                                    $script:exitReason = "vpn_connected:$flavor"
                                } else {
                                    $dcOK = Test-DC -hostname $DC_FQDN
                                    if ($dcOK) {
                                        Send-FlareEvent 'on_prem'
                                        Clear-CaptiveEventHistory "on-premises connection"
                                        $script:exitReason = "on_prem"
                                    } else {
                                        Send-FlareEvent 'off_prem_no_vpn'
                                        Clear-CaptiveEventHistory "off-premises connection"
                                        $script:exitReason = "off_prem_no_vpn"
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
                                        $svc = Wait-ForPostureService -TimeoutSec $PostureWaitSeconds
                                        if (-not $svc) {
                                            Send-FlareEvent 'ise_posture_service_unavailable'
                                            $script:exitReason = "ise_redirect_no_posture_service"
                                            return
                                        }
                                        Invoke-PostureRescan
                                        $complianceResult = Test-ISEPostureCompliance -TimeoutSec $PostureComplianceTimeout
                                        if ($complianceResult -eq "Compliant") {
                                            Send-FlareEvent 'ise_posture_compliant'
                                            Clear-CaptiveEventHistory "ISE posture compliant"
                                            $script:exitReason = "ise_employee_compliant"
                                        } else {
                                            Send-FlareEvent 'ise_posture_failed'
                                            $script:exitReason = "ise_employee_failed_$complianceResult"
                                        }
                                        return
                                    }
                                    "ISE_GUEST" {
                                        Invoke-CaptivePortalRemediation -PortalType "ISE_GUEST" -RedirectUrl $nwCheck2.RedirectUrl
                                        $script:exitReason = "ise_guest_browser_remediated"
                                        return
                                    }
                                    default {
                                        if ($redirectType2 -eq "UNKNOWN") { Send-FlareEvent 'unknown_captive_portal' }
                                        Invoke-CaptivePortalRemediation -PortalType "NON_ISE" -RedirectUrl $nwCheck2.RedirectUrl
                                        $script:exitReason = "non_ise_browser_remediated"
                                        return
                                    }
                                }
                            }
                            # nwcheck still unreachable after VPN disconnect and enroll didn't redirect
                            # (we tested enroll immediately at top of unreachable block)
                            Write-Log "nwcheck still unreachable after VPN disconnect - genuine network problem" "WARN"
                            $script:exitReason = "no_net_transient"
                            Invoke-BlackholeAction -Tag 'no_net_transient'
                            return
                        }
                        
                        # If we reach here: enroll didn't redirect, VPN not intermediate.
                        # Before declaring no_net_transient, check for walled-garden portal pattern.
                        # Walled gardens (Wyndham, Marriott, etc.) block DNS entirely - no redirect ever comes.
                        # Signature: gateway pingable (L3 works) + DNS fails = walled garden confirmed.
                        Write-Log "enroll.cisco.com no redirect, VPN disconnected - testing for walled-garden captive portal..." "INFO"

                        $walledGarden = Test-WalledGarden

                        if ($walledGarden.IsWalledGarden) {
                            Write-Log "WALLED GARDEN CAPTIVE PORTAL DETECTED (gateway=$($walledGarden.GatewayIP))" "WARN"
                            Write-Log "Portal type: DNS-blocking - handing off to cap_portal_runner for remediation" "INFO"

                            # Write portal context into the remediation state file.
                            # cap_portal_runner reads this at init and branches on portal_type.
                            # Runner is responsible for clearing this file on exit.
                            try {
                                $statePayload = @{
                                    timestamp   = (Get-Date).ToString('o')
                                    portal_type = "walled_garden"
                                    gateway_ip  = $walledGarden.GatewayIP
                                    ssid        = $networkInfo.SSID
                                    reason      = $walledGarden.Reason
                                } | ConvertTo-Json -Compress
                                Set-Content -Path $RemediationStateFile -Value $statePayload -Encoding UTF8 -Force
                                Write-Log "Remediation state file written: portal_type=walled_garden gateway=$($walledGarden.GatewayIP)" "INFO"
                            } catch {
                                Write-Log "Could not write remediation state file: $_" "WARN"
                            }

                            # Telemetry flare - SYSTEM context, fires immediately
                            $script:exitReason = "captive_walled_garden"
                            Send-FlareEvent -Tag "captive_walled_garden"

                            # Trigger the runner in USER context via Event 777 (existing mechanism - unchanged)
                            # Runner will read state file, open gateway IP browser, show toast, monitor completion
                            Send-FlareEvent "captive_portal_browser"

                            Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob
                            Write-RunEnd $script:exitReason
                            return

                        } else {
                            # Genuine connectivity problem - not a walled garden
                            Write-Log "WalledGarden test negative (reason: $($walledGarden.Reason)) - genuine network connectivity problem" "WARN"
                            Write-Log "enroll.cisco.com no redirect, VPN state OK - genuine network connectivity problem" "WARN"
                            $script:exitReason = "no_net_transient"
                            Send-FlareEvent "no_net_transient"
                            Invoke-BlackholeAction -Tag 'no_net_transient'
                            Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob
                            Write-RunEnd $script:exitReason
                            return
                        }
                    }
                }
                
            } catch {
                Write-Log "Error in main execution: $_" "ERROR"
                $script:exitReason = "error_exception"
            } finally {
                # Stop Cisco browser killer job if it's still running
                if ($ciscoBrowserKillerJob) {
                    Stop-CiscoBrowserKiller -Job $ciscoBrowserKillerJob
                }
                
                Write-RunEnd $script:exitReason
            }
        }
    }
    
    exit 0
}

