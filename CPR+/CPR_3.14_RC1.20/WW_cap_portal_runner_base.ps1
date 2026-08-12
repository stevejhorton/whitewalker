param(
    [switch]$Debug
)

<#
.SYNOPSIS
CPR-Base (Captive Portal Base Observer)

.DESCRIPTION
Version: 1.0.0_RC1.20
Author: steve.horton@optum.com
Date: 16-Jul-2026

Version 1.0.0_RC1.20 (initial):
  - NEW: AlwaysOn-native observer mode for captive portal handling
  - Designed for users with uhg_always_on.xml or uhg_always_on_elevated.xml VPN profiles
  - Cisco Secure Client XML changes in those profiles now handle captive portal detection
    and browser launch natively - this script observes and lets the client do its job
  - Does NOT kill Cisco browser processes - Cisco client is expected to be running them
  - Does NOT open Edge or any browser - native Cisco handling is preferred
  - Polls connectivity every $CheckIntervalSec seconds for up to $ObserveTimeoutSeconds
  - Logs VPN state on every poll cycle for full visibility into what Cisco client is doing
  - On success: writes SUCCESS_NATIVE completion flag, exits cleanly
  - On timeout: writes TIMEOUT_NATIVE flag, fires captive_portal_browser (Event 777) to
    escalate to WW_cap_portal_runner.ps1 as fallback - full runner takes over from here
  - Reads cap_portal_remediation_active.flag for portal context (portal_type, gateway_ip,
    ssid) - used for logging only in this version
  - Triggered by: Task Scheduler on FlareGun Event 778 (captive_portal_browser_base)

Purpose: Observe captive portal resolution in USER context without interfering with
         Cisco Secure Client's native captive portal handling
Triggered by: Task Scheduler on FlareGun Event 778

Task Scheduler Configuration:
  Program: conhost.exe
  Arguments: --headless powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_cap_portal_runner_base.ps1"
#>

# Configuration
$LogPath               = "C:\ProgramData\WhiteWalker\white_walker.cap_portal_base.log"
$FlagFile              = "C:\ProgramData\WhiteWalker\portal_complete.flag"
$ValidationSite        = "https://www.optum.com"
$ObserveTimeoutSeconds = 120   # seconds to observe before escalating to full runner
$CheckIntervalSec      = 10    # connectivity poll interval during observation window
$StateDir              = "C:\ProgramData\WhiteWalker"
$RemediationStateFile  = "C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag"
$VpnCliPath            = "C:\Program Files (x86)\Cisco\Cisco Secure Client\vpncli.exe"
$EscalationEventId     = 777   # Event ID for captive_portal_browser - full runner fallback
$EscalationEventSource = "WhiteWalkerFlareGun"

function Initialize-BaseCapPortalLogger {
    if (-not (Test-Path $StateDir)) {
        try {
            New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
        } catch {
            Write-Host "ERROR: Cannot create state directory $StateDir - $_"
            exit 1
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

function Write-BaseCapLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
    $logLine = "$ts [BASE] [$Level] $Message"

    try {
        Add-Content -Path $LogPath -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if can't write to log
    }

    if ($Debug) {
        Write-Host $logLine
    }
}

function Write-CompletionFlag {
    param([string]$Status, [string]$Details = "", [int]$CaptiveBrowserPID = 0)

    $flagContent = @{
        timestamp = (Get-Date).ToString('o')
        status = $Status
        details = $Details
        user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        captive_browser_pid = $CaptiveBrowserPID
    } | ConvertTo-Json -Compress

    try {
        Set-Content -Path $FlagFile -Value $flagContent -Encoding UTF8
        Write-BaseCapLog "Completion flag written: $Status (PID: $CaptiveBrowserPID)" "INFO"
    } catch {
        Write-BaseCapLog "Failed to write completion flag: $_" "ERROR"
    }
}

function Test-SiteReachability {
    param([string]$Url = $ValidationSite)

    Write-BaseCapLog "Testing site reachability silently: $Url" "DEBUG"

    try {
        # CRITICAL: 3s timeout ensures completion within polling interval (prevents hang)
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-BaseCapLog "Site validation successful: $Url (HTTP $($response.StatusCode))" "INFO"
            return $true
        } else {
            Write-BaseCapLog "Site validation failed: $Url (HTTP $($response.StatusCode))" "WARN"
            return $false
        }
    } catch {
        Write-BaseCapLog "Site validation failed: $Url - $($_.Exception.Message)" "DEBUG"
        return $false
    }
}

function Get-VpnStateQuick {
    try {
        if (-not (Test-Path $VpnCliPath)) {
            Write-BaseCapLog "vpncli not found at expected path: $VpnCliPath" "DEBUG"
            return "Unknown"
        }

        $stateOutput = & $VpnCliPath status 2>$null | Out-String
        if (-not $stateOutput) {
            return "Unknown"
        }

        $stateMatches = [regex]::Matches($stateOutput, '(?im)^\s*>>\s*state:\s*(\w+)\s*$')
        if ($stateMatches.Count -gt 0) {
            return $stateMatches[$stateMatches.Count - 1].Groups[1].Value
        }

        return "Unknown"
    } catch {
        Write-BaseCapLog "Get-VpnStateQuick error: $_" "DEBUG"
        return "Unknown"
    }
}

function Send-EscalationFlare {
    Write-BaseCapLog "Base runner timeout - escalating to full runner (Event 777 captive_portal_browser)" "WARN"

    try {
        $eventArgs = @(
            "/T", "INFORMATION",
            "/ID", $EscalationEventId,
            "/L", "APPLICATION",
            "/SO", $EscalationEventSource,
            "/D", "FLARE:captive_portal_browser"
        )

        $proc = Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
        if ($proc.ExitCode -eq 0) {
            Write-BaseCapLog "Escalation flare fired successfully (Event 777 captive_portal_browser)" "INFO"
        } else {
            Write-BaseCapLog "Escalation flare may have failed (ExitCode: $($proc.ExitCode))" "WARN"
        }
    } catch {
        Write-BaseCapLog "Failed to fire escalation flare: $_" "ERROR"
    }
}

# ================================ MAIN ======================================

try {
    Initialize-BaseCapPortalLogger

    Write-BaseCapLog "=== CPR-Base (Captive Portal Base Observer) v1.0.0_RC1.20 Starting ===" "INFO"
    Write-BaseCapLog "ObserveTimeoutSeconds: $ObserveTimeoutSeconds" "INFO"
    Write-BaseCapLog "CheckIntervalSec: $CheckIntervalSec" "INFO"
    Write-BaseCapLog "ValidationSite: $ValidationSite" "INFO"
    Write-BaseCapLog "FlagFile: $FlagFile" "INFO"

    # Read and log VPN profile from registry
    $vpnProfile = (Get-ItemProperty -Path "HKLM:\SYSTEM\UHG\DSM" -ErrorAction SilentlyContinue).VPN
    if ($vpnProfile) {
        Write-BaseCapLog "VPN profile: $vpnProfile" "INFO"
    } else {
        Write-BaseCapLog "VPN profile: NOT_SET" "WARN"
    }

    # Read and log remediation state file context
    if (Test-Path $RemediationStateFile) {
        try {
            $stateRaw = Get-Content -Path $RemediationStateFile -Raw -ErrorAction Stop
            $stateData = $stateRaw | ConvertFrom-Json -ErrorAction Stop
            Write-BaseCapLog "Remediation context: portal_type=$($stateData.portal_type) gateway_ip=$($stateData.gateway_ip) ssid=$($stateData.ssid)" "INFO"
        } catch {
            Write-BaseCapLog "Could not parse remediation state file: $_" "DEBUG"
        }
    } else {
        Write-BaseCapLog "No remediation state file present" "DEBUG"
    }

    Write-BaseCapLog "Observer mode active - NOT killing Cisco browsers, NOT opening Edge" "INFO"
    Write-BaseCapLog "Cisco Secure Client is expected to handle captive portal natively" "INFO"
    Write-BaseCapLog "Will escalate to full runner (Event 777) if not resolved within ${ObserveTimeoutSeconds}s" "INFO"

    $observed = $false
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($ObserveTimeoutSeconds)
    $iteration = 0

    while ((Get-Date) -lt $endTime) {
        $iteration++
        $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
        $remaining = [math]::Round(($endTime - (Get-Date)).TotalSeconds)

        $vpnState = Get-VpnStateQuick
        Write-BaseCapLog "Observe cycle $iteration - elapsed=${elapsed}s remaining=${remaining}s vpn_state=$vpnState" "INFO"

        if (Test-SiteReachability) {
            Write-BaseCapLog "Connectivity confirmed after ${elapsed}s - Cisco client resolved captive portal natively" "INFO"
            Write-CompletionFlag -Status "SUCCESS_NATIVE" -Details "Captive portal resolved by Cisco Secure Client in ${elapsed}s" -CaptiveBrowserPID 0
            $observed = $true
            break
        }

        Start-Sleep -Seconds $CheckIntervalSec
    }

    if (-not $observed) {
        $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
        Write-BaseCapLog "Observation window expired after ${elapsed}s - native resolution did not complete" "WARN"
        Write-BaseCapLog "Escalating to full runner via captive_portal_browser flare (Event 777)" "WARN"
        Write-CompletionFlag -Status "TIMEOUT_NATIVE" -Details "Cisco client did not resolve captive portal within ${ObserveTimeoutSeconds}s - escalating to WW_cap_portal_runner.ps1" -CaptiveBrowserPID 0
        Send-EscalationFlare
    }

    # Clean up remediation state file
    Remove-Item $RemediationStateFile -Force -ErrorAction SilentlyContinue
    Write-BaseCapLog "=== CPR-Base Complete ===" "INFO"

} catch {
    Write-BaseCapLog "Unhandled error in CPR-Base observer: $_" "FATAL"
    Write-CompletionFlag -Status "ERROR" -Details "Script error: $($_.Exception.Message)" -CaptiveBrowserPID 0
}

exit 0
