#Requires -Version 5.1
'''
<#
.SYNOPSIS
WhiteWalker FlareGun - USER Context Handler

.DESCRIPTION
Version: 1.0.0
Author: steve.horton@optum.com
Date: 01-Nov-2025

Purpose: Process WhiteWalker events that need USER context execution
Triggered by: Task Scheduler watching for WhiteWalkerFlareGun events

This script runs as the LOGGED-IN USER and handles:
- Event ID 777: Captive Portal Browser Launch (EXISTING)
- Event ID 780: User Tunnel Flare (/user_tun)
- Event ID 781: Management Tunnel Flare (/mgmt_tun)
- Event ID 782: Off-Prem Flare (/off_prem_no_vpn)

Task Scheduler Configuration:
  Trigger: Event Log
    Log: Application
    Source: WhiteWalkerFlareGun
    Event IDs: 777, 780, 781, 782
  Action: Program
    Program: powershell.exe
    Arguments: -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_flaregun_user.ps1"
  Settings:
    Run only when user is logged on: CHECKED
    Run with highest privileges: UNCHECKED (run as user)
#>
'''
# Configuration
$LogPath = "C:\ProgramData\WhiteWalker\white_walker.flaregun_user.log"
$FlareExe = "$env:SystemRoot\System32\rundll32.exe"
$CaptivePortalScript = "C:\ProgramData\WhiteWalker\WW_cap_portal_runner.ps1"
$FlareGunConfigPath = "C:\ProgramData\WhiteWalker\WW_flaregun_config.json"

# Initialize logging
function Initialize-FlareGunLogger {
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

function Write-FlareGunLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
    $logLine = "$ts [FLAREGUN-USER] [$Level] $Message"
    
    try {
        Add-Content -Path $LogPath -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

function Send-UserFlare {
    param([string]$Tag)
    
    try {
        $args = "/$Tag"
        Write-FlareGunLog "Sending USER flare: $FlareExe $args"
        Start-Process -FilePath $FlareExe -ArgumentList $args -WindowStyle Hidden -ErrorAction Stop | Out-Null
        Write-FlareGunLog "USER flare sent successfully: /$Tag" "INFO"
    } catch {
        Write-FlareGunLog "Failed to send USER flare /$Tag : $_" "ERROR"
    }
}

function Launch-CaptivePortalBrowser {
    try {
        Write-FlareGunLog "Launching captive portal browser script..."
        
        if (-not (Test-Path $CaptivePortalScript)) {
            Write-FlareGunLog "Captive portal script not found: $CaptivePortalScript" "ERROR"
            return $false
        }
        
        # Launch the captive portal runner as a separate process
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$CaptivePortalScript`""
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        
        $process = [System.Diagnostics.Process]::Start($psi)
        
        Write-FlareGunLog "Captive portal browser script launched (PID: $($process.Id))" "INFO"
        return $true
        
    } catch {
        Write-FlareGunLog "Failed to launch captive portal browser: $_" "ERROR"
        return $false
    }
}

# ================================= MAIN =======================================

Initialize-FlareGunLogger

Write-FlareGunLog "========================================" "INFO"
Write-FlareGunLog "WhiteWalker FlareGun USER Handler v1.0.0 Starting" "INFO"
Write-FlareGunLog "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" "INFO"

# Get the most recent WhiteWalkerFlareGun event
try {
    $event = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'WhiteWalkerFlareGun'
    } -MaxEvents 1 -ErrorAction Stop
    
    Write-FlareGunLog "Retrieved triggering event: ID $($event.Id), Time $($event.TimeCreated)" "INFO"
    Write-FlareGunLog "Event message: $($event.Message)" "DEBUG"
    
    # Parse message to extract flare tag: "FLARE:user_tun"
    if ($event.Message -match 'FLARE:(\w+)') {
        $flareTag = $matches[1]
        Write-FlareGunLog "Parsed flare tag from event message: $flareTag" "INFO"
        
        # Special case: Event ID 777 is captive portal (legacy behavior)
        if ($event.Id -eq 777) {
            Write-FlareGunLog "Event 777: Captive Portal Browser Launch (legacy path)" "INFO"
            Launch-CaptivePortalBrowser
        } else {
            # Send USER context flare
            Write-FlareGunLog "Sending USER context flare: /$flareTag (Event ID $($event.Id))" "INFO"
            Send-UserFlare -Tag $flareTag
        }
    } else {
        Write-FlareGunLog "ERROR: Could not parse flare tag from event message: $($event.Message)" "ERROR"
        Write-FlareGunLog "Expected format: 'FLARE:tag_name'" "ERROR"
    }
    
} catch {
    Write-FlareGunLog "ERROR: Could not retrieve triggering event: $_" "ERROR"
    Write-FlareGunLog "Event log may be empty or inaccessible" "ERROR"
    exit 1
}

Write-FlareGunLog "WhiteWalker FlareGun USER Handler Exiting" "INFO"
Write-FlareGunLog "========================================" "INFO"

exit 0
