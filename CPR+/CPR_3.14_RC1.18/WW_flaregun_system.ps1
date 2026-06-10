#Requires -RunAsAdministrator
<#
.SYNOPSIS
WhiteWalker FlareGun - SYSTEM Context Handler

.DESCRIPTION
Version: 1.0.0
Author: steve.horton@optum.com
Date: 01-Nov-2025

Purpose: Process WhiteWalker events that need SYSTEM context execution
Triggered by: Task Scheduler watching for WhiteWalkerFlareGun events

This script runs as SYSTEM and handles:
- Event ID 790: ISE Employee Rescan (/ise_employee_captive_portal)
- Event ID 791: ISE Compliance Success (/ise_posture_compliant)
- Event ID 792: ISE Compliance Failed (/ise_posture_failed)
- Event ID 793: On-Prem Flare (/on_prem)
- Event ID 799: Deep Diagnostics Collection (runs WW_collect_diag.ps1)

Task Scheduler Configuration:
  Trigger: Event Log
    Log: Application
    Source: WhiteWalkerFlareGun
    Event IDs: 790, 791, 792, 793, 799
  Action: Program
    Program: powershell.exe
    Arguments: -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_flaregun_system.ps1"
  Settings:
    Run whether user is logged on or not: CHECKED
    Run with highest privileges: CHECKED
    User account: SYSTEM
#>

# Configuration
$LogPath = "C:\ProgramData\WhiteWalker\white_walker.flaregun_system.log"
$FlareExe = "$env:SystemRoot\System32\rundll32.exe"
$DiagnosticsScript = "C:\ProgramData\WhiteWalker\WW_collect_diag.ps1"
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
    $logLine = "$ts [FLAREGUN-SYSTEM] [$Level] $Message"
    
    try {
        Add-Content -Path $LogPath -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

function Send-SystemFlare {
    param([string]$Tag)
    
    try {
        $args = "/$Tag"
        Write-FlareGunLog "Sending SYSTEM flare: $FlareExe $args"
        Start-Process -FilePath $FlareExe -ArgumentList $args -WindowStyle Hidden -ErrorAction Stop | Out-Null
        Write-FlareGunLog "SYSTEM flare sent successfully: /$Tag" "INFO"
    } catch {
        Write-FlareGunLog "Failed to send SYSTEM flare /$Tag : $_" "ERROR"
    }
}

function Invoke-DeepDiagnostics {
    try {
        Write-FlareGunLog "Launching deep diagnostics collection..."
        
        if (-not (Test-Path $DiagnosticsScript)) {
            Write-FlareGunLog "Diagnostics script not found: $DiagnosticsScript" "ERROR"
            return $false
        }
        
        # Launch the diagnostics script
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$DiagnosticsScript`""
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        
        $process = [System.Diagnostics.Process]::Start($psi)
        
        Write-FlareGunLog "Deep diagnostics collection launched (PID: $($process.Id))" "INFO"
        return $true
        
    } catch {
        Write-FlareGunLog "Failed to launch deep diagnostics: $_" "ERROR"
        return $false
    }
}

# ================================= MAIN =======================================

Initialize-FlareGunLogger

Write-FlareGunLog "========================================" "INFO"
Write-FlareGunLog "WhiteWalker FlareGun SYSTEM Handler v1.0.0 Starting" "INFO"
Write-FlareGunLog "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" "INFO"

# Get the most recent WhiteWalkerFlareGun event
try {
    $event = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'WhiteWalkerFlareGun'
    } -MaxEvents 1 -ErrorAction Stop
    
    Write-FlareGunLog "Retrieved triggering event: ID $($event.Id), Time $($event.TimeCreated)" "INFO"
    Write-FlareGunLog "Event message: $($event.Message)" "DEBUG"
    
    # Parse message to extract flare tag: "FLARE:on_prem"
    if ($event.Message -match 'FLARE:(\w+)') {
        $flareTag = $matches[1]
        Write-FlareGunLog "Parsed flare tag from event message: $flareTag" "INFO"
        
        # Special case: Event ID 799 is deep diagnostics
        if ($event.Id -eq 799) {
            Write-FlareGunLog "Event 799: Deep Diagnostics Collection" "INFO"
            Invoke-DeepDiagnostics
        } else {
            # Send SYSTEM context flare
            Write-FlareGunLog "Sending SYSTEM context flare: /$flareTag (Event ID $($event.Id))" "INFO"
            Send-SystemFlare -Tag $flareTag
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

Write-FlareGunLog "WhiteWalker FlareGun SYSTEM Handler Exiting" "INFO"
Write-FlareGunLog "========================================" "INFO"

exit 0
