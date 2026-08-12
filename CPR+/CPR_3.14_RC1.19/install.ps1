#Requires -RunAsAdministrator
<#
.SYNOPSIS
WhiteWalker Installation Script

.DESCRIPTION
Version: RC1.18-merged  (see $WW_Version in script body - update that, not this)
Author: steve.horton@optum.com
Date: 29-May-2026

========================================
Test Summary (from RC1.10)
========================================
Total:   268 tests
Passed:  261 ✅ (97.4% pass rate)
Failed:  0   🎯 (ZERO failures)
Skipped: 7   ⏭️ (intentional skips)
========================================

✅ Core VPN Logic (WW_main.ps1)
Blackhole VPN hairpin prevention (Invoke-BlackholeAction)
ISE posture compliance detection
Captive portal remediation
Network state detection (mgmt_tun vs user_tun vs no_vpn)
Log rotation (size-based, 5-file retention)
DNS chicken/egg problem detection
APIPA early exit logic
WLANi03 corporate SSID handling

✅ Captive Portal Runner (WW_cap_portal_runner.ps1)
Smart wait with polling (3s timeout fix - ER3 critical!)
Browser management (Edge fallback → default browser)
Cisco browser killer background job
Timeout notification with user-driven retry/exit
Network reconnect automation (WiFi disconnect/reconnect)
Flag file JSON contract validation

Test Coverage Highlights
Component               Tests       Coverage
Invoke-BlackholeAction  56 tests    On-prem detection, -add/-rm logic, WhatIf mode, startup safety
Get-NwCheckResult       11 tests    HTTP 200, 404 w/signature, redirects, unreachable states
Invoke-LogRotation      7 tests     1MB threshold, .1-.5 file shifting, missing file handling
Captive Portal Flow     47 tests    Browser launch, timeout handling, DNS detection, validation
VPN Tunnel Detection    8 tests     mgmt_tun, user_tun, no_vpn, fallback parsing
Network Reconnect       18 tests    SSID detection, disconnect/reconnect, retry flow
Configuration Defaults  21 tests    All config values verified against production requirements

🎯 Production Readiness Checklist
✅ Zero failures across all test scenarios
✅ Edge cases covered: timeouts, hangs, DNS failures, missing files
✅ Mocking strategy: All external calls isolated (Start-Process, Invoke-WebRequest, file I/O)
✅ Regression protection: ER3 timeout fix validated (3s vs 8s hang scenario)
✅ Contract testing: JSON flag files, flare tags, log formats
✅ Background job safety: Cisco killer cleanup, timeout handling
✅ User interaction: Notification display, retry/exit flow

Performs clean installation of WhiteWalker framework:
- Removes old Task Scheduler jobs
- Removes old script files (preserves logs and diagnostics)
- Removes stale flag files (NEW in 4.0.1 - fixes ER3→ER4 upgrade issues)
- Removes HayStack reroll stamp on upgrade so first run forces a clean reroll (NEW in RC1.14)
- Copies new scripts to deployment directories
- Deploys diagnostic scripts alongside main files (NEW in 4.1.0 - WW_diagnostics.ps1)
- Deploys tail scripts alongside main files (NEW in 4.1.0 - tail_ww_log.ps1, tail_ww_cap_log.ps1, tail_haystack_log.ps1)
- Deploys test scripts for validation (NEW in RC1.10)
- Deploys configuration files (including hostsinkhole.cfg, allowgroups.cfg)
- Deploys HayStack subsystem: haystack.ps1, haystack_action.ps1, needles.cfg, needles_local.cfg (NEW in RC1.14)
- Registers Task Scheduler jobs (including WW_notify)
- Validates installation

IMPORTANT: Run from any directory - script finds its own location
#>

# =============================================================================
# Version - update this ONE place on each release
# =============================================================================
$WW_Version = "RC1.19_merged"

# Script self-location (works from any directory)
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Deployment paths (variablized for future relocation)
$MainScriptDeployDir = "C:\ProgramData\WhiteWalker"      # TODO: Move to protected dir when OS team identifies location
$CapPortalDeployDir  = "C:\ProgramData\WhiteWalker"      # Stays here (needs USER context write access)
$ConfigDeployDir     = "C:\ProgramData\WhiteWalker"
$LogDir              = "C:\ProgramData\WhiteWalker"
$DiagDir             = "C:\ProgramData\WhiteWalker\diagnostics"
# Subdirectories to mirror from repo into deploy dir (archive and logs intentionally excluded)
# deploy dir.
$SubDirsToMirror = @(
    @{ Source = "$ScriptRoot\docs";        Dest = "C:\ProgramData\WhiteWalker\docs";        Label = "docs" }
    @{ Source = "$ScriptRoot\tests";       Dest = "C:\ProgramData\WhiteWalker\tests";       Label = "tests" }
    @{ Source = "$ScriptRoot\triggers";    Dest = "C:\ProgramData\WhiteWalker\triggers";    Label = "triggers" }
    @{ Source = "$ScriptRoot\diagnostics"; Dest = "C:\ProgramData\WhiteWalker\diagnostics"; Label = "diagnostics" }
    # archive  - dev artifact, never deployed
    # logs     - runtime generated, never touched by installer
)
# Convenience refs used elsewhere in this script
$DocsDeployDir  = ($SubDirsToMirror | Where-Object { $_.Label -eq "docs" }).Dest

# Installation log
$InstallLog = "$LogDir\white_walker_install.log"

# Script files to deploy (merged from both RC1.10 and v4.0.1)
$ScriptFiles = @(
    # === Core scripts ===
    @{ Name = "WW_main.ps1";              Source = "$ScriptRoot\WW_main.ps1";              Dest = $MainScriptDeployDir }
    @{ Name = "WW_cap_portal_runner.ps1"; Source = "$ScriptRoot\WW_cap_portal_runner.ps1"; Dest = $CapPortalDeployDir }
    @{ Name = "WW_flaregun_system.ps1";   Source = "$ScriptRoot\WW_flaregun_system.ps1";   Dest = $MainScriptDeployDir }
    @{ Name = "WW_flaregun_user.ps1";     Source = "$ScriptRoot\WW_flaregun_user.ps1";     Dest = $MainScriptDeployDir }
    @{ Name = "WW_collect_diag.ps1";      Source = "$ScriptRoot\WW_collect_diag.ps1";      Dest = $MainScriptDeployDir }
    @{ Name = "WW_diagnostics.ps1";       Source = "$ScriptRoot\WW_diagnostics.ps1";       Dest = $MainScriptDeployDir }
    @{ Name = "Set-VpnHostsEntry.ps1";    Source = "$ScriptRoot\Set-VpnHostsEntry.ps1";    Dest = $MainScriptDeployDir }
    

    # === Notification script (from v4.0.1) ===
    @{ Name = "WW_notify.ps1";            Source = "$ScriptRoot\WW_notify.ps1";            Dest = $MainScriptDeployDir }

    # === Tail scripts ===
    @{ Name = "tail_ww_log.ps1";          Source = "$ScriptRoot\tail_ww_log.ps1";          Dest = $MainScriptDeployDir }
    @{ Name = "tail_ww_cap_log.ps1";      Source = "$ScriptRoot\tail_ww_cap_log.ps1";      Dest = $MainScriptDeployDir }
    @{ Name = "tail_ww_blackhole.ps1";    Source = "$ScriptRoot\tail_ww_blackhole.ps1";    Dest = $MainScriptDeployDir }
    @{ Name = "tail_haystack_log.ps1";    Source = "$ScriptRoot\tail_haystack_log.ps1";    Dest = $MainScriptDeployDir }

    # === HayStack subsystem (RC1.14) ===
    @{ Name = "haystack.ps1";             Source = "$ScriptRoot\haystack.ps1";             Dest = $MainScriptDeployDir }
    @{ Name = "haystack_action.ps1";      Source = "$ScriptRoot\haystack_action.ps1";      Dest = $MainScriptDeployDir }
    @{ Name = "needles.cfg";              Source = "$ScriptRoot\needles.cfg";              Dest = $MainScriptDeployDir }
    @{ Name = "needles_local.cfg";        Source = "$ScriptRoot\needles_local.cfg";        Dest = $MainScriptDeployDir }
    @{ Name = "WW_syslog.ps1";            Source = "$ScriptRoot\WW_syslog.ps1";            Dest = $MainScriptDeployDir }

    # NOTE: Test scripts deployed via Copy-DirectoryContents from tests/ dir - no explicit entries needed
    # NOTE: Docs deployed via Copy-DirectoryContents from docs/ dir - no explicit entries needed

    # === Config files ===
    @{ Name = "hostsinkhole.cfg";         Source = "$ScriptRoot\hostsinkhole.cfg";         Dest = $MainScriptDeployDir }
    @{ Name = "allowgroups.cfg";          Source = "$ScriptRoot\allowgroups.cfg";          Dest = $MainScriptDeployDir }
    @{ Name = "trusted_ssids.cfg";        Source = "$ScriptRoot\trusted_ssids.cfg";        Dest = $MainScriptDeployDir }
)

# Config files to deploy
$ConfigFiles = @(
    @{ Name = "WW_flaregun_config.json"; Source = "$ScriptRoot\WW_flaregun_config.json"; Dest = $ConfigDeployDir }
)

# Task Scheduler XMLs to register (merged - includes WW_notify from v4.0.1)
$TaskXMLs = @(
    @{ Name = "WW_main";              Path = "$ScriptRoot\triggers\WW_main.xml" }
    @{ Name = "WW_cap_portal_runner"; Path = "$ScriptRoot\triggers\WW_cap_portal_runner.xml" }
    @{ Name = "WW_flaregun_user";     Path = "$ScriptRoot\triggers\WW_flaregun_user.xml" }
    @{ Name = "WW_flaregun_system";   Path = "$ScriptRoot\triggers\WW_flaregun_system.xml" }
    @{ Name = "WW_notify";            Path = "$ScriptRoot\triggers\WW_notify.xml" }
    @{ Name = "WW_blackhole_shutdown"; Path = "$ScriptRoot\triggers\WW_blackhole_shutdown.xml" }
)

# Known WhiteWalker task names (for clean uninstall - merged, includes WW_notify)
$KnownTaskNames = @(
    "WW_main",
    "WW_cap_portal_runner",
    "WW_flaregun_user",
    "WW_flaregun_system",
    "WW_notify",                     # From v4.0.1
    "HayStack_Monitor",              # RC1.14 - self-registered by haystack.ps1 -reroll
    "WW_blackhole_shutdown",          # RC1.18 - managed by Sync-BlackholeShutdownTask in WW_main
    "WhiteWalker_Main",              # Legacy names
    "WhiteWalker_CapPortal"          # Legacy names
)

# ================================ FUNCTIONS ===================================

function Write-InstallLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logLine = "$timestamp [$Level] $Message"
    
    # Console output
    switch ($Level) {
        "ERROR"   { Write-Host $logLine -ForegroundColor Red }
        "WARN"    { Write-Host $logLine -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logLine -ForegroundColor Green }
        default   { Write-Host $logLine }
    }
    
    # File output
    try {
        Add-Content -Path $InstallLog -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if can't write to log (might not exist yet)
    }
}

function Remove-OldTasks {
    Write-InstallLog "=== Removing Old Task Scheduler Jobs ===" "INFO"
    
    $removedCount = 0
    foreach ($taskName in $KnownTaskNames) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                Write-InstallLog "Removed task: $taskName" "SUCCESS"
                $removedCount++
            } else {
                Write-InstallLog "Task not found (OK): $taskName" "DEBUG"
            }
        } catch {
            Write-InstallLog "Error removing task $taskName : $_" "WARN"
        }
    }
    
    Write-InstallLog "Removed $removedCount old task(s)" "INFO"
}

function Remove-OldScripts {
    Write-InstallLog "=== Removing Old Script Files ===" "INFO"
    
    $removedCount = 0
    # RC1.14: added haystack*.ps1 and Run-HaystackTests.ps1 patterns
    $scriptPatterns = @("WW_*.ps1", "WhiteWalker*.ps1", "Set-Vpn*.ps1", "haystack*.ps1", "Run-HaystackTests.ps1")
    
    foreach ($dir in @($MainScriptDeployDir, $CapPortalDeployDir)) {
        if (Test-Path $dir) {
            foreach ($pattern in $scriptPatterns) {
                try {
                    $oldScripts = Get-ChildItem -Path $dir -Filter $pattern -File -ErrorAction SilentlyContinue
                    foreach ($script in $oldScripts) {
                        Remove-Item -Path $script.FullName -Force -ErrorAction Stop
                        Write-InstallLog "Removed old script: $($script.Name)" "SUCCESS"
                        $removedCount++
                    }
                } catch {
                    Write-InstallLog "Error removing scripts with pattern $pattern : $_" "WARN"
                }
            }
        }
    }
    
    # Remove old config files
    try {
        $oldConfigs = Get-ChildItem -Path $ConfigDeployDir -Filter "WW_*.json" -File -ErrorAction SilentlyContinue
        foreach ($config in $oldConfigs) {
            Remove-Item -Path $config.FullName -Force -ErrorAction Stop
            Write-InstallLog "Removed old config: $($config.Name)" "SUCCESS"
            $removedCount++
        }
    } catch {
        Write-InstallLog "Error removing old configs: $_" "WARN"
    }
    
    Write-InstallLog "Removed $removedCount old file(s)" "INFO"
}

function Remove-StaleFlagFiles {
    Write-InstallLog "=== Removing Stale Flag Files ===" "INFO"
    
    # Known flag files that can cause upgrade issues if left from previous versions
    $flagFiles = @(
        "$MainScriptDeployDir\portal_complete.flag",
        "$MainScriptDeployDir\network_interrupt.flag",
        "$MainScriptDeployDir\cap_portal_remediation_active.flag",
        "$MainScriptDeployDir\captive_failure.flag",
        "$MainScriptDeployDir\user_prompted.flag",
        # HayStack reroll stamp - cleared on install so first run always forces a clean reroll
        "$MainScriptDeployDir\haystack_reroll.stamp"
    )
    
    $removedCount = 0
    foreach ($flagFile in $flagFiles) {
        if (Test-Path $flagFile) {
            try {
                Remove-Item -Path $flagFile -Force -ErrorAction Stop
                Write-InstallLog "Removed stale flag: $(Split-Path $flagFile -Leaf)" "SUCCESS"
                $removedCount++
            } catch {
                Write-InstallLog "Error removing flag file $flagFile : $_" "WARN"
            }
        }
    }
    
    # Also remove any *.flag files we might have missed
    try {
        $wildcardFlags = Get-ChildItem -Path $MainScriptDeployDir -Filter "*.flag" -File -ErrorAction SilentlyContinue
        foreach ($flag in $wildcardFlags) {
            if (-not ($flagFiles -contains $flag.FullName)) {
                Remove-Item -Path $flag.FullName -Force -ErrorAction Stop
                Write-InstallLog "Removed unknown flag: $($flag.Name)" "SUCCESS"
                $removedCount++
            }
        }
    } catch {
        Write-InstallLog "Error removing wildcard flags: $_" "WARN"
    }
    
    if ($removedCount -eq 0) {
        Write-InstallLog "No stale flag files found" "DEBUG"
    } else {
        Write-InstallLog "Removed $removedCount stale flag file(s)" "INFO"
    }
}

function Ensure-Directories {
    Write-InstallLog "=== Ensuring Directory Structure ===" "INFO"
    
    $directories = @($MainScriptDeployDir, $CapPortalDeployDir, $ConfigDeployDir, $LogDir, $DiagDir) +
                   ($SubDirsToMirror | ForEach-Object { $_.Dest })
    $uniqueDirs = $directories | Select-Object -Unique
    
    foreach ($dir in $uniqueDirs) {
        if (-not (Test-Path $dir)) {
            try {
                New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-InstallLog "Created directory: $dir" "SUCCESS"
            } catch {
                Write-InstallLog "ERROR creating directory $dir : $_" "ERROR"
                return $false
            }
        } else {
            Write-InstallLog "Directory exists: $dir" "DEBUG"
        }
    }
    
    return $true
}

function Copy-DirectoryContents {
    <#
    .SYNOPSIS
    Copy all files from a source directory to a destination directory.
    Non-recursive by default. Skips gracefully if source dir does not exist.
    Avoids the need to enumerate files individually in the installer.
    #>
    param(
        [string]$SourceDir,
        [string]$DestDir,
        [string]$Label,
        [switch]$Recurse
    )

    Write-InstallLog "=== Copying $Label ===" "INFO"

    if (-not (Test-Path $SourceDir)) {
        Write-InstallLog "Source dir not found - skipping: $SourceDir" "WARN"
        return $true  # non-fatal - dir may not exist in all builds
    }

    $files = Get-ChildItem -Path $SourceDir -File -ErrorAction SilentlyContinue
    if ($Recurse) {
        $files = Get-ChildItem -Path $SourceDir -File -Recurse -ErrorAction SilentlyContinue
    }

    if (-not $files -or $files.Count -eq 0) {
        Write-InstallLog "Source dir is empty - nothing to copy: $SourceDir" "WARN"
        return $true
    }

    $copiedCount = 0
    $errors      = 0

    foreach ($file in $files) {
        # Preserve relative subdir structure when -Recurse is used
        $relativePath = $file.FullName.Substring($SourceDir.Length).TrimStart("\/")
        $destFile     = Join-Path $DestDir $relativePath
        $destSubDir   = Split-Path $destFile -Parent

        if (-not (Test-Path $destSubDir)) {
            try {
                New-Item -Path $destSubDir -ItemType Directory -Force | Out-Null
            } catch {
                Write-InstallLog "ERROR creating subdir $destSubDir : $_" "ERROR"
                $errors++
                continue
            }
        }

        try {
            Copy-Item -Path $file.FullName -Destination $destFile -Force -ErrorAction Stop
            Write-InstallLog "Copied: $relativePath -> $DestDir" "SUCCESS"
            $copiedCount++
        } catch {
            Write-InstallLog "ERROR copying $($file.Name): $_" "ERROR"
            $errors++
        }
    }

    Write-InstallLog "Copied $copiedCount file(s) from $Label, $errors error(s)" "INFO"
    return ($errors -eq 0)
}

function Copy-ScriptFiles {
    Write-InstallLog "=== Copying Script Files ===" "INFO"
    
    $copiedCount = 0
    $errors = 0
    
    foreach ($file in $ScriptFiles) {
        if (Test-Path $file.Source) {
            try {
                Copy-Item -Path $file.Source -Destination $file.Dest -Force -ErrorAction Stop
                Write-InstallLog "Copied: $($file.Name) -> $($file.Dest)" "SUCCESS"
                $copiedCount++
            } catch {
                Write-InstallLog "ERROR copying $($file.Name): $_" "ERROR"
                $errors++
            }
        } else {
            Write-InstallLog "ERROR: Source file not found: $($file.Source)" "ERROR"
            $errors++
        }
    }
    
    Write-InstallLog "Copied $copiedCount script file(s), $errors error(s)" "INFO"
    return ($errors -eq 0)
}

function Copy-ConfigFiles {
    Write-InstallLog "=== Copying Configuration Files ===" "INFO"
    
    $copiedCount = 0
    $errors = 0
    
    foreach ($file in $ConfigFiles) {
        if (Test-Path $file.Source) {
            try {
                Copy-Item -Path $file.Source -Destination $file.Dest -Force -ErrorAction Stop
                Write-InstallLog "Copied: $($file.Name) -> $($file.Dest)" "SUCCESS"
                $copiedCount++
            } catch {
                Write-InstallLog "ERROR copying $($file.Name): $_" "ERROR"
                $errors++
            }
        } else {
            Write-InstallLog "ERROR: Config file not found: $($file.Source)" "ERROR"
            $errors++
        }
    }
    
    Write-InstallLog "Copied $copiedCount config file(s), $errors error(s)" "INFO"
    return ($errors -eq 0)
}

function Register-Tasks {
    Write-InstallLog "=== Registering Task Scheduler Jobs ===" "INFO"
    
    $registeredCount = 0
    $errors = 0
    
    foreach ($task in $TaskXMLs) {
        if (Test-Path $task.Path) {
            try {
                $xmlContent = Get-Content $task.Path -Raw -ErrorAction Stop
                Register-ScheduledTask -Xml $xmlContent -TaskName $task.Name -Force -ErrorAction Stop | Out-Null
                Write-InstallLog "Registered task: $($task.Name)" "SUCCESS"
                $registeredCount++
            } catch {
                Write-InstallLog "ERROR registering task $($task.Name): $_" "ERROR"
                $errors++
            }
        } else {
            Write-InstallLog "ERROR: Task XML not found: $($task.Path)" "ERROR"
            $errors++
        }
    }
    
    Write-InstallLog "Registered $registeredCount task(s), $errors error(s)" "INFO"
    return ($errors -eq 0)
}

function Test-Installation {
    Write-InstallLog "=== Validating Installation ===" "INFO"
    
    $allGood = $true
    
    # Check scripts deployed
    Write-InstallLog "Checking deployed scripts..." "DEBUG"
    foreach ($file in $ScriptFiles) {
        $deployedPath = Join-Path $file.Dest $file.Name
        if (Test-Path $deployedPath) {
            Write-InstallLog "  OK: $($file.Name)" "DEBUG"
        } else {
            Write-InstallLog "  MISSING: $deployedPath" "ERROR"
            $allGood = $false
        }
    }

    # Check mirrored subdirs deployed
    Write-InstallLog "Checking mirrored subdirectories..." "DEBUG"
    foreach ($dir in $SubDirsToMirror) {
        if (Test-Path $dir.Dest) {
            $fileCount = (Get-ChildItem -Path $dir.Dest -File -ErrorAction SilentlyContinue).Count
            Write-InstallLog "  OK: $($dir.Label)/ ($fileCount file(s))" "DEBUG"
        } else {
            Write-InstallLog "  MISSING: $($dir.Dest)" "WARN"
        }
    }
    
    # Check configs deployed
    Write-InstallLog "Checking deployed configs..." "DEBUG"
    foreach ($file in $ConfigFiles) {
        $deployedPath = Join-Path $file.Dest $file.Name
        if (Test-Path $deployedPath) {
            Write-InstallLog "  OK: $($file.Name)" "DEBUG"
        } else {
            Write-InstallLog "  MISSING: $deployedPath" "ERROR"
            $allGood = $false
        }
    }
    
    # Check tasks registered
    Write-InstallLog "Checking registered tasks..." "DEBUG"
    foreach ($task in $TaskXMLs) {
        $scheduledTask = Get-ScheduledTask -TaskName $task.Name -ErrorAction SilentlyContinue
        if ($scheduledTask) {
            $state = $scheduledTask.State
            Write-InstallLog "  OK: $($task.Name) (State: $state)" "DEBUG"
        } else {
            Write-InstallLog "  MISSING: $($task.Name)" "ERROR"
            $allGood = $false
        }
    }
    
    return $allGood
}

# ================================== MAIN ======================================

Write-InstallLog "" "INFO"
Write-InstallLog "========================================" "INFO"
Write-InstallLog "WhiteWalker Installer $WW_Version" "INFO"
Write-InstallLog "========================================" "INFO"
Write-InstallLog "Script location: $ScriptRoot" "INFO"
Write-InstallLog "Install log: $InstallLog" "INFO"
Write-InstallLog "" "INFO"

# Check admin rights
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-InstallLog "ERROR: This script must be run as Administrator!" "ERROR"
    Write-InstallLog "Right-click PowerShell and select 'Run as Administrator'" "ERROR"
    exit 1
}

# Step 1: Clean uninstall
Remove-OldTasks
Remove-OldScripts
Remove-StaleFlagFiles

# Step 2: Ensure directories
if (-not (Ensure-Directories)) {
    Write-InstallLog "FATAL: Failed to create required directories" "ERROR"
    exit 1
}

# Step 3: Copy files
$scriptsOK = Copy-ScriptFiles
$configsOK = Copy-ConfigFiles
# Mirror all subdirectories from repo into deploy dir
$dirsOK = $true
foreach ($dir in $SubDirsToMirror) {
    $ok = Copy-DirectoryContents -SourceDir $dir.Source -DestDir $dir.Dest -Label $dir.Label
    if (-not $ok) { $dirsOK = $false }
}

# README.txt from repo root - informational, non-fatal if absent
$readmeSrc = Join-Path $ScriptRoot "README.txt"
if (Test-Path $readmeSrc) {
    try {
        Copy-Item -Path $readmeSrc -Destination $MainScriptDeployDir -Force -ErrorAction Stop
        Write-InstallLog "Copied: README.txt -> $MainScriptDeployDir" "SUCCESS"
    } catch {
        Write-InstallLog "Could not copy README.txt: $_" "WARN"
    }
}

if (-not $scriptsOK -or -not $configsOK -or -not $dirsOK) {
    Write-InstallLog "FATAL: Failed to copy required files" "ERROR"
    exit 1
}

# Step 4: Register tasks
$tasksOK = Register-Tasks

if (-not $tasksOK) {
    Write-InstallLog "FATAL: Failed to register Task Scheduler jobs" "ERROR"
    exit 1
}

# Step 5: Validation
Write-InstallLog "" "INFO"
$validated = Test-Installation

if ($validated) {
    Write-InstallLog "" "INFO"
    Write-InstallLog "========================================" "SUCCESS"
    Write-InstallLog "$WW_Version Installation completed successfully!" "SUCCESS"
    Write-InstallLog "========================================" "SUCCESS"
    Write-InstallLog "" "INFO"
    Write-InstallLog "WhiteWalker is now active and monitoring:" "INFO"
    Write-InstallLog "  - DHCP lease events" "INFO"
    Write-InstallLog "  - VPN state changes" "INFO"
    Write-InstallLog "  - Session unlock events" "INFO"
    Write-InstallLog "" "INFO"
    Write-InstallLog "HayStack subsystem deployed to: $MainScriptDeployDir" "INFO"
    Write-InstallLog "  needles.cfg       - shared trigger definitions (edit on NETLOGON share)" "INFO"
    Write-InstallLog "  needles_local.cfg - per-machine test needles (edit locally, never synced)" "INFO"
    Write-InstallLog "  Run first reroll: .\haystack.ps1 -reroll -Force" "INFO"
    Write-InstallLog "  Tail log:         .\tail_haystack_log.ps1" "INFO"
    Write-InstallLog "" "INFO"
    Write-InstallLog "Logs: $LogDir" "INFO"
    Write-InstallLog "Diagnostics: $DiagDir" "INFO"
    exit 0
} else {
    Write-InstallLog "" "ERROR"
    Write-InstallLog "========================================" "ERROR"
    Write-InstallLog "$WW_Version Installation validation FAILED!" "ERROR"
    Write-InstallLog "========================================" "ERROR"
    Write-InstallLog "Review errors above and retry installation" "ERROR"
    exit 1
}
