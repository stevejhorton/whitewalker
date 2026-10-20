#Requires -RunAsAdministrator
<#
.SYNOPSIS
WhiteWalker Installation Script

.DESCRIPTION
Version: RC2.0.1  (see $WW_Version in script body - update that, not this)
Author: steve.horton@optum.com
Date: 23-Jun-2026

Exit codes:
  0 = success
  1 = generic failure (fallback)
  2 = not running as Administrator
  3 = failed to create required directories
  4 = failed to copy required files
  5 = failed to register scheduled tasks
  6 = post-install validation failed
  9 = unexpected/unhandled installer error

========================================
Test Summary (from RC1.10)
========================================
Total:   268 tests
Passed:  261 (97.4% pass rate)
Failed:  0   (ZERO failures)
Skipped: 7   (intentional skips)
========================================

Core VPN Logic (WW_main.ps1)
Blackhole VPN hairpin prevention (Invoke-BlackholeAction)
ISE posture compliance detection
Captive portal remediation
Network state detection (mgmt_tun vs user_tun vs no_vpn)
Log rotation (size-based, 5-file retention)
DNS chicken/egg problem detection
APIPA early exit logic
WLANi03 corporate SSID handling

Captive Portal Runner (WW_cap_portal_runner.ps1)
Smart wait with polling (3s timeout fix - ER3 critical!)
Browser management (Edge fallback -> default browser)
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

Production Readiness Checklist
Zero failures across all test scenarios
Edge cases covered: timeouts, hangs, DNS failures, missing files
Mocking strategy: All external calls isolated (Start-Process, Invoke-WebRequest, file I/O)
Regression protection: ER3 timeout fix validated (3s vs 8s hang scenario)
Contract testing: JSON flag files, flare tags, log formats
Background job safety: Cisco killer cleanup, timeout handling
User interaction: Notification display, retry/exit flow

Performs clean installation of WhiteWalker framework:
- Removes old Task Scheduler jobs
- Removes old script files (preserves logs and diagnostics)
- Removes stale flag files (NEW in 4.0.1 - fixes ER3->ER4 upgrade issues)
- Removes HayStack reroll stamp on upgrade so first run forces a clean reroll (NEW in RC1.14)
- Removes the HayStack defender_flags directory on install/uninstall so Defender checks rerun fresh
- Copies new scripts to deployment directories
- Deploys diagnostic scripts alongside main files (NEW in 4.1.0 - WW_diagnostics.ps1)
- Deploys tail scripts alongside main files (NEW in 4.1.0 - tail_ww_log.ps1, tail_ww_cap_log.ps1, tail_haystack_log.ps1)
- Deploys test scripts for validation (NEW in RC1.10)
- Deploys configuration files (including hostsinkhole.cfg, allowgroups.cfg)
- Deploys HayStack subsystem: haystack.ps1, haystack_action.ps1, needles.cfg, needles_local.cfg (NEW in RC1.14),
  WW_haystack_schema.ps1 + support_files\haystack_msg_schema.psd1 (NEW in RC1.24's install manifest - these two
  files shipped in RC1.21 via PR #58 but were never added to $ScriptFiles/$SchemaFiles, so lint/validation never
  actually ran on deployed endpoints; fixed in RC1.24)
  RC1.25: haystack_msg_schema.psd1 is now ALSO deployed to support_files\ (the layout Get-HaystackMsgSchema
  probes first), and Test-RequiredHelperDeployment warns when any required telemetry helper is missing.
  Also deploys diagnostics\New-DefenderNeedlePreview.ps1 for read-only MDM firewall rule discovery.
- Deploys Log-and-Tee subsystem: WW_tee.ps1, WW_tee_events.psd1 (create-only), tee_profiles\ (NEW in RC1.20)
- Registers Task Scheduler jobs (including WW_notify)
- Validates installation

IMPORTANT: Run from any directory - script finds its own location

Uninstall usage:
  ./install.ps1 -Uninstall
  ./install.ps1 -rm
  ./install.ps1 -Remove
#>

param(
    # Uninstalls WhiteWalker: removes scheduled tasks, deployed scripts, configs,
    # schemas, and mirrored subdirs (docs/tests/triggers/tee_profiles). Logs and
    # diagnostics are preserved. Aliased so ./install.ps1 -rm or -Remove also work.
    [Alias('rm','Remove')]
    [switch]$Uninstall
)

# =============================================================================
# Version - update this ONE place on each release
# =============================================================================
$WW_Version = "RC2.0.1"

# Task Scheduler folder for ALL CPR jobs. KEEP IN SYNC with $CprTaskFolder in
# main\Main.Configuration.ps1 and $TsTaskPath in haystack.ps1 (a Pester test enforces it).
$CprTaskFolder = "\CPR\"

# Installer exit codes
$ExitCodeSuccess            = 0
$ExitCodeGenericFailure     = 1
$ExitCodeNotAdmin           = 2
$ExitCodeDirectorySetupFail = 3
$ExitCodeFileCopyFail       = 4
$ExitCodeTaskRegisterFail   = 5
$ExitCodeValidationFail     = 6
$ExitCodeUninstallIncomplete = 7   # -Uninstall could not remove everything (see C:\Windows\Temp\white_walker_uninstall.log)
$ExitCodeUnexpectedError    = 9

# Script self-location (works from any directory)
$InstallerScriptPath = $MyInvocation.MyCommand.Path
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Deployment paths (variablized for future relocation)
$MainScriptDeployDir = "C:\ProgramData\WhiteWalker"      # TODO: Move to protected dir when OS team identifies location
$CapPortalDeployDir  = "C:\ProgramData\WhiteWalker"      # Stays here (needs USER context write access)
$ConfigDeployDir     = "C:\ProgramData\WhiteWalker"
$LogDir              = "C:\ProgramData\WhiteWalker\logs"
$DiagDir             = "C:\ProgramData\WhiteWalker\diagnostics"
$SupportFilesDeployDir = "C:\ProgramData\WhiteWalker\support_files"
$InstallResultQueueFile = Join-Path $LogDir "haystack_syslog_queue.jsonl"
# RC2.1 (Required G): narrowly scoped USER telemetry drop directory. The
# captive-portal runners execute as the interactive user and cannot append to
# the SYSTEM-owned queue above; they drop one atomic file per event here and
# haystack_action.ps1 (SYSTEM) ingests them. The ACL grants Authenticated Users
# create/append on THIS DIRECTORY ONLY - never on scripts or configuration.
$TelemetrySpoolDir      = Join-Path $LogDir "spool"
$PendingInstallEventDir = "C:\ProgramData\WhiteWalkerPending"
# Subdirectories to mirror from repo into deploy dir (archive and logs intentionally excluded)
# deploy dir.
$SubDirsToMirror = @(
    @{ Source = "$ScriptRoot\docs";        Dest = "C:\ProgramData\WhiteWalker\docs";        Label = "docs" }
    @{ Source = "$ScriptRoot\tests";       Dest = "C:\ProgramData\WhiteWalker\tests";       Label = "tests" }
    @{ Source = "$ScriptRoot\triggers";    Dest = "C:\ProgramData\WhiteWalker\triggers";    Label = "triggers" }
    @{ Source = "$ScriptRoot\diagnostics"; Dest = "C:\ProgramData\WhiteWalker\diagnostics"; Label = "diagnostics" }
    @{ Source = "$ScriptRoot\main";        Dest = "C:\ProgramData\WhiteWalker\main";        Label = "main" }
    # admin - tech-facing admin/diagnostic/action tools (distinct from core runtime
    # scripts): Watch-WhiteWalkerLog.ps1 (log viewer) and Invoke-WhiteWalkerAction.ps1
    # (action console). Mirrored in full like main/ so techs always have the current
    # set of admin tools without needing an explicit $ScriptFiles entry per script.
    @{ Source = "$ScriptRoot\admin";       Dest = "C:\ProgramData\WhiteWalker\admin";       Label = "admin" }
    # tee_profiles - the tee volume-knob profiles (level_0 through level_5). Always mirrored
    # in full on every install/upgrade so techs always have the current full set to choose
    # from. This is SEPARATE from WW_tee_events.psd1 (the ACTIVE profile), which is
    # deliberately create-only - see Copy-TeeEventsIfMissing below.
    @{ Source = "$ScriptRoot\tee_profiles"; Dest = "C:\ProgramData\WhiteWalker\tee_profiles"; Label = "tee_profiles" }
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
    @{ Name = "WW_cap_portal_runner_base.ps1"; Source = "$ScriptRoot\WW_cap_portal_runner_base.ps1"; Dest = $CapPortalDeployDir }
    @{ Name = "WW_flaregun_system.ps1";   Source = "$ScriptRoot\WW_flaregun_system.ps1";   Dest = $MainScriptDeployDir }
    @{ Name = "WW_flaregun_user.ps1";     Source = "$ScriptRoot\WW_flaregun_user.ps1";     Dest = $MainScriptDeployDir }
    @{ Name = "WW_collect_diag.ps1";      Source = "$ScriptRoot\WW_collect_diag.ps1";      Dest = $MainScriptDeployDir }
    @{ Name = "WW_diagnostics.ps1";       Source = "$ScriptRoot\WW_diagnostics.ps1";       Dest = $MainScriptDeployDir }
    @{ Name = "Set-VpnHostsEntry.ps1";    Source = "$ScriptRoot\Set-VpnHostsEntry.ps1";    Dest = $MainScriptDeployDir }
    @{ Name = "WW_csc_client_info.ps1";   Source = "$ScriptRoot\WW_csc_client_info.ps1";   Dest = $MainScriptDeployDir }
    @{ Name = "WW_tee.ps1";               Source = "$ScriptRoot\WW_tee.ps1";               Dest = $MainScriptDeployDir }
    

    # === Notification script (from v4.0.1) ===
    @{ Name = "WW_notify.ps1";            Source = "$ScriptRoot\WW_notify.ps1";            Dest = $MainScriptDeployDir }

    # === Tail scripts ===
    # NOTE: Watch-WhiteWalkerLog.ps1 deployed via admin/ (mirrored subdir), not here.
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
    @{ Name = "WW_haystack_schema.ps1";   Source = "$ScriptRoot\WW_haystack_schema.ps1";   Dest = $MainScriptDeployDir }

    # === LEGACY-TASK-MIGRATION (TEMPORARY - remove with the migration; see script header) ===
    # One-shot: moves CPR jobs from root / \HayStack\ into \CPR\. Pivot:
    # $LegacyTaskMigrationEnabled in main\Main.Configuration.ps1. Delete this line when retiring it.
    @{ Name = "WW_migrate_legacy_tasks.ps1"; Source = "$ScriptRoot\WW_migrate_legacy_tasks.ps1"; Dest = $MainScriptDeployDir }

    # === HayStack diagnostics (operator-run, read-only) ===
    @{ Name = "New-NeedlePreview.ps1";    Source = "$ScriptRoot\diagnostics\New-NeedlePreview.ps1"; Dest = $DiagDir }
    @{ Name = "New-DefenderNeedlePreview.ps1"; Source = "$ScriptRoot\diagnostics\New-DefenderNeedlePreview.ps1"; Dest = $DiagDir }

    # === XmlVault subsystem (RC1.19) ===
    @{ Name = "WW_xml_vault.ps1";         Source = "$ScriptRoot\WW_xml_vault.ps1";         Dest = $MainScriptDeployDir }

    # === Master test runner ===
    @{ Name = "Run-AllTests.ps1";            Source = "$ScriptRoot\Run-AllTests.ps1";            Dest = $MainScriptDeployDir }

    # === Test runners and unit test files (root-level, deployed flat to WhiteWalker dir) ===
    @{ Name = "Run-WhiteWalkerTests.ps1";     Source = "$ScriptRoot\Run-WhiteWalkerTests.ps1";     Dest = $MainScriptDeployDir }
    @{ Name = "Run-HaystackTests.ps1";        Source = "$ScriptRoot\Run-HaystackTests.ps1";        Dest = $MainScriptDeployDir }
    @{ Name = "WW_Tests_Main.ps1";            Source = "$ScriptRoot\WW_Tests_Main.ps1";            Dest = $MainScriptDeployDir }
    @{ Name = "WW_Tests_CapPortalRunner.ps1"; Source = "$ScriptRoot\WW_Tests_CapPortalRunner.ps1"; Dest = $MainScriptDeployDir }
    @{ Name = "WW_Tests_Haystack.ps1";        Source = "$ScriptRoot\WW_Tests_Haystack.ps1";        Dest = $MainScriptDeployDir }
    @{ Name = "WW_Tests_TestDC.ps1";          Source = "$ScriptRoot\WW_Tests_TestDC.ps1";          Dest = $MainScriptDeployDir }
    @{ Name = "Check-CodeCoverage.ps1";       Source = "$ScriptRoot\Check-CodeCoverage.ps1";       Dest = $MainScriptDeployDir }
    @{ Name = "HaystackStandalone.Tests.ps1"; Source = "$ScriptRoot\HaystackStandalone.Tests.ps1"; Dest = $MainScriptDeployDir }
    @{ Name = "WW_cap_portal_runner.Tests.ps1"; Source = "$ScriptRoot\WW_cap_portal_runner.Tests.ps1"; Dest = $MainScriptDeployDir }

    # NOTE: tests/ subdir content deployed via Copy-DirectoryContents
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

# WW_tee_events.psd1 is the ACTIVE tee profile - it is a LIVE, tech-editable config,
# not a static asset. Unlike everything else in $ScriptFiles, this must NEVER be
# force-overwritten on upgrade, or a tech's chosen logging level (e.g. tee_level_3
# during an active investigation) would silently reset to whatever ships in the repo
# on every reinstall/upgrade. Copy-TeeEventsIfMissing (below) only deploys the repo's
# default copy if the file does not already exist on the box.
$TeeEventsDefaultFile = @{ Name = "WW_tee_events.psd1"; Source = "$ScriptRoot\WW_tee_events.psd1"; Dest = $MainScriptDeployDir }

# Schema files to deploy. TaskScheduler.xsd/AnyConnectProfile.xsd are reference-only
# (not actively used in validation). haystack_msg_schema.psd1 (NEW in RC1.24's install
# manifest - file itself shipped in RC1.21 via PR #58) IS actively used: it's the master
# HayStack telemetry contract dot-sourced at runtime by WW_haystack_schema.ps1's
# Import-HaystackSchemaHelpers (called from WW_tee.ps1/haystack_action.ps1) to lint/
# validate emitted payloads against mandatory fields (EvtTime/machine/user/action).
$SchemaFiles = @(
    @{ Name = "TaskScheduler.xsd";        Source = "$ScriptRoot\support_files\TaskScheduler.xsd";        Dest = $MainScriptDeployDir }
    @{ Name = "AnyConnectProfile.xsd";    Source = "$ScriptRoot\support_files\AnyConnectProfile.xsd";    Dest = $MainScriptDeployDir }
    @{ Name = "haystack_msg_schema.psd1"; Source = "$ScriptRoot\support_files\haystack_msg_schema.psd1"; Dest = $MainScriptDeployDir }
    # RC1.25: ALSO deploy the schema under support_files\, which is the layout
    # Get-HaystackMsgSchema probes first (Join-Path $PSScriptRoot
    # 'support_files\haystack_msg_schema.psd1'). RC1.24 only placed it flat in
    # the WhiteWalker root, so the runtime resolver never found it and schema
    # lint silently no-opped on every deployed endpoint.
    @{ Name = "haystack_msg_schema.psd1"; Source = "$ScriptRoot\support_files\haystack_msg_schema.psd1"; Dest = $SupportFilesDeployDir }
)

# =============================================================================
# Required runtime helpers (RC1.25)
# =============================================================================
# Files without which telemetry degrades silently rather than loudly:
#   WW_tee.ps1              - Write-TeeLog itself (no tee events at all if absent)
#   WW_haystack_schema.ps1  - Get-HaystackUserContext + schema lint. Absent =>
#                             user= falls back to an in-line probe and lint is off.
#   WW_tee_events.psd1      - the active tee profile (the volume knob)
#   haystack_msg_schema.psd1 - the schema contract the lint validates against
# Test-RequiredHelperDeployment warns (never fails the install) when one of
# these is missing after the copy phase, so the gap shows up in the install log
# instead of only as degraded fields in Splunk weeks later.
$RequiredRuntimeHelpers = @(
    @{ Name = "WW_tee.ps1";               Path = (Join-Path $MainScriptDeployDir "WW_tee.ps1") }
    @{ Name = "WW_haystack_schema.ps1";   Path = (Join-Path $MainScriptDeployDir "WW_haystack_schema.ps1") }
    @{ Name = "WW_tee_events.psd1";       Path = (Join-Path $MainScriptDeployDir "WW_tee_events.psd1") }
    @{ Name = "haystack_msg_schema.psd1"; Path = (Join-Path $SupportFilesDeployDir "haystack_msg_schema.psd1") }
)

# Task Scheduler XMLs to register (merged - includes WW_notify from v4.0.1)
$TaskXMLs = @(
    @{ Name = "WW_main";              TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_main.xml" }
    @{ Name = "WW_cap_portal_runner"; TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_cap_portal_runner.xml" }
    @{ Name = "WW_cap_portal_runner_base"; TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_cap_portal_runner_base.xml" }
    @{ Name = "WW_flaregun_user";     TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_flaregun_user.xml" }
    @{ Name = "WW_flaregun_system";   TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_flaregun_system.xml" }
    @{ Name = "WW_notify";            TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_notify.xml" }
    @{ Name = "WW_blackhole_shutdown"; TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_blackhole_shutdown.xml" }
    @{ Name = "WW_xml_vault";         TaskPath = $CprTaskFolder; Path = "$ScriptRoot\triggers\WW_xml_vault.xml" }
)

# Known WhiteWalker task names (for clean uninstall - merged, includes WW_notify)
$KnownTaskNames = @(
    "WW_main",
    "WW_cap_portal_runner",
    "WW_cap_portal_runner_base",
    "WW_flaregun_user",
    "WW_flaregun_system",
    "WW_notify",                     # From v4.0.1
    "HayStack_Monitor",              # RC1.14 - self-registered by haystack.ps1 -reroll
    "WW_blackhole_shutdown",          # RC1.18 - managed by Sync-BlackholeShutdownTask in WW_main
    "WW_xml_vault",                  # RC1.19 - managed by Sync-XmlVaultTask in WW_main
    "WhiteWalker_Main",              # Legacy names
    "WhiteWalker_CapPortal"          # Legacy names
)
$KnownTasks = @(
    $TaskXMLs | ForEach-Object { @{ Name = $_.Name; TaskPath = $_.TaskPath } }
) + @(
    @{ Name = "HayStack_Monitor"; TaskPath = $CprTaskFolder }
    @{ Name = "WhiteWalker_Main"; TaskPath = "\" }
    @{ Name = "WhiteWalker_CapPortal"; TaskPath = "\" }
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

function Exit-Installer {
    param(
        [int]$Code,
        [string]$Reason = ""
    )

    if ($Code -eq $ExitCodeSuccess) {
        Write-InstallLog "Installer exiting with code $Code (success)" "INFO"
    } else {
        if ([string]::IsNullOrWhiteSpace($Reason)) {
            Write-InstallLog "Installer exiting with code $Code" "ERROR"
        } else {
            Write-InstallLog "Installer exiting with code $Code ($Reason)" "ERROR"
        }
    }

    $resultAction = if ($Uninstall) { 'uninstall' } else { 'install' }
    Write-InstallResultEvent -Action $resultAction -ExitCode $Code -Reason $Reason
    exit $Code
}

function Get-InstallerTaskSnapshot {
    # One Task Scheduler provider call per phase. Filtering the in-memory snapshot
    # by exact name/path avoids the observed 3-7 second repeated lookup cost and
    # prevents same-named tasks in unrelated folders from being touched.
    return @(Get-ScheduledTask -ErrorAction SilentlyContinue)
}

# LEGACY-TASK-MIGRATION (TEMPORARY - remove with WW_migrate_legacy_tasks.ps1; block 1 of 2)
# Runs the one-shot migration of CPR jobs into \CPR\. Never fails the install: an
# incomplete migration is logged, left unflagged, and retried on the next install.
function Invoke-LegacyTaskMigrationStep {
    param([switch]$ForUninstall)   # uninstall removes legacy tasks regardless of the pivot or done-flag
    $script = Join-Path $ScriptRoot "WW_migrate_legacy_tasks.ps1"
    if (-not (Test-Path $script)) { Write-InstallLog "Legacy task migration: script not found ($script) - skipped" "WARN"; return }
    try {
        $res = if ($ForUninstall) { & $script -Force -IgnorePivot } else { & $script -ConfigPath (Join-Path $ScriptRoot "main\Main.Configuration.ps1") }
        if ($res.Ran) {
            $lvl = if ($res.Failed.Count -gt 0) { "WARN" } else { "SUCCESS" }
            Write-InstallLog ("Legacy task migration RAN: reason={0} removed={1} failed={2} (log: logs\legacy_task_migration.log)" -f $res.Reason, $res.Removed.Count, $res.Failed.Count) $lvl
        } else {
            Write-InstallLog "Legacy task migration skipped: $($res.Reason)" "INFO"
        }
    } catch {
        Write-InstallLog "Legacy task migration error (non-fatal): $_" "WARN"
    }
}

function Remove-OldTasks {
    Write-InstallLog "=== Removing Old Task Scheduler Jobs ===" "INFO"
    $phaseStartedAt = Get-Date
    $removedCount = 0
    $taskSnapshot = Get-InstallerTaskSnapshot
    foreach ($taskSpec in $KnownTasks) {
        $taskName = $taskSpec.Name
        $taskPath = $taskSpec.TaskPath
        $taskStartedAt = Get-Date
        try {
            $tasks = @($taskSnapshot | Where-Object {
                $_.TaskName -eq $taskName -and $_.TaskPath -eq $taskPath
            })
            if ($tasks.Count -gt 0) {
                foreach ($task in $tasks) {
                    Unregister-ScheduledTask -InputObject $task -Confirm:$false -ErrorAction Stop
                    Write-InstallLog "Removed task: $taskPath$taskName" "SUCCESS"
                    $removedCount += 1
                }
            } else {
                Write-InstallLog "Task not found (OK): $taskPath$taskName" "DEBUG"
            }
        } catch {
            Write-InstallLog "Error removing task $taskPath$taskName : $_" "WARN"
        }
        $taskElapsedMs = [math]::Round(((Get-Date) - $taskStartedAt).TotalMilliseconds)
        if ($taskElapsedMs -ge 1000) {
            Write-InstallLog "task_action_timing action=remove task='$taskPath$taskName' elapsed_ms=$taskElapsedMs" "WARN"
        }
    }
    Write-InstallLog "Removed $removedCount old task(s)" "INFO"
    Write-InstallLog ("installer_phase_timing phase=task_removal elapsed_ms={0} snapshot_count={1}" -f `
        [math]::Round(((Get-Date) - $phaseStartedAt).TotalMilliseconds), $taskSnapshot.Count) "INFO"
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

            # RC1.25 self-copy policy: install.ps1 belongs only in support_files.
            # Remove the duplicate root copy left by older bulk-copy deployments, but
            # never remove the intended uninstall copy under support_files.
            $staleRootInstaller = Join-Path $MainScriptDeployDir 'install.ps1'
            if (Test-Path -LiteralPath $staleRootInstaller) {
                try {
                    Remove-Item -LiteralPath $staleRootInstaller -Force -ErrorAction Stop
                    Write-InstallLog "Removed stale root installer copy: $staleRootInstaller" "SUCCESS"
                    $removedCount++
                } catch {
                    Write-InstallLog "Error removing stale root installer copy: $_" "WARN"
                }
            }

            # Watch-WhiteWalkerLog.ps1 moved from the flat WhiteWalker root into the
            # mirrored admin/ directory. It doesn't match "WW_*"/"WhiteWalker*", so the
            # wildcard patterns above never catch it - remove the stale flat copy left
            # by older installs explicitly so an upgrade doesn't leave two copies behind.
            $staleWatchLog = Join-Path $MainScriptDeployDir 'Watch-WhiteWalkerLog.ps1'
            if (Test-Path -LiteralPath $staleWatchLog) {
                try {
                    Remove-Item -LiteralPath $staleWatchLog -Force -ErrorAction Stop
                    Write-InstallLog "Removed stale flat copy: $staleWatchLog" "SUCCESS"
                    $removedCount++
                } catch {
                    Write-InstallLog "Error removing stale flat Watch-WhiteWalkerLog.ps1 copy: $_" "WARN"
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
        # Blackhole disabled-mode "already cleared" marker - reset on install/upgrade so a
        # lost marker just costs one extra harmless -rm, never a skipped cleanup (RC1.22)
        "$MainScriptDeployDir\vpn_blackhole_cleared.flag",
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

    # Defender flags are a per-label directory. Remove it wholesale so an
    # install/upgrade/uninstall cannot preserve stale registry-check state.
    $defenderFlagDir = Join-Path $MainScriptDeployDir 'defender_flags'
    if (Test-Path -LiteralPath $defenderFlagDir) {
        try {
            Remove-Item -LiteralPath $defenderFlagDir -Recurse -Force -ErrorAction Stop
            Write-InstallLog "Removed Defender flag directory: $defenderFlagDir" "SUCCESS"
            $removedCount++
        } catch {
            Write-InstallLog "Error removing Defender flag directory $defenderFlagDir : $_" "WARN"
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
    
    $directories = @($MainScriptDeployDir, $CapPortalDeployDir, $ConfigDeployDir, $LogDir, $DiagDir, $SupportFilesDeployDir) +
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
        [switch]$Recurse,
        # RC2.1: after a clean copy, delete files in DestDir that are NOT in the source
        # (leftovers from older builds). Use only for pure-code dirs (main, triggers).
        [switch]$Mirror
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

    if ($Mirror -and $errors -eq 0 -and (Test-Path -LiteralPath $DestDir)) {
        $keep = @{}
        foreach ($file in $files) {
            $keep[$file.FullName.Substring($SourceDir.Length).TrimStart("\/").ToLowerInvariant()] = $true
        }
        $pruned = 0
        $destFiles = if ($Recurse) { Get-ChildItem -LiteralPath $DestDir -File -Recurse -ErrorAction SilentlyContinue } `
                     else { Get-ChildItem -LiteralPath $DestDir -File -ErrorAction SilentlyContinue }
        foreach ($df in $destFiles) {
            $rel = $df.FullName.Substring($DestDir.Length).TrimStart("\/").ToLowerInvariant()
            if (-not $keep.ContainsKey($rel)) {
                try {
                    Remove-Item -LiteralPath $df.FullName -Force -ErrorAction Stop
                    Write-InstallLog "Pruned stale file from ${Label}: $rel" "SUCCESS"
                    $pruned++
                } catch {
                    Write-InstallLog "Could not prune stale file ${rel}: $_" "WARN"
                }
            }
        }
        if ($pruned -gt 0) { Write-InstallLog "Pruned $pruned stale file(s) from $Label" "INFO" }
    }
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

function Initialize-TelemetrySpool {
    <#
    .SYNOPSIS
    Creates and repairs the USER telemetry spool directory + ACL (Required G).

    .DESCRIPTION
    Idempotent by design so an upgrade repairs a missing directory or a missing
    ACE without ever widening rights elsewhere. Authenticated Users receive
    CreateFiles/AppendData/WriteData/ReadData on this one directory, with
    ObjectInherit so each dropped per-event file stays writable by its creator.
    Deliberately NOT 'Modify' and deliberately NOT applied to the script or
    configuration directories. Non-fatal: telemetry falls back to its existing
    truthful failure reporting if this cannot be established.
    #>
    Write-InstallLog "=== Telemetry Spool (user-context drop directory) ===" "INFO"

    try {
        if (-not (Test-Path $TelemetrySpoolDir)) {
            New-Item -Path $TelemetrySpoolDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-InstallLog "Created telemetry spool: $TelemetrySpoolDir" "SUCCESS"
        } else {
            Write-InstallLog "Telemetry spool exists: $TelemetrySpoolDir" "DEBUG"
        }

        $acl = Get-Acl -Path $TelemetrySpoolDir -ErrorAction Stop
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')  # Authenticated Users
        $rights = [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
                  [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                  [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                  [System.Security.AccessControl.FileSystemRights]::ReadData -bor
                  [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
                  [System.Security.AccessControl.FileSystemRights]::Synchronize

        $existing = $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::CreateFiles) -and
            ($_.IdentityReference.Value -match 'Authenticated Users|S-1-5-11')
        }
        if ($existing) {
            Write-InstallLog "Telemetry spool ACL already correct - no change" "DEBUG"
            return $true
        }

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $rights, 'ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $TelemetrySpoolDir -AclObject $acl -ErrorAction Stop
        Write-InstallLog "Applied narrow create/append ACL for Authenticated Users on the telemetry spool" "SUCCESS"
        return $true
    } catch {
        Write-InstallLog "Telemetry spool setup failed (non-fatal, telemetry stays fail-soft): $_" "WARN"
        return $false
    }
}

function Copy-TeeEventsIfMissing {
    <#
    .SYNOPSIS
    Deploys the repo's default WW_tee_events.psd1 ONLY if one does not already
    exist on the box. This is a create-only copy - unlike Copy-ScriptFiles,
    it never overwrites, so a tech's chosen active tee profile (e.g. swapped
    to tee_level_3 for an investigation) survives every upgrade/reinstall.

    First-ever install: file doesn't exist yet -> deploy repo default (level_1/core).
    Every subsequent upgrade: file already exists -> leave it alone, log and skip.
    #>
    Write-InstallLog "=== Deploying Active Tee Profile (create-only) ===" "INFO"

    $destPath = Join-Path $TeeEventsDefaultFile.Dest $TeeEventsDefaultFile.Name

    if (Test-Path $destPath) {
        Write-InstallLog "WW_tee_events.psd1 already present - leaving existing active profile untouched: $destPath" "INFO"
        return $true
    }

    if (-not (Test-Path $TeeEventsDefaultFile.Source)) {
        Write-InstallLog "ERROR: Default WW_tee_events.psd1 not found in repo: $($TeeEventsDefaultFile.Source)" "ERROR"
        return $false
    }

    try {
        Copy-Item -Path $TeeEventsDefaultFile.Source -Destination $destPath -Force -ErrorAction Stop
        Write-InstallLog "First install detected - deployed default WW_tee_events.psd1 (core profile) -> $destPath" "SUCCESS"
        return $true
    } catch {
        Write-InstallLog "ERROR copying default WW_tee_events.psd1: $_" "ERROR"
        return $false
    }
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

function Copy-SchemaFiles {
    Write-InstallLog "=== Copying Schema Files ===" "INFO"
    
    $copiedCount = 0
    $errors = 0
    
    foreach ($file in $SchemaFiles) {
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
            Write-InstallLog "ERROR: Schema file not found: $($file.Source)" "ERROR"
            $errors++
        }
    }
    
    Write-InstallLog "Copied $copiedCount schema file(s), $errors error(s)" "INFO"
    return ($errors -eq 0)
}

function Copy-InstallerSelfForUninstall {
    Write-InstallLog "=== Deploying install.ps1 copy for uninstall support ===" "INFO"

    $destScriptPath = Join-Path $SupportFilesDeployDir "install.ps1"
    $destNotePath = Join-Path $SupportFilesDeployDir "README_install_copy.txt"
    $noteContent = "This is a copy of install.ps1 deployed for -Uninstall use only. Do not run this copy to perform a fresh install - re-run from the original extracted release package instead."

    if (-not (Test-Path $InstallerScriptPath)) {
        Write-InstallLog "Could not copy install.ps1 for uninstall support: source script not found at $InstallerScriptPath" "WARN"
        return
    }

    try {
        Copy-Item -Path $InstallerScriptPath -Destination $destScriptPath -Force -ErrorAction Stop
        Write-InstallLog "Copied: install.ps1 -> $destScriptPath" "SUCCESS"
    } catch {
        Write-InstallLog "Could not copy install.ps1 for uninstall support: $_" "WARN"
    }

    try {
        Set-Content -Path $destNotePath -Value $noteContent -Encoding UTF8 -Force -ErrorAction Stop
        Write-InstallLog "Wrote uninstall-use note: $destNotePath" "SUCCESS"
    } catch {
        Write-InstallLog "Could not write uninstall-use note $destNotePath : $_" "WARN"
    }
}

function Register-Tasks {
    Write-InstallLog "=== Registering Task Scheduler Jobs ===" "INFO"
    $phaseStartedAt = Get-Date
    $registeredCount = 0
    $errors = 0
    
    foreach ($task in $TaskXMLs) {
        $taskStartedAt = Get-Date
        if (Test-Path $task.Path) {
            try {
                $xmlContent = Get-Content $task.Path -Raw -ErrorAction Stop
                Register-ScheduledTask -Xml $xmlContent -TaskName $task.Name -TaskPath $task.TaskPath -Force -ErrorAction Stop | Out-Null
                Write-InstallLog "Registered task: $($task.TaskPath)$($task.Name)" "SUCCESS"
                $registeredCount++
            } catch {
                Write-InstallLog "ERROR registering task $($task.Name): $_" "ERROR"
                $errors++
            }
        } else {
            Write-InstallLog "ERROR: Task XML not found: $($task.Path)" "ERROR"
            $errors++
        }
        $taskElapsedMs = [math]::Round(((Get-Date) - $taskStartedAt).TotalMilliseconds)
        if ($taskElapsedMs -ge 1000) {
            Write-InstallLog "task_action_timing action=register task='$($task.TaskPath)$($task.Name)' elapsed_ms=$taskElapsedMs" "WARN"
        }
    }
    
    Write-InstallLog "Registered $registeredCount task(s), $errors error(s)" "INFO"
    Write-InstallLog ("installer_phase_timing phase=task_registration elapsed_ms={0}" -f `
        [math]::Round(((Get-Date) - $phaseStartedAt).TotalMilliseconds)) "INFO"
    return ($errors -eq 0)
}

function Test-RequiredHelperDeployment {
    <#
    .SYNOPSIS
    RC1.25: verifies the helper files telemetry depends on actually landed in
    C:\ProgramData\WhiteWalker. Warns (does not fail the install) so a missing
    helper is visible in the install log rather than only as degraded
    user=/schema-lint behavior in Splunk later.
    #>
    Write-InstallLog "Checking required runtime helpers (telemetry)..." "DEBUG"

    $missing = @()
    foreach ($helper in $RequiredRuntimeHelpers) {
        if (Test-Path $helper.Path) {
            Write-InstallLog "  OK: $($helper.Name)" "DEBUG"
        } else {
            Write-InstallLog "  MISSING REQUIRED HELPER: $($helper.Path) - telemetry will run degraded (user resolution / schema lint)" "WARN"
            $missing += $helper.Name
        }
    }

    if ($missing.Count -gt 0) {
        Write-InstallLog "Required helper validation: $($missing.Count) missing ($($missing -join ', '))" "WARN"
        return $false
    }

    Write-InstallLog "Required helper validation: all $($RequiredRuntimeHelpers.Count) helper(s) present" "SUCCESS"
    return $true
}

function Test-Installation {
    Write-InstallLog "=== Validating Installation ===" "INFO"
    $validationStartedAt = Get-Date
    $allGood = $true

    # Required telemetry helpers (warn-only - never blocks an otherwise good install)
    $null = Test-RequiredHelperDeployment
    
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

    # Check active tee profile deployed (create-only - just confirm presence, not overwrite)
    Write-InstallLog "Checking active tee profile..." "DEBUG"
    $teeEventsPath = Join-Path $TeeEventsDefaultFile.Dest $TeeEventsDefaultFile.Name
    if (Test-Path $teeEventsPath) {
        Write-InstallLog "  OK: $($TeeEventsDefaultFile.Name)" "DEBUG"
    } else {
        Write-InstallLog "  MISSING: $teeEventsPath" "ERROR"
        $allGood = $false
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
    
    # Check schemas deployed
    Write-InstallLog "Checking deployed schemas..." "DEBUG"
    foreach ($file in $SchemaFiles) {
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
    $taskValidationStartedAt = Get-Date
    $taskSnapshot = Get-InstallerTaskSnapshot
    foreach ($task in $TaskXMLs) {
        $scheduledTask = $taskSnapshot | Where-Object {
            $_.TaskName -eq $task.Name -and $_.TaskPath -eq $task.TaskPath
        } | Select-Object -First 1
        if ($scheduledTask) {
            $state = $scheduledTask.State
            Write-InstallLog "  OK: $($task.Name) (State: $state)" "DEBUG"
        } else {
            Write-InstallLog "  MISSING: $($task.Name)" "ERROR"
            $allGood = $false
        }
    }
    Write-InstallLog ("installer_phase_timing phase=task_validation elapsed_ms={0} snapshot_count={1}" -f `
        [math]::Round(((Get-Date) - $taskValidationStartedAt).TotalMilliseconds), $taskSnapshot.Count) "INFO"
    Write-InstallLog ("installer_phase_timing phase=validation elapsed_ms={0}" -f `
        [math]::Round(((Get-Date) - $validationStartedAt).TotalMilliseconds)) "INFO"
    return $allGood
}

function Write-InstallResultEvent {
    param(
        [ValidateSet('install','uninstall')]
        [string]$Action,
        [int]$ExitCode,
        [string]$Reason = ""
    )

    try {
        $eventAction = if ($Action -eq 'install') { 'cpr_install_result' } else { 'cpr_uninstall_result' }
        if ($null -eq $Reason) { $Reason = "" }
        $evtTimeIso = (Get-Date).ToString("o")

        $pairs = New-Object System.Collections.Generic.List[string]
        $pairs.Add('action="{0}"' -f $eventAction)
        $pairs.Add('exit_code="{0}"' -f $ExitCode)
        $pairs.Add('reason="{0}"' -f $Reason)
        $pairs.Add('version="{0}"' -f $WW_Version)
        $pairs.Add('machine="{0}"' -f $env:COMPUTERNAME)
        $pairs.Add('EvtTime="{0}"' -f $evtTimeIso)

        $entry = @{
            ts        = $evtTimeIso
            payload   = ($pairs -join ' ')
            extraInfo = ""
        } | ConvertTo-Json -Compress

        if (Test-Path $MainScriptDeployDir) {
            try {
                Add-Content -Path $InstallResultQueueFile -Value $entry -Encoding UTF8 -ErrorAction Stop
                return
            } catch {
                Write-InstallLog "WARN: could not append install-result event to queue file $InstallResultQueueFile : $_" "WARN"
            }
        }

        if ($Action -eq 'uninstall') {
            Write-InstallLog "Uninstall result not queued for telemetry (the telemetry subsystem is gone); see this log" "INFO"
            return
        }
        try {
            if (-not (Test-Path $PendingInstallEventDir)) {
                New-Item -Path $PendingInstallEventDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            $pendingFile = "pending_{0}_{1}.json" -f (Get-Date -Format "yyyyMMddHHmmssfff"), ([guid]::NewGuid().ToString("N"))
            $pendingPath = Join-Path $PendingInstallEventDir $pendingFile
            Set-Content -Path $pendingPath -Value $entry -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-InstallLog "WARN: could not persist install-result event to pending directory $PendingInstallEventDir : $_" "WARN"
        }
    } catch {
        Write-InstallLog "WARN: could not build install-result event payload: $_" "WARN"
    }
}

function Drain-PendingInstallEvents {
    try {
        if (-not (Test-Path $PendingInstallEventDir)) { return }
        if (-not (Test-Path $MainScriptDeployDir)) { return }

        try {
            $queueHandle = [System.IO.File]::Open(
                $InstallResultQueueFile,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite
            )
            $queueHandle.Close()
        } catch {
            Write-InstallLog "WARN: queue file not writable for pending install-result drain: $InstallResultQueueFile : $_" "WARN"
            return
        }

        $drainedCount = 0
        $pendingFiles = Get-ChildItem -Path (Join-Path $PendingInstallEventDir "*.json") -File -ErrorAction SilentlyContinue | Sort-Object Name
        foreach ($pendingFile in $pendingFiles) {
            try {
                $rawEntry = Get-Content -Path $pendingFile.FullName -Raw -ErrorAction Stop
                Add-Content -Path $InstallResultQueueFile -Value $rawEntry -Encoding UTF8 -ErrorAction Stop
                Remove-Item -Path $pendingFile.FullName -Force -ErrorAction Stop
                $drainedCount++
            } catch {
                Write-InstallLog "WARN: could not drain pending event $($pendingFile.FullName): $_" "WARN"
            }
        }

        if ($drainedCount -gt 0) {
            Write-InstallLog "Drained $drainedCount pending install-result event(s) from WhiteWalkerPending" "INFO"
        }

        $remainingFiles = Get-ChildItem -Path $PendingInstallEventDir -File -ErrorAction SilentlyContinue
        if (-not $remainingFiles) {
            try {
                Remove-Item -Path $PendingInstallEventDir -Force -ErrorAction Stop
            } catch {
                Write-InstallLog "WARN: could not remove empty pending directory $PendingInstallEventDir : $_" "WARN"
            }
        }
    } catch {
        Write-InstallLog "WARN: could not drain pending install-result events: $_" "WARN"
    }
}

function Stop-WhiteWalkerProcesses {
    # Stop anything running out of the install dir (WW_main runs, HayStack, tail windows)
    # so files and the directory are not held open. Never touches this installer or its parents.
    $keep = @{ ([int]$PID) = $true }
    try {
        $p = $PID
        for ($i = 0; $i -lt 6; $i++) {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$p" -ErrorAction Stop
            if (-not $proc -or -not $proc.ParentProcessId) { break }
            $p = [int]$proc.ParentProcessId; $keep[$p] = $true
        }
    } catch { }
    $stopped = 0
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { $_.CommandLine -and $_.CommandLine -like "*$MainScriptDeployDir*" -and -not $keep.ContainsKey([int]$_.ProcessId) } |
            ForEach-Object {
                try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $stopped++
                      Write-InstallLog "Stopped process $($_.ProcessId) ($($_.Name))" "SUCCESS" } catch { }
            }
    } catch { Write-InstallLog "Could not enumerate processes: $_" "WARN" }
    Write-InstallLog "Stopped $stopped WhiteWalker process(es)" "INFO"
}

function Remove-CprTaskFolder {
    # Everything inside the CPR task folder is ours by definition: unregister it all,
    # then drop the folder itself (best effort).
    $dir = Join-Path $env:windir ("System32\Tasks\" + $CprTaskFolder.Trim('\'))
    $removed = 0
    if (Test-Path -LiteralPath $dir) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
            try {
                Unregister-ScheduledTask -TaskName $f.Name -TaskPath $CprTaskFolder -Confirm:$false -ErrorAction Stop
                Write-InstallLog "Removed task: $CprTaskFolder$($f.Name)" "SUCCESS"; $removed++
            } catch { Write-InstallLog "Could not remove task $CprTaskFolder$($f.Name): $_" "WARN" }
        }
        try {
            $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect()
            $svc.GetFolder('\').DeleteFolder($CprTaskFolder.Trim('\'), 0)
            Write-InstallLog "Removed task folder $CprTaskFolder" "SUCCESS"
        } catch { Write-InstallLog "Could not remove task folder ${CprTaskFolder}: $_" "WARN" }
    }
    return (-not (Test-Path -LiteralPath $dir) -or @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue).Count -eq 0)
}

function Remove-InstallDirectory {
    # Delete the whole deploy dir, logs included. Retries for transient locks.
    for ($try = 1; $try -le 4; $try++) {
        if (-not (Test-Path -LiteralPath $MainScriptDeployDir)) { return $true }
        try { Remove-Item -LiteralPath $MainScriptDeployDir -Recurse -Force -ErrorAction Stop } catch { }
        if (-not (Test-Path -LiteralPath $MainScriptDeployDir)) { break }
        & cmd.exe /c "rd /s /q `"$MainScriptDeployDir`"" 2>$null | Out-Null
        if (-not (Test-Path -LiteralPath $MainScriptDeployDir)) { break }
        Start-Sleep -Seconds 2
    }
    if (Test-Path -LiteralPath $MainScriptDeployDir) {
        $left = @(Get-ChildItem -LiteralPath $MainScriptDeployDir -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 10 -ExpandProperty FullName)
        Write-InstallLog ("Could not fully remove $MainScriptDeployDir; remaining (first 10): " + ($left -join '; ')) "ERROR"
        return $false
    }
    Write-InstallLog "Removed directory: $MainScriptDeployDir" "SUCCESS"
    return $true
}

function Uninstall-WhiteWalker {
    # -Uninstall means UNINSTALLED: stop everything, undo system changes, unregister
    # every task, delete the whole install dir (logs too), return an exit code.
    # The uninstall log is kept OUTSIDE the install dir so the evidence survives.
    $script:InstallLog = Join-Path $env:windir 'Temp\white_walker_uninstall.log'
    Write-InstallLog "" "INFO"
    Write-InstallLog "========================================" "INFO"
    Write-InstallLog "WhiteWalker Uninstaller $WW_Version" "INFO"
    Write-InstallLog "========================================" "INFO"

    # Release our current directory so the install dir can be deleted.
    try { Set-Location -LiteralPath $env:windir } catch { }

    $ok = $true
    Stop-WhiteWalkerProcesses

    # Undo hosts-file blackhole entries while the script still exists.
    $hostsScript = Join-Path $MainScriptDeployDir 'Set-VpnHostsEntry.ps1'
    if (Test-Path -LiteralPath $hostsScript) {
        try {
            Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$hostsScript`" -rm" -WindowStyle Hidden -Wait
            Write-InstallLog "Blackhole hosts entries cleared (-rm)" "SUCCESS"
        } catch { Write-InstallLog "Could not run blackhole -rm: $_" "WARN" }
    }

    # Tasks: legacy locations, known tasks, then anything left in the CPR folder.
    Invoke-LegacyTaskMigrationStep -ForUninstall
    Remove-OldTasks
    if (-not (Remove-CprTaskFolder)) { $ok = $false }

    # Self-update flags and the pending install-event dir are ours too.
    foreach ($f in @("C:\Windows\Temp\cpr_update_dev.flag", "C:\Windows\Temp\cpr_update_prod.flag")) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    if (-not (Remove-InstallDirectory)) { $ok = $false }

    Write-InstallLog "" "INFO"
    if ($ok) {
        Write-InstallLog "WhiteWalker uninstall completed. Nothing left in $MainScriptDeployDir. Log: $InstallLog" "SUCCESS"
    } else {
        Write-InstallLog "WhiteWalker uninstall INCOMPLETE - see messages above. Log: $InstallLog" "ERROR"
    }
    return $ok
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
    Exit-Installer -Code $ExitCodeNotAdmin -Reason "not running as Administrator"
}

Drain-PendingInstallEvents

if ($Uninstall) {
    try {
        if (Uninstall-WhiteWalker) { Exit-Installer -Code $ExitCodeSuccess }
        else { Exit-Installer -Code $ExitCodeUninstallIncomplete -Reason "uninstall incomplete" }
    } catch {
        Write-InstallLog "FATAL: Unexpected error during uninstall: $_" "ERROR"
        Exit-Installer -Code $ExitCodeUnexpectedError -Reason "unexpected uninstall error"
    }
}

try {
    # Step 1: Clean uninstall
    Write-InstallLog "" "INFO"
    Invoke-LegacyTaskMigrationStep   # LEGACY-TASK-MIGRATION (TEMPORARY, block 2 of 2)
    Remove-OldTasks
    Remove-OldScripts
    Remove-StaleFlagFiles

    # Step 2: Ensure directories
    Write-InstallLog "" "INFO"
    if (-not (Ensure-Directories)) {
        Write-InstallLog "FATAL: Failed to create required directories" "ERROR"
        Exit-Installer -Code $ExitCodeDirectorySetupFail -Reason "required directory creation failed"
    }

    # Step 3: Copy files (schemas deployed but not actively used for validation)
    Write-InstallLog "" "INFO"
    $fileDeploymentStartedAt = Get-Date
    $schemasOK = Copy-SchemaFiles
    $scriptsOK = Copy-ScriptFiles
    $configsOK = Copy-ConfigFiles
    $teeEventsOK = Copy-TeeEventsIfMissing
    $null = Initialize-TelemetrySpool
    Copy-InstallerSelfForUninstall
    # Mirror all subdirectories from repo into deploy dir
    $dirsOK = $true
    foreach ($dir in $SubDirsToMirror) {
        # RC2.1: main\ (code) and triggers\ (task XML) must match the build exactly.
        $ok = Copy-DirectoryContents -SourceDir $dir.Source -DestDir $dir.Dest -Label $dir.Label `
                  -Mirror:($dir.Label -eq 'main' -or $dir.Label -eq 'triggers')
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
    Write-InstallLog ("installer_phase_timing phase=file_deployment elapsed_ms={0}" -f `
        [math]::Round(((Get-Date) - $fileDeploymentStartedAt).TotalMilliseconds)) "INFO"

    if (-not $schemasOK -or -not $scriptsOK -or -not $configsOK -or -not $teeEventsOK -or -not $dirsOK) {
        Write-InstallLog "FATAL: Failed to copy required files" "ERROR"
        Exit-Installer -Code $ExitCodeFileCopyFail -Reason "required file copy failed"
    }

    # Step 4: Register tasks
    Write-InstallLog "" "INFO"
    $tasksOK = Register-Tasks

    if (-not $tasksOK) {
        Write-InstallLog "FATAL: Failed to register Task Scheduler jobs" "ERROR"
        Exit-Installer -Code $ExitCodeTaskRegisterFail -Reason "task registration failed"
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
        Write-InstallLog "Log-and-Tee subsystem deployed to: $MainScriptDeployDir" "INFO"
        Write-InstallLog "  WW_tee_events.psd1 - ACTIVE profile (create-only, never overwritten on upgrade)" "INFO"
        Write-InstallLog "  tee_profiles\      - level_0 (silent) through level_5 (debug) - swap via copy" "INFO"
        Write-InstallLog "  Example: cp tee_profiles\tee_level_3.psd1 WW_tee_events.psd1" "INFO"
        Write-InstallLog "" "INFO"
        Write-InstallLog "Logs: $LogDir" "INFO"
        Write-InstallLog "Diagnostics: $DiagDir" "INFO"
        Exit-Installer -Code $ExitCodeSuccess
    } else {
        Write-InstallLog "" "ERROR"
        Write-InstallLog "========================================" "ERROR"
        Write-InstallLog "$WW_Version Installation validation FAILED!" "ERROR"
        Write-InstallLog "========================================" "ERROR"
        Write-InstallLog "Review errors above and retry installation" "ERROR"
        Exit-Installer -Code $ExitCodeValidationFail -Reason "post-install validation failed"
    }
} catch {
    Write-InstallLog "FATAL: Unexpected installer error: $_" "ERROR"
    Exit-Installer -Code $ExitCodeUnexpectedError -Reason "unexpected unhandled error"
}
