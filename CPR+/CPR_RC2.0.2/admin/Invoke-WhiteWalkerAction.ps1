#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Menu-driven tech action console for CPR RC2 (WhiteWalker).
    CPR version: 3.14.0_RC2.1.0 (keep in sync with $ver in main\Main.Configuration.ps1; a test enforces it)
    Console version: 1.0.0
    Author: steve.horton@optum.com (with AI assist)

.DESCRIPTION
    Companion to Watch-WhiteWalkerLog.ps1 - where the log viewer lets a tech
    SEE what WhiteWalker is doing, this console lets a tech ACT: restore the
    VPN profile XML, force a vault sync, trigger a self-update, check in via
    telemetry, diff needles.cfg against the share, build a new needle, pick a
    tee log level, launch diagnostics, and run a handful of lower-risk quick
    actions.

    Uses only Windows PowerShell 5.1 built-ins - no external modules, no
    PowerShell Gallery dependency, same numbered-menu/Read-Host convention as
    Watch-WhiteWalkerLog.ps1. Every action writes to its own local audit log
    (white_walker.admin_actions.log) and is wrapped in try/catch so a single
    failure can never crash the console - it always returns to the main menu.

    Run with no parameters for the interactive menu.
#>
[CmdletBinding()]
param()

# =============================================================================
# Paths / configuration
# =============================================================================
$script:WWRoot           = "C:\ProgramData\WhiteWalker"
$script:WWLogDir          = Join-Path $script:WWRoot "logs"
$script:AdminActionLog    = Join-Path $script:WWLogDir "white_walker.admin_actions.log"
$script:AdminActionLogMaxBytes = 1MB
$script:AdminActionLogKeep     = 5

$script:XmlRestoreFlag    = "C:\Windows\Temp\xml_restore.flag"
$script:XmlVaultScript    = Join-Path $script:WWRoot "WW_xml_vault.ps1"
$script:XmlVaultLog       = Join-Path $script:WWLogDir "white_walker.xml_vault.log"

$script:SelfUpdateDevFlag  = "C:\Windows\Temp\cpr_update_dev.flag"
$script:SelfUpdateProdFlag = "C:\Windows\Temp\cpr_update_prod.flag"
$script:SelfUpdateInstallLog = Join-Path $script:WWLogDir "white_walker_install.log"

$script:HaystackScript     = Join-Path $script:WWRoot "haystack.ps1"
$script:NeedlesLocalFile   = Join-Path $script:WWRoot "needles_local.cfg"
$script:TeeMasterFile      = Join-Path $script:WWRoot "WW_tee_master.psd1"
$script:TeeSetScript       = Join-Path $script:WWRoot "WW_set_tee_level.ps1"
$script:ActiveTeeProfile   = Join-Path $script:WWRoot "WW_tee_events.psd1"

$script:WWMainScript       = Join-Path $script:WWRoot "WW_main.ps1"
$script:VpnHostsScript     = Join-Path $script:WWRoot "Set-VpnHostsEntry.ps1"

# Curated (NOT auto-discovered) launcher entries. Each is a script a field
# tech could reasonably want to run directly. Genuine Pester unit-test suites
# and anything destructive/inappropriate for ad-hoc use are intentionally
# excluded here - see the PR description for the full include/exclude list
# and reasoning.
$script:DiagToolInventory = @(
    [pscustomobject]@{ Path = "diagnostics\Get-CapPortalDiag.ps1";                     Description = "Consolidated captive-portal telemetry diagnostic (Haystack/Tee config, queue, state.json, HayStack_Monitor task)." }
    [pscustomobject]@{ Path = "diagnostics\New-NeedlePreview.ps1";                     Description = "Read-only: preview a NEEDLE candidate against real Event Log data before committing it." }
    [pscustomobject]@{ Path = "diagnostics\New-DefenderNeedlePreview.ps1";             Description = "Read-only: list MDM firewall rules and generate a ready-to-paste DEFENDER needle line." }
    [pscustomobject]@{ Path = "diagnostics\Test-CprSyslogPath.ps1";                  Description = "Read-only: can this box reach the syslog VIP? (state, DNS, route, queue). Quick Actions option 5 also sends a CPR_TESTER test message." }
    [pscustomobject]@{ Path = "diagnostics\Test-DefenderFwRuleExists.ps1";             Description = "Read-only: check whether a specific MDM-delivered firewall rule exists in the registry." }
    [pscustomobject]@{ Path = "diagnostics\browser_test.ps1";                         Description = "Launches a test browser session the same way CPR does from SYSTEM context." }
    [pscustomobject]@{ Path = "diagnostics\get_webview2_ver.ps1";                      Description = "Quick check of the installed WebView2 runtime version/path." }
    [pscustomobject]@{ Path = "diagnostics\Monitor-CaptivePortalRemediation.ps1";      Description = "Live interactive monitor of captive-portal remediation behavior (press Q+Enter to stop)." }
    [pscustomobject]@{ Path = "diagnostics\trigger_remdiation.ps1";                    Description = "Fires Event ID 777 to manually trigger captive portal remediation." }
    [pscustomobject]@{ Path = "tests\TEST_WakeDetection.ps1";                          Description = "Quick check for recent Kernel-Power wake events." }
    [pscustomobject]@{ Path = "tests\TEST_direct_toast.ps1";                           Description = "Direct WinRT toast notification test (bypasses Event Log/Task Scheduler)." }
    [pscustomobject]@{ Path = "tests\Trigger_WW_Notify800.ps1";                        Description = "Fires Event ID 800 to trigger WW_notify.ps1's toast notification path." }
    [pscustomobject]@{ Path = "tests\TEST_send_syslog_msg_from_powershell_simple.ps1"; Description = "Sends a simple raw UDP syslog test message to the Splunk receiver." }
    [pscustomobject]@{ Path = "tests\TEST_simulate_cap_portal.ps1";                    Description = "Simulates captive-portal plumbing end-to-end without a live captive-portal network." }
    [pscustomobject]@{ Path = "tests\TEST_mock_cap_portal_flow.ps1";                   Description = "Mock captive portal flow: real HTTP redirect detection + off-network queue/drain with WDAC-immune browser substitution." }
    [pscustomobject]@{ Path = "tests\gather_fw_rulz.ps1";                              Description = "Read-only: dumps MDM-delivered Windows Firewall rules." }
    [pscustomobject]@{ Path = "tests\get_win_sleep_logs.ps1";                          Description = "Read-only: dumps the last 10 Kernel-Power sleep/wake events." }
    [pscustomobject]@{ Path = "tests\bump_ISE.testable.ps1";                          Description = "Standalone ISE posture rescan tool (-WWDebug/-WWTrace/-WhatIf supported)." }
)

# =============================================================================
# Logging  (same 1MB/5-keep rotation pattern as haystack.ps1 Write-HSLog /
# WW_xml_vault.ps1 Invoke-XmlVaultLogRotation)
# =============================================================================
function Write-WWAdminLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts [$Level] [AdminAction] $Message"
    Write-Verbose $line
    try {
        if (-not (Test-Path -LiteralPath $script:WWLogDir)) {
            New-Item -Path $script:WWLogDir -ItemType Directory -Force | Out-Null
        }
        if (Test-Path -LiteralPath $script:AdminActionLog) {
            $sz = (Get-Item -LiteralPath $script:AdminActionLog -ErrorAction SilentlyContinue).Length
            if ($sz -and $sz -ge $script:AdminActionLogMaxBytes) {
                $oldest = "$script:AdminActionLog.$script:AdminActionLogKeep"
                if (Test-Path -LiteralPath $oldest) { Remove-Item -LiteralPath $oldest -Force -ErrorAction SilentlyContinue }
                for ($i = ($script:AdminActionLogKeep - 1); $i -ge 1; $i--) {
                    $src = "$script:AdminActionLog.$i"
                    $dst = "$script:AdminActionLog.$($i + 1)"
                    if (Test-Path -LiteralPath $src) { Rename-Item -LiteralPath $src -NewName (Split-Path $dst -Leaf) -Force -ErrorAction SilentlyContinue }
                }
                Rename-Item -LiteralPath $script:AdminActionLog -NewName (Split-Path "$script:AdminActionLog.1" -Leaf) -Force -ErrorAction SilentlyContinue
            }
        }
        Add-Content -LiteralPath $script:AdminActionLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

# =============================================================================
# Haystack / Tee bootstrap
#
# haystack.ps1's own entry point throws if neither -reroll nor -remove is
# passed (by design - see haystack.ps1's "Entry Point" block). Everything we
# need (Write-HSLog, Get-HsFileVersion, Get-HsFileHash, Sync-NeedlesFile,
# Read-NeedleFile, $HaystackHeaderFields, $RemoteNeedlesFile/$LocalNeedlesFile)
# is defined *before* that final throw, so dot-sourcing it here at script
# scope and swallowing the expected throw leaves all of that usable for the
# rest of this script - without re-implementing any of its validation/
# comparison logic. This must run at the TOP LEVEL of this script (not inside
# a function) so the definitions persist in Script scope for every function
# defined below.
# =============================================================================
if (Test-Path -LiteralPath $script:HaystackScript) {
    try { . $script:HaystackScript } catch { }
}

# Fallback definitions in case haystack.ps1 isn't present at the expected
# deployed path (e.g. running this script from a repo checkout rather than a
# deployed box) - keeps the needle wizard/diff usable with sane defaults.
if (-not (Get-Variable -Name HaystackHeaderFields -Scope Script -ErrorAction SilentlyContinue)) {
    $script:HaystackHeaderFields = @('ww_version','os','model','serial','last_boot','csc_version','csc_source','vpn_profile')
}
if (-not (Get-Variable -Name RemoteNeedlesFile -Scope Script -ErrorAction SilentlyContinue)) {
    $script:RemoteConfigDir   = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN\CPR"
    $script:RemoteNeedlesFile = Join-Path $script:RemoteConfigDir "needles.cfg"
}
if (-not (Get-Variable -Name LocalNeedlesFile -Scope Script -ErrorAction SilentlyContinue)) {
    $script:LocalNeedlesFile = Join-Path $script:WWRoot "needles.cfg"
}
if (-not (Get-Command Write-HSLog -ErrorAction SilentlyContinue)) {
    function Write-HSLog { param([string]$Message, [string]$Level = "INFO") Write-WWAdminLog -Message $Message -Level $Level }
}
if (-not (Get-Command Get-HsFileVersion -ErrorAction SilentlyContinue)) {
    function Get-HsFileVersion {
        param([string]$Path)
        try {
            $firstLine = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
            if ($firstLine -match '^version:(.+)$') { return $matches[1].Trim() }
        } catch { }
        return $null
    }
}
if (-not (Get-Command Get-HsFileHash -ErrorAction SilentlyContinue)) {
    function Get-HsFileHash {
        param([string]$Path)
        try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return $null }
    }
}

# Reuse WW_tee.ps1's real Write-TeeLog (same pattern as haystack.ps1's
# Write-HaystackTelemetry bootstrap) - no parallel telemetry pathway.
#
# Write-TeeLog resolves its gates at CALL time and checks Global scope FIRST,
# falling back to Script scope (see WW_tee.ps1's "Master switches" block).
# Relying on the Script-scope fallback alone from this console proved
# unreliable in the field (a Tech Check-In reported success while nothing was
# ever queued), so establish the values in Global scope - exactly the scope
# the proven manual bootstrap used:
#     . .\WW_tee.ps1; $HaystackEnabled = $true; $TeeEnabled = $true; ...
# Script-scope copies are kept for this script's own reads.
$script:HaystackEnabled = $true
$script:TeeEnabled      = $true
$script:TeeEventsFile   = $script:ActiveTeeProfile
$global:HaystackEnabled = $true
$global:TeeEnabled      = $true
$global:TeeEventsFile   = $script:ActiveTeeProfile

# Same queue haystack_action.ps1 drains - used only to VERIFY that a telemetry
# call actually landed. This tool never writes/sends it directly. Assigned
# AFTER the dot-source below so this script and the dot-sourced Write-TeeLog
# (which reads $script:TeeQueueFile out of this same scope) always agree on
# the path being checked.
if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) {
    $teePath = Join-Path $script:WWRoot "WW_tee.ps1"
    if (Test-Path -LiteralPath $teePath) {
        try { . $teePath } catch { }
    }
}
$script:TeeQueueFile    = Join-Path $script:WWLogDir "haystack_syslog_queue.jsonl"

function Get-WWQueueState {
    <#
    Cheap snapshot of the syslog queue file used to prove a telemetry call
    actually wrote something. Never throws.
    #>
    param([string]$Path = $script:TeeQueueFile)
    $state = [pscustomobject]@{ Exists = $false; Lines = 0; LastWrite = $null; Length = 0 }
    try {
        if (Test-Path -LiteralPath $Path) {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            $state.Exists    = $true
            $state.Length    = $item.Length
            $state.LastWrite = $item.LastWriteTimeUtc
            $state.Lines     = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue).Count
        }
    } catch { }
    return $state
}

function Send-WWTelemetry {
    <#
    Fires a tee event through the ONE supported pipeline (Write-TeeLog ->
    haystack_syslog_queue.jsonl -> haystack_action.ps1's drain -> WW_syslog).
    With -PassThru it also reports whether the queue file actually changed,
    so an interactive caller can avoid claiming success it cannot prove.
    #>
    param(
        [Parameter(Mandatory)][string]$Tag,
        [hashtable]$Data = @{},
        [switch]$PassThru
    )

    $result = [pscustomobject]@{
        Tag       = $Tag
        Queued    = $false
        Reason    = 'write_teelog_unavailable'
        Error     = $null
        QueueFile = $script:TeeQueueFile
    }

    try {
        if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) {
            Write-WWAdminLog "Write-TeeLog not available - '$Tag' telemetry not sent" "DEBUG"
            if ($PassThru) { return $result }
            return
        }

        # The queue's parent directory must exist or Write-TeeLog's Add-Content
        # throws into its own fail-soft catch and the event vanishes silently.
        $queueDir = Split-Path -Parent $script:TeeQueueFile
        if ($queueDir -and -not (Test-Path -LiteralPath $queueDir)) {
            New-Item -Path $queueDir -ItemType Directory -Force | Out-Null
        }

        $before = Get-WWQueueState

        $teeResult = $null
        if ((Get-Command Write-TeeLog).Parameters.ContainsKey('PassThru')) {
            $teeResult = Write-TeeLog -Tag $Tag -Data $Data -PassThru
        } else {
            # Older WW_tee.ps1 without -PassThru: fall back to queue-change proof only.
            Write-TeeLog $Tag $Data
        }

        $after = Get-WWQueueState
        $queueChanged = $after.Exists -and (
            (-not $before.Exists) -or
            ($after.Lines -gt $before.Lines) -or
            ($after.Length -ne $before.Length) -or
            ($after.LastWrite -ne $before.LastWrite)
        )

        $result.Queued = [bool]$queueChanged
        if ($teeResult) {
            $result.Reason = $teeResult.Reason
            $result.Error  = $teeResult.Error
            if (-not $queueChanged -and $teeResult.Reason -eq 'queued') {
                $result.Reason = 'queue_unchanged'
            }
        } else {
            $result.Reason = if ($queueChanged) { 'queued' } else { 'queue_unchanged' }
        }
    } catch {
        $result.Queued = $false
        $result.Reason = 'error'
        $result.Error  = "$_"
        Write-WWAdminLog "Telemetry emit failed for tag '$Tag': $_" "WARN"
    }

    if ($PassThru) { return $result }
}

function Get-WWTelemetryFailureHelp {
    <#
    Maps a Send-WWTelemetry failure reason to something a tech can act on.
    #>
    param([Parameter(Mandatory)][string]$Reason, [string]$ErrorText)
    switch ($Reason) {
        'haystack_disabled' { "HayStack telemetry is disabled - the event was gated before it was written. Verify HayStack is installed/enabled on this box." }
        'tee_disabled'      { "The tee pipeline is disabled - the event was gated before it was written." }
        'tag_not_in_profile'{ "The active tee profile ($script:ActiveTeeProfile) does not include this tag. If your selected level should already have it, the active profile is STALE - run option 'T' (Refresh Active Tee Profile) to add the new tags without changing your level. Otherwise use the Tee Log Level Picker (option 7) to select level 2 or higher, then retry." }
        'write_teelog_unavailable' { "WW_tee.ps1 / Write-TeeLog could not be loaded from $script:WWRoot - telemetry cannot be sent from this console." }
        'queue_unchanged'   { "Write-TeeLog returned without writing to $script:TeeQueueFile. Check permissions on $script:WWLogDir and the active tee profile." }
        'error'             { "Write-TeeLog failed: $ErrorText" }
        default             { "Telemetry was not queued (reason: $Reason)." }
    }
}

# =============================================================================
# Generic helpers
# =============================================================================
function Confirm-WWAction {
    param([Parameter(Mandatory)][string]$Prompt)
    $answer = Read-Host "$Prompt (y/n)"
    return ($answer -match '^(?i)y(es)?$')
}

function Invoke-WWAction {
    <#
    Wraps every menu action so a single failure (file missing, network
    unreachable, script error) is logged and returned to the caller instead
    of crashing the console.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    try {
        Write-WWAdminLog "Action started: $Name"
        & $Action
        Write-WWAdminLog "Action completed: $Name"
    } catch {
        Write-Host "Action failed: $_" -ForegroundColor Red
        Write-WWAdminLog "Action FAILED: $Name - $_" "ERROR"
    }
}

# =============================================================================
# 1. VPN Profile Restore
# =============================================================================
function Invoke-WWVpnProfileRestore {
    Write-Host "`nThis touches the restore flag so the next WW_main run (lock/unlock" -ForegroundColor Cyan
    Write-Host "or log off/on) restores the VPN profile XML from the local vault." -ForegroundColor Cyan
    Write-Host "Flag: $script:XmlRestoreFlag" -ForegroundColor Gray
    if (-not (Confirm-WWAction "Create the restore flag now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    New-Item -Path $script:XmlRestoreFlag -ItemType File -Force | Out-Null
    Write-WWAdminLog "Touched xml_restore.flag: $script:XmlRestoreFlag"

    Write-Host "`nDone. Flag created." -ForegroundColor Green
    Write-Host "Next steps for the tech:" -ForegroundColor Cyan
    Write-Host "  1. Lock and unlock your screen (or log off/on) to complete the restore." -ForegroundColor White
    Write-Host "  2. Verify success by checking: $script:XmlVaultLog" -ForegroundColor White
}

# =============================================================================
# 2. Force XmlVault Sync (bypass cooldown)
# =============================================================================
function Invoke-WWForceXmlVaultSync {
    if (-not (Test-Path -LiteralPath $script:XmlVaultScript)) {
        Write-Host "WW_xml_vault.ps1 not found at $script:XmlVaultScript" -ForegroundColor Red
        return
    }
    Write-Host "`nThis runs WW_xml_vault.ps1 directly in sync mode with -Force," -ForegroundColor Cyan
    Write-Host "bypassing the normal 24h cooldown, to refresh the local vault now." -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Force a vault sync now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    & $script:XmlVaultScript -Force
    Write-WWAdminLog "Forced XmlVault sync via: $script:XmlVaultScript -Force"
    Write-Host "`nDone. Check results in: $script:XmlVaultLog" -ForegroundColor Green
}

# =============================================================================
# 3. Self-Update Trigger
# =============================================================================
function Invoke-WWSelfUpdateTrigger {
    Write-Host "`nChoose an update channel:" -ForegroundColor Cyan
    Write-Host "  1. DEV"
    Write-Host "  2. PROD"
    $choice = Read-Host "Select channel"

    $flagPath = switch ($choice) {
        '1' { $script:SelfUpdateDevFlag }
        '2' { $script:SelfUpdateProdFlag }
        default { $null }
    }
    if (-not $flagPath) { Write-Host "Invalid selection." -ForegroundColor Red; return }

    # Optional: also set the tee level once the update has SUCCEEDED (cpr_update_<ch>_tee_<N>[_keep].flag).
    # "keep" = the level sticks; without it the level reverts on its own after the normal flag revert time.
    $teeAns = (Read-Host "Tee level to set after a successful update, 1-5 (Enter = leave the level alone)").Trim()
    if ($teeAns -ne '') {
        if ($teeAns -notmatch '^[1-5]$') { Write-Host "Invalid tee level '$teeAns' - use 1-5 or Enter." -ForegroundColor Red; return }
        $keepAns = (Read-Host "Keep that level (no automatic revert)? [y/N]").Trim()
        $suffix  = "_tee_$teeAns" + $(if ($keepAns -match '^(?i)y(es)?$') { '_keep' } else { '' })
        $flagPath = $flagPath -replace '\.flag$', "$suffix.flag"
    }

    Write-Host "`nThis touches the flag: $flagPath" -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Trigger a self-update on this channel?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    New-Item -Path $flagPath -ItemType File -Force | Out-Null
    Write-WWAdminLog "Touched self-update flag: $flagPath"

    Write-Host "`nDone. Flag created." -ForegroundColor Green
    Write-Host "Next steps for the tech:" -ForegroundColor Cyan
    Write-Host "  1. Lock and unlock your screen (or wait for the next trigger) to complete the update." -ForegroundColor White
    Write-Host "  2. Review results in: $script:SelfUpdateInstallLog" -ForegroundColor White
}

# =============================================================================
# 4. Tech Check-In (telemetry)
# =============================================================================
function Invoke-WWTechCheckIn {
    Write-Host "`nThis fires a 'tech_checkin' telemetry event via the existing" -ForegroundColor Cyan
    Write-Host "Write-TeeLog pipeline - it is QUEUED locally and shipped to Splunk" -ForegroundColor Cyan
    Write-Host "by HayStack on its next wake, separate from this tool's local" -ForegroundColor Cyan
    Write-Host "admin-actions log." -ForegroundColor Cyan
    $note = Read-Host "Optional short note (e.g. 'troubleshooting ticket #12345'), or press Enter to skip"
    if (-not (Confirm-WWAction "Send check-in now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    $result = Send-WWTelemetry -Tag 'tech_checkin' -Data @{ note = $note } -PassThru

    if ($result -and $result.Queued) {
        Write-WWAdminLog "Tech check-in queued to $($result.QueueFile) (note: $note)"
        Write-Host "`nDone. Check-in QUEUED locally." -ForegroundColor Green
        Write-Host "  Queue file: $($result.QueueFile)" -ForegroundColor White
        Write-Host "  It is not in Splunk yet - the next HayStack wake (normally a" -ForegroundColor White
        Write-Host "  lock/unlock, or the HayStack_Monitor heartbeat) drains the queue" -ForegroundColor White
        Write-Host "  and sends it." -ForegroundColor White
        return
    }

    $reason = if ($result) { $result.Reason } else { 'no_result' }
    $errText = if ($result) { $result.Error } else { $null }
    $help    = Get-WWTelemetryFailureHelp -Reason $reason -ErrorText $errText
    Write-WWAdminLog "Tech check-in NOT queued (reason: $reason; error: $errText; note: $note)" "ERROR"
    Write-Host "`nCheck-in was NOT sent." -ForegroundColor Red
    Write-Host "  Reason: $reason" -ForegroundColor Yellow
    Write-Host "  $help" -ForegroundColor Yellow
    Write-Host "  Logged to: $script:AdminActionLog" -ForegroundColor Gray
}

# =============================================================================
# 5. Needles Sync Check (diff, read-only)
#
# Mirrors (does not reinvent) haystack.ps1's Sync-NeedlesFile comparison:
# version-line compare first, SHA256 hash fallback.
# =============================================================================
function Get-WWNeedlesSyncStatus {
    if (-not (Test-Path -LiteralPath $script:RemoteNeedlesFile)) {
        return [pscustomobject]@{ Status = 'share_unreachable'; LocalVersion = (Get-HsFileVersion -Path $script:LocalNeedlesFile); RemoteVersion = $null }
    }

    $remoteVersion = Get-HsFileVersion -Path $script:RemoteNeedlesFile
    $localVersion  = Get-HsFileVersion -Path $script:LocalNeedlesFile

    if ($remoteVersion -and $localVersion -and ($remoteVersion -eq $localVersion)) {
        return [pscustomobject]@{ Status = 'in_sync'; LocalVersion = $localVersion; RemoteVersion = $remoteVersion }
    }

    $remoteHash = Get-HsFileHash -Path $script:RemoteNeedlesFile
    $localHash  = Get-HsFileHash -Path $script:LocalNeedlesFile
    if ($remoteHash -and $localHash -and ($remoteHash -eq $localHash)) {
        return [pscustomobject]@{ Status = 'in_sync'; LocalVersion = $localVersion; RemoteVersion = $remoteVersion }
    }

    return [pscustomobject]@{ Status = 'out_of_sync'; LocalVersion = $localVersion; RemoteVersion = $remoteVersion }
}

function Invoke-WWNeedlesSyncCheck {
    Write-Host "`nComparing local needles.cfg against the NETLOGON share copy (read-only)..." -ForegroundColor Cyan
    $result = Get-WWNeedlesSyncStatus
    switch ($result.Status) {
        'in_sync' {
            Write-Host "In sync (version $($result.LocalVersion))." -ForegroundColor Green
        }
        'out_of_sync' {
            Write-Host "Out of sync: local version $($result.LocalVersion) vs share version $($result.RemoteVersion)." -ForegroundColor Yellow
            Write-Host "No action was taken - HayStack's own reroll cycle (or 'haystack.ps1 -reroll -Force') will pick this up." -ForegroundColor Gray
        }
        'share_unreachable' {
            Write-Host "Share unreachable: $script:RemoteNeedlesFile" -ForegroundColor Yellow
            Write-Host "Local version in use: $($result.LocalVersion)" -ForegroundColor Gray
        }
    }
    Write-WWAdminLog "Needles sync check: $($result.Status) (local=$($result.LocalVersion) remote=$($result.RemoteVersion))"
}

# =============================================================================
# 6. New Needle Wizard
#
# Validates against the exact same rules enforced by haystack.ps1's
# Read-NeedleFile (reused via Test-WWNeedleCandidateLine below) BEFORE
# appending to needles_local.cfg - never needles.cfg, which is share-managed.
# =============================================================================
function Test-WWLabelSafe {
    param([string]$Label)
    if ([string]::IsNullOrWhiteSpace($Label)) { return $false }
    if ($Label -match '[\\\/\:\*\?"<>\|\s]') { return $false }
    return $true
}

function Test-WWNeedleCandidateLine {
    <#
    Validates a candidate needles_local.cfg line using the same parsing
    rules as haystack.ps1's Read-NeedleFile, by writing it to a throwaway
    temp file and parsing it with the real function (already dot-sourced
    into script scope above). Returns $true only if exactly one needle
    object was produced (i.e. Read-NeedleFile didn't warn-and-skip it).
    #>
    param([Parameter(Mandatory)][string]$Line)

    if (-not (Get-Command Read-NeedleFile -ErrorAction SilentlyContinue)) {
        # haystack.ps1 wasn't available to dot-source from - fail safe by
        # rejecting rather than writing an unvalidated line.
        return $false
    }

    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        Set-Content -LiteralPath $tempFile -Value $Line -Encoding UTF8
        $parsed = @(Read-NeedleFile -Path $tempFile -SourceTag 'wizard_preview')
        return ($parsed.Count -eq 1)
    } finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function New-WWNeedleCandidateLine {
    <#
    Prompts for the fields relevant to the chosen directive type, validates
    each before moving on, and returns the fully-assembled candidate line (or
    $null if the tech cancels). Does not write anything to disk itself.
    #>
    param([Parameter(Mandatory)][ValidateSet('NEEDLE','SESSION','DEFENDER','HEADER')][string]$Type)

    switch ($Type) {
        'NEEDLE' {
            $logName = Read-Host "LogName (e.g. Application, System)"
            if ([string]::IsNullOrWhiteSpace($logName)) { Write-Host "LogName cannot be empty." -ForegroundColor Red; return $null }

            $eventId = Read-Host "EventID (numeric)"
            if ($eventId -notmatch '^\d+$') { Write-Host "EventID must be numeric." -ForegroundColor Red; return $null }

            $xpath = Read-Host "XPathFilter (optional, press Enter for a bare EventID match)"

            $label = Read-Host "Label (no spaces, no \/:*?`"<>|)"
            if (-not (Test-WWLabelSafe $label)) { Write-Host "Label is empty or contains invalid characters." -ForegroundColor Red; return $null }

            $ext = Read-Host "ExtendedLogging (optional: 0, 1, 2, all - press Enter for default)"
            if ($ext -and ($ext.ToLowerInvariant() -notin @('0','1','2','all'))) {
                Write-Host "ExtendedLogging must be 0, 1, 2, all, or empty." -ForegroundColor Red; return $null
            }

            $line = "NEEDLE|$logName|$eventId|$xpath|$label"
            if ($ext) { $line += "|$ext" }
            return $line
        }
        'SESSION' {
            $validStateChanges = @('SessionLock','SessionUnlock','RemoteConnect','RemoteDisconnect','ConsoleConnect','ConsoleDisconnect')
            Write-Host "Valid StateChange values: $($validStateChanges -join ', ')" -ForegroundColor Gray
            $stateChange = Read-Host "StateChange"
            if ($validStateChanges -notcontains $stateChange) { Write-Host "StateChange is not valid." -ForegroundColor Red; return $null }

            $label = Read-Host "Label (no spaces, no \/:*?`"<>|)"
            if (-not (Test-WWLabelSafe $label)) { Write-Host "Label is empty or contains invalid characters." -ForegroundColor Red; return $null }

            return "SESSION|$stateChange|$label"
        }
        'DEFENDER' {
            Write-Host "Matching is literal (never regex), case-insensitive and separator-tolerant:" -ForegroundColor Gray
            Write-Host "spaces, - _ / . and repeated whitespace are normalized away before the substring" -ForegroundColor Gray
            Write-Host "test. Use a distinctive, stable descriptive substring of the rule name." -ForegroundColor Gray
            $ruleNameMatch = Read-Host "RuleNameMatch (substring to match against MDM firewall rule names)"
            if ([string]::IsNullOrWhiteSpace($ruleNameMatch)) { Write-Host "RuleNameMatch cannot be empty." -ForegroundColor Red; return $null }
            if ($ruleNameMatch -notmatch '[\p{L}\p{Nd}]') { Write-Host "RuleNameMatch must contain at least one letter or digit." -ForegroundColor Red; return $null }

            $intervalRaw = Read-Host "IntervalHours (optional, numeric - press Enter for the global default)"
            $parsedInterval = 0
            if ($intervalRaw -and -not [int]::TryParse($intervalRaw, [ref]$parsedInterval)) {
                Write-Host "IntervalHours must be numeric or empty." -ForegroundColor Red; return $null
            }

            $label = Read-Host "Label (no spaces, no \/:*?`"<>|)"
            if (-not (Test-WWLabelSafe $label)) { Write-Host "Label is empty or contains invalid characters." -ForegroundColor Red; return $null }

            $ext = Read-Host "ExtendedLogging (optional: 0, 1, 2, all - press Enter for default)"
            if ($ext -and ($ext.ToLowerInvariant() -notin @('0','1','2','all'))) {
                Write-Host "ExtendedLogging must be 0, 1, 2, all, or empty." -ForegroundColor Red; return $null
            }

            $line = "DEFENDER|$ruleNameMatch|$intervalRaw|$label"
            if ($ext) { $line += "|$ext" }
            return $line
        }
        'HEADER' {
            Write-Host "Valid FieldName values: $($script:HaystackHeaderFields -join ', '), or * for all fields" -ForegroundColor Gray
            $fieldName = Read-Host "FieldName"
            $normalizedField = $fieldName.ToLowerInvariant()
            if ($normalizedField -ne '*' -and $script:HaystackHeaderFields -notcontains $normalizedField) {
                Write-Host "FieldName is not a known run-header field (and is not *)." -ForegroundColor Red; return $null
            }

            $label = Read-Host "Label (no spaces, no \/:*?`"<>|)"
            if (-not (Test-WWLabelSafe $label)) { Write-Host "Label is empty or contains invalid characters." -ForegroundColor Red; return $null }

            $refreshRaw = Read-Host "RefreshHours (optional, numeric - press Enter for the global default)"
            $parsedRefresh = 0
            if ($refreshRaw -and -not [int]::TryParse($refreshRaw, [ref]$parsedRefresh)) {
                Write-Host "RefreshHours must be numeric or empty." -ForegroundColor Red; return $null
            }
            $sendRaw = Read-Host "SendHours (optional, numeric - press Enter for the global default)"
            $parsedSend = 0
            if ($sendRaw -and -not [int]::TryParse($sendRaw, [ref]$parsedSend)) {
                Write-Host "SendHours must be numeric or empty." -ForegroundColor Red; return $null
            }

            $line = "HEADER|$normalizedField|$label"
            if ($refreshRaw) { $line += "|RefreshHours=$refreshRaw" }
            if ($sendRaw)    { $line += "|SendHours=$sendRaw" }
            return $line
        }
    }
}

function Get-WWFileNewline {
    <#
    Detects the newline convention already in use in a text file so the
    wizard can preserve it instead of forcing Add-Content's platform CRLF
    default. Returns 'LF' or 'CRLF'. A missing, empty, or single-line
    (no-newline) file falls back to 'CRLF', the sensible Windows default.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return 'CRLF' }

    $raw = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrEmpty($raw)) { return 'CRLF' }
    if ($raw.Contains("`r`n")) { return 'CRLF' }
    if ($raw.Contains("`n")) { return 'LF' }
    return 'CRLF'
}

function Add-WWNeedleLine {
    <#
    Appends a dated provenance comment and a validated needle line to
    needles_local.cfg as one logical write, preserving whatever newline
    convention the file already uses (LF or CRLF) rather than always
    introducing Windows CRLF via Add-Content. A missing terminal newline
    on the existing content gets exactly one separator added first, and a
    missing/empty file falls back to the Windows CRLF default. Throws on
    failure so the caller's try/catch can log and report fail-soft.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Line
    )

    $newline = Get-WWFileNewline -Path $Path
    $sep = if ($newline -eq 'LF') { "`n" } else { "`r`n" }

    $needsLeadingSep = $false
    if (Test-Path -LiteralPath $Path) {
        $existing = [System.IO.File]::ReadAllText($Path)
        if ($existing.Length -gt 0 -and -not ($existing.EndsWith("`n"))) {
            $needsLeadingSep = $true
        }
    }

    $timestamp = Get-Date -Format 'o'
    $comment = "# Added via Invoke-WhiteWalkerAction.ps1 on $timestamp"

    $toAppend = New-Object System.Text.StringBuilder
    if ($needsLeadingSep) { [void]$toAppend.Append($sep) }
    [void]$toAppend.Append($comment).Append($sep).Append($Line).Append($sep)

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText($Path, $toAppend.ToString(), $utf8NoBom)
}

function Invoke-WWNewNeedleWizard {
    Write-Host "`nWhich needle type do you want to add to needles_local.cfg?" -ForegroundColor Cyan
    Write-Host "  1. NEEDLE   - Event Log trigger"
    Write-Host "  2. SESSION  - session state change trigger"
    Write-Host "  3. DEFENDER - inline MDM firewall rule check"
    Write-Host "  4. HEADER   - run-header field telemetry"
    $choice = Read-Host "Select type"

    $type = switch ($choice) {
        '1' { 'NEEDLE' }
        '2' { 'SESSION' }
        '3' { 'DEFENDER' }
        '4' { 'HEADER' }
        default { $null }
    }
    if (-not $type) { Write-Host "Invalid selection." -ForegroundColor Red; return }

    $line = New-WWNeedleCandidateLine -Type $type
    if (-not $line) { Write-Host "Cancelled - no line written." -ForegroundColor Yellow; return }

    if (-not (Test-WWNeedleCandidateLine -Line $line)) {
        Write-Host "This line failed validation and was NOT written: $line" -ForegroundColor Red
        Write-WWAdminLog "New needle wizard: candidate line failed validation - $line" "WARN"
        return
    }

    Write-Host "`nCandidate line: $line" -ForegroundColor Gray
    Write-Host "This will be appended to: $script:NeedlesLocalFile" -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Append this line?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    try {
        Add-WWNeedleLine -Path $script:NeedlesLocalFile -Line $line
    } catch {
        Write-Host "Failed to write to needles_local.cfg: $($_.Exception.Message)" -ForegroundColor Red
        Write-WWAdminLog "New needle wizard: failed to append line - $line - $($_.Exception.Message)" "ERROR"
        return
    }
    Write-WWAdminLog "Appended needle to needles_local.cfg: $line"

    Write-Host "`nDone. Remember:" -ForegroundColor Green
    Write-Host "  - HayStack needs to reroll to pick this up: wait for the next automatic" -ForegroundColor White
    Write-Host "    reroll, or trigger one now with: haystack.ps1 -reroll -Force" -ForegroundColor White
    Write-Host "  - needles_local.cfg entries always win on label collision with the share copy." -ForegroundColor White
}

# =============================================================================
# 7. Tee Log Level Picker
# =============================================================================
function Get-WWTeeMaster {
    <# Reads the single tee master. Returns $null if missing/unreadable. #>
    if (-not (Test-Path -LiteralPath $script:TeeMasterFile)) { return $null }
    try { return (Import-PowerShellDataFile -LiteralPath $script:TeeMasterFile -ErrorAction Stop) } catch { return $null }
}

function Get-WWTeeLevelFiles {
    <# Levels 0-5 as defined by WW_tee_master.psd1 (name kept for the picker/tests). #>
    $master = Get-WWTeeMaster
    if ($null -eq $master) { return @() }
    $results = [System.Collections.Generic.List[object]]::new()
    for ($n = 0; $n -le 5; $n++) {
        $desc = if ($master.LevelDescriptions -and $master.LevelDescriptions["L$n"]) { [string]$master.LevelDescriptions["L$n"] } else { "level $n" }
        $results.Add([pscustomobject]@{ Name = "tee_level_$n"; Level = $n; Path = $script:TeeMasterFile; Description = $desc })
    }
    return $results
}

function Get-WWActiveTeeProfileName {
    <#
    The explicit Level marker in the active profile is authoritative (profiles are generated by
    WW_set_tee_level.ps1 and always carry it). A profile with no marker (pre-RC2.1 or hand-made)
    reports $null - callers must not guess.
    #>
    if (-not (Test-Path -LiteralPath $script:ActiveTeeProfile)) { return $null }
    try {
        $active = Import-PowerShellDataFile -LiteralPath $script:ActiveTeeProfile -ErrorAction Stop
        if ($null -ne $active.Level) {
            $n = 0
            if ([int]::TryParse([string]$active.Level, [ref]$n) -and $n -ge 0 -and $n -le 5) { return "tee_level_$n" }
        }
    } catch { }
    return $null
}

function Test-WWTeeProfileStale {
    <#
    .SYNOPSIS
    Reports whether the ACTIVE tee profile is out of date versus the master.

    .DESCRIPTION
    Compares the active profile's tags to what the master defines for the SAME selected level:
    missing tags (new in this build), extra tags (no longer supported), and a ProfileVersion that
    differs from the master's MasterVersion. It NEVER guesses the level: if the level cannot be
    determined the result is 'unknown_level' and the profile is left unchanged.
    #>
    $result = [pscustomobject]@{
        Active = $script:ActiveTeeProfile; Level = $null; Stale = $false
        Reason = 'not_installed'; MissingTags = @(); ExtraTags = @(); ReferencePath = $script:TeeMasterFile
    }
    if (-not (Test-Path -LiteralPath $script:ActiveTeeProfile)) { return $result }

    $levelName = Get-WWActiveTeeProfileName
    if (-not $levelName) { $result.Reason = 'unknown_level'; return $result }
    $result.Level = $levelName

    if (-not (Test-Path -LiteralPath $script:TeeSetScript) -or -not (Test-Path -LiteralPath $script:TeeMasterFile)) {
        $result.Reason = 'reference_missing'; return $result
    }
    try {
        . $script:TeeSetScript   # function scope only
        $n = [int]($levelName -replace '^tee_level_', '')
        $expected   = Get-CprTeeLevelProfile -Level $n -MasterPath $script:TeeMasterFile
        $activeData = Import-PowerShellDataFile -LiteralPath $script:ActiveTeeProfile -ErrorAction Stop
    } catch {
        $result.Reason = 'unreadable'
        return $result
    }

    $activeTags   = @($activeData.Events.Keys)
    $expectedTags = @($expected.Events.Keys)
    $result.MissingTags = @($expectedTags | Where-Object { $activeTags -notcontains $_ })
    $result.ExtraTags   = @($activeTags | Where-Object { $expectedTags -notcontains $_ })
    if ($result.MissingTags.Count -gt 0) { $result.Stale = $true; $result.Reason = 'missing_tags' }
    elseif ($result.ExtraTags.Count -gt 0) { $result.Stale = $true; $result.Reason = 'extra_tags' }
    elseif ([string]$activeData.ProfileVersion -ne [string]$expected.MasterVersion) { $result.Stale = $true; $result.Reason = 'version_mismatch' }
    else { $result.Reason = 'current' }
    return $result
}

function Invoke-WWTeeProfileRefresh {
    <#
    .SYNOPSIS
    One-step repair: regenerate the ACTIVE tee profile at its OWN selected level from the master.

    .DESCRIPTION
    New tags become available and unsupported ones disappear WITHOUT changing the selected volume
    knob. If the level cannot be reliably determined it reports the problem and leaves the
    profile untouched rather than guessing.
    #>
    param([switch]$Force)

    $status = Test-WWTeeProfileStale
    Write-Host "`
Active tee profile: $($status.Active)" -ForegroundColor Cyan
    Write-Host "Selected level    : $(if ($status.Level) { $status.Level } else { 'UNKNOWN' })" -ForegroundColor Cyan
    Write-Host "Status            : $($status.Reason)" -ForegroundColor $(if ($status.Stale) { 'Yellow' } else { 'Green' })

    if (-not $status.Level) {
        Write-Host "Cannot determine the selected level - leaving the active profile UNCHANGED." -ForegroundColor Red
        Write-Host "Use the Tee Log Level Picker to select a level explicitly." -ForegroundColor White
        Write-WWAdminLog "Tee profile refresh skipped: level could not be determined (reason=$($status.Reason))"
        return $false
    }
    if (-not $status.Stale -and -not $Force) {
        Write-Host "Active profile already matches the master for $($status.Level) - nothing to do." -ForegroundColor Green
        return $true
    }
    if ($status.MissingTags.Count -gt 0) { Write-Host "Missing tags: $($status.MissingTags -join ', ')" -ForegroundColor Yellow }
    if ($status.ExtraTags.Count -gt 0)   { Write-Host "Unsupported tags: $($status.ExtraTags -join ', ')" -ForegroundColor Yellow }
    if (-not $Force -and -not (Confirm-WWAction "Regenerate the active profile at $($status.Level) from the master (selected level is preserved)?")) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return $false
    }

    try {
        . $script:TeeSetScript   # function scope only
        $n = [int]($status.Level -replace '^tee_level_', '')
        $r = Set-CprTeeLevel -Level $n -MasterPath $script:TeeMasterFile -ActivePath $script:ActiveTeeProfile -GeneratedBy 'admin_console_refresh' -Reason 'console_refresh'
        if (-not $r.Success) { throw $r.Error }
        Write-WWAdminLog "Refreshed active tee profile at '$($status.Level)' from master (selected level preserved)"
        Write-Host "Done. Active profile regenerated at $($status.Level); the selected level is unchanged." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Refresh failed: $_" -ForegroundColor Red
        Write-WWAdminLog "Tee profile refresh FAILED: $_"
        return $false
    }
}

function Invoke-WWTeeLevelPicker {
    $levels = @(Get-WWTeeLevelFiles)
    if ($levels.Count -eq 0) {
        Write-Host "Tee master not found or unreadable: $script:TeeMasterFile" -ForegroundColor Red
        return
    }

    $activeName = Get-WWActiveTeeProfileName
    $staleStatus = Test-WWTeeProfileStale
    if ($staleStatus.Stale) {
        Write-Host "WARNING: the active profile is STALE ($($staleStatus.Reason))." -ForegroundColor Yellow
        Write-Host "         Use 'Refresh active tee profile' to rebuild it without changing your selected level." -ForegroundColor Yellow
    }
    Write-Host "`nCurrently active profile: $(if ($activeName) { $activeName } else { 'unknown/custom' })" -ForegroundColor Cyan
    Write-Host "Available tee log levels:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $levels.Count; $i++) {
        Write-Host ("  {0}. {1,-14} {2}" -f ($i + 1), $levels[$i].Name, $levels[$i].Description)
    }
    $selection = Read-Host "Select a level to activate (or press Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($selection)) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    $index = 0
    if (-not [int]::TryParse($selection, [ref]$index) -or $index -lt 1 -or $index -gt $levels.Count) {
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }
    $chosen = $levels[$index - 1]

    Write-Host "`nThis will regenerate the ACTIVE profile ($script:ActiveTeeProfile) at $($chosen.Name)." -ForegroundColor Yellow
    if (-not (Confirm-WWAction "Overwrite the active tee profile now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    try {
        . $script:TeeSetScript   # function scope only
        $r = Set-CprTeeLevel -Level $chosen.Level -MasterPath $script:TeeMasterFile -ActivePath $script:ActiveTeeProfile -GeneratedBy 'admin_console' -Reason 'console_pick'
        if (-not $r.Success) { throw $r.Error }
    } catch {
        Write-Host "Failed to activate $($chosen.Name): $_" -ForegroundColor Red
        Write-WWAdminLog "Tee level activation FAILED ($($chosen.Name)): $_"
        return
    }
    Write-WWAdminLog "Activated tee level '$($chosen.Name)' -> $script:ActiveTeeProfile (generated from master)"
    Write-Host "`nDone. Active profile is now $($chosen.Name)." -ForegroundColor Green
}

# =============================================================================
# 8. Diagnostics & Test Tools Launcher
# =============================================================================
function Invoke-WWDiagnosticsLauncher {
    $cprRoot = Split-Path -Parent $PSScriptRoot
    $entries = @($script:DiagToolInventory | Where-Object { Test-Path -LiteralPath (Join-Path $cprRoot $_.Path) })
    if ($entries.Count -eq 0) {
        Write-Host "No launcher-eligible diagnostics/tests scripts were found." -ForegroundColor Red
        return
    }

    Write-Host "`nDiagnostics & Test Tools:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $entries.Count; $i++) {
        Write-Host ("  {0,2}. {1,-45} {2}" -f ($i + 1), $entries[$i].Path, $entries[$i].Description)
    }
    $selection = Read-Host "Select a tool to launch (or press Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($selection)) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    $index = 0
    if (-not [int]::TryParse($selection, [ref]$index) -or $index -lt 1 -or $index -gt $entries.Count) {
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }
    $chosen = $entries[$index - 1]
    $fullPath = Join-Path $cprRoot $chosen.Path

    $argLine = Read-Host "Enter any parameters (e.g. -LogName System -EventID 10000), or press Enter for defaults"
    if (-not (Confirm-WWAction "Launch $($chosen.Path)?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    Write-WWAdminLog "Launching diagnostics tool: $fullPath $argLine"
    if ([string]::IsNullOrWhiteSpace($argLine)) {
        & $fullPath
    } else {
        Invoke-Expression "& `"$fullPath`" $argLine"
    }
}

# =============================================================================
# 9. Quick Actions
# =============================================================================
function Invoke-WWQuickHaystackReroll {
    Write-Host "`nThis runs: haystack.ps1 -reroll -Force (bypasses the TS task reroll cooldown)." -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Force a HayStack reroll now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    if (-not (Test-Path -LiteralPath $script:HaystackScript)) { Write-Host "haystack.ps1 not found at $script:HaystackScript" -ForegroundColor Red; return }
    & $script:HaystackScript -reroll -Force
    Write-WWAdminLog "Forced HayStack reroll via: $script:HaystackScript -reroll -Force"
    Write-Host "`nDone." -ForegroundColor Green
}

function Invoke-WWQuickClearStaleFlags {
    <#
    Reuses main\Main.Network.ps1's Clear-StaleFlagFiles (same age-threshold
    logic the live runtime uses) rather than reimplementing it. Dot-sources
    its dependencies (Main.Configuration.ps1 for the flag path variables,
    Main.Logging.ps1 for Write-Log) and calls it immediately within this same
    function body, so the import never needs to persist beyond this call.
    #>
    Write-Host "`nThis reuses the runtime's own Clear-StaleFlagFiles function to clear" -ForegroundColor Cyan
    Write-Host "any flag files older than its normal staleness threshold." -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Clear stale flag files now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }

    $mainDir = Join-Path $script:WWRoot "main"
    $configPath  = Join-Path $mainDir "Main.Configuration.ps1"
    $loggingPath = Join-Path $mainDir "Main.Logging.ps1"
    $networkPath = Join-Path $mainDir "Main.Network.ps1"

    if (-not ((Test-Path -LiteralPath $configPath) -and (Test-Path -LiteralPath $loggingPath) -and (Test-Path -LiteralPath $networkPath))) {
        Write-Host "main\ library files not found - cannot safely reuse Clear-StaleFlagFiles." -ForegroundColor Red
        Write-WWAdminLog "Clear stale flags: main\ library files not found" "WARN"
        return
    }

    try {
        . $configPath
        . $loggingPath
        . $networkPath
        if (Get-Command Clear-StaleFlagFiles -ErrorAction SilentlyContinue) {
            Clear-StaleFlagFiles
            Write-WWAdminLog "Cleared stale flag files via Clear-StaleFlagFiles"
            Write-Host "`nDone." -ForegroundColor Green
        } else {
            Write-Host "Clear-StaleFlagFiles function not found after import." -ForegroundColor Red
        }
    } catch {
        Write-Host "Failed to clear stale flag files: $_" -ForegroundColor Red
        Write-WWAdminLog "Clear stale flags failed: $_" "ERROR"
    }
}

function Invoke-WWQuickForceMainRun {
    Write-Host "`nThis runs WW_main.ps1 directly (bypasses waiting for the next DHCP/lock-event trigger)." -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Force an immediate WW_main run now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    if (-not (Test-Path -LiteralPath $script:WWMainScript)) { Write-Host "WW_main.ps1 not found at $script:WWMainScript" -ForegroundColor Red; return }
    & $script:WWMainScript
    Write-WWAdminLog "Forced immediate WW_main run via: $script:WWMainScript"
    Write-Host "`nDone." -ForegroundColor Green
}

function Invoke-WWQuickClearVpnHosts {
    Write-Host "`nThis runs: Set-VpnHostsEntry.ps1 -rm (clears Blackhole VPN hosts-file entries)." -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Clear Blackhole hosts-file entries now?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    if (-not (Test-Path -LiteralPath $script:VpnHostsScript)) { Write-Host "Set-VpnHostsEntry.ps1 not found at $script:VpnHostsScript" -ForegroundColor Red; return }
    & $script:VpnHostsScript -rm
    Write-WWAdminLog "Cleared Blackhole hosts entries via: $script:VpnHostsScript -rm"
    Write-Host "`nDone." -ForegroundColor Green
}

function Invoke-WWQuickSyslogPathTest {
    Write-Host "`nThis checks the path to the syslog VIP (state, DNS, route, queue) and sends ONE UDP test message" -ForegroundColor Cyan
    Write-Host "(machine=CPR_TESTER Label=cpr_syslog_path_test) that you can search for in Splunk." -ForegroundColor Cyan
    if (-not (Confirm-WWAction "Run the syslog path test and send one test message?")) { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    $syslogTest = Join-Path $script:WWRoot "diagnostics\Test-CprSyslogPath.ps1"
    if (-not (Test-Path -LiteralPath $syslogTest)) { Write-Host "Test-CprSyslogPath.ps1 not found at $syslogTest" -ForegroundColor Red; return }
    & $syslogTest -Send
    Write-WWAdminLog "Ran syslog path test (sent 1 CPR_TESTER message) via: $syslogTest -Send"
    Write-Host "`nDone." -ForegroundColor Green
}

function Invoke-WWQuickActionsMenu {
    Write-Host "`nQuick Actions:" -ForegroundColor Cyan
    Write-Host "  1. Force HayStack reroll"
    Write-Host "  2. Clear stale flag files"
    Write-Host "  3. Force an immediate WW_main run"
    Write-Host "  4. Clear Blackhole VPN hosts entries"
    Write-Host "  5. Syslog path test (checks the route to the syslog VIP, sends one CPR_TESTER message)"
    $choice = Read-Host "Select a quick action (or press Enter to cancel)"
    switch ($choice) {
        '1' { Invoke-WWAction -Name 'QuickAction:HaystackReroll' -Action { Invoke-WWQuickHaystackReroll } }
        '2' { Invoke-WWAction -Name 'QuickAction:ClearStaleFlags' -Action { Invoke-WWQuickClearStaleFlags } }
        '3' { Invoke-WWAction -Name 'QuickAction:ForceMainRun' -Action { Invoke-WWQuickForceMainRun } }
        '4' { Invoke-WWAction -Name 'QuickAction:ClearVpnHosts' -Action { Invoke-WWQuickClearVpnHosts } }
        '5' { Invoke-WWAction -Name 'QuickAction:SyslogPathTest' -Action { Invoke-WWQuickSyslogPathTest } }
        default { Write-Host "Cancelled." -ForegroundColor Yellow }
    }
}

# =============================================================================
# W. Watch a WhiteWalker log (in-process, Q/Esc returns to this menu)
# =============================================================================
function Get-WWWatchStreamChoices {
    <#
    The streams a tech most often needs while working a captive-portal or VPN
    incident. Names and PATHS are sourced from Watch-WhiteWalkerLog.ps1's own
    inventory (the single configured log inventory) - nothing is hardcoded
    here beyond which of those streams to surface.
    #>
    $preferred = @('Main', 'CapPortal', 'CapPortalBase', 'FlareGunUser', 'XmlVault', 'Haystack', 'AdminActions')
    $inventory = @(Get-WWLogInventory)
    $choices = @()
    foreach ($name in $preferred) {
        $definition = $inventory | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($definition) { $choices += $definition }
    }
    return $choices
}

function Get-WWBrowseLogFiles {
    # Every log-like file under logs\ (top level + spool\), newest first.
    $root  = $script:WWLogDir
    $found = @()
    foreach ($dir in @($root, (Join-Path $root 'spool'))) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        $found += @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.log', '.txt', '.jsonl', '.json', '.bak') })
    }
    return @($found | Sort-Object LastWriteTime -Descending)
}

function Invoke-WWBrowseLogs {
    <#
    Pick ANY file under logs\ (not just the curated streams): tail it live, view
    its last 200 lines, or open it in Notepad. Type text instead of a number to
    filter the list. Runs inside Invoke-WWWatchLog, so Show-WWLogStream is
    already loaded. Read-only: it never changes a log.
    #>
    $root = $script:WWLogDir
    $all  = @(Get-WWBrowseLogFiles)
    if ($all.Count -eq 0) { Write-Host "No log files found under $root" -ForegroundColor Red; return }
    $view = $all
    while ($true) {
        $shown = @($view | Select-Object -First 40)
        Write-Host ("`nFiles under {0} (newest first, {1} shown of {2}):" -f $root, $shown.Count, $view.Count) -ForegroundColor Cyan
        for ($i = 0; $i -lt $shown.Count; $i++) {
            $rel = $shown[$i].FullName.Substring($root.Length + 1)
            Write-Host ("  {0,2}. {1,-48} {2,8} KB  {3:MM-dd HH:mm}" -f ($i + 1), $rel, [math]::Ceiling($shown[$i].Length / 1KB), $shown[$i].LastWriteTime)
        }
        $sel = Read-Host "Number to open, text to filter the list, or Enter to cancel"
        if ([string]::IsNullOrWhiteSpace($sel)) { Write-Host "Cancelled." -ForegroundColor Yellow; return }
        $n = 0
        if ([int]::TryParse($sel, [ref]$n)) {
            if ($n -lt 1 -or $n -gt $shown.Count) { Write-Host "Invalid selection." -ForegroundColor Red; continue }
            $file = $shown[$n - 1]
            $rel  = $file.FullName.Substring($root.Length + 1)
            $mode = Read-Host "[T]ail live, [V]iew last 200 lines, [O]pen in Notepad (Enter cancels)"
            $def  = [pscustomobject]@{ Name = $rel; File = $rel; Description = ''; Json = ($file.Extension -eq '.jsonl') }
            switch -Regex ($mode) {
                '^[Tt]' { Write-WWAdminLog "BrowseLogs: tailing $rel"; Show-WWLogStream -Definition $def -Count 50 -Match $null -Follow -AllowExitKey; return }
                '^[Vv]' { Write-WWAdminLog "BrowseLogs: viewing $rel"; Show-WWLogStream -Definition $def -Count 200 -Match $null; return }
                '^[Oo]' {
                    Write-WWAdminLog "BrowseLogs: opening $rel in Notepad"
                    try { Start-Process -FilePath 'notepad.exe' -ArgumentList ('"{0}"' -f $file.FullName) -ErrorAction Stop }
                    catch { Write-Host "Could not open Notepad: $($_.Exception.Message)" -ForegroundColor Red }
                    return
                }
                default { Write-Host "Cancelled." -ForegroundColor Yellow; return }
            }
        }
        $match = @($all | Where-Object { $_.Name -like "*$sel*" })
        if ($match.Count -eq 0) { Write-Host "No file name contains '$sel'." -ForegroundColor Yellow; $view = $all } else { $view = $match }
    }
}

function Invoke-WWWatchLog {
    <#
    Runs the existing admin\Watch-WhiteWalkerLog.ps1 viewer IN-PROCESS so the
    tech does not have to bounce between the two tools. The standalone script
    keeps working unchanged - it is dot-sourced here, which its own entry-point
    guard explicitly supports. Q or Esc breaks the tail loop (non-blocking key
    check) and returns to this console's main menu; the console never exits.
    Fail-soft: a missing log is reported and control returns to the menu.
    #>
    $watcher = Join-Path $PSScriptRoot 'Watch-WhiteWalkerLog.ps1'
    if (-not (Test-Path -LiteralPath $watcher)) {
        Write-Host "Watch-WhiteWalkerLog.ps1 not found at $watcher" -ForegroundColor Red
        Write-WWAdminLog "WatchLog: viewer not found at $watcher" "WARN"
        return
    }

    . $watcher

    $choices = @(Get-WWWatchStreamChoices)
    if ($choices.Count -eq 0) {
        Write-Host "No log streams are available to tail." -ForegroundColor Red
        Write-WWAdminLog "WatchLog: no streams available" "WARN"
        return
    }

    Write-Host "`nWatch a WhiteWalker log:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $choices.Count; $i++) {
        Write-Host ("  {0,2}. {1,-15} {2}" -f ($i + 1), $choices[$i].Name, $choices[$i].Description)
    }
    Write-Host "   A. Browse ALL files under logs\ (tail, view, or open in Notepad)"
    $selection = Read-Host "Select a log to tail, A for all files (or press Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($selection)) { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    if ($selection -in @('A', 'a')) { Invoke-WWBrowseLogs; return }

    $index = 0
    if (-not [int]::TryParse($selection, [ref]$index) -or $index -lt 1 -or $index -gt $choices.Count) {
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }
    $definition = $choices[$index - 1]
    $path = Get-WWLogPath $definition

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Host "Log not found (it may not have been created yet): $path" -ForegroundColor DarkYellow
        Write-WWAdminLog "WatchLog: $($definition.Name) not present at $path - returned to menu" "WARN"
        return
    }

    Write-WWAdminLog "WatchLog: tailing $($definition.Name) ($path)"
    Show-WWLogStream -Definition $definition -Count 50 -Match $null -Follow -AllowExitKey
    Write-WWAdminLog "WatchLog: stopped tailing $($definition.Name)"
}

# =============================================================================
# Main menu
# =============================================================================
function Get-WWCprVersion {
    # The deployed CPR build version, read from the deployed config ($ver there is authoritative).
    try {
        $cfg = Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.Configuration.ps1'
        $m = Select-String -LiteralPath $cfg -Pattern '^\$ver\s*=\s*"([^"]+)"' -ErrorAction Stop | Select-Object -First 1
        if ($m) { return $m.Matches[0].Groups[1].Value }
    } catch { }
    return 'unknown'
}

function Show-WWMainMenu {
    Write-Host ("`nWhiteWalker tech action console - CPR v{0}" -f (Get-WWCprVersion)) -ForegroundColor Cyan
    Write-Host "  1. VPN Profile Restore"
    Write-Host "  2. Force XmlVault Sync (bypass cooldown)"
    Write-Host "  3. Self-Update Trigger"
    Write-Host "  4. Tech Check-In (telemetry)"
    Write-Host "  5. Needles Sync Check (diff, read-only)"
    Write-Host "  6. New Needle Wizard"
    Write-Host "  7. Tee Log Level Picker"
    Write-Host "  T. Refresh Active Tee Profile (keeps your selected level)"
    Write-Host "  8. Diagnostics & Test Tools Launcher"
    Write-Host "  9. Quick Actions"
    Write-Host "  W. Watch / browse WhiteWalker logs (Q or Esc returns here)"
    Write-Host "  0. Exit"
}

function Start-WWActionMenu {
    while ($true) {
        Show-WWMainMenu
        $choice = Read-Host "Select an action"
        switch ($choice) {
            '1' { Invoke-WWAction -Name 'VpnProfileRestore'  -Action { Invoke-WWVpnProfileRestore } }
            '2' { Invoke-WWAction -Name 'ForceXmlVaultSync'  -Action { Invoke-WWForceXmlVaultSync } }
            '3' { Invoke-WWAction -Name 'SelfUpdateTrigger'  -Action { Invoke-WWSelfUpdateTrigger } }
            '4' { Invoke-WWAction -Name 'TechCheckIn'        -Action { Invoke-WWTechCheckIn } }
            '5' { Invoke-WWAction -Name 'NeedlesSyncCheck'   -Action { Invoke-WWNeedlesSyncCheck } }
            '6' { Invoke-WWAction -Name 'NewNeedleWizard'    -Action { Invoke-WWNewNeedleWizard } }
            '7' { Invoke-WWAction -Name 'TeeLevelPicker'     -Action { Invoke-WWTeeLevelPicker } }
            # RC2.1 (Required H): one-step repair for a sticky/stale active
            # profile. Refreshes from the SELECTED level - never changes it.
            { $_ -in @('T', 't') } { Invoke-WWAction -Name 'TeeProfileRefresh' -Action { Invoke-WWTeeProfileRefresh } }
            '8' { Invoke-WWAction -Name 'DiagnosticsLauncher' -Action { Invoke-WWDiagnosticsLauncher } }
            '9' { Invoke-WWAction -Name 'QuickActionsMenu'   -Action { Invoke-WWQuickActionsMenu } }
            # RC2.2 (Required F): in-process log watcher. Q/Esc breaks the tail
            # loop and returns here - it never exits the console.
            { $_ -in @('W', 'w') } { Invoke-WWAction -Name 'WatchLog' -Action { Invoke-WWWatchLog } }
            '0' { Write-Host "Exiting."; return }
            default { Write-Host "Invalid selection." -ForegroundColor Red }
        }
    }
}

if (-not ($MyInvocation.InvocationName -eq '.')) {
    Start-WWActionMenu
}
