#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HayStack Action Script - Event Capture and Structured Logging
  Version: 1.1.2
  Author: steve.horton@optum.com
  Date: 30-May-2026

  Changes in 1.1.2:
    - Added HEADER directives: SendHours-gated shipping of cached run-header
      fields from header_cache.json via Write-HaystackTelemetry/Write-TeeLog.
    - HEADER checks run inline on any event/session/heartbeat wake.

  Changes in 1.1.1:
    - Added flag-gated DEFENDER checks for MDM firewall rule presence.
    - DEFENDER checks run inline on any event/session/heartbeat wake.

  Changes in 1.1.0:
    - NEW: Syslog/Splunk forwarding via WW_syslog.ps1
      $SyslogEnabled = $true/$false gate - set $false during testing
      Every NEEDLE_HIT (event and SESSION) forwarded to cpr-syslog.uhc.com:514
      RFC 3164 format, key=value payload for clean Splunk field extraction
      Auto-enriched with machine name and logged-on user (Win32_ComputerSystem)
      ExtraInfo freeform field available at each call site for additional context
      Invoked via call operator + splatting so quoted payloads pass through intact
      Non-fatal - syslog failure logs WARN locally, execution continues
    - NEW: Get-LoggedOnUser helper (Win32_ComputerSystem - works from SYSTEM context)
    - NEW: Invoke-SyslogSend helper (inline - no dependency on WW_syslog.ps1 existing)

.DESCRIPTION
  Fired by the HayStack_Monitor Task Scheduler task when any registered
  needle event fires. Runs as SYSTEM, hidden, no window.

  On wake:
    1. Load the merged needle list (local cache + local test bed)
    2. For each needle, query its log for matching events in the last
       $HaystackLookbackSeconds seconds
    3. For every hit found, write a structured entry to haystack.log

  No loops. No polling. No sleep. Fires once per TS wake, does the
  lookback, writes hits, exits. The OS is the scheduler.

  If two needle triggers fire close together (race condition), both events
  will be captured in the same action run via the lookback window - no
  hits are lost.

  Log format (one line per hit):
    YYYY-MM-DD HH:mm:ss.fff [HAYSTACK] [Label] LogName/EventID | TimeCreated | MachineName | Message

.NOTES
  This script is ONLY called by Task Scheduler (HayStack_Monitor task).
  It can also be run manually for testing: .\haystack_action.ps1 -Verbose
  Use -LookbackSeconds to override the default window for manual runs.
#>

[CmdletBinding()]
param(
    [int]$LookbackSeconds = 60    # How far back to look for matching events on each wake
                                   # Default 60s gives comfortable coverage even if TS fires
                                   # slightly late. Overlapping runs are prevented by
                                   # MultipleInstancesPolicy = IgnoreNew in the task.
)

# =============================================================================
# Configuration
# =============================================================================

$HaystackVersion        = "1.1.2"

$LocalCacheDir          = "C:\ProgramData\WhiteWalker"
$LogDir                 = Join-Path $LocalCacheDir "logs"
$LocalNeedlesFile       = Join-Path $LocalCacheDir "needles.cfg"        # synced from share
$LocalNeedlesFile_Local = Join-Path $LocalCacheDir "needles_local.cfg"  # local test bed

$HaystackLogFile        = Join-Path $LogDir "haystack.log"
$HaystackLogMaxBytes    = 1MB
$HaystackLogKeep        = 5

# Syslog / Splunk forwarding
# Set $SyslogEnabled = $false during testing to suppress syslog without changing anything else.
$SyslogEnabled          = $true
$SyslogServer           = 'cpr-syslog.uhc.com'
$SyslogPort             = 514
$SyslogFacility         = 16     # local0
$SyslogSeverity         = 5      # Notice
$WWSyslogScript         = Join-Path $LocalCacheDir "WW_syslog.ps1"
$SyslogQueueFile        = Join-Path $LogDir "haystack_syslog_queue.jsonl"
# RC2.1 (Required G): narrowly scoped USER drop directory. Non-SYSTEM producers
# (WW_cap_portal_runner_base.ps1 and the full captive-portal runner run as the
# interactive user) cannot append to the SYSTEM-owned queue above, so WW_tee.ps1
# drops one atomic file per event here and this SYSTEM-context script ingests
# them into the canonical queue. Queue format and drain semantics are unchanged.
$SyslogSpoolDir         = Join-Path $LogDir "spool"
$SyslogSpoolMaxFiles    = 500    # ingestion cap per pass, protects against a flood
$SyslogQueueMaxEntries  = 500    # max queued hits before oldest are dropped
$SyslogQueueMaxAgeDays  = 7      # entries older than this are discarded on drain
$WwStateFile            = "C:\Windows\UHGLogs\state.json"  # read currentState

# DEFENDER registry checks
$DefenderFwRegPath             = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\FirewallRules'
$DefenderFlagDir               = Join-Path $LocalCacheDir 'defender_flags'
$DefenderCheckIntervalHours    = 6

# HEADER run-header telemetry
# Consolidated cache written by WW_main's Write-RunHeader (main\Main.Logging.ps1).
# One JSON file for every known run-header field: value, collected_at, last_sent_at.
$HeaderCacheFile               = Join-Path $LocalCacheDir 'header_cache.json'
$HeaderSendIntervalHours       = 24   # global default SendHours for HEADER needles

# Tee gating for this process. The HayStack_Monitor task only exists when
# WW_main registered it with $HaystackEnabled = $true, so haystack is on by
# definition here. $TeeEnabled/$TeeEventsFile live in WW_main's config block
# and are not visible to this standalone process - the real volume knob for
# HEADER telemetry remains the active WW_tee_events.psd1 profile (the tag must
# be present there) plus the needle itself being configured.
$HaystackEnabled               = $true
$TeeEnabled                    = $true
$TeeEventsFile                 = Join-Path $LocalCacheDir 'WW_tee_events.psd1'

# =============================================================================
# Syslog Helpers
# Inline copy - does not depend on WW_syslog.ps1 being present.
# WW_syslog.ps1 is the standalone callable wrapper for external use.
# =============================================================================
function Get-LoggedOnUser {
    # Returns the interactive logged-on user.
    # $env:USERNAME returns SYSTEM when running in SYSTEM context.
    # Win32_ComputerSystem.UserName returns the actual interactive user.
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($cs.UserName)) { return $cs.UserName }
        return 'NO_INTERACTIVE_USER'
    } catch {
        return 'USER_UNKNOWN'
    }
}

# =============================================================================
# Schema helper loader (Test-HaystackMsgSchema)
# Lazily dot-sources WW_haystack_schema.ps1 from the deploy dir if present.
# Lint/validation is a no-op (never blocks a real NEEDLE_HIT) if it's missing.
# =============================================================================
$WWHaystackSchemaScript = Join-Path $LocalCacheDir "WW_haystack_schema.ps1"

function Import-HaystackSchemaHelpers {
    if (Get-Command Test-HaystackMsgSchema -ErrorAction SilentlyContinue) { return }
    try {
        if (Test-Path -LiteralPath $WWHaystackSchemaScript) {
            . $WWHaystackSchemaScript
        }
    } catch {
        Write-HALog "Could not load WW_haystack_schema.ps1: $_" "WARN"
    }
}

function Get-CurrentNetworkState {
    # Read currentState from ww_state.json written by WW_main Send-FlareEvent.
    # Returns the state string (e.g. "user_tun", "on_prem") or empty string if unknown.
    try {
        if (Test-Path $WwStateFile) {
            $s = Get-Content $WwStateFile -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($s.currentState) { return $s.currentState }
        }
    } catch { }
    return ""
}

function Test-SyslogReachable {
    # Check currentState to determine if syslog server is likely reachable.
    # on_prem / user_tun / mgmt_tun = corporate network reachable = send live.
    # Anything else = off-prem / captive portal = cache the hit.
    $state = Get-CurrentNetworkState
    $reachableStates = @("on_prem","user_tun","mgmt_tun")
    return ($reachableStates -contains $state)
}

function Write-SyslogQueue {
    param([string]$Payload, [string]$ExtraInfo = "")
    try {
        $entry = @{
            ts        = (Get-Date).ToString("o")
            payload   = $Payload
            extraInfo = $ExtraInfo
        } | ConvertTo-Json -Compress
        Add-Content -Path $SyslogQueueFile -Value $entry -Encoding UTF8 -ErrorAction Stop
        Write-HALog "SyslogQueue: hit cached (syslog unreachable) payload=$Payload" "DEBUG"
    } catch {
        Write-HALog "SyslogQueue: failed to write queue entry: $_" "WARN"
    }
}

function Import-SyslogSpool {
    <#
    .SYNOPSIS
    Ingests USER-context spool drops into the canonical queue (Required G).

    .DESCRIPTION
    Each spool file holds exactly ONE queue line, byte-identical to what the
    canonical JSONL holds, written atomically (temp + move) by WW_tee.ps1. This
    SYSTEM-context pass appends them in creation order and deletes each file
    only after it is safely in the queue, so a crash can at worst re-ingest a
    duplicate rather than lose evidence. In-progress .tmp files are skipped.
    Strictly fail-soft: any failure leaves the drop in place for the next pass.
    #>
    if (-not (Test-Path $SyslogSpoolDir)) { return 0 }

    $ingested = 0
    try {
        $files = @(Get-ChildItem -Path $SyslogSpoolDir -Filter 'evt_*.json' -File -ErrorAction Stop |
                   Sort-Object CreationTimeUtc, Name |
                   Select-Object -First $SyslogSpoolMaxFiles)
        foreach ($file in $files) {
            try {
                $line = (Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
                if ([string]::IsNullOrWhiteSpace($line)) {
                    Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                    continue
                }
                # Only ingest something that actually parses as a queue entry.
                $null = $line | ConvertFrom-Json -ErrorAction Stop
                Add-Content -Path $SyslogQueueFile -Value $line -Encoding UTF8 -ErrorAction Stop
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                $ingested++
            } catch {
                Write-HALog "SyslogSpool: could not ingest $($file.Name): $_" "DEBUG"
            }
        }
        if ($ingested -gt 0) {
            Write-HALog "SyslogSpool: ingested $ingested user-context event(s) into the canonical queue" "INFO"
        }
    } catch {
        Write-HALog "SyslogSpool: ingestion pass failed: $_" "DEBUG"
    }
    return $ingested
}

function Drain-SyslogQueue {
    # Called before sending a live hit when syslog IS reachable.
    # Sends queued entries FIFO, skips entries older than $SyslogQueueMaxAgeDays.
    # Truncates queue to $SyslogQueueMaxEntries if overfull (drops oldest).
    # Pull in anything USER-context runners dropped before deciding the queue
    # is empty, otherwise their evidence would never ship. Guarded so harnesses
    # that extract Drain-SyslogQueue in isolation keep working unchanged.
    if (Get-Command Import-SyslogSpool -ErrorAction SilentlyContinue) {
        $null = Import-SyslogSpool
    }

    # Claim the queue ATOMICALLY by renaming it, then work on the claimed copy. Writers that append
    # while we drain create a fresh queue file, so nothing they add can be read-then-deleted (the old
    # read / send / Remove-Item left a window where an entry appended mid-drain was destroyed unsent).
    $workFile = "$SyslogQueueFile.draining"
    try {
        if (Test-Path -LiteralPath $workFile) {
            $claimAge = ((Get-Date) - (Get-Item -LiteralPath $workFile -ErrorAction Stop).LastWriteTime).TotalMinutes
            if ($claimAge -lt 5) {
                Write-HALog "SyslogQueue: another drain is active (claim $([math]::Round($claimAge,1))m old) - skipping" "DEBUG"
                return
            }
            Write-HALog "SyslogQueue: recovering a stale claimed queue left by an earlier drain" "WARN"
        } else {
            if (-not (Test-Path -LiteralPath $SyslogQueueFile)) { return }
            Move-Item -LiteralPath $SyslogQueueFile -Destination $workFile -ErrorAction Stop
        }
        (Get-Item -LiteralPath $workFile -ErrorAction Stop).LastWriteTime = Get-Date   # stamp the claim time
    } catch {
        Write-HALog "SyslogQueue: could not claim the queue for draining (a writer has it open?): $_" "DEBUG"
        return
    }

    try {
        $lines = Get-Content -LiteralPath $workFile -Encoding UTF8 -ErrorAction Stop
        if (-not $lines -or $lines.Count -eq 0) {
            Remove-Item -LiteralPath $workFile -Force -ErrorAction SilentlyContinue
            return
        }

        # Trim to max entries (keep newest)
        if ($lines.Count -gt $SyslogQueueMaxEntries) {
            $dropped = $lines.Count - $SyslogQueueMaxEntries
            $lines   = $lines | Select-Object -Last $SyslogQueueMaxEntries
            Write-HALog "SyslogQueue: trimmed $dropped oldest entries (max=$SyslogQueueMaxEntries)" "WARN"
        }

        $cutoff  = (Get-Date).AddDays(-$SyslogQueueMaxAgeDays)
        $sent    = 0
        $expired = 0
        $failed  = 0
        $keep    = @()

        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $entry = $line | ConvertFrom-Json
                $age   = [datetime]::Parse($entry.ts)
                if ($age -lt $cutoff) { $expired++; continue }

                # Attempt send - call operator + splatting so payloads containing
                # embedded double-quotes are passed intact (Start-Process
                # -ArgumentList mangles them when building the child command line)
                $splatArgs = @{
                    Message      = $entry.payload
                    SyslogServer = $SyslogServer
                    Port         = $SyslogPort
                    Facility     = $SyslogFacility
                    Severity     = $SyslogSeverity
                }
                if ($entry.extraInfo) { $splatArgs['ExtraInfo'] = $entry.extraInfo }
                & $WWSyslogScript @splatArgs
                if ($LASTEXITCODE -eq 0) {
                    $sent++
                    $sentAction = if ([string]$entry.payload -match 'action="([^"]+)"') { $Matches[1] } else { '?' }
                    Write-HALog "SyslogQueue: sent action=$sentAction queued_at=$($entry.ts)" "DEBUG"
                } else { $failed++; $keep += $line }
            } catch {
                $failed++
                $keep += $line  # re-queue on failure
            }
        }

        # Put failed entries back by APPENDING to the live queue (never overwrite what writers added
        # meanwhile). If cleanup fails the claimed file is kept and a later drain recovers it.
        try {
            if ($keep.Count -gt 0) { Add-Content -LiteralPath $SyslogQueueFile -Value $keep -Encoding UTF8 -ErrorAction Stop }
            Remove-Item -LiteralPath $workFile -Force -ErrorAction Stop
        } catch {
            Write-HALog "SyslogQueue: could not finish cleanup (claimed file kept for the next drain): $_" "WARN"
        }

        Write-HALog "SyslogQueue: drained - sent=$sent expired=$expired failed=$failed remaining=$($keep.Count)" "INFO"

    } catch {
        Write-HALog "SyslogQueue: drain error: $_" "WARN"
    }
}

function Invoke-SyslogSend {
    <#
    .SYNOPSIS
    Sends a single RFC 3164 syslog message to the enterprise collector.
    Non-fatal - errors are logged locally and execution continues.
    Gated by $SyslogEnabled - set $false to suppress without code changes.
    #>
    param(
        [string]$Payload,           # key=value body built by caller
        [string]$ExtraInfo = ''    # freeform quoted field - empty if not needed
    )

    if (-not $SyslogEnabled) { return }

    if (-not (Test-Path $WWSyslogScript)) {
        Write-HALog "WW_syslog.ps1 not found at $WWSyslogScript - caching hit" "WARN"
        Write-SyslogQueue -Payload $Payload -ExtraInfo $ExtraInfo
        return
    }

    # Check network state - only send live when corp network is reachable
    if (-not (Test-SyslogReachable)) {
        Write-HALog "Syslog: network state offline/captive - caching hit for later drain" "DEBUG"
        Write-SyslogQueue -Payload $Payload -ExtraInfo $ExtraInfo
        return
    }

    # Drain any previously cached hits first (FIFO)
    Drain-SyslogQueue

    # Send current hit and verify delivery via exit code
    try {
        $splatArgs = @{
            Message      = $Payload
            SyslogServer = $SyslogServer
            Port         = $SyslogPort
            Facility     = $SyslogFacility
            Severity     = $SyslogSeverity
        }
        if ($ExtraInfo) { $splatArgs['ExtraInfo'] = $ExtraInfo }
        & $WWSyslogScript @splatArgs
        if ($LASTEXITCODE -eq 0) {
            Write-HALog "Syslog fired: $Payload$(if ($ExtraInfo) { ' ExtraInfo="' + $ExtraInfo + '"' })" "DEBUG"
        } else {
            Write-HALog "Syslog send failed (exit=$LASTEXITCODE) - caching hit" "WARN"
            Write-SyslogQueue -Payload $Payload -ExtraInfo $ExtraInfo
        }
    } catch {
        Write-HALog "Syslog send failed - caching hit: $_" "WARN"
        Write-SyslogQueue -Payload $Payload -ExtraInfo $ExtraInfo
    }
}

# =============================================================================
# Logging
# Same rotation model as WW_main.ps1 and haystack.ps1
# =============================================================================
function Write-HALog {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts [$Level] [HayStack_Action] $Message"
    Write-Verbose $line
    try {
        if (Test-Path $HaystackLogFile) {
            $sz = (Get-Item $HaystackLogFile -ErrorAction SilentlyContinue).Length
            if ($sz -and $sz -ge $HaystackLogMaxBytes) {
                $oldest = "$HaystackLogFile.$HaystackLogKeep"
                if (Test-Path $oldest) { Remove-Item $oldest -Force -ErrorAction SilentlyContinue }
                for ($i = ($HaystackLogKeep - 1); $i -ge 1; $i--) {
                    $src = "$HaystackLogFile.$i"
                    $dst = "$HaystackLogFile.$($i + 1)"
                    if (Test-Path $src) { Rename-Item $src $dst -Force -ErrorAction SilentlyContinue }
                }
                Rename-Item $HaystackLogFile "$HaystackLogFile.1" -Force -ErrorAction SilentlyContinue
            }
        }
        Add-Content -Path $HaystackLogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

function Write-HaystackHit {
    <#
    .SYNOPSIS
    Writes a structured NEEDLE_HIT entry to haystack.log.
    Separate from Write-HALog so hits are visually distinct and easy to
    grep/parse later (e.g. by Read-Haystack.ps1 or a SIEM shipper).
    #>
    param(
        [string]$Label,
        $Event,
        [object]$Needle = $null
    )

    $ts          = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $evtTime     = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
    $evtTimeIso  = $Event.TimeCreated.ToString("o")
    $evtId       = $Event.Id
    $logName     = $Event.LogName
    $machine     = $Event.MachineName
    $provider    = $Event.ProviderName

    # Pull message - suppress format errors on events with missing message DLLs
    try {
        $msg = $Event.FormatDescription()
        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = "(no message - DLL may be missing)" }
        # Flatten to single line for structured log
        $msg = $msg.Trim() -replace '\r?\n', ' | '
    } catch {
        $msg = "(message format failed: $_)"
    }

    # Structured hit line - prefix NEEDLE_HIT makes it trivially greppable
    $line = "$ts [NEEDLE_HIT] [$Label] $logName/EventID:$evtId Provider:$provider Machine:$machine EvtTime:$evtTime MSG: $msg"

    try {
        Add-Content -Path $HaystackLogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        Write-Verbose $line
    } catch {
        Write-HALog "Failed to write hit for label '$Label': $_" "WARN"
    }

    # Forward to syslog/Splunk if enabled
    $hitUser = Get-LoggedOnUser
    $syslogPayload = 'action=needle_hit machine="{0}" user="{1}" Label="{2}" EventID="{3}" LogName="{4}" Provider="{5}" EvtTime="{6}"' -f `
        $env:COMPUTERNAME, $hitUser, $Label, $evtId, $logName, $provider, $evtTimeIso

    $extendedLoggingMode = '0'
    if ($Needle -and ($Needle.PSObject.Properties.Name -contains 'ExtendedLogging')) {
        $extendedLoggingMode = ([string]$Needle.ExtendedLogging).Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($extendedLoggingMode)) { $extendedLoggingMode = '0' }
    }

    if ($extendedLoggingMode -in @('1','2','all')) {
        try {
            $lookupLogName = if ($Needle.LogName) { $Needle.LogName } else { $logName }
            $lookupEventId = if ($Needle.EventID) { [int]$Needle.EventID } else { [int]$evtId }
            $eventBody = Get-WinEvent -FilterHashtable @{
                LogName = $lookupLogName
                Id      = $lookupEventId
            } -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message -First 1

            if (-not [string]::IsNullOrEmpty($eventBody)) {
                if ($extendedLoggingMode -eq '1' -and $eventBody.Length -gt 128) {
                    $eventBody = $eventBody.Substring(0, 128)
                }
                if ($extendedLoggingMode -in @('2','all')) {
                    $eventBody = $eventBody -replace '\r?\n', ' | '
                }
                $eventBody = $eventBody -replace '"', "'"
                $syslogPayload += ' body="{0}"' -f $eventBody
            }
        } catch {
            Write-HALog "Unable to fetch extended event body for label '$Label': $_" "DEBUG"
        }
    }

    Invoke-SyslogSend -Payload $syslogPayload
}

# =============================================================================
# Needle Parser  (self-contained copy - action script must be independent)
# Identical logic to haystack.ps1 Read-NeedleFile.
# We do NOT dot-source haystack.ps1 to keep the action script standalone
# and resilient to haystack.ps1 deployment timing.
# =============================================================================

# Known run-header field names a HEADER directive may reference. Keep in sync
# with $HaystackHeaderFields in haystack.ps1 and $HeaderCacheFieldNames in
# main\Main.Logging.ps1.
$HaystackHeaderFields = @(
    'ww_version'
    'os'
    'model'
    'serial'
    'last_boot'
    'csc_version'
    'csc_source'
    'vpn_profile'
)

# -----------------------------------------------------------------------------
# DEFENDER rule-name normalization (keep identical to haystack.ps1)
# -----------------------------------------------------------------------------
# The Defender/MDM team does not follow a stable naming convention, so the same
# rule has shipped as both "V2 - MsWebView2 Any Out" and "V2-MsWebView2 Any Out".
# Literal matching produced a false MISSING. We therefore compare a collapsed
# token form: lowercase, then drop every character that is not a letter or
# digit. That makes matching case-insensitive and tolerant of spaces, hyphens,
# underscores, slashes, dots, and repeated whitespace.
#
# TRADEOFF: because separators are removed, "Allow-Web" and "AllowWeb" (and in
# theory "A-B" vs "AB") collapse to the same key, so an extremely short or
# generic RuleNameMatch can collide with an unrelated rule. Matching remains a
# SUBSTRING test (not a full-name equality test) exactly as before, so operators
# should configure a distinctive, stable, descriptive substring of the rule name.
function ConvertTo-DefenderRuleNameKey {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return [regex]::Replace($Text.ToLowerInvariant(), '[^\p{L}\p{Nd}]', '')
}

function Test-DefenderRuleNameMatch {
    <#
    .SYNOPSIS
    Case-insensitive, separator-tolerant literal substring match of a configured
    DEFENDER RuleNameMatch against a firewall rule's Name= value.
    Returns $false for an empty/whitespace-only or fully-normalized-away needle
    so an unusable configuration never matches everything.
    #>
    param(
        [string]$RuleName,
        [string]$RuleNameMatch
    )

    $needleKey = ConvertTo-DefenderRuleNameKey -Text $RuleNameMatch
    if (-not $needleKey) { return $false }

    $ruleKey = ConvertTo-DefenderRuleNameKey -Text $RuleName
    if (-not $ruleKey) { return $false }

    return $ruleKey.Contains($needleKey)
}

function Read-NeedleFile {
    param(
        [string]$Path,
        [string]$SourceTag = "share"
    )

    $validStateChanges = @('SessionLock','SessionUnlock','RemoteConnect','RemoteDisconnect','ConsoleConnect','ConsoleDisconnect')
    $results = [System.Collections.Generic.List[object]]::new()

    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    try {
        $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    } catch {
        Write-HALog "[$SourceTag] Could not read needle file: $Path - $_" "WARN"
        return @()
    }

    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.Trim()

        if ($trimmed.Length -eq 0)        { continue }
        if ($trimmed.StartsWith('#'))      { continue }
        if ($trimmed -match '^version:')  { continue }

        # --- SESSION trigger ---
        if ($trimmed -match '^SESSION\|') {
            $parts = $trimmed -split '\|', 3
            if ($parts.Count -lt 3) {
                Write-HALog "[$SourceTag] Line $lineNum : SESSION entry expected 3 pipe-delimited fields, got $($parts.Count) - skipping" "WARN"
                continue
            }

            $stateChange = $parts[1].Trim()
            $label       = $parts[2].Trim()

            if (-not $stateChange) {
                Write-HALog "[$SourceTag] Line $lineNum : SESSION StateChange is empty - skipping" "WARN"
                continue
            }
            if (-not $label) {
                Write-HALog "[$SourceTag] Line $lineNum : SESSION Label is empty - skipping" "WARN"
                continue
            }
            if ($validStateChanges -notcontains $stateChange) {
                Write-HALog "[$SourceTag] Line $lineNum : SESSION StateChange '$stateChange' is not valid (must be one of: $($validStateChanges -join ', ')) - skipping" "WARN"
                continue
            }
            if ($label -match '[\\\/\:\*\?"<>\|\s]') {
                Write-HALog "[$SourceTag] Line $lineNum : Label '$label' contains invalid characters (no spaces, no \/:*?`"<>|) - skipping" "WARN"
                continue
            }

            $results.Add([pscustomobject]@{
                Type        = 'SESSION'
                StateChange = $stateChange
                Label       = $label
                Source      = $SourceTag
            })
            continue
        }

        # --- DEFENDER inline check (never a Task Scheduler trigger) ---
        if ($trimmed -match '^DEFENDER\|') {
            $parts = $trimmed -split '\|', 5
            if ($parts.Count -lt 4) {
                Write-HALog "[$SourceTag] Line $lineNum : DEFENDER entry expected 4 or 5 pipe-delimited fields, got $($parts.Count) - skipping" "WARN"
                continue
            }

            $ruleNameMatch = $parts[1].Trim()
            $intervalRaw   = $parts[2].Trim()
            $label         = $parts[3].Trim()
            $intervalHours = $null
            $parsedInterval = 0
            if ([int]::TryParse($intervalRaw, [ref]$parsedInterval) -and $parsedInterval -gt 0) {
                $intervalHours = $parsedInterval
            } elseif ($intervalRaw) {
                Write-HALog "[$SourceTag] Line $lineNum : DEFENDER IntervalHours '$intervalRaw' is invalid - using global default" "WARN"
            }

            $extendedLogging = '0'
            if ($parts.Count -ge 5 -and -not [string]::IsNullOrWhiteSpace($parts[4])) {
                $extMode = $parts[4].Trim().ToLowerInvariant()
                if ($extMode -in @('0','1','2','all')) {
                    $extendedLogging = $extMode
                } else {
                    Write-HALog "[$SourceTag] Line $lineNum : ExtendedLogging '$($parts[4].Trim())' is invalid (allowed: 0, 1, 2, all, or empty) - defaulting to 0" "WARN"
                }
            }

            if (-not $ruleNameMatch) {
                Write-HALog "[$SourceTag] Line $lineNum : DEFENDER RuleNameMatch is empty - skipping" "WARN"
                continue
            }
            if (-not (ConvertTo-DefenderRuleNameKey -Text $ruleNameMatch)) {
                Write-HALog "[$SourceTag] Line $lineNum : DEFENDER RuleNameMatch '$ruleNameMatch' contains no letters or digits - skipping" "WARN"
                continue
            }
            if (-not $label) {
                Write-HALog "[$SourceTag] Line $lineNum : DEFENDER Label is empty - skipping" "WARN"
                continue
            }
            if ($label -match '[\\\/\:\*\?"<>\|\s]') {
                Write-HALog "[$SourceTag] Line $lineNum : Label '$label' contains invalid characters (no spaces, no \/:*?`"<>|) - skipping" "WARN"
                continue
            }

            $results.Add([pscustomobject]@{
                Type            = 'DEFENDER'
                RuleNameMatch   = $ruleNameMatch
                IntervalHours   = $intervalHours
                Label           = $label
                ExtendedLogging = $extendedLogging
                Source          = $SourceTag
            })
            continue
        }

        # --- HEADER run-header telemetry (never a Task Scheduler trigger) ---
        if ($trimmed -match '^HEADER\|') {
            $parts = $trimmed -split '\|'
            if ($parts.Count -lt 3) {
                Write-HALog "[$SourceTag] Line $lineNum : HEADER entry expected at least 3 pipe-delimited fields, got $($parts.Count) - skipping" "WARN"
                continue
            }

            $fieldName = $parts[1].Trim()
            $label     = $parts[2].Trim()

            if (-not $fieldName) {
                Write-HALog "[$SourceTag] Line $lineNum : HEADER FieldName is empty - skipping" "WARN"
                continue
            }
            if (-not $label) {
                Write-HALog "[$SourceTag] Line $lineNum : HEADER Label is empty - skipping" "WARN"
                continue
            }
            if ($label -match '[\\\/\:\*\?"<>\|\s]') {
                Write-HALog "[$SourceTag] Line $lineNum : Label '$label' contains invalid characters (no spaces, no \/:*?`"<>|) - skipping" "WARN"
                continue
            }

            $normalizedField = $fieldName.ToLowerInvariant()
            if ($normalizedField -ne '*' -and $HaystackHeaderFields -notcontains $normalizedField) {
                Write-HALog "[$SourceTag] Line $lineNum : HEADER FieldName '$fieldName' is not a known run-header field (known: $($HaystackHeaderFields -join ', ') or * for all) - skipping" "WARN"
                continue
            }

            # RefreshHours=N / SendHours=M are optional and order-flexible.
            $refreshHours = $null
            $sendHours    = $null
            for ($i = 3; $i -lt $parts.Count; $i++) {
                $token = $parts[$i].Trim()
                if (-not $token) { continue }
                if ($token -match '^(?i)(RefreshHours|SendHours)\s*=\s*(.*)$') {
                    $tokenKey = $matches[1].ToLowerInvariant()
                    $tokenRaw = $matches[2].Trim()
                    $parsedHours = 0
                    if ([int]::TryParse($tokenRaw, [ref]$parsedHours) -and $parsedHours -gt 0) {
                        if ($tokenKey -eq 'refreshhours') { $refreshHours = $parsedHours } else { $sendHours = $parsedHours }
                    } else {
                        Write-HALog "[$SourceTag] Line $lineNum : HEADER $($matches[1]) '$tokenRaw' is invalid - using global default" "WARN"
                    }
                } else {
                    Write-HALog "[$SourceTag] Line $lineNum : HEADER token '$token' is not recognized (expected RefreshHours=N or SendHours=M) - ignoring" "WARN"
                }
            }

            $results.Add([pscustomobject]@{
                Type         = 'HEADER'
                FieldName    = $normalizedField
                Label        = $label
                RefreshHours = $refreshHours
                SendHours    = $sendHours
                Source       = $SourceTag
            })
            continue
        }

        # --- NEEDLE (event) trigger ---
        if ($trimmed -notmatch '^NEEDLE\|') {
            Write-HALog "[$SourceTag] Line $lineNum : unrecognized format - skipping" "WARN"
            continue
        }

        $parts = $trimmed -split '\|', 6
        if ($parts.Count -lt 5) { continue }

        $logName   = $parts[1].Trim()
        $eventId   = $parts[2].Trim()
        $xpathFilt = $parts[3].Trim()
        $label     = $parts[4].Trim()
        $extendedLogging = '0'
        if ($parts.Count -ge 6) {
            $extRaw = $parts[5]
            if (-not [string]::IsNullOrWhiteSpace($extRaw)) {
                $extMode = $extRaw.Trim().ToLowerInvariant()
                if ($extMode -in @('0','1','2','all')) {
                    $extendedLogging = $extMode
                } else {
                    Write-HALog "[$SourceTag] Line $lineNum : ExtendedLogging '$($parts[5].Trim())' is invalid (allowed: 0, 1, 2, all, or empty) - defaulting to 0" "WARN"
                    $extendedLogging = '0'
                }
            }
        }

        if (-not $logName -or -not $eventId -or -not $label) { continue }
        if ($eventId -notmatch '^\d+$') { continue }

        $results.Add([pscustomobject]@{
            Type        = 'NEEDLE'
            LogName     = $logName
            EventID     = [int]$eventId
            XPathFilter = $xpathFilt
            Label       = $label
            ExtendedLogging = $extendedLogging
            Source      = $SourceTag
        })
    }

    return $results.ToArray()
}

function Merge-Needles {
    param(
        [object[]]$ShareNeedles,
        [object[]]$LocalNeedles
    )

    $merged     = [System.Collections.Generic.List[object]]::new()
    $seenLabels = @{}

    # Labels are intentionally deduplicated across all directive types.
    foreach ($n in $LocalNeedles) {
        if ($seenLabels.ContainsKey($n.Label)) { continue }
        $seenLabels[$n.Label] = 'local'
        $merged.Add($n)
    }

    foreach ($n in $ShareNeedles) {
        if ($seenLabels.ContainsKey($n.Label)) { continue }
        $seenLabels[$n.Label] = 'share'
        $merged.Add($n)
    }

    return $merged.ToArray()
}

# =============================================================================
# DEFENDER Registry Checks
# =============================================================================
function Test-DefenderCheckDue {
    param([Parameter(Mandatory=$true)][object]$Needle)

    $flagPath = Join-Path $DefenderFlagDir "$($Needle.Label).flag"
    if (-not (Test-Path -LiteralPath $flagPath)) { return $true }

    try {
        $flag = Get-Content -LiteralPath $flagPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (-not $flag.NextCheck) { return $true }
        $nextCheck = [datetimeoffset]::Parse([string]$flag.NextCheck)
        return ($nextCheck -le [datetimeoffset]::Now)
    } catch {
        Write-HALog "[$($Needle.Label)] Defender flag unreadable/corrupt - forcing check" "WARN"
        return $true
    }
}

function Write-DefenderFlag {
    param(
        [Parameter(Mandatory=$true)][object]$Needle,
        [Parameter(Mandatory=$true)][ValidateSet('PRESENT','MISSING')][string]$LastState
    )

    $intervalHours = if ($null -ne $Needle.IntervalHours -and [int]$Needle.IntervalHours -gt 0) {
        [int]$Needle.IntervalHours
    } else {
        $DefenderCheckIntervalHours
    }
    $now = [datetimeoffset]::Now
    $flag = [ordered]@{
        LastCheck = $now.ToString('o')
        NextCheck = $now.AddHours($intervalHours).ToString('o')
        LastState = $LastState
    }

    try {
        if (-not (Test-Path -LiteralPath $DefenderFlagDir)) {
            New-Item -Path $DefenderFlagDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $flag | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $DefenderFlagDir "$($Needle.Label).flag") -Encoding UTF8 -Force -ErrorAction Stop
    } catch {
        Write-HALog "[$($Needle.Label)] Could not write Defender flag: $_" "WARN"
    }
}

function Invoke-DefenderNeedleCheck {
    param([object[]]$Needles)

    $dueNeedles = @($Needles | Where-Object { Test-DefenderCheckDue -Needle $_ })
    if ($dueNeedles.Count -eq 0) { return 0 }

    $ruleData = @()
    if (Test-Path -LiteralPath $DefenderFwRegPath) {
        try {
            $registryItem = Get-Item -LiteralPath $DefenderFwRegPath -ErrorAction Stop
            $ruleData = @($registryItem.GetValueNames() | ForEach-Object { [string]$registryItem.GetValue($_) })
        } catch {
            # A transient read failure is not proof the rule is missing. Leave
            # flags untouched so the next wake retries immediately.
            Write-HALog "Defender firewall registry key could not be read; due checks will retry next wake: $_" "WARN"
            return 0
        }
    }

    $totalHits = 0
    foreach ($needle in $dueNeedles) {
        $matchedData = $null
        foreach ($data in $ruleData) {
            $nameMatch = [regex]::Match($data, '(?:^|\|)Name=([^|]*)')
            # Case-insensitive, separator-tolerant literal substring match - the
            # configured RuleNameMatch is NEVER treated as a regex.
            if ($nameMatch.Success -and (Test-DefenderRuleNameMatch -RuleName $nameMatch.Groups[1].Value -RuleNameMatch ([string]$needle.RuleNameMatch))) {
                $matchedData = $data
                break
            }
        }

        $state = if ($null -ne $matchedData) { 'PRESENT' } else { 'MISSING' }
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $tsIso = Get-Date -Format 'o'
        $line = "$ts [NEEDLE_HIT] [$($needle.Label)] DEFENDER/RulePresence Machine:$env:COMPUTERNAME EvtTime:$ts MSG: Rule '$($needle.RuleNameMatch)' is $state"
        try {
            Add-Content -Path $HaystackLogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
            Write-Verbose $line
        } catch {
            Write-HALog "Failed to write DEFENDER hit for label '$($needle.Label)': $_" "WARN"
        }

        $hitUser = Get-LoggedOnUser
        $safeRuleMatch = ([string]$needle.RuleNameMatch) -replace '"', "'"
        $payload = 'action=needle_hit machine="{0}" user="{1}" Label="{2}" EventID="DEFENDER" rule_match="{3}" rule_state="{4}" EvtTime="{5}"' -f `
            $env:COMPUTERNAME, $hitUser, $needle.Label, $safeRuleMatch, $state, $tsIso

        $extendedMode = ([string]$needle.ExtendedLogging).Trim().ToLowerInvariant()
        if ($null -ne $matchedData -and $extendedMode -in @('1','2','all')) {
            $body = $matchedData -replace '\r?\n', ' | ' -replace '"', "'"
            if ($extendedMode -eq '1' -and $body.Length -gt 128) {
                $body = $body.Substring(0, 128)
            }
            $payload += ' body="{0}"' -f $body
        }

        Invoke-SyslogSend -Payload $payload
        Write-DefenderFlag -Needle $needle -LastState $state
        $totalHits++
    }

    return $totalHits
}

# =============================================================================
# HEADER Run-Header Telemetry
# Inline-evaluated on every wake (event, session, or heartbeat) exactly like
# the DEFENDER checks above. No Task Scheduler trigger is ever created for a
# HEADER directive. Values are never computed here - they are read from the
# consolidated header_cache.json that WW_main's Write-RunHeader refreshes on
# its own RefreshHours cadence. This half only decides whether a cached value
# is due to be SHIPPED, ships it through the existing tee pathway, and stamps
# last_sent_at back into the same single cache file.
# =============================================================================
function Write-HaystackTelemetry {
    param(
        [Parameter(Mandatory=$true)][string]$Tag,
        [Parameter(Mandatory=$true)][hashtable]$Data
    )

    try {
        if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) {
            $candidates = @()
            if ($PSCommandPath) { $candidates += (Join-Path (Split-Path -Parent $PSCommandPath) 'WW_tee.ps1') }
            if ($LocalCacheDir) { $candidates += (Join-Path $LocalCacheDir 'WW_tee.ps1') }
            foreach ($teePath in $candidates) {
                if ($teePath -and (Test-Path -LiteralPath $teePath)) {
                    . $teePath
                    break
                }
            }
        }
        if (Get-Command Write-TeeLog -ErrorAction SilentlyContinue) {
            Write-TeeLog $Tag $Data
        } else {
            Write-HALog "HayStack telemetry skipped for tag '$Tag' - WW_tee.ps1 not found" "DEBUG"
        }
    } catch {
        Write-HALog "HayStack telemetry emit failed for tag '$Tag': $_" "DEBUG"
    }
}

function ConvertTo-HeaderCacheStamp {
    # ConvertFrom-Json rehydrates ISO-8601 strings as [datetime]. Normalize any
    # timestamp back to a round-trip ISO string so the cache stays stable and
    # culture-independent across reads/writes.
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.ToString('o') }
    if ($Value -is [datetime])       { return ([datetimeoffset]$Value).ToString('o') }
    return [string]$Value
}

function ConvertTo-HeaderCacheTable {
    # Normalizes the deserialized header_cache.json into a plain ordered
    # hashtable so callers can mutate it and round-trip it back to disk.
    param([object]$Raw)

    $table = [ordered]@{
        SchemaVersion = 1
        UpdatedAt     = $null
        Fields        = [ordered]@{}
        Bundles       = [ordered]@{}
    }
    if ($null -eq $Raw) { return $table }

    if ($Raw.PSObject.Properties.Name -contains 'UpdatedAt') { $table.UpdatedAt = ConvertTo-HeaderCacheStamp -Value $Raw.UpdatedAt }
    if ($Raw.PSObject.Properties.Name -contains 'Fields' -and $Raw.Fields) {
        foreach ($prop in $Raw.Fields.PSObject.Properties) {
            $table.Fields[$prop.Name] = [ordered]@{
                value        = $prop.Value.value
                collected_at = ConvertTo-HeaderCacheStamp -Value $prop.Value.collected_at
                last_sent_at = ConvertTo-HeaderCacheStamp -Value $prop.Value.last_sent_at
            }
        }
    }
    if ($Raw.PSObject.Properties.Name -contains 'Bundles' -and $Raw.Bundles) {
        foreach ($prop in $Raw.Bundles.PSObject.Properties) {
            $table.Bundles[$prop.Name] = [ordered]@{ last_sent_at = ConvertTo-HeaderCacheStamp -Value $prop.Value.last_sent_at }
        }
    }
    return $table
}

function Read-HeaderCache {
    if (-not (Test-Path -LiteralPath $HeaderCacheFile)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $HeaderCacheFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        return (ConvertTo-HeaderCacheTable -Raw $raw)
    } catch {
        Write-HALog "Header cache unreadable/corrupt ($HeaderCacheFile): $_" "WARN"
        return $null
    }
}

function Save-HeaderCache {
    param([Parameter(Mandatory=$true)][object]$Cache)

    try {
        $Cache.UpdatedAt = (Get-Date).ToString('o')
        $Cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $HeaderCacheFile -Encoding UTF8 -Force -ErrorAction Stop
        return $true
    } catch {
        Write-HALog "Could not write header cache ($HeaderCacheFile): $_" "WARN"
        return $false
    }
}

function Test-HeaderSendDue {
    # $LastSentAt is an ISO-8601 string or $null/empty (never sent).
    param([string]$LastSentAt, [int]$SendHours)

    if ([string]::IsNullOrWhiteSpace($LastSentAt)) { return $true }
    try {
        $last = [datetimeoffset]::Parse($LastSentAt)
    } catch {
        return $true
    }
    return ($last.AddHours($SendHours) -le [datetimeoffset]::Now)
}

function Invoke-HeaderNeedleCheck {
    <#
    .SYNOPSIS
    Ships cached run-header fields for every HEADER needle whose SendHours has
    elapsed. FieldName = '*' sends every known field as ONE combined payload
    under that needle's Label; a named field sends just that field.

    Returns the number of telemetry payloads sent.
    #>
    param([object[]]$Needles)

    if (-not $Needles -or $Needles.Count -eq 0) { return 0 }

    $cache = Read-HeaderCache
    if ($null -eq $cache) {
        Write-HALog "HEADER needle(s) configured but no header cache yet ($HeaderCacheFile) - WW_main will populate it on its next run" "INFO"
        return 0
    }

    $now       = [datetimeoffset]::Now
    $sent      = 0
    $cacheDirty = $false

    foreach ($needle in $Needles) {
        $sendHours = if ($null -ne $needle.SendHours -and [int]$needle.SendHours -gt 0) {
            [int]$needle.SendHours
        } else {
            $HeaderSendIntervalHours
        }

        if ($needle.FieldName -eq '*') {
            # Bundle: one payload, all known fields, stamped per-Label.
            if ($cache.Bundles.Contains($needle.Label)) {
                $lastSent = [string]$cache.Bundles[$needle.Label].last_sent_at
            } else {
                $lastSent = $null
            }
            if (-not (Test-HeaderSendDue -LastSentAt $lastSent -SendHours $sendHours)) {
                Write-HALog "[$($needle.Label)] HEADER bundle not due (SendHours=$sendHours, last_sent_at=$lastSent)" "DEBUG"
                continue
            }
            if ($cache.Fields.Count -eq 0) {
                Write-HALog "[$($needle.Label)] HEADER bundle due but cache holds no fields yet - skipping" "DEBUG"
                continue
            }

            $data = @{ Label = $needle.Label; header_field = '*' }
            foreach ($fieldName in $cache.Fields.Keys) {
                $data[$fieldName] = [string]$cache.Fields[$fieldName].value
            }

            Write-HaystackTelemetry -Tag 'haystack_header_fields' -Data $data
            $cache.Bundles[$needle.Label] = [ordered]@{ last_sent_at = $now.ToString('o') }
            $cacheDirty = $true
            $sent++
            Write-HALog "[$($needle.Label)] HEADER bundle sent ($($cache.Fields.Count) field(s), SendHours=$sendHours)" "INFO"
            continue
        }

        if (-not $cache.Fields.Contains($needle.FieldName)) {
            Write-HALog "[$($needle.Label)] HEADER field '$($needle.FieldName)' not present in header cache yet - skipping" "DEBUG"
            continue
        }

        $entry = $cache.Fields[$needle.FieldName]
        if (-not (Test-HeaderSendDue -LastSentAt ([string]$entry.last_sent_at) -SendHours $sendHours)) {
            Write-HALog "[$($needle.Label)] HEADER field '$($needle.FieldName)' not due (SendHours=$sendHours, last_sent_at=$($entry.last_sent_at))" "DEBUG"
            continue
        }

        $data = @{
            Label        = $needle.Label
            header_field = $needle.FieldName
            collected_at = [string]$entry.collected_at
        }
        $data[$needle.FieldName] = [string]$entry.value

        Write-HaystackTelemetry -Tag 'haystack_header_fields' -Data $data
        $entry.last_sent_at = $now.ToString('o')
        $cacheDirty = $true
        $sent++
        Write-HALog "[$($needle.Label)] HEADER field '$($needle.FieldName)' sent (SendHours=$sendHours)" "INFO"
    }

    # One write per wake regardless of how many needles were shipped.
    if ($cacheDirty) { Save-HeaderCache -Cache $cache | Out-Null }

    return $sent
}

# =============================================================================
# Event Lookback
# One Get-WinEvent call per needle. No loops inside. Fires and exits.
# =============================================================================
function Invoke-NeedleLookback {
    <#
    .SYNOPSIS
    Queries each needle's event log for matching events within the lookback
    window. Writes a structured hit line for each match found.

    Uses Get-WinEvent with a FilterHashtable for simple (bare EventID) needles
    and falls back to -FilterXPath for needles with custom XPath filters.

    Both paths are single queries - no loops, no retries.
    #>
    param(
        [object[]]$Needles,
        [int]$LookbackSeconds
    )

    $since    = (Get-Date).AddSeconds(-$LookbackSeconds)
    $totalHits = 0

    Write-HALog "Lookback window: last ${LookbackSeconds}s (since $($since.ToString('yyyy-MM-dd HH:mm:ss')))" "INFO"

    foreach ($needle in $Needles) {
        try {

            # SESSION triggers have no event log - the action firing IS the hit
            if ($needle.Type -eq 'SESSION') {
                $ts      = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                $tsIso   = Get-Date -Format 'o'
                $line    = "$ts [NEEDLE_HIT] [$($needle.Label)] SESSION/$($needle.StateChange) Machine:$env:COMPUTERNAME EvtTime:$ts MSG: Session state change fired"
                try {
                    Add-Content -Path $HaystackLogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
                    Write-Verbose $line
                } catch {
                    Write-HALog "Failed to write SESSION hit for label '$($needle.Label)': $_" "WARN"
                }

                # Forward to syslog/Splunk if enabled
                $syslogPayload = 'action=needle_hit machine="{0}" Label="{1}" EventID="SESSION" LogName="{2}" EvtTime="{3}"' -f `
                    $env:COMPUTERNAME, $needle.Label, $needle.StateChange, $tsIso
                Invoke-SyslogSend -Payload $syslogPayload

                $totalHits++
                continue
            }

            $events = $null

            if ($needle.XPathFilter -and $needle.XPathFilter.Length -gt 0) {
                # Custom XPath path - build a full XPath query with time bound
                # We wrap the user XPath in a banded query so we only get recent events.
                # The XPath is used as the Select body inside a QueryList.
                $xpath = $needle.XPathFilter

                # Note: We do NOT embed timediff() in the XPath because Get-WinEvent
                # handles the StartTime filter more reliably via FilterHashtable's
                # StartTime key. But FilterHashtable can't combine with XPath.
                # Trade-off: use -FilterXPath and accept we may get slightly older
                # events on very slow machines where the action fires late.
                # In practice the MultipleInstancesPolicy = IgnoreNew means we only
                # ever fire once per event burst anyway.
                $queryXml = @"
<QueryList>
  <Query Id="0" Path="$($needle.LogName)">
    <Select Path="$($needle.LogName)">$xpath</Select>
  </Query>
</QueryList>
"@
                $events = Get-WinEvent -FilterXml $queryXml -MaxEvents 20 -ErrorAction SilentlyContinue |
                          Where-Object { $_.TimeCreated -ge $since }

            } else {
                # Simple bare EventID - use FilterHashtable (fastest path)
                $events = Get-WinEvent -FilterHashtable @{
                    LogName   = $needle.LogName
                    Id        = $needle.EventID
                    StartTime = $since
                } -MaxEvents 20 -ErrorAction SilentlyContinue
            }

            if ($events) {
                $hitCount = @($events).Count
                Write-HALog "[$($needle.Label)] $hitCount hit(s) in $($needle.LogName)/EventID:$($needle.EventID)" "INFO"
                foreach ($evt in @($events)) {
                    Write-HaystackHit -Label $needle.Label -Event $evt -Needle $needle
                    $totalHits++
                }
            } else {
                # No hits in window - normal, not a warning. The trigger fired but the
                # event may have been just outside the lookback window on a loaded system.
                Write-HALog "[$($needle.Label)] No events in lookback window ($($needle.LogName)/EventID:$($needle.EventID))" "DEBUG"
            }

        } catch {
            Write-HALog "[$($needle.Label)] Error querying $($needle.LogName)/EventID:$($needle.EventID) : $_" "WARN"
        }
    }

    return $totalHits
}

# =============================================================================
# Main
# =============================================================================
$runTs = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
Write-HALog ("=" * 60) "INFO"
Write-HALog "HayStack_Action v$HaystackVersion fired at $runTs (pid:$PID)" "INFO"

# Ensure log directory exists
if (-not (Test-Path $LocalCacheDir)) {
    try {
        New-Item -Path $LocalCacheDir -ItemType Directory -Force | Out-Null
    } catch {
        # Nothing we can do if we can't even create the dir - exit silently
        exit 1
    }
}

# Heartbeat backstop: attempt an unconditional queue drain here, near the top
# of Main, so a heartbeat-only wake (zero needle hits this cycle) still gives
# the syslog queue a chance to flush. Gated by the same Test-SyslogReachable
# check used elsewhere - a fast no-op when off-domain. If hits are found and
# processed below, Invoke-SyslogSend will drain again there too; that's
# harmless/idempotent, just avoids a needle hit sitting stuck behind a queue
# that never got attention on a quiet run.
if (Test-SyslogReachable) {
    Drain-SyslogQueue
}

# Load needles - local wins on collision (same merge logic as haystack.ps1)
$shareNeedles = Read-NeedleFile -Path $LocalNeedlesFile      -SourceTag "share"
$localNeedles = Read-NeedleFile -Path $LocalNeedlesFile_Local -SourceTag "local"
$allNeedles   = Merge-Needles  -ShareNeedles $shareNeedles -LocalNeedles $localNeedles

Write-HALog "Loaded $($allNeedles.Count) needle(s) ($($localNeedles.Count) local, $($shareNeedles.Count) share)" "INFO"

if ($allNeedles.Count -eq 0) {
    Write-HALog "No needles loaded - nothing to scan. Exiting." "WARN"
    Write-HALog ("=" * 60) "INFO"
    exit 0
}

# Event/session needles use event lookback; DEFENDER and HEADER directives are
# checked separately so they can never reach Get-WinEvent.
$eventNeedles    = @($allNeedles | Where-Object { @('DEFENDER','HEADER') -notcontains $_.Type })
$defenderNeedles = @($allNeedles | Where-Object { $_.Type -eq 'DEFENDER' })
$headerNeedles   = @($allNeedles | Where-Object { $_.Type -eq 'HEADER' })
$hits = Invoke-NeedleLookback -Needles $eventNeedles -LookbackSeconds $LookbackSeconds
$hits += Invoke-DefenderNeedleCheck -Needles $defenderNeedles
$hits += Invoke-HeaderNeedleCheck -Needles $headerNeedles

Write-HALog "Run complete - $hits total hit(s) logged" "INFO"
Write-HALog ("=" * 60) "INFO"

exit 0
