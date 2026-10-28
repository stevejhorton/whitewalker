#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HayStack Action Script - Event Capture and Structured Logging
  Version: 1.0.0
  Author: steve.horton@optum.com
  Date: 13-May-2026

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

$HaystackVersion        = "1.0.0"

$LocalCacheDir          = "C:\ProgramData\WhiteWalker"
$LocalNeedlesFile       = Join-Path $LocalCacheDir "needles.cfg"        # synced from share
$LocalNeedlesFile_Local = Join-Path $LocalCacheDir "needles_local.cfg"  # local test bed

$HaystackLogFile        = Join-Path $LocalCacheDir "haystack.log"
$HaystackLogMaxBytes    = 1MB
$HaystackLogKeep        = 5

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
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )

    $ts          = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $evtTime     = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
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
}

# =============================================================================
# Needle Parser  (self-contained copy - action script must be independent)
# Identical logic to haystack.ps1 Read-NeedleFile.
# We do NOT dot-source haystack.ps1 to keep the action script standalone
# and resilient to haystack.ps1 deployment timing.
# =============================================================================
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

        # --- NEEDLE (event) trigger ---
        if ($trimmed -notmatch '^NEEDLE\|') {
            Write-HALog "[$SourceTag] Line $lineNum : unrecognized format - skipping" "WARN"
            continue
        }

        $parts = $trimmed -split '\|', 5
        if ($parts.Count -lt 5) { continue }

        $logName   = $parts[1].Trim()
        $eventId   = $parts[2].Trim()
        $xpathFilt = $parts[3].Trim()
        $label     = $parts[4].Trim()

        if (-not $logName -or -not $eventId -or -not $label) { continue }
        if ($eventId -notmatch '^\d+$') { continue }

        $results.Add([pscustomobject]@{
            Type        = 'NEEDLE'
            LogName     = $logName
            EventID     = [int]$eventId
            XPathFilter = $xpathFilt
            Label       = $label
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
                $line    = "$ts [NEEDLE_HIT] [$($needle.Label)] SESSION/$($needle.StateChange) Machine:$env:COMPUTERNAME EvtTime:$ts MSG: Session state change fired"
                try {
                    Add-Content -Path $HaystackLogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
                    Write-Verbose $line
                } catch {
                    Write-HALog "Failed to write SESSION hit for label '$($needle.Label)': $_" "WARN"
                }
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
                    Write-HaystackHit -Label $needle.Label -Event $evt
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

# Do the lookback across all needles
$hits = Invoke-NeedleLookback -Needles $allNeedles -LookbackSeconds $LookbackSeconds

Write-HALog "Run complete - $hits total hit(s) logged" "INFO"
Write-HALog ("=" * 60) "INFO"

exit 0
