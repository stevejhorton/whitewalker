#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Simulates captive portal plumbing by writing synthetic state and firing real Event Log flare triggers.

.DESCRIPTION
    Validates end-to-end WhiteWalker captive portal plumbing (Event Log trigger, Task Scheduler
    dispatch, runner execution, completion flag, and Haystack syslog queueing) without requiring
    connection to a live captive portal network.

    RC1.25: the Plumbing mode now separates the three producers that are easily conflated -
    the Windows Event Log FLARE (Event 777/778, dispatch only), the LEGACY queue event
    (action="network_state_change", event_class="legacy_haystack"), and the NORMALIZED
    cap_portal_* tee events - prints the raw matching queue lines, reports which required
    fields are present/missing/empty, and reports whether EvtTime was stamped locally before
    queueing. PASS is reported ONLY when a normalized cap_portal_* event with the full
    required field set is observed; a fired Event 778 (or a completion flag, or a legacy
    queue row) is explicitly NOT a pass.

    The script remains non-destructive: it never edits fleet toggles (HaystackEnabled /
    TeeEnabled) or tee profiles, so an endpoint with tee disabled will correctly FAIL rather
    than being silently "fixed" by the test.

    Modes:
      - Plumbing (default): Performs preflight diagnostics, writes synthetic remediation state,
        fires the real flare event via eventcreate.exe, polls for completion flag, inspects
        syslog queue tail, displays ready-to-use Splunk queries, and cleans up synthetic state.
      - DirectReference: Prints reference command to execute direct syslog transport validation
        via Test-HayStackSyslog.ps1.

.PARAMETER Mode
    Execution mode for captive portal simulation.
    Values:
      - 'Plumbing': Runs real event log and runner plumbing simulation (default).
      - 'DirectReference': Displays pointer to direct syslog transport simulation.

.PARAMETER RunnerMode
    Target captive portal runner to trigger in Plumbing mode.
    Values:
      - 'base': Fires Event 778 (FLARE:captive_portal_browser_base) for WW_cap_portal_runner_base.ps1 (default).
      - 'full': Fires Event 777 (FLARE:captive_portal_browser) for WW_cap_portal_runner.ps1.

.PARAMETER TimeoutSeconds
    Maximum seconds to poll for portal_complete.flag. Default: 90.

.PARAMETER PollIntervalSeconds
    Seconds between polls for portal_complete.flag. Default: 3.

.EXAMPLE
    .\TEST_simulate_cap_portal.ps1
    Runs plumbing simulation for base runner mode with 90-second timeout.

.EXAMPLE
    .\TEST_simulate_cap_portal.ps1 -RunnerMode full -TimeoutSeconds 120
    Runs plumbing simulation for full runner mode with 120-second timeout.

.EXAMPLE
    .\TEST_simulate_cap_portal.ps1 -Mode DirectReference
    Prints direct transport simulation command and exits.
#>

[CmdletBinding()]
param(
    [ValidateSet('Plumbing', 'DirectReference')]
    [string]$Mode = 'Plumbing',

    [ValidateSet('base', 'full')]
    [string]$RunnerMode = 'base',

    [int]$TimeoutSeconds = 90,

    [int]$PollIntervalSeconds = 3
)

# ---------------------------------------------------------------------------
# Mode: DirectReference
# ---------------------------------------------------------------------------
if ($Mode -eq 'DirectReference') {
    Write-Host "[OK] Direct transport simulation lives in:" -ForegroundColor Green
    Write-Host "     tests/Test-HayStackSyslog.ps1 -SimulateCaptivePortal -DeliveryMode direct" -ForegroundColor Cyan
    exit 0
}

# ---------------------------------------------------------------------------
# Mode: Plumbing (Main Path)
# ---------------------------------------------------------------------------

# A. Constants / Deployed Runtime Paths
$RemediationStateFile = "C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag"
$FlagFile             = "C:\ProgramData\WhiteWalker\portal_complete.flag"
$SyslogQueueFile      = "C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl"
$TeeEventsFile        = "C:\ProgramData\WhiteWalker\WW_tee_events.psd1"

# Preflight Checks / Diagnostics
Write-Host "[STEP] Preflight checks: inspecting WhiteWalker environment..." -ForegroundColor Cyan

if (-not (Test-Path $TeeEventsFile)) {
    Write-Host "[WARN] Tee events file missing: $TeeEventsFile" -ForegroundColor Yellow
} else {
    try {
        $teeContent = Get-Content -Path $TeeEventsFile -Raw -ErrorAction Stop
        $hasRedirect = $teeContent -match 'cap_portal_redirect'
        $hasPassed   = $teeContent -match 'cap_portal_remediation_passed'
        $hasFailed   = $teeContent -match 'cap_portal_remediation_failed'

        if (-not ($hasRedirect -or $hasPassed -or $hasFailed)) {
            Write-Host "[WARN] None of the captive portal telemetry events (cap_portal_redirect, cap_portal_remediation_passed, cap_portal_remediation_failed) are present in $TeeEventsFile" -ForegroundColor Yellow
        } else {
            Write-Host "[OK] Tee events profile verified: captive portal events present in $TeeEventsFile" -ForegroundColor Green
        }
    } catch {
        Write-Host "[WARN] Could not read $TeeEventsFile : $_" -ForegroundColor Yellow
    }
}

Write-Host "[STEP] Note: Task Scheduler triggers must be installed for Event 777/778 consumers; otherwise event is logged but no runner will execute." -ForegroundColor Cyan

# B. Write Synthetic Remediation State File
$stateDir = Split-Path $RemediationStateFile -Parent
if (-not (Test-Path $stateDir)) {
    try {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Created state directory: $stateDir" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Cannot create state directory $stateDir : $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[STEP] Writing synthetic remediation state file: $RemediationStateFile..." -ForegroundColor Cyan

$syntheticState = [ordered]@{
    portal_type = "NON_ISE"
    fqdn        = "portal.cpr-test.example.com"
    protocol    = "https"
    port        = 8443
    url         = "https://portal.cpr-test.example.com:8443"
    ssid        = "CPR-PLUMBING-TEST"
    timestamp   = (Get-Date).ToString("o")
}
# NOTE: ip/gw/dns are deliberately NOT seeded here. Those must come from the
# runner's own live reading of this machine (Get-BaseCapNetworkContext) - that
# is precisely what this simulation is validating. Seeding them would fake a
# pass.

try {
    $stateJson = $syntheticState | ConvertTo-Json -Compress
    Set-Content -Path $RemediationStateFile -Value $stateJson -Encoding UTF8 -Force -ErrorAction Stop
    Write-Host "[OK] Synthetic remediation state written to $RemediationStateFile" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to write synthetic remediation state file: $_" -ForegroundColor Red
    exit 1
}

# C. Fire Real Event Log Trigger
if ($RunnerMode -eq 'base') {
    $eventId = 778
    $eventDesc = 'FLARE:captive_portal_browser_base'
} else {
    $eventId = 777
    $eventDesc = 'FLARE:captive_portal_browser'
}

Write-Host "[STEP] Firing Event Log trigger via eventcreate.exe (Event ID: $eventId, Mode: $RunnerMode)..." -ForegroundColor Cyan

$eventArgs = @(
    "/T", "INFORMATION",
    "/ID", [string]$eventId,
    "/L", "APPLICATION",
    "/SO", "WhiteWalkerFlareGun",
    "/D", $eventDesc
)

$eventFailed = $false
$eventExitCode = -1

$testStartTimeUtc = [DateTime]::UtcNow.AddSeconds(-2)
$flagExistedAtStart = Test-Path $FlagFile

# Queue baseline - everything appended AFTER this index is attributable to this run.
$queueLineCountAtStart = 0
if (Test-Path $SyslogQueueFile) {
    try {
        $queueLineCountAtStart = @(Get-Content -Path $SyslogQueueFile -ErrorAction Stop).Count
    } catch {
        Write-Host "[WARN] Could not baseline syslog queue line count: $_" -ForegroundColor Yellow
    }
}
Write-Host "[OK] Syslog queue baseline: $queueLineCountAtStart existing line(s)" -ForegroundColor Green

try {
    $proc = Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    $eventExitCode = $proc.ExitCode
    if ($eventExitCode -eq 0) {
        Write-Host "[OK] Event Log trigger fired successfully (Source: WhiteWalkerFlareGun, ID: $eventId, ExitCode: 0)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] eventcreate.exe returned non-zero exit code: $eventExitCode" -ForegroundColor Red
        $eventFailed = $true
    }
} catch {
    Write-Host "[FAIL] Failed to execute eventcreate.exe: $_" -ForegroundColor Red
    $eventFailed = $true
}

if ($eventFailed) {
    if (Test-Path $RemediationStateFile) {
        Remove-Item -Path $RemediationStateFile -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Cleaned up synthetic remediation state file after failure" -ForegroundColor Green
    }
    exit 1
}

# D. Poll for Completion Flag
Write-Host "[STEP] Polling for completion flag at $FlagFile (Timeout: ${TimeoutSeconds}s, Interval: ${PollIntervalSeconds}s)..." -ForegroundColor Cyan

$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
$foundFlag = $false

while ([DateTime]::UtcNow -lt $deadline) {
    if (Test-Path $FlagFile) {
        $flagItem = Get-Item -Path $FlagFile -ErrorAction SilentlyContinue
        if ($flagItem -and ((-not $flagExistedAtStart) -or ($flagItem.LastWriteTimeUtc -ge $testStartTimeUtc))) {
            $foundFlag = $true
            break
        }
    }
    Start-Sleep -Seconds $PollIntervalSeconds
}

if ($foundFlag) {
    Write-Host "[OK] Completion flag detected at $FlagFile" -ForegroundColor Green
    try {
        $rawContent = Get-Content -Path $FlagFile -Raw -ErrorAction Stop
        Write-Host "[OK] Raw completion flag content:" -ForegroundColor Green
        Write-Host $rawContent

        $flagJson = $rawContent | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($flagJson) {
            Write-Host "[OK] Parsed completion flag fields:" -ForegroundColor Green
            if ($null -ne $flagJson.status) {
                Write-Host "     status    : $($flagJson.status)"
            }
            if ($null -ne $flagJson.details) {
                Write-Host "     details   : $($flagJson.details)"
            }
            if ($null -ne $flagJson.timestamp) {
                Write-Host "     timestamp : $($flagJson.timestamp)"
            }
        }
    } catch {
        Write-Host "[WARN] Could not read or parse completion flag: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] INCOMPLETE: Event fired but no runner completion observed within ${TimeoutSeconds} seconds." -ForegroundColor Yellow
    if ($flagExistedAtStart) {
        Write-Host "[WARN] (Pre-existing flag from earlier run was present at $FlagFile, but was not updated by runner during test)" -ForegroundColor Yellow
    }
}

# E. Evidence Classification (flare vs legacy vs normalized)
# ---------------------------------------------------------------------------
# Three DIFFERENT producers can look like "captive portal telemetry", and
# conflating them is exactly how an Event-778-fired-so-it-works conclusion gets
# reached when no normalized event ever shipped:
#
#   1. FLARE          - a Windows Event Log record (Event 777/778) written by
#                       eventcreate.exe. Proves only that the trigger fired and
#                       Task Scheduler had something to dispatch on. It is NOT
#                       telemetry and never reaches Splunk as a cap_portal_* row.
#   2. LEGACY QUEUE   - action="network_state_change" (event_class="legacy_haystack")
#                       written by the runner. Preserved for existing views; it
#                       carries no user/EvtTime/ssid and is NOT a normalized event.
#   3. NORMALIZED TEE - action="cap_portal_redirect" / "cap_portal_remediation_passed"
#                       / "cap_portal_remediation_failed" written by Write-TeeLog.
#                       These are the rows Splunk dashboards are built on.
#
# PASS is reported ONLY for #3. See the LIMITATIONS block at the end.
# ---------------------------------------------------------------------------
$NormalizedActions = @('cap_portal_redirect', 'cap_portal_remediation_passed', 'cap_portal_remediation_failed')
$RequiredNormalizedFields = @(
    'EvtTime', 'action', 'machine', 'user', 'ssid', 'url', 'port',
    'ip', 'gw', 'dns', 'vpn_state', 'portal_type', 'status', 'reason'
)

function ConvertFrom-QueuePayload {
    param([string]$Payload)
    $fields = @{}
    if ([string]::IsNullOrWhiteSpace($Payload)) { return $fields }
    foreach ($m in [regex]::Matches($Payload, '([A-Za-z0-9_]+)="((?:[^"\\]|\\.)*)"')) {
        $fields[$m.Groups[1].Value] = $m.Groups[2].Value
    }
    return $fields
}

Write-Host "[STEP] Inspecting Haystack syslog queue ($SyslogQueueFile)..." -ForegroundColor Cyan

$newQueueLines   = @()
$normalizedRows  = @()
$legacyRows      = @()

if (Test-Path $SyslogQueueFile) {
    try {
        $allLines = @(Get-Content -Path $SyslogQueueFile -ErrorAction Stop)
        if ($allLines.Count -gt $queueLineCountAtStart) {
            $newQueueLines = $allLines[$queueLineCountAtStart..($allLines.Count - 1)]
        }
        Write-Host "[OK] Queue grew by $($newQueueLines.Count) line(s) during this test (total: $($allLines.Count))" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Failed reading syslog queue file: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] Haystack syslog queue file does not exist: $SyslogQueueFile" -ForegroundColor Yellow
}

foreach ($line in $newQueueLines) {
    $payload = $null
    try {
        $entry = $line | ConvertFrom-Json -ErrorAction Stop
        $payload = [string]$entry.payload
    } catch {
        $payload = [string]$line
    }

    $fields = ConvertFrom-QueuePayload -Payload $payload
    $action = [string]$fields['action']

    if ($NormalizedActions -contains $action) {
        $normalizedRows += [pscustomobject]@{ Raw = $line; Payload = $payload; Fields = $fields; Action = $action }
    } elseif ($action -eq 'network_state_change') {
        $legacyRows += [pscustomobject]@{ Raw = $line; Payload = $payload; Fields = $fields; Action = $action }
    }
}

# --- 1. FLARE evidence -----------------------------------------------------
Write-Host "[STEP] Evidence 1/3 - Windows Event Log FLARE (dispatch only, not telemetry):" -ForegroundColor Cyan
if ($eventExitCode -eq 0) {
    Write-Host "[OK] Flare Event $eventId was written to the Application log (eventcreate exit 0)" -ForegroundColor Green
    Write-Host "[WARN] A fired flare proves ONLY that the trigger fired. It is NOT a normalized telemetry event and on its own is NOT a PASS." -ForegroundColor Yellow
} else {
    Write-Host "[FAIL] Flare Event $eventId was not written (exit code: $eventExitCode)" -ForegroundColor Red
}

# --- 2. LEGACY queue evidence ---------------------------------------------
Write-Host "[STEP] Evidence 2/3 - LEGACY queue events (action=network_state_change):" -ForegroundColor Cyan
if ($legacyRows.Count -gt 0) {
    Write-Host "[OK] $($legacyRows.Count) legacy queue event(s) observed. Raw line(s):" -ForegroundColor Green
    foreach ($row in $legacyRows) { Write-Host "     $($row.Raw)" }
    Write-Host "[WARN] Legacy rows carry no user/EvtTime/ssid/vpn_state - they are preserved for existing Splunk views and are NOT normalized outcome rows." -ForegroundColor Yellow
} else {
    Write-Host "[OK] No legacy queue events observed during this run." -ForegroundColor Green
}

# --- 3. NORMALIZED tee evidence -------------------------------------------
Write-Host "[STEP] Evidence 3/3 - NORMALIZED cap_portal_* tee events:" -ForegroundColor Cyan
$normalizedComplete = $false

if ($normalizedRows.Count -eq 0) {
    Write-Host "[FAIL] No normalized cap_portal_* events were queued during this run." -ForegroundColor Red
    Write-Host "       Check, in order: HaystackEnabled/TeeEnabled are true; the tag exists in $TeeEventsFile;" -ForegroundColor Yellow
    Write-Host "       WW_tee.ps1 + WW_haystack_schema.ps1 are deployed to C:\ProgramData\WhiteWalker." -ForegroundColor Yellow
} else {
    Write-Host "[OK] $($normalizedRows.Count) normalized cap_portal_* event(s) observed." -ForegroundColor Green
    foreach ($row in $normalizedRows) {
        Write-Host "[OK] Raw queue line for '$($row.Action)':" -ForegroundColor Green
        Write-Host "     $($row.Raw)"

        $present = @()
        $missing = @()
        foreach ($field in $RequiredNormalizedFields) {
            if ($row.Fields.ContainsKey($field)) { $present += $field } else { $missing += $field }
        }

        $empty = @($present | Where-Object { [string]::IsNullOrWhiteSpace($row.Fields[$_]) })

        Write-Host "     fields present ($($present.Count)/$($RequiredNormalizedFields.Count)): $($present -join ',')"
        if ($missing.Count -gt 0) {
            Write-Host "[FAIL] fields MISSING from payload: $($missing -join ',')" -ForegroundColor Red
        } else {
            Write-Host "[OK] All required normalized fields are present in the payload." -ForegroundColor Green
        }
        if ($empty.Count -gt 0) {
            Write-Host "[WARN] fields present but EMPTY (value unavailable on this box): $($empty -join ',')" -ForegroundColor Yellow
        }

        # EvtTime must be stamped locally, at event creation, before Splunk ingest.
        if ($row.Fields.ContainsKey('EvtTime') -and -not [string]::IsNullOrWhiteSpace($row.Fields['EvtTime'])) {
            $parsedEvtTime = $null
            if ([datetime]::TryParse($row.Fields['EvtTime'], [ref]$parsedEvtTime)) {
                Write-Host "[OK] Local EvtTime stamped before queueing: $($row.Fields['EvtTime'])" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] EvtTime present but not parseable as a timestamp: $($row.Fields['EvtTime'])" -ForegroundColor Red
            }
        } else {
            Write-Host "[FAIL] No local EvtTime in the queued payload - Splunk would have to infer the time." -ForegroundColor Red
        }

        # user must not be an unresolved lookup failure
        $userValue = [string]$row.Fields['user']
        if ($userValue -eq 'USER_UNKNOWN') {
            Write-Host "[FAIL] user=USER_UNKNOWN - the user lookup itself failed (see white_walker log for the failing probe)." -ForegroundColor Red
        } elseif ($userValue -eq 'NO_INTERACTIVE_USER') {
            Write-Host "[WARN] user=NO_INTERACTIVE_USER - no interactive session on this box (expected when logged off)." -ForegroundColor Yellow
        } elseif (-not [string]::IsNullOrWhiteSpace($userValue)) {
            Write-Host "[OK] user resolved to an interactive account." -ForegroundColor Green
        }

        if ($missing.Count -eq 0) { $normalizedComplete = $true }
    }
}

# --- Verdict ---------------------------------------------------------------
Write-Host "[STEP] Verdict:" -ForegroundColor Cyan
if ($normalizedRows.Count -gt 0 -and $normalizedComplete) {
    Write-Host "[PASS] A normalized cap_portal_* event with the full required field set was queued locally." -ForegroundColor Green
} elseif ($normalizedRows.Count -gt 0) {
    Write-Host "[FAIL] Normalized cap_portal_* event(s) were queued but the required field set is incomplete (see MISSING above)." -ForegroundColor Red
} else {
    Write-Host "[FAIL] No normalized cap_portal_* event observed. Event $eventId firing, a completion flag, and legacy queue rows do NOT constitute a pass." -ForegroundColor Red
}

Write-Host "[STEP] Limitations of this simulator:" -ForegroundColor Cyan
Write-Host "     - It validates LOCAL queueing only (haystack_syslog_queue.jsonl). It does not prove syslog delivery or Splunk ingest - use tests/Test-HayStackSyslog.ps1 for transport."
Write-Host "     - It uses a synthetic remediation state (SSID 'CPR-PLUMBING-TEST'), so url/port/portal_type are synthetic; ip/gw/dns/ssid/vpn_state are whatever the runner really reads on this box."
Write-Host '     - It is non-destructive: it never edits fleet toggles (HaystackEnabled/TeeEnabled) or tee profiles. If tee is off, no normalized event can appear and this test will correctly FAIL.'
Write-Host "     - A completion flag only proves the runner ran; it says nothing about telemetry."

Write-Host "[STEP] Operator Validation Splunk Queries:" -ForegroundColor Cyan
Write-Host "[OK] Normalized events only (what dashboards should use):" -ForegroundColor Green
Write-Host 'index=cba_cpr_logging action IN ("cap_portal_redirect","cap_portal_remediation_passed","cap_portal_remediation_failed") ssid="CPR-PLUMBING-TEST" | table EvtTime,action,machine,user,ssid,url,port,ip,gw,dns,vpn_state,portal_type,status,reason | sort 0 - EvtTime'
Write-Host "[OK] Legacy queue events only (explicitly NOT normalized outcomes):" -ForegroundColor Green
Write-Host 'index=cba_cpr_logging action="network_state_change" event_class="legacy_haystack" | sort 0 - _time'
Write-Host "[OK] Everything matching the synthetic markers (mixed producers - read with care):" -ForegroundColor Green
Write-Host 'index=cba_cpr_logging ("CPR-PLUMBING-TEST" OR "portal.cpr-test.example.com") | sort 0 - _time'

# F. Cleanup
Write-Host "[STEP] Cleaning up synthetic test state..." -ForegroundColor Cyan
if (Test-Path $RemediationStateFile) {
    try {
        Remove-Item -Path $RemediationStateFile -Force -ErrorAction Stop
        Write-Host "[OK] Synthetic remediation state file removed: $RemediationStateFile" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Failed to remove synthetic remediation state file: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] Synthetic remediation state file already cleaned up." -ForegroundColor Green
}

if (Test-Path $FlagFile) {
    Write-Host "[OK] Diagnostic completion flag preserved at: $FlagFile" -ForegroundColor Green
} else {
    Write-Host "[WARN] Completion flag not present at: $FlagFile" -ForegroundColor Yellow
}
