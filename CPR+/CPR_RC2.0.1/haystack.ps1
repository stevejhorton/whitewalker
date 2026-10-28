#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HayStack - Standalone event monitor subsystem for CPR
  Version: 1.0.2
  Author: steve.horton@optum.com
  Date: 13-May-2026

.DESCRIPTION
  Runs the HayStack event monitoring subsystem as a standalone script.

  Changes in 1.0.2:
    - Added HEADER directives for opt-in run-header field telemetry.
    - HEADER directives are inline-evaluated and produce no TS trigger XML.

  Changes in 1.0.1:
    - Added DEFENDER directives for inline, flag-gated MDM firewall rule checks.
    - DEFENDER directives are intentionally excluded from Task Scheduler triggers.

  -reroll syncs needles.cfg from the NETLOGON share, merges it with
  needles_local.cfg, then registers or updates the HayStack_Monitor task.

  -remove unregisters the HayStack_Monitor task without performing a sync.

  The reroll flow only re-registers the task when needed:
    * needles.cfg changed on share (subject to cooldown)
    * needles_local.cfg LastWriteTime changed (bypasses cooldown)

  This script is fully standalone and may be called from WW_main.ps1 or
  directly from an elevated PowerShell prompt.

.NOTES
  One task. Many event triggers. TS is our inotify_wait.
  MultipleInstancesPolicy = IgnoreNew gives us OS-level thrash protection for free.

  Task fires haystack_action.ps1 on any matching Windows Event.
  haystack_action.ps1 does a short lookback, captures the event detail, appends
  to haystack.log. No loop. No poll. Completely reactive.

  Usage:
    .\haystack.ps1 -reroll
    .\haystack.ps1 -reroll -Force          # bypass cooldown - forces immediate reroll
    .\haystack.ps1 -remove
    .\haystack.ps1 -reroll -RerollCooldownMinutes 15
#>

[CmdletBinding()]
param(
    [switch]$reroll,
    [switch]$remove,
    [switch]$Force,               # bypass cooldown check - for manual runs
    [int]$RerollCooldownMinutes = 0
)

# =============================================================================
# Configuration - tunables here, not buried in logic below
# =============================================================================

$HaystackVersion            = "1.0.2"

# Minimum minutes between TS task rerolls (optional override via -RerollCooldownMinutes)
$HaystackRerollCooldownMinutes = if ($RerollCooldownMinutes -gt 0) { $RerollCooldownMinutes } else { 60 }

# DC share
$RemoteConfigDir            = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN\CPR"
$RemoteNeedlesFile          = Join-Path $RemoteConfigDir "needles.cfg"

# Local paths
$LocalCacheDir              = "C:\ProgramData\WhiteWalker"
$LogDir                     = Join-Path $LocalCacheDir "logs"
$LocalNeedlesFile           = Join-Path $LocalCacheDir "needles.cfg"        # synced from share
$LocalNeedlesFile_Local     = Join-Path $LocalCacheDir "needles_local.cfg"  # local test bed, never synced
$RerollStampFile            = Join-Path $LocalCacheDir "haystack_reroll.stamp"

# HayStack hit log (separate from white_walker.main.log)
$HaystackLogFile            = Join-Path $LogDir "haystack.log"
$HaystackLogMaxBytes        = 1MB
$HaystackLogKeep            = 5

# Action script fired by Task Scheduler on needle match
$ActionScriptPath           = Join-Path $LocalCacheDir "haystack_action.ps1"

# Task Scheduler registration
$TsTaskName                 = "HayStack_Monitor"
$TsTaskPath                 = "\CPR\"   # keep in sync with $CprTaskFolder (Main.Configuration.ps1, install.ps1)

# Heartbeat trigger - guarantees a periodic opportunity to drain the syslog
# queue even when no needle event fires (e.g. quiet box sitting on VPN).
# OS wakes haystack_action.ps1 on this interval same as any other trigger -
# not a resident loop. Test-SyslogReachable still gates whether a drain is
# actually attempted, so this is a no-op (fast exit) when off-domain.
$HeartbeatIntervalMinutes   = 30

# Jitter window for the heartbeat trigger. Task Scheduler randomizes each fire
# time within this window independently on every endpoint, so a fleet-wide
# reroll does not synchronize ~500k clients onto the same 30 minute boundary
# and thundering-herd the syslog receiver. Set to 0 to disable jitter entirely.
$HeartbeatRandomDelayMinutes = 10

# =============================================================================
# Logging  (mirrors Set-VpnHostsEntry.ps1 Write-SVLog pattern)
# Log rotation inline - same size/keep model as WW_main.ps1 Invoke-LogRotation
# =============================================================================
function Write-HSLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts [$Level] [HayStack] $Message"
    Write-Host $line
    try {
        # Rotate if needed before writing
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

function Write-HaystackTelemetry {
    param(
        [Parameter(Mandatory=$true)][string]$Tag,
        [Parameter(Mandatory=$true)][hashtable]$Data
    )

    try {
        if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) {
            if ($PSCommandPath) {
                $teePath = Join-Path (Split-Path -Parent $PSCommandPath) "WW_tee.ps1"
                if (Test-Path -LiteralPath $teePath) {
                    . $teePath
                }
            }
        }
        if (Get-Command Write-TeeLog -ErrorAction SilentlyContinue) {
            Write-TeeLog $Tag $Data
        }
    } catch {
        Write-HSLog "HayStack telemetry emit failed for tag '$Tag': $_" "DEBUG"
    }
}

function Write-HaystackRerollTelemetry {
    param(
        [Parameter(Mandatory=$true)][string]$Result,
        [int]$NeedleCount = 0,
        [string]$Reason = ""
    )

    Write-HaystackTelemetry -Tag 'haystack_reroll_result' -Data @{
        result       = $Result
        needle_count = $NeedleCount
        reason       = $Reason
    }
}

# =============================================================================
# Config Sync  (same pattern as Set-VpnHostsEntry.ps1 Sync-ConfigFile)
# Version string compare first (fast), SHA256 fallback (authoritative)
# =============================================================================
function Get-HsFileVersion {
    param([string]$Path)
    try {
        $firstLine = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
        if ($firstLine -match '^version:(.+)$') { return $matches[1].Trim() }
    } catch { }
    return $null
}

function Get-HsFileHash {
    param([string]$Path)
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { return $null }
}

function Sync-NeedlesFile {
    # Syncs needles.cfg from remote to local cache.
    # Returns $true if local file is usable (synced or already current).

    if (-not (Test-Path -LiteralPath $RemoteNeedlesFile)) {
        Write-HSLog "Remote needles.cfg not found: $RemoteNeedlesFile - using local cache" "WARN"
        return (Test-Path -LiteralPath $LocalNeedlesFile)
    }

    $remoteVersion = Get-HsFileVersion -Path $RemoteNeedlesFile
    $localVersion  = Get-HsFileVersion -Path $LocalNeedlesFile

    Write-HSLog "needles.cfg - local:$localVersion remote:$remoteVersion" "DEBUG"

    if ($remoteVersion -and $localVersion -and ($remoteVersion -eq $localVersion)) {
        Write-HSLog "needles.cfg version match ($remoteVersion) - no pull needed" "DEBUG"
        return $true
    }

    # Version mismatch or a version header is missing - hash check to confirm actual difference
    $remoteHash = Get-HsFileHash -Path $RemoteNeedlesFile
    $localHash  = Get-HsFileHash -Path $LocalNeedlesFile

    if ($remoteHash -and $localHash -and ($remoteHash -eq $localHash)) {
        Write-HSLog "needles.cfg hash match - no pull needed (version tag drifted)" "DEBUG"
        return $true
    }

    # Files are actually different - pull it
    try {
        Copy-Item -LiteralPath $RemoteNeedlesFile -Destination $LocalNeedlesFile -Force -ErrorAction Stop
        Write-HSLog "needles.cfg updated from share (remote version: $remoteVersion)" "INFO"
        return $true
    } catch {
        Write-HSLog "Failed to pull needles.cfg from share: $_" "WARN"
        return (Test-Path -LiteralPath $LocalNeedlesFile)  # fall back to whatever local we have
    }
}

function Invoke-NeedleSync {
    # Checks share reachability, then delegates to Sync-NeedlesFile.
    # Returns $true if local needles.cfg is usable after the attempt.

    if (-not (Test-Path -LiteralPath $RemoteConfigDir)) {
        Write-HSLog "DC share unreachable: $RemoteConfigDir - using local cache" "WARN"
        return (Test-Path -LiteralPath $LocalNeedlesFile)
    }

    return (Sync-NeedlesFile)
}

# =============================================================================
# Needle Parser
# =============================================================================

# Known run-header field names a HEADER directive may reference. These are the
# fields Write-RunHeader (main\Main.Logging.ps1) computes today and caches in
# header_cache.json. Keep this list in sync with $HeaderCacheFieldNames there
# and with the same list in haystack_action.ps1.
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
# DEFENDER rule-name normalization (keep identical to haystack_action.ps1)
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
    <#
    .SYNOPSIS
    Parses a needle file into an array of needle objects.
    Skips version:, blank, and comment (#) lines.
    Returns empty array (never null) if file is missing or unreadable.

    FORMAT: NEEDLE|LogName|EventID|XPathFilter|Label[|ExtendedLogging]
            XPathFilter may be empty (trailing pipe = bare EventID match).
            ExtendedLogging is optional; valid values are:
            empty/0 (disabled), 1 (128-char body), 2/all (full body).

            SESSION|StateChange|Label
            StateChange must be a valid TS SessionStateChangeTrigger value:
            SessionLock, SessionUnlock, RemoteConnect, RemoteDisconnect,
            ConsoleConnect, ConsoleDisconnect

            DEFENDER|RuleNameMatch|IntervalHours|Label[|ExtendedLogging]
            RuleNameMatch is literal text matched as a case-insensitive,
            separator-tolerant substring of the rule's Name= value.
            IntervalHours is optional; invalid/empty values use the action
            script's global default.

            HEADER|FieldName|Label[|RefreshHours=N][|SendHours=M]
            FieldName is one of $HaystackHeaderFields or * (all fields bundled
            into a single payload). RefreshHours/SendHours are optional
            key=value tokens; invalid/omitted values use the global defaults.
    #>
    param(
        [string]$Path,
        [string]$SourceTag = "share"
    )

    $validStateChanges = @('SessionLock','SessionUnlock','RemoteConnect','RemoteDisconnect','ConsoleConnect','ConsoleDisconnect')
    $results = [System.Collections.Generic.List[object]]::new()

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-HSLog "[$SourceTag] Needle file not found - skipping: $(Split-Path $Path -Leaf)" "DEBUG"
        return @()
    }

    try {
        $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    } catch {
        Write-HSLog "[$SourceTag] Could not read needle file: $Path - $_" "WARN"
        return @()
    }

    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.Trim()

        # Skip blanks, comments, version header
        if ($trimmed.Length -eq 0)         { continue }
        if ($trimmed.StartsWith('#'))       { continue }
        if ($trimmed -match '^version:')   { continue }

        # --- SESSION trigger ---
        if ($trimmed -match '^SESSION\|') {
            $parts = $trimmed -split '\|', 3
            if ($parts.Count -lt 3) {
                Write-HSLog "[$SourceTag] Line $lineNum : SESSION entry expected 3 pipe-delimited fields, got $($parts.Count) - skipping" "WARN"
                continue
            }

            $stateChange = $parts[1].Trim()
            $label       = $parts[2].Trim()

            if (-not $stateChange) {
                Write-HSLog "[$SourceTag] Line $lineNum : SESSION StateChange is empty - skipping" "WARN"
                continue
            }
            if (-not $label) {
                Write-HSLog "[$SourceTag] Line $lineNum : SESSION Label is empty - skipping" "WARN"
                continue
            }
            if ($validStateChanges -notcontains $stateChange) {
                Write-HSLog "[$SourceTag] Line $lineNum : SESSION StateChange '$stateChange' is not valid (must be one of: $($validStateChanges -join ', ')) - skipping" "WARN"
                continue
            }
            if ($label -match '[\\\/\:\*\?"<>\|\s]') {
                Write-HSLog "[$SourceTag] Line $lineNum : Label '$label' contains invalid characters (no spaces, no \/:*?`"<>|) - skipping" "WARN"
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
                Write-HSLog "[$SourceTag] Line $lineNum : DEFENDER entry expected 4 or 5 pipe-delimited fields, got $($parts.Count) - skipping" "WARN"
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
                Write-HSLog "[$SourceTag] Line $lineNum : DEFENDER IntervalHours '$intervalRaw' is invalid - using global default" "WARN"
            }

            $extendedLogging = '0'
            if ($parts.Count -ge 5 -and -not [string]::IsNullOrWhiteSpace($parts[4])) {
                $extMode = $parts[4].Trim().ToLowerInvariant()
                if ($extMode -in @('0','1','2','all')) {
                    $extendedLogging = $extMode
                } else {
                    Write-HSLog "[$SourceTag] Line $lineNum : ExtendedLogging '$($parts[4].Trim())' is invalid (allowed: 0, 1, 2, all, or empty) - defaulting to 0" "WARN"
                }
            }

            if (-not $ruleNameMatch) {
                Write-HSLog "[$SourceTag] Line $lineNum : DEFENDER RuleNameMatch is empty - skipping" "WARN"
                continue
            }
            if (-not (ConvertTo-DefenderRuleNameKey -Text $ruleNameMatch)) {
                Write-HSLog "[$SourceTag] Line $lineNum : DEFENDER RuleNameMatch '$ruleNameMatch' contains no letters or digits - skipping" "WARN"
                continue
            }
            if (-not $label) {
                Write-HSLog "[$SourceTag] Line $lineNum : DEFENDER Label is empty - skipping" "WARN"
                continue
            }
            if ($label -match '[\\\/\:\*\?"<>\|\s]') {
                Write-HSLog "[$SourceTag] Line $lineNum : Label '$label' contains invalid characters (no spaces, no \/:*?`"<>|) - skipping" "WARN"
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
                Write-HSLog "[$SourceTag] Line $lineNum : HEADER entry expected at least 3 pipe-delimited fields, got $($parts.Count) - skipping" "WARN"
                continue
            }

            $fieldName = $parts[1].Trim()
            $label     = $parts[2].Trim()

            if (-not $fieldName) {
                Write-HSLog "[$SourceTag] Line $lineNum : HEADER FieldName is empty - skipping" "WARN"
                continue
            }
            if (-not $label) {
                Write-HSLog "[$SourceTag] Line $lineNum : HEADER Label is empty - skipping" "WARN"
                continue
            }
            if ($label -match '[\\\/\:\*\?"<>\|\s]') {
                Write-HSLog "[$SourceTag] Line $lineNum : Label '$label' contains invalid characters (no spaces, no \/:*?`"<>|) - skipping" "WARN"
                continue
            }

            $normalizedField = $fieldName.ToLowerInvariant()
            if ($normalizedField -ne '*' -and $HaystackHeaderFields -notcontains $normalizedField) {
                Write-HSLog "[$SourceTag] Line $lineNum : HEADER FieldName '$fieldName' is not a known run-header field (known: $($HaystackHeaderFields -join ', ') or * for all) - skipping" "WARN"
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
                        Write-HSLog "[$SourceTag] Line $lineNum : HEADER $($matches[1]) '$tokenRaw' is invalid - using global default" "WARN"
                    }
                } else {
                    Write-HSLog "[$SourceTag] Line $lineNum : HEADER token '$token' is not recognized (expected RefreshHours=N or SendHours=M) - ignoring" "WARN"
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
            Write-HSLog "[$SourceTag] Line $lineNum : unrecognized format - skipping: $trimmed" "WARN"
            continue
        }

        # Split into 5 or 6 fields (6th field optional extended-logging flag)
        $parts = $trimmed -split '\|', 6

        if ($parts.Count -lt 5) {
            Write-HSLog "[$SourceTag] Line $lineNum : expected 5 or 6 pipe-delimited fields, got $($parts.Count) - skipping" "WARN"
            continue
        }

        $logName    = $parts[1].Trim()
        $eventId    = $parts[2].Trim()
        $xpathFilt  = $parts[3].Trim()
        $label      = $parts[4].Trim()
        $extendedLogging = '0'
        if ($parts.Count -ge 6) {
            $extRaw = $parts[5]
            if (-not [string]::IsNullOrWhiteSpace($extRaw)) {
                $extMode = $extRaw.Trim().ToLowerInvariant()
                if ($extMode -in @('0','1','2','all')) {
                    $extendedLogging = $extMode
                } else {
                    Write-HSLog "[$SourceTag] Line $lineNum : ExtendedLogging '$($parts[5].Trim())' is invalid (allowed: 0, 1, 2, all, or empty) - defaulting to 0" "WARN"
                    $extendedLogging = '0'
                }
            }
        }

        # Validate required fields
        if (-not $logName) {
            Write-HSLog "[$SourceTag] Line $lineNum : LogName is empty - skipping" "WARN"
            continue
        }
        if (-not $eventId) {
            Write-HSLog "[$SourceTag] Line $lineNum : EventID is empty - skipping" "WARN"
            continue
        }
        if (-not $label) {
            Write-HSLog "[$SourceTag] Line $lineNum : Label is empty - skipping" "WARN"
            continue
        }

        # EventID must be numeric
        if ($eventId -notmatch '^\d+$') {
            Write-HSLog "[$SourceTag] Line $lineNum : EventID '$eventId' is not numeric - skipping" "WARN"
            continue
        }

        # Label must be safe for TS task names and XML attribute values
        if ($label -match '[\\\/\:\*\?"<>\|\s]') {
            Write-HSLog "[$SourceTag] Line $lineNum : Label '$label' contains invalid characters (no spaces, no \/:*?`"<>|) - skipping" "WARN"
            continue
        }

        $results.Add([pscustomobject]@{
            Type        = 'NEEDLE'
            LogName     = $logName
            EventID     = $eventId
            XPathFilter = $xpathFilt
            Label       = $label
            ExtendedLogging = $extendedLogging
            Source      = $SourceTag
        })
    }

    Write-HSLog "[$SourceTag] Parsed $($results.Count) needle(s) from: $(Split-Path $Path -Leaf)" "INFO"
    return $results.ToArray()
}

function Merge-Needles {
    <#
    .SYNOPSIS
    Merges share and local needle lists into one deduplicated list.
    Local needles are processed first and WIN on label collision.
    Logs a warning for every collision so it is obvious during troubleshooting.
    #>
    param(
        [object[]]$ShareNeedles,
        [object[]]$LocalNeedles
    )

    $merged     = [System.Collections.Generic.List[object]]::new()
    $seenLabels = @{}
    $collisions = 0

    # Labels are intentionally deduplicated across all directive types.
    # Local needles first - they win on collision.
    foreach ($n in $LocalNeedles) {
        if ($seenLabels.ContainsKey($n.Label)) {
            Write-HSLog "Duplicate label '$($n.Label)' within local list - keeping first, skipping repeat" "WARN"
            $collisions++
            continue
        }
        $seenLabels[$n.Label] = 'local'
        $merged.Add($n)
    }

    # Share needles - skip if label already claimed by local
    foreach ($n in $ShareNeedles) {
        if ($seenLabels.ContainsKey($n.Label)) {
            if ($seenLabels[$n.Label] -eq 'local') {
                Write-HSLog "Label '$($n.Label)' from share overridden by local needle - local wins" "INFO"
            } else {
                Write-HSLog "Duplicate label '$($n.Label)' within share list - keeping first, skipping repeat" "WARN"
                $collisions++
            }
            continue
        }
        $seenLabels[$n.Label] = 'share'
        $merged.Add($n)
    }

    Write-HSLog "Needle merge complete: $($merged.Count) active ($($LocalNeedles.Count) local, $($ShareNeedles.Count) share, $collisions collision(s) resolved)" "INFO"
    return $merged.ToArray()
}

# =============================================================================
# Task Scheduler XML Builder
# Event-based triggers require XML/CIM registration.
# New-ScheduledTaskTrigger cannot create event-based triggers - do not use it.
# =============================================================================
function ConvertTo-XmlEscaped {
    # Escapes a string for safe embedding as XML text content
    param([string]$s)
    $s = $s.Replace('&',  '&amp;')   # must be first
    $s = $s.Replace('<',  '&lt;')
    $s = $s.Replace('>',  '&gt;')
    $s = $s.Replace('"',  '&quot;')
    $s = $s.Replace("'",  '&apos;')
    return $s
}

function Build-EventTriggerXml {
    <#
    .SYNOPSIS
    Builds one <EventTrigger> XML block for a single needle.

    The <Subscription> value is a QueryList XML fragment, XML-escaped for
    embedding inside the outer task XML. This is the correct and only way to
    create event-based triggers via the Task Scheduler XML registration path.
    #>
    param([object]$Needle)

    $logName = $Needle.LogName
    $eventId = $Needle.EventID
    $label   = $Needle.Label

    # XPath Select body: use custom filter if provided, otherwise bare EventID match
    if ($Needle.XPathFilter -and $Needle.XPathFilter.Length -gt 0) {
        $selectBody = $Needle.XPathFilter                  # use the custom XPath from needles.cfg
    } else {
        $selectBody = "*[System[EventID=$eventId]]"        # bare EventID fallback - TS-safe syntax
    }

    # Build the inner QueryList XML (this gets XML-escaped and embedded in <Subscription>)
    # Note: double-quotes inside the here-string are literal - no escaping needed here
    $innerXml = "<QueryList><Query Id=`"0`" Path=`"$logName`"><Select Path=`"$logName`">$selectBody</Select></Query></QueryList>"

    # XML-escape the inner XML for safe embedding as text content of <Subscription>
    $escaped = ConvertTo-XmlEscaped -s $innerXml

    # Id attribute identifies this trigger in schtasks /query output - useful for debugging
    return @"
    <EventTrigger id="HayStack_$label">
      <Enabled>true</Enabled>
      <Subscription>$escaped</Subscription>
    </EventTrigger>
"@
}

function Build-SessionTriggerXml {
    <#
    .SYNOPSIS
    Builds one <SessionStateChangeTrigger> XML block for a single SESSION needle.
    No event log subscription - this is a pure OS session state trigger.
    #>
    param([object]$Needle)

    return @"
    <SessionStateChangeTrigger id="HayStack_$($Needle.Label)">
      <Enabled>true</Enabled>
      <StateChange>$($Needle.StateChange)</StateChange>
    </SessionStateChangeTrigger>
"@
}

function Build-HeartbeatTriggerXml {
    <#
    .SYNOPSIS
    Builds the low-frequency <TimeTrigger> XML block that gives the syslog
    queue a guaranteed periodic opportunity to drain, independent of whether
    any needle event happens to fire.

    This is the exact same "OS wakes process, it runs once, it exits" model
    as every other HayStack trigger - a Repetition/Interval on a TimeTrigger,
    not a resident loop or sleep-based script. haystack_action.ps1's own
    Test-SyslogReachable check still gates whether a drain is actually
    attempted, so a heartbeat fire while off-domain is a fast no-op.

    $RandomDelayMinutes emits a <RandomDelay> element - a direct child of
    <TimeTrigger> and a sibling of <StartBoundary>/<Repetition>, per the Task
    Scheduler schema (it is NOT nested inside <Repetition>). Task Scheduler
    offsets each actual fire time by a random amount within that window, which
    spreads fleet-wide load. 0 omits the element entirely (no jitter).
    #>
    param([datetime]$StartBoundary, [int]$IntervalMinutes, [int]$RandomDelayMinutes = 0)

    $start    = $StartBoundary.ToString('yyyy-MM-ddTHH:mm:ss')
    $interval = "PT${IntervalMinutes}M"

    $randomDelayLine = ''
    if ($RandomDelayMinutes -gt 0) {
        $randomDelayLine = "`n      <RandomDelay>PT${RandomDelayMinutes}M</RandomDelay>"
    }

    return @"
    <TimeTrigger id="HayStack_Heartbeat">
      <Enabled>true</Enabled>
      <StartBoundary>$start</StartBoundary>
      <Repetition>
        <Interval>$interval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>$randomDelayLine
    </TimeTrigger>
"@
}

function Build-HaystackTaskXml {
    <#
    .SYNOPSIS
    Builds the complete Task Scheduler XML for the HayStack_Monitor task.
    One task. One action. One event/session trigger per trigger-producing needle,
    plus one heartbeat TimeTrigger. DEFENDER and HEADER needles are evaluated
    inline by the action and intentionally produce no trigger XML.

    Key settings:
      MultipleInstancesPolicy = IgnoreNew  -> OS-level thrash protection. If a second
        event fires while the action is still running, the OS drops it. No stacking.
      ExecutionTimeLimit = PT2M            -> Action cannot run away. 2 minute hard cap.
      UserId = S-1-5-18                   -> Runs as SYSTEM (same as CPR).
      Hidden = true                        -> No visible window.
    #>
    param([object[]]$Needles)

    if ($Needles.Count -eq 0) {
        Write-HSLog "Cannot build task XML - merged needle list is empty" "WARN"
        return $null
    }

    # DEFENDER and HEADER directives are evaluated inline by haystack_action.ps1
    # and never produce Task Scheduler trigger XML.
    $triggerNeedles = @($Needles | Where-Object { @('DEFENDER','HEADER') -notcontains $_.Type })
    $triggerBlocks = ($triggerNeedles | ForEach-Object {
        if ($_.Type -eq 'SESSION') {
            Build-SessionTriggerXml -Needle $_
        } else {
            Build-EventTriggerXml -Needle $_
        }
    }) -join "`n"

    $regDateTime = Get-Date
    $regDate     = $regDateTime.ToString('yyyy-MM-ddTHH:mm:ss')

    # Heartbeat trigger - additive, alongside the needle triggers above. Gives
    # the syslog queue a guaranteed periodic drain opportunity independent of
    # any needle event firing.
    $heartbeatBlock = Build-HeartbeatTriggerXml -StartBoundary $regDateTime -IntervalMinutes $HeartbeatIntervalMinutes -RandomDelayMinutes $HeartbeatRandomDelayMinutes
    $triggerBlocks  = $triggerBlocks + "`n" + $heartbeatBlock

    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>HayStack Event Monitor - CPR subsystem v$HaystackVersion. $($triggerNeedles.Count) trigger(s), $(@($Needles | Where-Object Type -eq 'DEFENDER').Count) Defender check(s) active. Managed by haystack.ps1 - do not edit manually.</Description>
    <Author>CPR/HayStack</Author>
    <Date>$regDate</Date>
  </RegistrationInfo>
  <Triggers>
$triggerBlocks
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File "$ActionScriptPath"</Arguments>
      <WorkingDirectory>$LocalCacheDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

    return $xml
}

# =============================================================================
# Reroll Stamp  (thrash protection + version/mtime change detection)
# Stored as JSON: {
#   LastReroll: ISO8601,
#   LocalCfgMtime: ISO8601|null,
#   ShareNeedlesVersion: string|null,
#   LocalNeedlesVersion: string|null
# }
# =============================================================================
function Read-RerollStamp {
    if (-not (Test-Path $RerollStampFile)) { return $null }
    try {
        return (Get-Content $RerollStampFile -Raw -ErrorAction Stop | ConvertFrom-Json)
    } catch {
        Write-HSLog "Could not read reroll stamp: $_" "WARN"
        return $null
    }
}

function Get-RerollStampData {
    $stamp = Read-RerollStamp
    if ($null -eq $stamp) {
        return [pscustomobject]@{
            ShareVersion = $null
            LocalVersion = $null
            LastReroll   = $null
            LocalMtime   = $null
        }
    }

    return [pscustomobject]@{
        ShareVersion = if ($null -ne $stamp.ShareNeedlesVersion) { [string]$stamp.ShareNeedlesVersion } else { $null }
        LocalVersion = if ($null -ne $stamp.LocalNeedlesVersion) { [string]$stamp.LocalNeedlesVersion } else { $null }
        LastReroll   = if ($null -ne $stamp.LastReroll) { [string]$stamp.LastReroll } else { $null }
        LocalMtime   = if ($null -ne $stamp.LocalCfgMtime) { [string]$stamp.LocalCfgMtime } else { $null }
    }
}

function Write-RerollStamp {
    $localMtime = if (Test-Path $LocalNeedlesFile_Local) {
        (Get-Item $LocalNeedlesFile_Local -ErrorAction SilentlyContinue).LastWriteTime.ToString('o')
    } else {
        $null
    }

    $shareNeedlesVersion = Get-HsFileVersion -Path $LocalNeedlesFile
    $localNeedlesVersion = Get-HsFileVersion -Path $LocalNeedlesFile_Local

    $stamp = [pscustomobject]@{
        LastReroll          = (Get-Date).ToString('o')
        LocalCfgMtime       = $localMtime
        ShareNeedlesVersion = $shareNeedlesVersion
        LocalNeedlesVersion = $localNeedlesVersion
    }

    try {
        $stamp | ConvertTo-Json | Set-Content -Path $RerollStampFile -Encoding UTF8 -Force
        Write-HSLog "Reroll stamp updated (ShareNeedlesVersion: $shareNeedlesVersion LocalNeedlesVersion: $localNeedlesVersion LocalCfgMtime: $localMtime)" "DEBUG"
    } catch {
        Write-HSLog "Could not write reroll stamp: $_" "WARN"
    }
}

function Test-RerollNeeded {
    <#
    .SYNOPSIS
    Determines whether the TS task needs to be rerolled.

    Returns $true (reroll) if any of:
      - No valid stamp exists
      - needles_local.cfg LastWriteTime changed since last reroll
      - needles_local.cfg appeared or disappeared since last reroll
      - Either share/local needles version differs from stamped version

    Returns $false (skip reroll) only if:
      - Both current needles versions match stamp versions
    #>

    $stamp = Get-RerollStampData
    if (-not $stamp.LastReroll) {
        Write-HSLog "No valid reroll stamp found - reroll required" "INFO"
        return $true
    }

    # --- Local cfg change detection (bypasses cooldown) ---
    $localExists = Test-Path $LocalNeedlesFile_Local

    if ($localExists) {
        $currentLocalMtime = (Get-Item $LocalNeedlesFile_Local -ErrorAction SilentlyContinue).LastWriteTime.ToString('o')
        if ($stamp.LocalMtime -ne $currentLocalMtime) {
            Write-HSLog "needles_local.cfg changed since last reroll (was: $($stamp.LocalMtime) now: $currentLocalMtime) - forcing immediate reroll" "INFO"
            return $true
        }
    } elseif ($stamp.LocalMtime) {
        # File was present at last reroll but is now gone - reroll to remove those triggers
        Write-HSLog "needles_local.cfg was present at last reroll but is now gone - forcing reroll to remove local triggers" "INFO"
        return $true
    }

    # --- Version change detection (source of truth, checked before cooldown) ---
    $currentShareNeedlesVersion = Get-HsFileVersion -Path $LocalNeedlesFile
    $currentLocalNeedlesVersion = Get-HsFileVersion -Path $LocalNeedlesFile_Local

    if (($stamp.ShareVersion -eq $currentShareNeedlesVersion) -and ($stamp.LocalVersion -eq $currentLocalNeedlesVersion)) {
        Write-HSLog "Needles versions unchanged (share:$currentShareNeedlesVersion local:$currentLocalNeedlesVersion) - skipping reroll" "DEBUG"
        return $false
    }

    Write-HSLog "Needles version change detected (share:$($stamp.ShareVersion)->$currentShareNeedlesVersion local:$($stamp.LocalVersion)->$currentLocalNeedlesVersion) - forcing reroll" "INFO"
    return $true
}

# =============================================================================
# Task Registration
# =============================================================================
function Unregister-HaystackTask {
    try {
        $existing = Get-ScheduledTask -TaskName $TsTaskName -TaskPath $TsTaskPath -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskName $TsTaskName -TaskPath $TsTaskPath -Confirm:$false -ErrorAction Stop
            Write-HSLog "Unregistered existing HayStack_Monitor task" "INFO"
        } else {
            Write-HSLog "No existing HayStack_Monitor task found - nothing to unregister" "DEBUG"
        }
    } catch {
        Write-HSLog "Error unregistering HayStack_Monitor: $_" "WARN"
        # Non-fatal - we will attempt to re-register with -Force anyway
    }
}

function Register-HaystackTask {
    param([string]$XmlString)

    try {
        Register-ScheduledTask `
            -Xml      $XmlString `
            -TaskName $TsTaskName `
            -TaskPath $TsTaskPath `
            -Force    `
            -ErrorAction Stop | Out-Null

        Write-HSLog "HayStack_Monitor task registered at: $TsTaskPath$TsTaskName" "INFO"
        return $true
    } catch {
        Write-HSLog "Failed to register HayStack_Monitor task: $_" "ERROR"
        return $false
    }
}

# =============================================================================
# Main Entry Point
# =============================================================================
function Invoke-HaystackReroll {
    <#
    .SYNOPSIS
    Full HayStack sync + merge + reroll cycle.
    Called by WW_main.ps1 when $HaystackEnabled = $true.
    Safe to call on every WW_main run - cooldown and change detection prevent thrash.
    #>
    param([switch]$Force)

    Write-HSLog ("=" * 60) "INFO"
    Write-HSLog "HayStack v$HaystackVersion - reroll check starting" "INFO"

    # Ensure local cache directory exists
    if (-not (Test-Path $LocalCacheDir)) {
        try {
            New-Item -Path $LocalCacheDir -ItemType Directory -Force | Out-Null
            Write-HSLog "Created local cache dir: $LocalCacheDir" "INFO"
        } catch {
            Write-HSLog "Cannot create cache dir $LocalCacheDir : $_ - aborting" "ERROR"
            Write-HaystackRerollTelemetry -Result 'failed' -NeedleCount 0 -Reason 'cache_dir_create_failed'
            return
        }
    }

    # Validate action script is deployed - no point registering a task with a missing payload
    if (-not (Test-Path $ActionScriptPath)) {
        Write-HSLog "haystack_action.ps1 not found at: $ActionScriptPath" "ERROR"
        Write-HSLog "Cannot register TS task without the action script - check CPR deployment" "ERROR"
        Write-HaystackRerollTelemetry -Result 'failed' -NeedleCount 0 -Reason 'action_script_missing'
        return
    }

    # Sync needles.cfg from share (version + hash gated - will be fast on cache hit)
    $syncOk = Invoke-NeedleSync
    if (-not $syncOk) {
        Write-HSLog "needles.cfg unavailable (share unreachable, no local cache) - cannot proceed" "WARN"
        Write-HaystackRerollTelemetry -Result 'failed' -NeedleCount 0 -Reason 'needles_unavailable'
        return
    }

    # Check whether a reroll is actually needed before doing any parse/register work
    if ($Force) {
        Write-HSLog "Force flag set - bypassing cooldown check, rerolling now" "INFO"
    } elseif (-not (Test-RerollNeeded)) {
        Write-HSLog "HayStack - no reroll needed, existing task is current" "INFO"
        Write-HaystackRerollTelemetry -Result 'skipped' -NeedleCount 0 -Reason 'no_reroll_needed'
        Write-HSLog ("=" * 60) "INFO"
        return
    }

    # Parse both needle sources
    $shareNeedles = Read-NeedleFile -Path $LocalNeedlesFile      -SourceTag "share"
    $localNeedles = Read-NeedleFile -Path $LocalNeedlesFile_Local -SourceTag "local"

    # Merge (local wins on label collision)
    $mergedNeedles = Merge-Needles -ShareNeedles $shareNeedles -LocalNeedles $localNeedles

    # Edge case: all needles were invalid or files were empty
    if ($mergedNeedles.Count -eq 0) {
        Write-HSLog "Merged needle list is empty - nothing to monitor" "WARN"
        Write-HSLog "Unregistering any existing HayStack task to prevent stale triggers" "WARN"
        Unregister-HaystackTask
        Write-RerollStamp   # stamp it so we don't re-attempt every run
        Write-HaystackRerollTelemetry -Result 'skipped' -NeedleCount 0 -Reason 'no_active_needles'
        Write-HSLog ("=" * 60) "INFO"
        return
    }

    # Log what we are about to register
    $triggerNeedles  = @($mergedNeedles | Where-Object { @('DEFENDER','HEADER') -notcontains $_.Type })
    $defenderNeedles = @($mergedNeedles | Where-Object { $_.Type -eq 'DEFENDER' })
    $headerNeedles   = @($mergedNeedles | Where-Object { $_.Type -eq 'HEADER' })
    Write-HSLog "Building task with $($triggerNeedles.Count) event/session trigger(s), $($defenderNeedles.Count) Defender check(s), $($headerNeedles.Count) Header check(s) (evaluated inline, no TS trigger):" "INFO"
    foreach ($n in $mergedNeedles) {
        if ($n.Type -eq 'SESSION') {
            Write-HSLog "  [$($n.Source.PadRight(5))] $($n.Label.PadRight(30)) SESSION / $($n.StateChange)" "INFO"
        } elseif ($n.Type -eq 'DEFENDER') {
            $intervalNote = if ($null -ne $n.IntervalHours) { "$($n.IntervalHours)h" } else { "default interval" }
            Write-HSLog "  [$($n.Source.PadRight(5))] $($n.Label.PadRight(30)) DEFENDER / $($n.RuleNameMatch) ($intervalNote)" "INFO"
        } elseif ($n.Type -eq 'HEADER') {
            $refreshNote = if ($null -ne $n.RefreshHours) { "refresh $($n.RefreshHours)h" } else { "default refresh" }
            $sendNote    = if ($null -ne $n.SendHours)    { "send $($n.SendHours)h" }        else { "default send" }
            Write-HSLog "  [$($n.Source.PadRight(5))] $($n.Label.PadRight(30)) HEADER / $($n.FieldName) ($refreshNote, $sendNote)" "INFO"
        } else {
            $xpathNote = if ($n.XPathFilter -and $n.XPathFilter.Length -gt 0) { "custom XPath" } else { "bare EventID" }
            Write-HSLog "  [$($n.Source.PadRight(5))] $($n.Label.PadRight(30)) $($n.LogName) / EventID $($n.EventID) ($xpathNote)" "INFO"
        }
    }
    Write-HSLog "Heartbeat trigger added: every $HeartbeatIntervalMinutes minute(s)" "INFO"
    if ($HeartbeatRandomDelayMinutes -gt 0) {
        Write-HSLog "Heartbeat jitter window active: up to $HeartbeatRandomDelayMinutes minute(s) random delay" "INFO"
    }

    # Build task XML
    $taskXml = Build-HaystackTaskXml -Needles $mergedNeedles
    if (-not $taskXml) {
        Write-HSLog "Task XML build failed - aborting reroll" "ERROR"
        Write-HaystackRerollTelemetry -Result 'failed' -NeedleCount $mergedNeedles.Count -Reason 'task_xml_build_failed'
        return
    }

    # Unregister old, register new
    Unregister-HaystackTask
    $ok = Register-HaystackTask -XmlString $taskXml

    if ($ok) {
        Write-RerollStamp
        Write-HSLog "HayStack reroll complete - $($triggerNeedles.Count) event/session trigger(s) registered, $($defenderNeedles.Count) Defender check(s), $($headerNeedles.Count) Header check(s) active" "INFO"
        Write-HaystackRerollTelemetry -Result 'success' -NeedleCount $mergedNeedles.Count -Reason 'task_registered'
    } else {
        Write-HSLog "HayStack reroll FAILED - see errors above" "ERROR"
        Write-HaystackRerollTelemetry -Result 'failed' -NeedleCount $mergedNeedles.Count -Reason 'task_register_failed'
    }

    Write-HSLog ("=" * 60) "INFO"
}

# =============================================================================
# Entry Point
# =============================================================================
if ((-not $reroll -and -not $remove) -or ($reroll -and $remove)) {
    throw "Specify exactly one flag: -reroll OR -remove"
}

if ($remove) {
    Write-HSLog "HayStack -remove: unregistering TS task" "INFO"
    Unregister-HaystackTask
    exit 0
}

if ($reroll) {
    Invoke-HaystackReroll -Force:$Force
    exit 0
}
