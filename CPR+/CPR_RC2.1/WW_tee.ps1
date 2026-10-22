<#
.SYNOPSIS
  WW_tee - CPR Log-and-Tee Engine
  Version: 1.0.0
  Author: steve.horton@optum.com
  Date: 28-Aug-2026

.DESCRIPTION
  Lets any CPR script (WW_main.ps1, Set-VpnHostsEntry.ps1, cap_portal_runner, etc.)
  "tee" a nugget of data it ALREADY has in hand to the syslog/Splunk pipeline -
  without any extra gathering, polling, or searching.

  The pattern at every call site:

      Write-Log "Captive portal redirect detected: $redirectUrl" "INFO"   # existing, unchanged
      Write-TeeLog 'cap_portal_redirect' @{ url = $redirectUrl; ssid = $ssid }   # NEW, one line

  Write-TeeLog is a complete no-op (zero cost, zero risk) unless ALL of the
  following are true:
    1. $HaystackEnabled = $true   (master kill switch - lives in WW_main.ps1)
    2. $TeeEnabled      = $true   (tee kill switch - lives in WW_main.ps1)
    3. The tag passed to Write-TeeLog exists as a key in the loaded event profile

  THE PROFILE FILE IS THE VOLUME KNOB.
  WW_tee_events.psd1 is the ACTIVE profile. It is just a hashtable of tags.
  If a tag is a key in the file, that nugget fires. If not, it's silently
  dropped. Swapping logging intensity fleet-wide (or on one box for an
  incident) is just a file copy:

      .\WW_set_tee_level.ps1 -Level 0   # silence everything
      .\WW_set_tee_level.ps1 -Level 5   # everything, for an incident
      (or touch C:\Windows\Temp\cpr_tee_<1-5>.flag - no admin needed; levels live in WW_tee_master.psd1)

  Domain-share sync of these profile files is a future enhancement - NOT
  implemented here. For now, profile swaps are manual (or via existing
  CPR deployment/update mechanisms).

  DOWNSTREAM: Write-TeeLog appends to the SAME queue haystack_action.ps1
  already drains (haystack_syslog_queue.jsonl). No new queue, no new drain
  logic, no new syslog sender. haystack_action.ps1's existing Drain-SyslogQueue
  (v1.1.1+) picks these up on its next fire and ships them via WW_syslog.ps1,
  which stamps user= on every outbound packet. machine= is stamped here, at
  event creation time, so it is tied to the real event rather than the drain.

  This means: if $HaystackEnabled = $false, the queue is never drained and
  WW_syslog.ps1 is never called - i.e. "haystack off" == "no remote logging
  at all", exactly as intended. Write-TeeLog's own $HaystackEnabled check
  is a belt-and-suspenders no-op guard so we don't even write to the queue
  file when haystack is off.

.NOTES
  Dot-source this near the top of WW_main.ps1, same pattern as
  WW_csc_client_info.ps1:

      . "C:\ProgramData\WhiteWalker\WW_tee.ps1"

  Requires these variables to already be defined in the calling scope
  (WW_main.ps1 config block) BEFORE dot-sourcing:
      $HaystackEnabled   [bool]
      $TeeEnabled         [bool]   (NEW - add to WW_main.ps1 config block)
      $TeeEventsFile      [string] (NEW - path to active WW_tee_events.psd1)

  If those variables are not yet defined at dot-source time (e.g. dot-sourced
  before the config block), Write-TeeLog defaults to safe-off until they are
  set - it re-checks $global:HaystackEnabled/$global:TeeEnabled at CALL time,
  not at dot-source time, so ordering is forgiving.

  Never throws. Any failure here must not affect WW_main's real job.
#>

# =============================================================================
# Configuration (paths only - behavior toggles live in WW_main.ps1)
# =============================================================================
$script:TeeQueueFile   = "C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl"  # same queue as haystack_action.ps1
# RC2.1 (Required G): narrowly scoped USER drop directory. Non-SYSTEM callers
# (Base / full captive-portal runner) write ONE atomic file per event here
# instead of appending to the SYSTEM-owned queue; haystack_action.ps1 (SYSTEM)
# ingests and drains them into the canonical queue. This removes the
# "Access to the path ... haystack_syslog_queue.jsonl is denied." data loss
# WITHOUT granting Users Modify on scripts or configuration, and avoids
# concurrent JSONL corruption because no two writers share a file.
$script:TeeSpoolDir    = "C:\ProgramData\WhiteWalker\logs\spool"
$script:TeeProfileCache = $null   # loaded lazily, cached per-run
$script:TeeProfileLoadedFrom = $null

# =============================================================================
# Schema helper loader
# =============================================================================
function Import-HaystackSchemaHelpers {
    <#
    .SYNOPSIS
    Lazily dot-sources WW_haystack_schema.ps1 (Test-HaystackMsgSchema,
    Get-HaystackUserContext) if it isn't already loaded.

    RC1.25: $PSScriptRoot is empty when this file is dot-sourced from a
    string/expression rather than from disk, and a USER-context runner may
    be launched from a working directory that has no copy of the helper -
    which is how user= silently degraded to USER_UNKNOWN in the field. Probe
    the script's own directory first, then the standard deploy directory,
    and WARN (rather than fail silently) when nothing is found, so the gap
    is visible in the log instead of only in Splunk.
    #>
    if (Get-Command Test-HaystackMsgSchema -ErrorAction SilentlyContinue) { return }

    $candidates = @()
    if ($PSScriptRoot) { $candidates += (Join-Path $PSScriptRoot 'WW_haystack_schema.ps1') }
    $candidates += 'C:\ProgramData\WhiteWalker\WW_haystack_schema.ps1'

    foreach ($schemaScript in $candidates) {
        try {
            if ($schemaScript -and (Test-Path -LiteralPath $schemaScript)) {
                . $schemaScript
                if (Get-Command Test-HaystackMsgSchema -ErrorAction SilentlyContinue) {
                    $script:TeeSchemaHelpersFrom = $schemaScript
                    return
                }
            }
        } catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log "WW_tee: could not load '$schemaScript': $_" "WARN"
            }
        }
    }

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log "WW_tee: WW_haystack_schema.ps1 not found (looked in: $($candidates -join '; ')) - schema lint disabled and user= resolution falls back to local probe" "WARN"
    }
}

# =============================================================================
# Normalized captive portal payload contract
# =============================================================================
# Every normalized cap_portal_* tee event carries this exact flat field set so
# a single Splunk table works regardless of which producer (WW_main.ps1 full
# mode, WW_main.ps1 walled-garden, WW_cap_portal_runner_base.ps1,
# WW_cap_portal_runner.ps1) emitted it. A field the producer genuinely could
# not determine is emitted as an empty string - it is never dropped, and it is
# never fabricated. action/machine/user/EvtTime are stamped by Write-TeeLog
# itself and are therefore not repeated here.
$script:TeeCapPortalTags = @(
    'cap_portal_redirect',
    'cap_portal_remediation_passed',
    'cap_portal_remediation_failed'
)
$script:TeeCapPortalFields = @(
    'ssid', 'url', 'port', 'ip', 'gw', 'dns', 'vpn_state', 'portal_type', 'status', 'reason'
)

function ConvertTo-NormalizedCapPortalData {
    <#
    .SYNOPSIS
    Returns a copy of $Data guaranteed to contain every normalized captive
    portal field (missing ones added as empty strings), so a cap_portal_*
    row in Splunk always has the same shape. Non-cap_portal tags are passed
    through untouched.
    #>
    param(
        [Parameter(Mandatory)][string]$Tag,
        [Parameter(Mandatory)][hashtable]$Data
    )

    if ($script:TeeCapPortalTags -notcontains $Tag) { return $Data }

    $normalized = @{}
    foreach ($key in $Data.Keys) { $normalized[$key] = $Data[$key] }

    $filled = New-Object System.Collections.Generic.List[string]
    foreach ($field in $script:TeeCapPortalFields) {
        if (-not $normalized.ContainsKey($field) -or $null -eq $normalized[$field]) {
            $normalized[$field] = ''
            $filled.Add($field)
        }
    }

    if ($filled.Count -gt 0 -and (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
        Write-Log "WW_tee: '$Tag' producer supplied no value for: $($filled -join ',') - emitted empty (field present, value unavailable)" "DEBUG"
    }

    return $normalized
}

# =============================================================================
# Profile Loader
# =============================================================================
function Get-TeeProfile {
    <#
    .SYNOPSIS
    Loads and caches the active WW_tee_events.psd1 profile.
    Returns an empty hashtable (never null, never throws) if the file is
    missing, malformed, or unreadable - in every failure case, tee simply
    fires nothing rather than breaking the caller.
    #>
    param([string]$Path)

    if ($script:TeeProfileCache -and $script:TeeProfileLoadedFrom -eq $Path) {
        return $script:TeeProfileCache
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        # Silent - this is a normal state if a tech hasn't dropped a profile in yet
        $script:TeeProfileCache = @{ Events = @{} }
        $script:TeeProfileLoadedFrom = $Path
        return $script:TeeProfileCache
    }

    try {
        $data = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
        if (-not $data.ContainsKey('Events') -or $null -eq $data.Events) {
            $data = @{ Events = @{} }
        }
        $script:TeeProfileCache = $data
        $script:TeeProfileLoadedFrom = $Path
        return $data
    } catch {
        # Malformed profile - fail safe to empty, never throw into caller's flow
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "WW_tee: failed to load profile '$Path': $_ - tee will fire nothing this run" "WARN"
        }
        $script:TeeProfileCache = @{ Events = @{} }
        $script:TeeProfileLoadedFrom = $Path
        return $script:TeeProfileCache
    }
}

# =============================================================================
# Write-TeeLog - the only public entry point
# =============================================================================
function Get-TeeUserContextFallback {
    <#
    .SYNOPSIS
    Last-resort user resolution used only when WW_haystack_schema.ps1 could
    not be loaded. Mirrors Get-HaystackUserContext's contract:
      domain\user         - resolved
      NO_INTERACTIVE_USER - probes worked, nobody is interactively logged on
      USER_UNKNOWN        - every probe failed (true lookup failure)
    Never throws.
    #>
    $probesOk = 0

    try {
        $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $probesOk++
        if (-not [string]::IsNullOrWhiteSpace($current)) {
            $leaf = if ($current.Contains('\')) { $current.Substring($current.LastIndexOf('\') + 1) } else { $current }
            $isMachineAccount = $leaf.EndsWith('$') -or
                                (@('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'LOCALSYSTEM') -contains $leaf.ToUpperInvariant())
            if (-not $isMachineAccount) { return $current }
        }
    } catch { }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $probesOk++
        if (-not [string]::IsNullOrWhiteSpace($cs.UserName)) { return $cs.UserName }
    } catch { }

    if ($probesOk -gt 0) { return 'NO_INTERACTIVE_USER' }
    return 'USER_UNKNOWN'
}

# =============================================================================
# Queue writer (ACL / concurrency aware, always truthful)
# =============================================================================
function Repair-TeeQueueAccess {
    <#
    .SYNOPSIS
    Makes the shared HayStack queue writable by both contexts that produce events.

    .DESCRIPTION
    WW_main.ps1 runs as SYSTEM and WW_cap_portal_runner_base.ps1 / the full
    runner run as the interactive USER, but both append to the SAME
    haystack_syslog_queue.jsonl. When SYSTEM created the file first, the
    USER-context runner hit "Access to the path ... is denied" and its
    structured events silently disappeared while raw needles still shipped.
    This grants the local Users group Modify on the queue file so either
    context can append. Windows-only and strictly fail-soft: on any failure
    (non-Windows, no privilege, file missing) it simply returns $false.
    #>
    param([string]$Path = $script:TeeQueueFile)

    try {
        if (-not (Get-Command Get-Acl -ErrorAction SilentlyContinue)) { return $false }
        if (-not (Test-Path $Path)) { return $false }

        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
        # RC2.1 (Required G): NARROW rights. Append/write/read only - deliberately
        # NOT 'Modify', so an unprivileged caller can add evidence but can never
        # delete the queue or change its permissions.
        $rights = [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                  [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                  [System.Security.AccessControl.FileSystemRights]::ReadData -bor
                  [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
                  [System.Security.AccessControl.FileSystemRights]::Synchronize
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $usersSid, $rights, 'None', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-TeeRunningAsSystem {
    <#
    Returns $true when the current process is the SYSTEM account (the owner and
    authoritative consumer of the canonical queue). Fail-soft: anything that
    cannot be determined is treated as NOT SYSTEM, which routes the event to the
    safe spool rather than attempting a privileged append.
    #>
    try {
        if (-not ([System.Environment]::OSVersion.Platform -eq 'Win32NT')) { return $false }
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -eq $identity) { return $false }
        return ($identity.User.Value -eq 'S-1-5-18')
    } catch {
        return $false
    }
}

function Test-TeeSpoolRequired {
    <#
    Spooling exists solely to work around the Windows ACL split between the
    SYSTEM-owned queue and the USER-context captive-portal runners. On a
    non-Windows host (sandbox/CI) there is no such split, so the direct append
    path - and every existing queue-format test - behaves exactly as before.
    #>
    try {
        if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') { return $false }
    } catch {
        return $false
    }
    return (-not (Test-TeeRunningAsSystem))
}

function Initialize-TeeSpoolDirectory {
    <#
    .SYNOPSIS
    Creates the narrowly scoped USER drop directory and its ACL (Required G).

    .DESCRIPTION
    Grants authenticated interactive users CreateFiles/AppendData/WriteData on
    this ONE directory only - never on the WhiteWalker scripts or configuration.
    Object-inherit so each dropped per-event file is writable by its creator.
    Idempotent: safe to call on every write and on every upgrade. Fail-soft.
    #>
    param([string]$Path = $script:TeeSpoolDir)

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        if (-not (Get-Command Get-Acl -ErrorAction SilentlyContinue)) { return $true }

        $acl = Get-Acl -Path $Path -ErrorAction Stop
        # S-1-5-11 = Authenticated Users.
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
        $already = $acl.Access | Where-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-11' -and
            $_.AccessControlType -eq 'Allow' -and
            ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::CreateFiles)
        }
        if ($already) { return $true }

        $rights = [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
                  [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                  [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                  [System.Security.AccessControl.FileSystemRights]::ReadData -bor
                  [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
                  [System.Security.AccessControl.FileSystemRights]::Synchronize
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $rights, 'ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Add-TeeSpoolEntry {
    <#
    .SYNOPSIS
    Drops ONE event as an atomic per-event file in the USER spool (Required G).

    .DESCRIPTION
    The payload is byte-identical to the JSONL line the canonical queue holds,
    so haystack_action.ps1 can ingest it verbatim and downstream drain semantics
    are unchanged. Written to a .tmp name and then MOVED into place, so the
    SYSTEM ingester can never read a half-written event. One file per event
    means no two writers ever share a handle - JSONL corruption is impossible.
    #>
    param(
        [Parameter(Mandatory)][string]$Entry,
        [string]$Path = $script:TeeSpoolDir
    )

    $result = [pscustomobject]@{ Queued = $false; Reason = 'error'; Error = $null; File = $null }
    try {
        $null = Initialize-TeeSpoolDirectory -Path $Path
        if (-not (Test-Path $Path)) {
            $result.Reason = 'spool_unavailable'
            return $result
        }
        $name = "evt_{0}_{1}" -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfff'), ([guid]::NewGuid().ToString('N'))
        $temp = Join-Path $Path ($name + '.tmp')
        $final = Join-Path $Path ($name + '.json')
        [System.IO.File]::WriteAllText($temp, $Entry, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $final -Force -ErrorAction Stop
        $result.Queued = $true
        $result.Reason = 'spooled'
        $result.File = $final
        return $result
    } catch {
        $message = [string]$_.Exception.Message
        $result.Error = $message
        if (($_.Exception -is [System.UnauthorizedAccessException]) -or ($message -match 'is denied')) {
            $result.Reason = 'spool_access_denied'
        }
        return $result
    }
}

function Add-TeeQueueEntry {
    <#
    .SYNOPSIS
    Appends one JSON line to the HayStack queue and reports the TRUTH.

    .DESCRIPTION
    Queue format and the existing haystack_action.ps1 drain behavior are
    unchanged - this only makes the append robust and honest:
      * creates the queue directory/file when missing (and opens it up for both
        SYSTEM and USER context),
      * retries briefly on a sharing violation (two contexts can append
        concurrently),
      * repairs the ACL once and retries on access-denied,
      * returns Reason = queued | access_denied | error so the caller can log
        exactly what happened instead of silently losing the event.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Entry
    )

    $result = [pscustomobject]@{ Queued = $false; Reason = 'error'; Error = $null }
    $aclRepairTried = $false

    # RC2.1 (Required G): SYSTEM owns the canonical queue. Any other context
    # (Base / full captive-portal runner running as the interactive USER) drops
    # its event into the narrowly scoped spool and lets SYSTEM/HayStack ingest
    # it, instead of appending to a file it has no rights to. If the spool is
    # unavailable the direct append below is still attempted, and the real
    # reason is still reported truthfully.
    $spoolRequired = $false
    if (Get-Command Test-TeeSpoolRequired -ErrorAction SilentlyContinue) {
        $spoolRequired = Test-TeeSpoolRequired
    }
    if ($spoolRequired) {
        $spoolWrite = Add-TeeSpoolEntry -Entry $Entry
        if ($spoolWrite.Queued) { return $spoolWrite }
        $result.Reason = $spoolWrite.Reason
        $result.Error = $spoolWrite.Error
    }

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $dir = Split-Path -Path $Path -Parent
            if ($dir -and -not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            $created = $false
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -ItemType File -Force -ErrorAction Stop | Out-Null
                $created = $true
            }
            if ($created) { $null = Repair-TeeQueueAccess -Path $Path }

            Add-Content -Path $Path -Value $Entry -Encoding UTF8 -ErrorAction Stop
            $result.Queued = $true
            $result.Reason = 'queued'
            return $result
        } catch {
            $message = [string]$_.Exception.Message
            $isDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or ($message -match 'is denied')
            $result.Error = $message

            if ($isDenied) {
                $result.Reason = 'access_denied'
                if (-not $aclRepairTried) {
                    $aclRepairTried = $true
                    if (Repair-TeeQueueAccess -Path $Path) { continue }
                }
                return $result
            }

            $result.Reason = 'error'
            if ($attempt -lt 3) {
                Start-Sleep -Milliseconds (50 * $attempt)
                continue
            }
        }
    }

    return $result
}

function Write-TeeLog {
    <#
    .SYNOPSIS
    Tees an already-in-hand nugget of data to the syslog/Splunk queue,
    gated entirely by (a) haystack/tee master switches and (b) whether the
    tag is present in the active WW_tee_events.psd1 profile.

    .PARAMETER Tag
    The event tag, e.g. 'cap_portal_redirect'. Must match a key in the
    active profile's Events hashtable to actually fire. Becomes the
    action= field in the outbound Splunk payload.

    .PARAMETER Data
    Hashtable of field => value pairs already known at the call site.
    e.g. @{ url = $redirectUrl; ssid = $ssid; vpn_state = $vpnState }
    Values are converted to strings and quoted key="value" for clean
    Splunk field extraction, matching the existing WW_syslog.ps1 format.

    .PARAMETER PassThru
    OPT-IN only. Production callers never pass this and their behavior is
    completely unchanged: Write-TeeLog stays silent, fail-soft and emits
    nothing to the pipeline. When -PassThru IS supplied (admin\Invoke-
    WhiteWalkerAction.ps1's Tech Check-In), a single result object is
    returned so an interactive caller can tell the tech the truth instead
    of assuming success:
        Queued [bool]    - an entry was appended to the queue file
        Reason [string]  - queued | haystack_disabled | tee_disabled |
                           tag_not_in_profile | access_denied | error
        Error  [string]  - exception text when Reason = 'error'
        QueueFile        - the queue path that was (or would be) written

    .EXAMPLE
    Write-Log "Captive portal redirect detected: $redirectUrl" "INFO"
    Write-TeeLog 'cap_portal_redirect' @{ url = $redirectUrl; ssid = $networkInfo.SSID }
    #>
    param(
        [Parameter(Mandatory)][string]$Tag,
        [Parameter(Mandatory)][hashtable]$Data,
        [switch]$PassThru
    )

    $teeResult = [pscustomobject]@{
        Tag       = $Tag
        Queued    = $false
        Reason    = 'error'
        Error     = $null
        QueueFile = $script:TeeQueueFile
    }

    try {
        # Master switches - re-checked at call time (not dot-source time) so
        # variable definition order in WW_main.ps1 never matters.
        $haystackOn = $false
        $teeOn      = $false

        if (Get-Variable -Name HaystackEnabled -Scope Global -ErrorAction SilentlyContinue) {
            $haystackOn = [bool]$global:HaystackEnabled
        } elseif (Get-Variable -Name HaystackEnabled -Scope Script -ErrorAction SilentlyContinue) {
            $haystackOn = [bool]$script:HaystackEnabled
        }

        if (Get-Variable -Name TeeEnabled -Scope Global -ErrorAction SilentlyContinue) {
            $teeOn = [bool]$global:TeeEnabled
        } elseif (Get-Variable -Name TeeEnabled -Scope Script -ErrorAction SilentlyContinue) {
            $teeOn = [bool]$script:TeeEnabled
        }

        if (-not $haystackOn) {
            # haystack off = no remote logging, full stop
            $teeResult.Reason = 'haystack_disabled'
            if ($PassThru) { return $teeResult } else { return }
        }
        if (-not $teeOn) {
            # tee independently silenced
            $teeResult.Reason = 'tee_disabled'
            if ($PassThru) { return $teeResult } else { return }
        }

        # Resolve active profile path - default to standard install location
        $profilePath = if (Get-Variable -Name TeeEventsFile -Scope Global -ErrorAction SilentlyContinue) {
            $global:TeeEventsFile
        } elseif (Get-Variable -Name TeeEventsFile -Scope Script -ErrorAction SilentlyContinue) {
            $script:TeeEventsFile
        } else {
            "C:\ProgramData\WhiteWalker\WW_tee_events.psd1"
        }

        $profileData = Get-TeeProfile -Path $profilePath
        if (-not $profileData.Events.ContainsKey($Tag)) {
            # Tag not in active profile - this is the volume knob working as intended
            $teeResult.Reason = 'tag_not_in_profile'
            if ($PassThru) { return $teeResult } else { return }
        }

        $eventDef = $profileData.Events[$Tag]
        $action   = if ($eventDef.action) { $eventDef.action } else { $Tag }

        Import-HaystackSchemaHelpers
        $user = if (Get-Command Get-HaystackUserContext -ErrorAction SilentlyContinue) {
            Get-HaystackUserContext
        } else {
            # Helper genuinely unavailable (not deployed / not loadable). Do a
            # minimal in-line probe honouring the same contract rather than
            # blanket-stamping USER_UNKNOWN, which is what made every tee event
            # from a helper-less process look like a lookup failure.
            Get-TeeUserContextFallback
        }

        # EvtTime is stamped HERE, at event creation, before the entry is
        # queued - never at drain time. A producer that already stamped its own
        # EvtTime (e.g. an event it observed earlier in the run) wins.
        $evtTime = if ($Data.ContainsKey('EvtTime') -and -not [string]::IsNullOrWhiteSpace([string]$Data['EvtTime'])) {
            [string]$Data['EvtTime']
        } else {
            (Get-Date -Format 'o')
        }

        $Data = ConvertTo-NormalizedCapPortalData -Tag $Tag -Data $Data

        # Build key="value" payload - machine=, user=, and EvtTime= are stamped
        # here, at event creation time, so all three survive queuing and
        # reflect when the event actually happened rather than when the
        # queue was drained.
        $pairs = New-Object System.Collections.Generic.List[string]
        $pairs.Add('action="{0}"' -f $action)
        $pairs.Add('machine="{0}"' -f $env:COMPUTERNAME)
        $pairs.Add('user="{0}"' -f $user)
        $pairs.Add(('EvtTime="{0}"' -f $evtTime))

        foreach ($key in $Data.Keys) {
            # action/machine/user/EvtTime are owned by Write-TeeLog - never let a
            # caller-supplied duplicate produce two copies of the same field.
            if (@('action', 'machine', 'user', 'EvtTime') -contains $key) { continue }
            $val = $Data[$key]
            if ($null -eq $val) { $val = '' }
            $pairs.Add(('{0}="{1}"' -f $key, $val))
        }

        $payload = $pairs -join ' '

        if (Get-Command Test-HaystackMsgSchema -ErrorAction SilentlyContinue) {
            $schemaCheck = Test-HaystackMsgSchema -Payload $payload
            if (-not $schemaCheck.IsValid) {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log "WW_tee: payload for tag '$Tag' failed schema validation - missing: $($schemaCheck.MissingFields -join ',')" "WARN"
                }
            } elseif ($schemaCheck.UnknownFields.Count -gt 0) {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log "WW_tee: payload for tag '$Tag' has unrecognized field(s): $($schemaCheck.UnknownFields -join ',') - check haystack_msg_schema.psd1" "WARN"
                }
            }
        }

        $entry = @{
            ts        = (Get-Date).ToString("o")
            payload   = $payload
            extraInfo = ""
        } | ConvertTo-Json -Compress

        $queueWrite = Add-TeeQueueEntry -Path $script:TeeQueueFile -Entry $entry

        if ($queueWrite.Queued) {
            # 'spooled' means the event was dropped atomically into the USER
            # spool for SYSTEM/HayStack to ingest - it is NOT lost, so it is
            # reported truthfully with its own reason token rather than as
            # 'queued'.
            $acceptedReason = if ($queueWrite.Reason -eq 'spooled') { 'spooled' } else { 'queued' }
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log "WW_tee: $acceptedReason '$Tag' -> $payload" "DEBUG"
            }
            $teeResult.Queued = $true
            $teeResult.Reason = $acceptedReason
        } else {
            # Truthful failure: the event is NOT in the queue. Say which reason
            # token applies instead of letting it disappear.
            $teeResult.Queued = $false
            $teeResult.Reason = $queueWrite.Reason
            $teeResult.Error  = $queueWrite.Error
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log "WW_tee: '$Tag' NOT queued (reason=$($queueWrite.Reason) queue=$($script:TeeQueueFile)): $($queueWrite.Error)" "WARN"
            }
        }
        if ($PassThru) { return $teeResult }

    } catch {
        # Never let a tee failure affect the caller's actual job.
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "WW_tee: Write-TeeLog failed for tag '$Tag': $_" "WARN"
        }
        $teeResult.Reason = 'error'
        $teeResult.Error  = "$_"
        if ($PassThru) { return $teeResult }
    }
}
