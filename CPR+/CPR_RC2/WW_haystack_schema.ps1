<#
.SYNOPSIS
  WW_haystack_schema - Haystack message schema lint/validation helper
  Version: 1.0.0
  Author: steve.horton@optum.com
  Date: 01-Oct-2026

.DESCRIPTION
  Dot-sourceable, standalone helper that any emitter (WW_tee.ps1,
  haystack_action.ps1, install.ps1, future emitters) or test file can load
  independently to validate/lint a haystack syslog payload against the
  canonical schema defined in:

      support_files/haystack_msg_schema.psd1

  Exposes:
    Get-HaystackMsgSchema      - loads/caches the schema .psd1
    ConvertFrom-HaystackPayload - parses a key="value" string into a hashtable
    Test-HaystackMsgSchema     - validates a payload (string OR hashtable)
                                 against Mandatory fields and lints unknown
                                 field names against the known catalog
    Resolve-HaystackUserContext - layered interactive-user resolution with
                                 per-probe diagnostics (RC1.25)
    Get-HaystackUserContext    - the user= field value every emitter stamps

  Never throws. Mirrors the fail-soft / non-fatal pattern used throughout
  this codebase (e.g. Invoke-SyslogSend's try/catch style) - callers get a
  structured result object back and decide what to do (log-and-drop,
  log-and-flag, etc.) rather than having an exception interrupt the
  emitting script's real job.

.NOTES
  Dot-source this near the top of any emitter, same pattern as other
  shared WW_*.ps1 helpers:

      . "C:\ProgramData\WhiteWalker\WW_haystack_schema.ps1"

  Or, in a test BeforeAll block:

      . "$PSScriptRoot/WW_haystack_schema.ps1"
#>

# =============================================================================
# Schema loader (cached per-process)
# =============================================================================
$script:HaystackSchemaCache     = $null
$script:HaystackSchemaLoadedFrom = $null

function Get-HaystackMsgSchema {
    <#
    .SYNOPSIS
    Loads and caches support_files/haystack_msg_schema.psd1.
    Returns a safe empty-shape schema (never null, never throws) if the
    file is missing or malformed - callers that depend on this should treat
    an empty Mandatory/Optional set as "schema unavailable" and fail open
    (warn, don't block), consistent with the rest of this codebase's
    fail-soft posture.

    .PARAMETER Path
    Optional explicit path to the schema file. Defaults to
    support_files/haystack_msg_schema.psd1 next to this script.
    #>
    param([string]$Path)

    if (-not $Path) {
        # RC1.25: resolve across every location the schema is actually deployed to.
        # install.ps1 copies haystack_msg_schema.psd1 BOTH into the WhiteWalker root
        # (flat, legacy manifest behavior) and into support_files\ (repo layout), so
        # probe repo-relative first, then the deployed variants. Previously only the
        # repo-relative support_files path was tried, which does not exist on a
        # deployed endpoint - schema lint silently no-opped in production.
        $candidates = @()
        if ($PSScriptRoot) {
            $candidates += (Join-Path $PSScriptRoot 'support_files\haystack_msg_schema.psd1')
            $candidates += (Join-Path $PSScriptRoot 'haystack_msg_schema.psd1')
        }
        $candidates += 'C:\ProgramData\WhiteWalker\support_files\haystack_msg_schema.psd1'
        $candidates += 'C:\ProgramData\WhiteWalker\haystack_msg_schema.psd1'

        $Path = $candidates[0]
        foreach ($candidate in $candidates) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) {
                $Path = $candidate
                break
            }
        }
    }

    if ($script:HaystackSchemaCache -and $script:HaystackSchemaLoadedFrom -eq $Path) {
        return $script:HaystackSchemaCache
    }

    $empty = @{ SchemaVersion = ''; Mandatory = @{}; Optional = @{}; CanonicalCasing = @() }

    if (-not (Test-Path -LiteralPath $Path)) {
        $script:HaystackSchemaCache      = $empty
        $script:HaystackSchemaLoadedFrom = $Path
        return $empty
    }

    try {
        $data = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
        if (-not $data.ContainsKey('Mandatory')) { $data.Mandatory = @{} }
        if (-not $data.ContainsKey('Optional'))  { $data.Optional  = @{} }
        if (-not $data.ContainsKey('CanonicalCasing')) { $data.CanonicalCasing = @() }
        $script:HaystackSchemaCache      = $data
        $script:HaystackSchemaLoadedFrom = $Path
        return $data
    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "WW_haystack_schema: failed to load schema '$Path': $_" "WARN"
        }
        $script:HaystackSchemaCache      = $empty
        $script:HaystackSchemaLoadedFrom = $Path
        return $empty
    }
}

# =============================================================================
# Payload parser
# =============================================================================
function ConvertFrom-HaystackPayload {
    <#
    .SYNOPSIS
    Parses a key="value" key2="value2" ... payload string (the format built
    by WW_tee.ps1 / haystack_action.ps1 / install.ps1) into a hashtable.
    Handles quoted values containing embedded '=' or spaces correctly.

    .PARAMETER Payload
    The raw key="value" string.

    .EXAMPLE
    ConvertFrom-HaystackPayload 'action="needle_hit" machine="HOST1" reason="a=b c"'
    #>
    param([Parameter(Mandatory)][string]$Payload)

    $result = @{}
    if ([string]::IsNullOrWhiteSpace($Payload)) { return $result }

    # Matches: key="value with any chars except an unescaped closing quote"
    $pattern = '([A-Za-z0-9_]+)="((?:[^"\\]|\\.)*)"'
    $regexMatches = [regex]::Matches($Payload, $pattern)
    foreach ($m in $regexMatches) {
        $key = $m.Groups[1].Value
        $val = $m.Groups[2].Value -replace '\\"', '"'
        $result[$key] = $val
    }
    return $result
}

# =============================================================================
# Validator / Linter
# =============================================================================
function Test-HaystackMsgSchema {
    <#
    .SYNOPSIS
    Validates a haystack payload (string OR pre-parsed hashtable) against
    the canonical schema's Mandatory field list, and lints (warns on) any
    field name present that is not in the schema's known field catalog
    (Mandatory + Optional).

    Never throws - always returns a [PSCustomObject] result so callers can
    log-and-drop or log-and-flag per the "can't be sorted, can't be used"
    policy without the emitting script's own job being interrupted.

    .PARAMETER Payload
    A key="value" ... string, as built today by the production emitters.

    .PARAMETER Fields
    A pre-parsed hashtable of field => value, as an alternative to -Payload.

    .PARAMETER SchemaPath
    Optional explicit path to haystack_msg_schema.psd1. Defaults to the
    standard support_files location next to this script.

    .OUTPUTS
    [PSCustomObject] with:
        IsValid        - [bool] true only if all Mandatory fields are present and non-empty
        MissingFields  - [string[]] Mandatory fields that are missing or empty
        UnknownFields  - [string[]] fields present in the payload not found in the schema catalog
        Payload        - [hashtable] the parsed field => value map
        SchemaVersion  - [string] the schema's date-stamped version, for traceability

    .EXAMPLE
    Test-HaystackMsgSchema -Payload 'action="x" machine="HOST1" EvtTime="2026-10-01T00:00:00Z" user="jdoe"'

    .EXAMPLE
    $result = Test-HaystackMsgSchema -Payload $payload
    if (-not $result.IsValid) {
        Write-Log "Payload missing mandatory fields: $($result.MissingFields -join ',') - dropping" "WARN"
    }
    #>
    [CmdletBinding(DefaultParameterSetName = 'Payload')]
    param(
        [Parameter(ParameterSetName = 'Payload', Position = 0)]
        [string]$Payload,

        [Parameter(ParameterSetName = 'Fields')]
        [hashtable]$Fields,

        [string]$SchemaPath
    )

    $missing = New-Object System.Collections.Generic.List[string]
    $unknown = New-Object System.Collections.Generic.List[string]
    $parsed  = @{}
    $schema  = @{ Mandatory = @{}; Optional = @{}; SchemaVersion = '' }

    try {
        $schema = Get-HaystackMsgSchema -Path $SchemaPath

        if ($PSCmdlet.ParameterSetName -eq 'Fields') {
            $parsed = $Fields
        } else {
            $parsed = ConvertFrom-HaystackPayload -Payload $Payload
        }

        $knownFields = New-Object System.Collections.Generic.HashSet[string]
        foreach ($k in $schema.Mandatory.Keys) { [void]$knownFields.Add($k) }
        foreach ($k in $schema.Optional.Keys)  { [void]$knownFields.Add($k) }

        foreach ($mandatoryField in $schema.Mandatory.Keys) {
            $hasValue = $parsed.ContainsKey($mandatoryField) -and -not [string]::IsNullOrWhiteSpace([string]$parsed[$mandatoryField])
            if (-not $hasValue) {
                $missing.Add($mandatoryField)
            }
        }

        foreach ($key in $parsed.Keys) {
            if (-not $knownFields.Contains($key)) {
                $unknown.Add($key)
            }
        }
    } catch {
        # Fail-soft: if validation itself blows up (bad schema, bad payload),
        # treat as invalid rather than throwing into the caller's real job.
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "WW_haystack_schema: Test-HaystackMsgSchema failed: $_" "WARN"
        }
        if ($missing.Count -eq 0) { $missing.Add('(validation error - see log)') }
    }

    return [PSCustomObject]@{
        IsValid       = ($missing.Count -eq 0)
        MissingFields = $missing.ToArray()
        UnknownFields = $unknown.ToArray()
        Payload       = $parsed
        SchemaVersion = $schema.SchemaVersion
    }
}

# =============================================================================
# Shared user-context resolver
# =============================================================================
function Write-HaystackSchemaDiag {
    <#
    .SYNOPSIS
    Internal diagnostic sink. Routes to the caller's Write-Log when one is
    loaded (WW_main.ps1, haystack_action.ps1, etc.) and is a no-op otherwise.
    Deliberately logs the resolution SOURCE and probe outcomes only - never
    credentials, tokens, or anything beyond the user principal name the
    payload is about to carry anyway.
    #>
    param([string]$Message, [string]$Level = 'DEBUG')
    try {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "WW_haystack_schema: $Message" $Level
        }
    } catch { }
}

function Test-HaystackMachineAccount {
    <#
    .SYNOPSIS
    True when an account name is a machine/service principal (SYSTEM,
    LOCAL SERVICE, NETWORK SERVICE, or HOSTNAME$) rather than a real
    interactive human user. Used to decide whether the CURRENT process
    identity is usable as the telemetry user.
    #>
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }

    $leaf = $Name
    if ($Name.Contains('\')) { $leaf = $Name.Substring($Name.LastIndexOf('\') + 1) }

    if ($leaf.EndsWith('$')) { return $true }

    $serviceAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'LOCALSYSTEM')
    return ($serviceAccounts -contains $leaf.ToUpperInvariant())
}

function Get-HaystackCurrentIdentityName {
    <#
    .SYNOPSIS
    The current process identity name. Separated out so Resolve-HaystackUserContext
    can treat it as one probe among several (and so tests can exercise the
    probe-ordering contract without depending on the host platform).
    Throws on failure - the caller records that as a failed probe.
    #>
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Resolve-HaystackUserContext {
    <#
    .SYNOPSIS
    Layered, diagnosable resolution of the interactive user for telemetry.
    Returns a result object (never throws) so callers/tests can see WHICH
    probe answered and which probes errored.

    .DESCRIPTION
    Probe order (first non-empty answer wins):
      1. current process identity, when it is NOT a machine/service account
         (USER-context producers such as WW_cap_portal_runner_base.ps1 and
         WW_flaregun_user.ps1 already run as the human - cheapest and most
         accurate answer, and it works when CIM is unavailable/blocked)
      2. Win32_ComputerSystem.UserName via CIM (the SYSTEM-context answer -
         same source WW_syslog.ps1's Get-LoggedOnUser uses)
      3. Win32_ComputerSystem.UserName via legacy WMI (Get-WmiObject), for
         endpoints where the CIM/WinRM path is broken but WMI still answers
      4. owner of a running explorer.exe (a locked-but-logged-on console
         session leaves UserName populated, but an RDP/fast-user-switch or
         WinLogon race can briefly blank it while explorer is still up)

    Outcomes:
      Resolved      - domain\user string from whichever probe answered
      NO_INTERACTIVE_USER - every probe ran cleanly and agreed nobody is
                            interactively logged on (true for unattended
                            installs / logged-off boxes)
      USER_UNKNOWN  - every probe FAILED (CIM broken, access denied, etc.),
                      i.e. a real lookup failure rather than "nobody home"

    .OUTPUTS
    [PSCustomObject] User / Source / ProbeErrors / ProbesRun
    #>
    [CmdletBinding()]
    param()

    $probeErrors = New-Object System.Collections.Generic.List[string]
    $probesRun   = New-Object System.Collections.Generic.List[string]
    $probesOk    = 0

    # --- Probe 1: current process identity (USER-context fast path) --------
    try {
        $probesRun.Add('current_identity')
        $current = Get-HaystackCurrentIdentityName
        $probesOk++
        if (-not (Test-HaystackMachineAccount -Name $current)) {
            Write-HaystackSchemaDiag "user context resolved via current_identity"
            return [PSCustomObject]@{
                User        = $current
                Source      = 'current_identity'
                ProbeErrors = $probeErrors.ToArray()
                ProbesRun   = $probesRun.ToArray()
            }
        }
    } catch {
        $probeErrors.Add('current_identity')
        Write-HaystackSchemaDiag "current_identity probe failed: $_" 'DEBUG'
    }

    # --- Probe 2: Win32_ComputerSystem via CIM (SYSTEM-context path) -------
    try {
        $probesRun.Add('cim_computersystem')
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $probesOk++
        if (-not [string]::IsNullOrWhiteSpace($cs.UserName) -and
            -not (Test-HaystackMachineAccount -Name $cs.UserName)) {
            Write-HaystackSchemaDiag "user context resolved via cim_computersystem"
            return [PSCustomObject]@{
                User        = $cs.UserName
                Source      = 'cim_computersystem'
                ProbeErrors = $probeErrors.ToArray()
                ProbesRun   = $probesRun.ToArray()
            }
        }
    } catch {
        $probeErrors.Add('cim_computersystem')
        Write-HaystackSchemaDiag "cim_computersystem probe failed: $_" 'WARN'
    }

    # --- Probe 3: Win32_ComputerSystem via legacy WMI ----------------------
    try {
        if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
            $probesRun.Add('wmi_computersystem')
            $wmiCs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
            $probesOk++
            if (-not [string]::IsNullOrWhiteSpace($wmiCs.UserName) -and
                -not (Test-HaystackMachineAccount -Name $wmiCs.UserName)) {
                Write-HaystackSchemaDiag "user context resolved via wmi_computersystem"
                return [PSCustomObject]@{
                    User        = $wmiCs.UserName
                    Source      = 'wmi_computersystem'
                    ProbeErrors = $probeErrors.ToArray()
                    ProbesRun   = $probesRun.ToArray()
                }
            }
        }
    } catch {
        $probeErrors.Add('wmi_computersystem')
        Write-HaystackSchemaDiag "wmi_computersystem probe failed: $_" 'DEBUG'
    }

    # --- Probe 4: owner of explorer.exe ------------------------------------
    try {
        $probesRun.Add('explorer_owner')
        $explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop |
                    Select-Object -First 1
        $probesOk++
        if ($explorer) {
            $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner -ErrorAction Stop
            if ($owner -and -not [string]::IsNullOrWhiteSpace($owner.User)) {
                $resolved = if ([string]::IsNullOrWhiteSpace($owner.Domain)) {
                    $owner.User
                } else {
                    "$($owner.Domain)\$($owner.User)"
                }
                if (Test-HaystackMachineAccount -Name $resolved) {
                    throw "explorer_owner returned a machine or service identity"
                }
                Write-HaystackSchemaDiag "user context resolved via explorer_owner"
                return [PSCustomObject]@{
                    User        = $resolved
                    Source      = 'explorer_owner'
                    ProbeErrors = $probeErrors.ToArray()
                    ProbesRun   = $probesRun.ToArray()
                }
            }
        }
    } catch {
        $probeErrors.Add('explorer_owner')
        Write-HaystackSchemaDiag "explorer_owner probe failed: $_" 'DEBUG'
    }

    # No probe produced a user. Distinguish "nobody logged on" from "every
    # lookup broke" - the whole point of this RC1.25 change. USER_UNKNOWN is
    # reserved for the latter so Splunk can alert on it as a real defect.
    if ($probesOk -gt 0) {
        Write-HaystackSchemaDiag "no interactive user found (probes run: $($probesRun -join ','))" 'DEBUG'
        return [PSCustomObject]@{
            User        = 'NO_INTERACTIVE_USER'
            Source      = 'no_interactive_session'
            ProbeErrors = $probeErrors.ToArray()
            ProbesRun   = $probesRun.ToArray()
        }
    }

    Write-HaystackSchemaDiag "user lookup FAILED on every probe ($($probeErrors -join ',')) - emitting USER_UNKNOWN" 'WARN'
    return [PSCustomObject]@{
        User        = 'USER_UNKNOWN'
        Source      = 'lookup_failed'
        ProbeErrors = $probeErrors.ToArray()
        ProbesRun   = $probesRun.ToArray()
    }
}

function Get-HaystackUserContext {
    <#
    .SYNOPSIS
    Resolves the "user" field value for haystack telemetry payloads.

    .DESCRIPTION
    Thin wrapper over Resolve-HaystackUserContext (see that function for the
    full probe order). Returns:
      domain\user         - an interactive user was resolved
      NO_INTERACTIVE_USER - no interactive session exists (expected state on
                            an unattended/logged-off box)
      USER_UNKNOWN        - every lookup probe failed (a real defect worth
                            alerting on, not just "nobody logged in")

    Never throws.

    .PARAMETER AsObject
    Return the full resolution result (User/Source/ProbeErrors/ProbesRun)
    instead of just the user string, for diagnostics and tests.
    #>
    param([switch]$AsObject)

    try {
        $result = Resolve-HaystackUserContext
        if ($AsObject) { return $result }
        return $result.User
    } catch {
        Write-HaystackSchemaDiag "Get-HaystackUserContext failed unexpectedly: $_" 'WARN'
        if ($AsObject) {
            return [PSCustomObject]@{
                User        = 'USER_UNKNOWN'
                Source      = 'resolver_exception'
                ProbeErrors = @('resolver_exception')
                ProbesRun   = @()
            }
        }
        return 'USER_UNKNOWN'
    }
}
