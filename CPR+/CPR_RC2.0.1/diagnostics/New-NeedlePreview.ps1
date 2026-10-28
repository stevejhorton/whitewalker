<#
.SYNOPSIS
HayStack Needle Preview - verify a needle candidate against real Event Log data

.DESCRIPTION
Version: 1.0.0
Author: steve.horton@optum.com
Date: 03-Sep-2026

Read-only reconnaissance tool for building HayStack needles. Given a LogName and
EventID (and optionally a custom XPath filter), it queries the real Windows Event
Log using the exact same XPath/QueryList semantics as haystack.ps1's
Build-EventTriggerXml, prints the most recent matching event(s), and then prints
a ready-to-paste NEEDLE line for needles_local.cfg / needles.cfg.

This lets an operator confirm the channel name, EventID and filter are correct
BEFORE committing a needle and waiting on a real-world trigger to prove it out.

Safe to run anytime: it never writes needles.cfg, needles_local.cfg, the registry,
or any scheduled task. It only queries and prints.

NOTE: reading the Security log via Get-WinEvent normally requires elevation. If
access is denied, this script says so plainly instead of dumping a raw exception.

.PARAMETER LogName
The event log channel name/path to query, e.g.
"Microsoft-Windows-WLAN-AutoConfig/Operational". Remember the /Operational (or
similar) suffix on newer split channels. In -ListLogs mode this is optional and
is treated as a wildcard filter instead, e.g. "*WLAN*".

.PARAMETER EventID
The numeric Event ID to match.

.PARAMETER XPathFilter
Optional. A custom XPath <Select> body to test instead of the bare EventID match.
Used verbatim, exactly as haystack.ps1 would use it.

.PARAMETER Label
Optional. The needle label to embed in the generated NEEDLE line. If omitted, a
<LABEL_HERE> placeholder is emitted instead.

.PARAMETER Count
How many recent matching events to show, most recent first. Defaults to 1.

.PARAMETER ListLogs
List available event logs (optionally narrowed by a -LogName wildcard) instead of
querying events. Useful for discovering exact channel names/paths.

.EXAMPLE
.\New-NeedlePreview.ps1 -LogName "Microsoft-Windows-WLAN-AutoConfig/Operational" -EventID 8001 -Label Wifi_Connect_SUCCESS
Preview what a needle for WLAN connect success would look like

.EXAMPLE
.\New-NeedlePreview.ps1 -LogName "Microsoft-Windows-WLAN-AutoConfig/Operational" -EventID 8001 -Count 5
See the last 5 matches

.EXAMPLE
.\New-NeedlePreview.ps1 -LogName "Security" -EventID 4625 -XPathFilter "*[System[EventID=4625]] and *[EventData[Data[@Name='TargetUserName']!='ANONYMOUS LOGON']]"
Test a custom XPath filter before committing it

.EXAMPLE
.\New-NeedlePreview.ps1 -ListLogs -LogName "*WLAN*"
Not sure of the exact channel name/path - list available logs matching a wildcard
#>

[CmdletBinding(DefaultParameterSetName = 'Preview')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Preview')]
    [Parameter(Mandatory = $false, ParameterSetName = 'ListLogs')]
    [string]$LogName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Preview')]
    [int]$EventID,

    [Parameter(ParameterSetName = 'Preview')]
    [string]$XPathFilter,

    [Parameter(ParameterSetName = 'Preview')]
    [string]$Label,

    [Parameter(ParameterSetName = 'Preview')]
    [int]$Count = 1,

    [Parameter(Mandatory = $true, ParameterSetName = 'ListLogs')]
    [switch]$ListLogs
)

$previewVersion = "1.0.0"

# -----------------------------------------------------------------------------
# Output helpers - duplicated locally (not dot-sourced) on purpose.
# WW_diagnostics.ps1 dot-sources WW_main.ps1 to get its functions; this tool is
# standalone and read-only, so it must not pull in that dependency chain.
# -----------------------------------------------------------------------------
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Failure { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Info    { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}
function Write-SubHeader {
    param([string]$Message)
    Write-Host ""
    Write-Host ("-" * 80) -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor DarkCyan
    Write-Host ("-" * 80) -ForegroundColor DarkCyan
}

function Show-AvailableLogs {
    <#
    .SYNOPSIS
    Print available event logs, optionally narrowed by a wildcard pattern.
    #>
    param([string]$Pattern)

    Write-Header "HayStack Needle Preview v$previewVersion - Available Event Logs"

    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
    } catch {
        Write-Failure "Unable to enumerate event logs: $($_.Exception.Message)"
        return
    }

    if (-not $logs) {
        Write-Failure "No event logs could be enumerated on this machine."
        return
    }

    if ($Pattern) {
        Write-Info "Filtering log names with pattern: $Pattern"
        $logs = $logs | Where-Object { $_.LogName -like $Pattern }
    }

    if (-not $logs) {
        Write-Warning "No event logs matched pattern: $Pattern"
        Write-Info "Try a broader wildcard, e.g. -ListLogs -LogName `"*WLAN*`""
        return
    }

    $logs | Sort-Object LogName | Select-Object LogName, RecordCount | Format-Table -AutoSize | Out-Host
    Write-Success "$(@($logs).Count) log(s) listed."
}

function Resolve-LogNameOrSuggest {
    <#
    .SYNOPSIS
    Confirm the LogName resolves. If not, print fuzzy suggestions.
    Returns $true when the log exists, $false otherwise.
    #>
    param([string]$Name)

    $log = Get-WinEvent -ListLog $Name -ErrorAction SilentlyContinue
    if ($log) { return $true }

    Write-Failure "Event log not found: $Name"
    Write-Info "Newer 'Applications and Services Logs' channels need the full path, including the /Operational (or similar) suffix."

    $leaf = $Name
    try { $leaf = Split-Path $Name -Leaf } catch { $leaf = $Name }
    if (-not $leaf) { $leaf = $Name }

    try {
        $candidates = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                      Where-Object { $_.LogName -like "*$leaf*" }
    } catch {
        $candidates = $null
    }

    if ($candidates) {
        Write-SubHeader "Did you mean one of these?"
        foreach ($c in ($candidates | Sort-Object LogName)) {
            Write-Host "  $($c.LogName)" -ForegroundColor Yellow
        }
    } else {
        Write-Warning "No similar log names found matching '*$leaf*'."
        Write-Info "Run: .\New-NeedlePreview.ps1 -ListLogs -LogName `"*$leaf*`""
    }

    return $false
}

function Get-NeedleSelectBody {
    <#
    .SYNOPSIS
    Same XPath <Select> body semantics as haystack.ps1's Build-EventTriggerXml:
    custom filter verbatim when provided, bare EventID match otherwise.
    #>
    param([string]$Filter, [int]$Id)

    if ($Filter -and $Filter.Length -gt 0) { return $Filter }
    return "*[System[EventID=$Id]]"
}

function Show-EventDetail {
    <#
    .SYNOPSIS
    Print one event in a readable, Event Viewer "General tab" style block.
    #>
    param([object]$Event)

    Write-SubHeader "Event  |  $($Event.TimeCreated)"
    Write-Host "  TimeCreated      : $($Event.TimeCreated)"
    Write-Host "  LogName          : $($Event.LogName)"
    Write-Host "  ProviderName     : $($Event.ProviderName)"
    Write-Host "  Id               : $($Event.Id)"
    Write-Host "  LevelDisplayName : $($Event.LevelDisplayName)"
    if ($Event.UserId) {
        Write-Host "  UserId           : $($Event.UserId)"
    }
    Write-Host "  MachineName      : $($Event.MachineName)"

    # Some providers return a null .Message and require FormatDescription()
    $message = $Event.Message
    if (-not $message) {
        try { $message = $Event.FormatDescription() } catch { $message = $null }
    }
    if (-not $message) { $message = "(no formatted message available for this provider)" }

    Write-Host ""
    Write-Host "  Message:" -ForegroundColor DarkCyan
    foreach ($line in ($message -split "`r?`n")) {
        Write-Host "    $line"
    }
}

function Show-NeedleLine {
    <#
    .SYNOPSIS
    Print the ready-to-paste NEEDLE line for needles_local.cfg / needles.cfg.
    #>
    param([string]$Name, [int]$Id, [string]$Filter, [string]$NeedleLabel)

    $labelField = if ($NeedleLabel) { $NeedleLabel } else { "<LABEL_HERE>" }
    $filterField = if ($Filter) { $Filter } else { "" }

    Write-SubHeader "Ready-to-paste needle line"
    Write-Host "NEEDLE|$Name|$Id|$filterField|$labelField" -ForegroundColor Green
    Write-Host ""

    if (-not $NeedleLabel) {
        Write-Warning "Replace <LABEL_HERE> with your own label before saving."
        Write-Info "Label rules (enforced by haystack.ps1's Read-NeedleFile): no spaces and none of \/:*?`"<>|"
    }
    if (-not $Filter) {
        Write-Info "XPathFilter field left blank - HayStack falls back to the bare EventID match."
    }
    Write-Info "Paste into needles_local.cfg to test locally, then: .\haystack.ps1 -reroll -Force"
}

# =============================================================================
# Main
# =============================================================================

if ($ListLogs) {
    Show-AvailableLogs -Pattern $LogName
    return
}

Write-Header "HayStack Needle Preview v$previewVersion"
Write-Info "LogName : $LogName"
Write-Info "EventID : $EventID"

if (-not (Resolve-LogNameOrSuggest -Name $LogName)) {
    return
}
Write-Success "Event log resolved: $LogName"

if ($Count -lt 1) {
    Write-Warning "-Count must be at least 1 - using 1."
    $Count = 1
}

$selectBody = Get-NeedleSelectBody -Filter $XPathFilter -Id $EventID
# Same QueryList/Query/Select structure haystack.ps1 registers with Task Scheduler
$filterXml  = "<QueryList><Query Id=`"0`" Path=`"$LogName`"><Select Path=`"$LogName`">$selectBody</Select></Query></QueryList>"

Write-Info "XPath select body: $selectBody"
Write-Info "FilterXml        : $filterXml"

$events = $null
try {
    $events = Get-WinEvent -FilterXml $filterXml -MaxEvents $Count -ErrorAction Stop
} catch {
    $msg = $_.Exception.Message
    if ($msg -match 'No events were found') {
        Write-Warning "Query is valid, but no matching events are in this log's current retention window."
        Write-Info "That is still a useful result - the filter looks correct, this just has not happened recently (or ever) on this box."
        Show-NeedleLine -Name $LogName -Id $EventID -Filter $XPathFilter -NeedleLabel $Label
        return
    }
    if ($msg -match 'Attempted to perform an unauthorized operation|access is denied') {
        Write-Failure "Access denied reading log: $LogName"
        Write-Info "Reading this log (e.g. Security) requires elevation - re-run this script from an elevated PowerShell prompt."
        return
    }
    Write-Failure "Event log query failed: $msg"
    Write-Info "Check the LogName and XPath filter above - this is the error Windows Event Log returned."
    return
}

if (-not $events) {
    Write-Warning "Query is valid, but no matching events are in this log's current retention window."
    Write-Info "That is still a useful result - the filter looks correct, this just has not happened recently (or ever) on this box."
    Show-NeedleLine -Name $LogName -Id $EventID -Filter $XPathFilter -NeedleLabel $Label
    return
}

$matched = @($events)
Write-Success "$($matched.Count) matching event(s) found (most recent first)."

foreach ($evt in $matched) {
    Show-EventDetail -Event $evt
}

Show-NeedleLine -Name $LogName -Id $EventID -Filter $XPathFilter -NeedleLabel $Label
