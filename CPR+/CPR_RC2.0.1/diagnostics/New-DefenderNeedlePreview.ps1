<#
.SYNOPSIS
HayStack DEFENDER Needle Preview - list and preview MDM-delivered Windows
Firewall rules from the registry, and generate a ready-to-paste DEFENDER
needle line.

.DESCRIPTION
Version: 1.0.2
Author: steve.horton@optum.com
Date: 05-Oct-2026

Changes in 1.0.2:
  - Documented the DEFENDER matching semantics the generated line will be
    evaluated under at runtime: the RuleNameMatch field is literal text (never
    a regex), matched as a case-insensitive, separator-tolerant SUBSTRING of
    the rule's Name= value. Spaces, hyphens, underscores, slashes and dots are
    normalized away, so a generated line keeps working if the Defender team
    reshuffles punctuation. Because separators are dropped, a short/generic
    substring can collide with an unrelated rule - prefer a distinctive, stable
    descriptive substring.

Changes in 1.0.1:
  - Fixed array-unwrap bug: when exactly one rule name matched, PowerShell
    collapsed $uniqueNames to a scalar string and $uniqueNames[0] indexed
    into the string's characters instead of the array element (e.g.
    "V2 - MsWebView2 Any Out" produced just "V" in the generated line).
    Fixed by forcing array context with @(...) around the Select-Object
    -Unique result and the subsequent Count check.

Companion to New-NeedlePreview.ps1 (which previews NEEDLE/event triggers).
This one is for the DEFENDER directive - the flag-gated registry presence
check added for MDM Firewall rule verification (e.g. the WebView2 rule
captive portal remediation depends on).

Reads:
  HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\FirewallRules

Each value under this key is one MDM-delivered rule. The value NAME is a
GUID_suffix (unstable across resyncs); the value DATA is a pipe-delimited
string containing a Name=... field (the stable, human-meaningful part).

Read-only. Never writes the registry, needles.cfg, needles_local.cfg, or
any flag file. Safe to run anytime, including non-elevated (HKLM read only,
no admin token needed for this particular key).

.PARAMETER Filter
Preview-only wildcard/substring used to narrow this listing. It is NOT the
runtime matcher: haystack_action.ps1 evaluates the generated needle's
RuleNameMatch as a case-insensitive, separator-tolerant literal substring of
the rule's Name= value.

Optional substring (or wildcard) to narrow the Name= field search, e.g.
"WebView2" or "*Teams*". Omit to list ALL MDM firewall rules currently on
the box - useful the first time, when you don't yet know the exact name.

.PARAMETER IntervalHours
Interval to embed in the generated DEFENDER line. Defaults to 6.

.PARAMETER Label
Needle label to embed in the generated line. If omitted, a <LABEL_HERE>
placeholder is printed instead and you fill it in by hand.

.PARAMETER ExtendedLogging
Value to embed in the 5th field of the generated line (0/1/2/all). Defaults
to 'all' since these rules are low-volume/high-value - the full matched
rule string is worth having in Splunk.

.PARAMETER Raw
Show the full, untruncated pipe-delimited Data string for every match
instead of just the parsed Name=/Action=/Protocol= summary columns.

.EXAMPLE
.\New-DefenderNeedlePreview.ps1
List every MDM firewall rule currently present on this endpoint - use this
first when you don't know the exact rule name yet.

.EXAMPLE
.\New-DefenderNeedlePreview.ps1 -Filter "WebView2"
Find the WebView2 rule specifically and see its full detail.

.EXAMPLE
.\New-DefenderNeedlePreview.ps1 -Filter "WebView2" -Label WebView2_FW_Allow -IntervalHours 6
Confirm the rule, then print a ready-to-paste DEFENDER line for needles_local.cfg.

.EXAMPLE
.\New-DefenderNeedlePreview.ps1 -Filter "WebView2" -Raw
Full raw Data string for the match - useful when the summary columns don't
show the field you care about (e.g. a specific RPort or RA4 range).
#>

[CmdletBinding()]
param(
    [string]$Filter,
    [int]$IntervalHours = 6,
    [string]$Label,
    [ValidateSet('0','1','2','all')]
    [string]$ExtendedLogging = 'all',
    [switch]$Raw
)

$DefenderFwRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\FirewallRules'

function Parse-FwRuleData {
    # Pulls a handful of human-useful fields out of the pipe-delimited Data
    # string for the summary table. Best-effort - fields not present are
    # left blank, this is a preview tool, not a strict schema parser.
    param([string]$Data)

    $get = {
        param($pattern)
        if ($Data -match $pattern) { return $Matches[1] }
        return ''
    }

    [pscustomobject]@{
        Name     = & $get 'Name=([^|]*)'
        Action   = & $get 'Action=([^|]*)'
        Dir      = & $get 'Dir=([^|]*)'
        Protocol = & $get 'Protocol=([^|]*)'
        Active   = & $get 'Active=([^|]*)'
        App      = & $get 'App=([^|]*)'
    }
}

if (-not (Test-Path -LiteralPath $DefenderFwRegPath)) {
    Write-Host "Registry path not found: $DefenderFwRegPath" -ForegroundColor Yellow
    Write-Host "No MDM-delivered firewall rules on this box - either policy hasn't synced yet," -ForegroundColor Yellow
    Write-Host "or this endpoint isn't enrolled in the Defender MDM channel." -ForegroundColor Yellow
    exit 1
}

try {
    $item       = Get-Item -LiteralPath $DefenderFwRegPath -ErrorAction Stop
    $valueNames = $item.GetValueNames()
} catch {
    Write-Host "Failed to read '$DefenderFwRegPath': $_" -ForegroundColor Red
    exit 2
}

if ($valueNames.Count -eq 0) {
    Write-Host "Key exists but contains no values - no MDM firewall rules currently present." -ForegroundColor Yellow
    exit 1
}

$rows = foreach ($vName in $valueNames) {
    $data = $item.GetValue($vName)
    $parsed = Parse-FwRuleData -Data $data
    [pscustomobject]@{
        ValueName = $vName
        Name      = $parsed.Name
        Action    = $parsed.Action
        Dir       = $parsed.Dir
        Protocol  = $parsed.Protocol
        Active    = $parsed.Active
        App       = $parsed.App
        Data      = $data
    }
}

if ($Filter) {
    $rows = $rows | Where-Object { $_.Name -like "*$Filter*" -or $_.ValueName -like "*$Filter*" }
}

if (-not $rows -or @($rows).Count -eq 0) {
    Write-Host "No MDM firewall rules matched filter '$Filter'." -ForegroundColor Yellow
    Write-Host "Run with no -Filter to see the full list of $($valueNames.Count) rule(s) on this box." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "=== MDM Firewall Rules$(if ($Filter) { " matching '$Filter'" }) - $(@($rows).Count) found ===" -ForegroundColor Cyan
Write-Host ""

if ($Raw) {
    foreach ($r in $rows) {
        Write-Host "ValueName: $($r.ValueName)" -ForegroundColor Green
        Write-Host "Data:      $($r.Data)"
        Write-Host ""
    }
} else {
    $rows | Select-Object Name, Action, Dir, Protocol, Active, App, @{N='ValueName';E={$_.ValueName.Substring(0, [Math]::Min(20, $_.ValueName.Length)) + '...'}} |
        Format-Table -AutoSize
}

# Only emit a ready-to-paste line when the filter resolved to exactly one
# rule - otherwise it's ambiguous which Name= substring to lock the needle to.
#
# NOTE (fixed in 1.0.1): Select-Object -Unique collapses a single-element
# result to a bare scalar string, not a 1-element array. Wrapping in @(...)
# forces array context so $uniqueNames[0] always indexes the array element
# (the full rule name) rather than character-indexing into the string.
$uniqueNames = @($rows | Select-Object -ExpandProperty Name -Unique)

if (@($rows).Count -eq 1 -or $uniqueNames.Count -eq 1) {
    $ruleNameForNeedle = $uniqueNames[0]
    if ([string]::IsNullOrWhiteSpace($ruleNameForNeedle)) { $ruleNameForNeedle = $Filter }

    $labelForNeedle = if ($Label) { $Label } else { '<LABEL_HERE>' }

    Write-Host ""
    Write-Host "=== Generated DEFENDER needle line ===" -ForegroundColor Cyan
    Write-Host "DEFENDER|$ruleNameForNeedle|$IntervalHours|$labelForNeedle|$ExtendedLogging"
    Write-Host ""
    Write-Host "Paste into needles_local.cfg to test, then promote to needles.cfg (NETLOGON share) once confirmed." -ForegroundColor DarkGray
    Write-Host "Matching at runtime is literal (never regex), case-insensitive and separator-tolerant:" -ForegroundColor DarkGray
    Write-Host "spaces, - _ / . and repeated whitespace are normalized away before the substring test," -ForegroundColor DarkGray
    Write-Host "so punctuation changes by the Defender team will not cause a false MISSING. Prefer a" -ForegroundColor DarkGray
    Write-Host "distinctive, stable descriptive substring - short/generic values can match unrelated rules." -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "Multiple distinct rule names matched - narrow -Filter to generate a single needle line." -ForegroundColor Yellow
}
