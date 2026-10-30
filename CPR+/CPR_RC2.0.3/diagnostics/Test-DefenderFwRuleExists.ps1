<#
.SYNOPSIS
Checks for existence of a specific MDM-delivered Windows Firewall rule in
the registry (the rules Intune/MDM pushes land here, NOT in the normal
Get-NetFirewallRule GPO store).

.DESCRIPTION
Version: 1.0.1
Author: steve.horton@optum.com
Date: 05-Oct-2026

Changes in 1.0.1:
  - -RuleNameMatch now uses the same case-insensitive, separator-tolerant
    normalized substring match as the runtime DEFENDER needle check, so this
    diagnostic and haystack_action.ps1 can never disagree.

Reads:
  HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\FirewallRules

Each value under this key is one firewall rule, named with a GUID_suffix
pattern (e.g. "bb936b3f1fd54e3db4a911ff6897d1f2_hAMAAA") and a pipe-delimited
data string (e.g. "v2.32|Action=Allow|...|Name=V2 - MsWebView2|...").

This is read-only. It never writes the registry, never calls
Set-NetFirewallRule, and is safe to run as a HayStack needle companion
check or standalone diagnostic.

.PARAMETER RuleNameMatch
Literal substring to match against the rule's Name= field (e.g. "MsWebView2").
This is usually the most stable identifier since the value NAME (GUID_suffix)
can change between policy syncs/reissues.

Matching mirrors haystack_action.ps1's DEFENDER needle check: case-insensitive
and separator-tolerant (both sides are lowercased and stripped of every
non-alphanumeric character), so "V2 - MsWebView2 Any Out" matches a deployed
rule named "V2-MsWebView2 Any Out". The value is literal text, never a regex.
Because separators are removed, prefer a distinctive, stable, descriptive
substring - very short or generic values can collide with unrelated rules.

.PARAMETER ValueNameMatch
Optional. Exact or wildcard match against the registry VALUE NAME itself
(the "bb936b3f1fd54e3db4a911ff6897d1f2_hAMAAA" part), if you know it and
expect it to be stable. Supports * wildcards.

.PARAMETER Quiet
Suppress console output. Only sets $LASTEXITCODE / return value. Useful
when called from haystack_action.ps1 or another automation wrapper.

.OUTPUTS
Boolean ($true/$false) via exit code (0 = found, 1 = not found, 2 = error)
and via pipeline (PSCustomObject with Found/MatchedValueName/MatchedData).

.EXAMPLE
.\Test-DefenderFwRuleExists.ps1 -RuleNameMatch "MsWebView2"
Find the MDM firewall rule for MsWebView2 by its friendly Name= field.

.EXAMPLE
.\Test-DefenderFwRuleExists.ps1 -ValueNameMatch "bb936b3f1fd54e3db4a911ff6897d1f2_hAMAAA"
Find by the exact registry value name (GUID-based), if you already captured it.

.EXAMPLE
.\Test-DefenderFwRuleExists.ps1 -RuleNameMatch "MsWebView2" -Quiet; $LASTEXITCODE
Silent check for use in scripted/CI contexts - 0 = present, 1 = missing.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$RuleNameMatch,

    [Parameter()]
    [string]$ValueNameMatch,

    [switch]$Quiet
)

$RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\FirewallRules'

# Keep identical to ConvertTo-DefenderRuleNameKey / Test-DefenderRuleNameMatch
# in haystack_action.ps1 and haystack.ps1 so this diagnostic and the runtime
# check always agree about what "present" means.
function ConvertTo-DefenderRuleNameKey {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return [regex]::Replace($Text.ToLowerInvariant(), '[^\p{L}\p{Nd}]', '')
}

function Test-DefenderRuleNameMatch {
    param([string]$RuleName, [string]$RuleNameMatch)

    $needleKey = ConvertTo-DefenderRuleNameKey -Text $RuleNameMatch
    if (-not $needleKey) { return $false }

    $ruleKey = ConvertTo-DefenderRuleNameKey -Text $RuleName
    if (-not $ruleKey) { return $false }

    return $ruleKey.Contains($needleKey)
}

function Write-Out {
    param([string]$Message, [string]$Level = 'INFO')
    if ($Quiet) { return }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "$ts [$Level] $Message"
}

if (-not $RuleNameMatch -and -not $ValueNameMatch) {
    Write-Out "Must supply -RuleNameMatch or -ValueNameMatch." 'ERROR'
    exit 2
}

if ($RuleNameMatch -and -not (ConvertTo-DefenderRuleNameKey -Text $RuleNameMatch)) {
    Write-Out "-RuleNameMatch '$RuleNameMatch' contains no letters or digits - refusing to match everything." 'ERROR'
    exit 2
}

if (-not (Test-Path -LiteralPath $RegPath)) {
    Write-Out "Registry path not found: $RegPath (no MDM firewall rules on this box, or Defender MDM channel not in use)" 'WARN'
    [PSCustomObject]@{ Found = $false; MatchedValueName = $null; MatchedData = $null }
    exit 1
}

try {
    $item = Get-Item -LiteralPath $RegPath -ErrorAction Stop
    $valueNames = $item.GetValueNames()
} catch {
    Write-Out "Failed to read registry key '$RegPath': $_" 'ERROR'
    exit 2
}

$match = $null

foreach ($vName in $valueNames) {
    if ($ValueNameMatch -and ($vName -like $ValueNameMatch)) {
        $match = $vName
        break
    }
    if ($RuleNameMatch) {
        $data = [string]$item.GetValue($vName)
        $nameMatch = [regex]::Match($data, '(?:^|\|)Name=([^|]*)')
        if ($nameMatch.Success -and (Test-DefenderRuleNameMatch -RuleName $nameMatch.Groups[1].Value -RuleNameMatch $RuleNameMatch)) {
            $match = $vName
            break
        }
    }
}

if ($match) {
    $matchedData = $item.GetValue($match)
    Write-Out "FOUND: ValueName='$match'" 'INFO'
    Write-Out "Data: $matchedData" 'DEBUG'
    [PSCustomObject]@{ Found = $true; MatchedValueName = $match; MatchedData = $matchedData }
    exit 0
} else {
    $criteria = if ($RuleNameMatch) { "RuleNameMatch='$RuleNameMatch'" } else { "ValueNameMatch='$ValueNameMatch'" }
    Write-Out "NOT FOUND: no rule matched $criteria under $RegPath (checked $($valueNames.Count) values)" 'WARN'
    [PSCustomObject]@{ Found = $false; MatchedValueName = $null; MatchedData = $null }
    exit 1
}
