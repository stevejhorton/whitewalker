# CPR RC2 shared primitives.
# Depends on: nothing. This file MUST load first so every later library (and
# any path that dot-sources only part of the tree) can rely on these helpers.
#
# RC2.2 (Required B). Live evidence from xfinitywifi:
#
#   [ERROR] Error in main execution: Method invocation failed because
#   [System.Collections.Specialized.OrderedDictionary] does not contain a
#   method named 'ContainsKey'.
#
# [ordered]@{} produces a System.Collections.Specialized.OrderedDictionary,
# which implements the NON-generic IDictionary: it has Contains(), not
# ContainsKey(). A plain @{} (Hashtable) has both. Code that probes a map it
# did not build therefore cannot safely call .ContainsKey(). Rather than
# scattering type checks, every such probe goes through these two helpers.

function Test-CprMapKey {
    <#
    .SYNOPSIS
    Safe "does this map contain this key" test for ANY dictionary shape.

    .DESCRIPTION
    Accepts Hashtable, [ordered]@{} (OrderedDictionary), any other
    IDictionary, or a PSCustomObject (as produced by ConvertFrom-Json), and
    returns $true/$false without ever throwing. A $null map or a $null/empty
    key is simply $false.
    #>
    param(
        $Map,
        [string]$Key
    )

    if ($null -eq $Map -or [string]::IsNullOrEmpty($Key)) { return $false }

    try {
        if ($Map -is [System.Collections.IDictionary]) {
            # IDictionary.Contains() exists on Hashtable AND OrderedDictionary.
            return [bool]$Map.Contains($Key)
        }
        if ($Map -is [System.Management.Automation.PSObject] -or $Map.PSObject) {
            return (@($Map.PSObject.Properties.Name) -contains $Key)
        }
    } catch { }

    return $false
}

function Get-CprMapValue {
    <#
    .SYNOPSIS
    Safe value read for ANY dictionary shape, with a default when the key is
    absent or its value is $null.
    #>
    param(
        $Map,
        [string]$Key,
        $Default = $null
    )

    if (-not (Test-CprMapKey -Map $Map -Key $Key)) { return $Default }

    try {
        $value = if ($Map -is [System.Collections.IDictionary]) { $Map[$Key] } else { $Map.$Key }
        if ($null -eq $value) { return $Default }
        return $value
    } catch {
        return $Default
    }
}
