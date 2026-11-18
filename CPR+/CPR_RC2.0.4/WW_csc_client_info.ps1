<#
  WW_csc_client_info.ps1
  Version: 1.0.0
  Author: steve.horton@optum.com (with AI assist)
  Date: 27-Jul-2026

.SYNOPSIS
  Cisco Secure Client version + module inventory helper for WhiteWalker (CPR+) run headers.

.DESCRIPTION
  Dot-sourced by WW_main.ps1. Provides Get-CiscoSecureClientInfo, which returns the
  installed Cisco Secure Client core version plus a full module inventory (VPNCore,
  ISECompliance, DART, Umbrella, NAM, etc.) for inclusion in the main log header.

  Primary source: *Manifest*.xml files under "C:\ProgramData\Cisco\Cisco Secure Client".
  Confirmed schema (from live fleet samples):
    <vpn rev="1.0">
      <file version="5.1.17.3394" id="VPNCore" is_core="yes" type="msi" action="install">
        <uri>binaries/cisco-secure-client-win-5.1.17.3394-core-vpn-webdeploy-k9.msi</uri>
        <display-name>Cisco Secure Client</display-name>
      </file>
    </vpn>

    <vpn rev="1.0">
      <file version="4.3.6087.8192" id="ISECompliance" is_core="no" type="msi"
            action="install" module="isecompliance">
        <uri>binaries/cisco-secure-client-win-4.3.6087.8192-isecompliance-predeploy-k9.msi</uri>
        <display-name>Cisco Secure Client ISE Compliance</display-name>
      </file>
    </vpn>

  is_core="yes" identifies the headline client version; id is the module name; module
  (lowercase slug) is captured for grouping/Splunk if present.

  Fallback source: update.txt single-line version string (used if manifests unavailable,
  or none flag is_core - e.g. very old client / non-standard install).

  Caching / Change Detection:
    Fast path (every run): hash update.txt, compare to cached hash in csc_client_info.json.
      - Hash matches AND cache age < $CscInfoRescanHours -> return cached data, zero manifest I/O.
      - Hash differs, OR cache stale/missing, OR update.txt unreadable -> full manifest rescan,
        cache refreshed with new hash + timestamp.
    This avoids a Get-ChildItem -Recurse + XML parse sweep on every single WW_main run.

  Requires the caller (WW_main.ps1) to already have Write-Log defined (dot-source AFTER
  Write-Log is declared, or ensure Write-Log exists before calling Get-CiscoSecureClientInfo).
  All functions are defensive - if Write-Log isn't available yet, calls are wrapped so they
  won't throw (falls back to silent no-op logging).

.USAGE (from WW_main.ps1)
    . "C:\ProgramData\WhiteWalker\WW_csc_client_info.ps1"
    ...
    $cscInfo = Get-CiscoSecureClientInfo
    Add-LogLine ("csc_version={0}  source={1}" -f $cscInfo.CoreVersion, $cscInfo.Source)
#>

# ------------------------------- Config ---------------------------------------
# Cisco Secure Client version/module inventory (header context)
# Manifest*.xml sweep gives full module list (VPNCore, ISECompliance, DART, Umbrella, NAM, etc.)
# update.txt gives a fast single-line version - used as the change-detection trigger and fallback.
# Full manifest rescan only runs when update.txt hash changes, OR every $CscInfoRescanHours
# as a safety net (catches module add/remove that doesn't touch update.txt).
if (-not (Get-Variable -Name CscInfoEnabled -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CscInfoEnabled          = $true    # set $false to disable entirely (no header lines, zero I/O)
}
if (-not (Get-Variable -Name CscInfoBaseDir -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CscInfoBaseDir          = "C:\ProgramData\Cisco\Cisco Secure Client"
}
if (-not (Get-Variable -Name CscInfoUpdateTxtPath -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CscInfoUpdateTxtPath    = Join-Path $global:CscInfoBaseDir "update.txt"
}
if (-not (Get-Variable -Name CscInfoCacheFile -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CscInfoCacheFile        = "C:\ProgramData\WhiteWalker\csc_client_info.json"
}
if (-not (Get-Variable -Name CscInfoRescanHours -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CscInfoRescanHours      = 12       # safety-net full rescan interval even if update.txt unchanged
}
if (-not (Get-Variable -Name CscInfoLogModulesAlways -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CscInfoLogModulesAlways = $false   # $false = csc_modules= line only under -WWDebug/-WWTrace
}

# ------------------------------- Logging shim ----------------------------------
# If the host script (WW_main.ps1) hasn't defined Write-Log yet, provide a harmless
# fallback so this file can be dot-sourced early without erroring.
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    function Write-Log { param([Parameter(Mandatory=$true)][string]$Message, [string]$Level = "INFO") }
}

function Get-UpdateTxtHash {
    <#
    .SYNOPSIS
    Cheap change-detection signal for the Cisco Secure Client install.
    Hashes update.txt content (not just presence) so a version bump is always caught.
    Returns $null if file missing/unreadable - caller treats that as "force rescan".
    #>
    if (-not (Test-Path $global:CscInfoUpdateTxtPath)) { return $null }
    try {
        $content = Get-Content -Path $global:CscInfoUpdateTxtPath -Raw -ErrorAction Stop
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
        $hashBytes = $sha.ComputeHash($bytes)
        return [System.BitConverter]::ToString($hashBytes).Replace('-','')
    } catch {
        Write-Log "CscInfo: failed to hash update.txt: $_" "DEBUG"
        return $null
    }
}

function Get-CscInfoCache {
    if (Test-Path $global:CscInfoCacheFile) {
        try {
            return Get-Content -Path $global:CscInfoCacheFile -Raw -ErrorAction Stop | ConvertFrom-Json
        } catch {
            Write-Log "CscInfo: cache read/parse failed, forcing rescan: $_" "DEBUG"
            return $null
        }
    }
    return $null
}

function Save-CscInfoCache($obj) {
    try {
        $obj | ConvertTo-Json -Depth 6 | Set-Content -Path $global:CscInfoCacheFile -Encoding UTF8 -Force
    } catch {
        Write-Log "CscInfo: failed to write cache: $_" "WARN"
    }
}

function Invoke-CscManifestScan {
    <#
    .SYNOPSIS
    Full sweep of *Manifest*.xml files under the Secure Client install dir.
    Expensive relative to the hash check - only called on change or rescan interval.
    See file header for confirmed manifest schema. Falls back to update.txt if no
    manifests parse cleanly (or none flag is_core).
    #>
    $result = @{
        CoreVersion = "Unknown"
        Modules     = @()
        Source      = "none"
    }

    try {
        if (Test-Path $global:CscInfoBaseDir) {
            $manifests = Get-ChildItem -Path $global:CscInfoBaseDir -Filter "*Manifest*.xml" -Recurse -ErrorAction SilentlyContinue

            if ($manifests) {
                $result.Source = "manifest"
                $seenIds = @{}   # de-dupe - same manifest is often mirrored across module subfolders

                foreach ($m in $manifests) {
                    try {
                        [xml]$xml = Get-Content -Path $m.FullName -Raw -ErrorAction Stop
                        $fileNodes = $xml.SelectNodes("//file")

                        foreach ($node in $fileNodes) {
                            $id         = $node.GetAttribute("id")
                            $ver        = $node.GetAttribute("version")
                            $isCore     = $node.GetAttribute("is_core")
                            $moduleSlug = $node.GetAttribute("module")   # e.g. "isecompliance"
                            $display    = $node.SelectSingleNode("display-name")
                            $displayName = if ($display) { $display.InnerText } else { $id }

                            if (-not $id) { continue }
                            if ($seenIds.ContainsKey($id)) { continue }
                            $seenIds[$id] = $true

                            $result.Modules += [PSCustomObject]@{
                                Module     = $id
                                ModuleSlug = $(if ($moduleSlug) { $moduleSlug } else { $id.ToLower() })
                                Name       = $displayName
                                Version    = $(if ($ver) { $ver } else { "Unknown" })
                                IsCore     = ($isCore -eq "yes")
                                File       = $m.Name
                            }

                            if ($isCore -eq "yes" -and $ver -and $result.CoreVersion -eq "Unknown") {
                                $result.CoreVersion = $ver
                            }
                        }
                    } catch {
                        Write-Log "CscInfo: failed to parse manifest $($m.FullName): $_" "DEBUG"
                    }
                }
            }
        }

        # Fallback if no manifests found, or none flagged is_core (older client / non-standard schema)
        if ($result.Source -eq "none" -or $result.CoreVersion -eq "Unknown") {
            if (Test-Path $global:CscInfoUpdateTxtPath) {
                try {
                    $line = (Get-Content -Path $global:CscInfoUpdateTxtPath -TotalCount 1 -ErrorAction Stop).Trim()
                    if ($line) {
                        $result.CoreVersion = $line
                        if ($result.Source -eq "none") { $result.Source = "update.txt" }
                    }
                } catch {
                    Write-Log "CscInfo: failed to read update.txt fallback: $_" "DEBUG"
                }
            }
        }
    } catch {
        Write-Log "CscInfo: unexpected error during manifest scan: $_" "DEBUG"
    }

    return $result
}

function Get-CiscoSecureClientInfo {
    <#
    .SYNOPSIS
    Cached, change-detected Cisco Secure Client version + module inventory.

    .DESCRIPTION
    Fast path (every run): hash update.txt, compare to cache.
      - Hash matches + cache age < $CscInfoRescanHours -> return cached data, zero manifest I/O.
      - Hash differs, OR cache stale/missing, OR update.txt unreadable -> full manifest rescan,
        cache refreshed with new hash + timestamp.
    Never throws - always returns a hashtable/object with at least CoreVersion+Source.
    Call this from WW_main.ps1's Write-RunHeader (or anywhere a fresh snapshot is needed).
    #>
    if (-not $global:CscInfoEnabled) {
        return @{ CoreVersion = "disabled"; Modules = @(); Source = "disabled" }
    }

    $currentHash = Get-UpdateTxtHash
    $cache = Get-CscInfoCache

    $needsRescan = $true
    if ($cache -and $currentHash) {
        $hashMatches = ($cache.updateTxtHash -eq $currentHash)
        $ageHours = 999
        try { $ageHours = ((Get-Date) - [datetime]::Parse($cache.lastFullScanTime)).TotalHours } catch { }

        if ($hashMatches -and ($ageHours -lt $global:CscInfoRescanHours)) {
            Write-Log ("CscInfo: cache hit (hash match, {0}h old) - skipping manifest scan" -f [math]::Round($ageHours,1)) "DEBUG"
            $needsRescan = $false
        } elseif (-not $hashMatches) {
            Write-Log "CscInfo: update.txt changed since last scan - forcing manifest rescan" "INFO"
        } else {
            Write-Log ("CscInfo: cache stale ({0}h old, limit {1}h) - forcing manifest rescan" -f [math]::Round($ageHours,1), $global:CscInfoRescanHours) "INFO"
        }
    } else {
        Write-Log "CscInfo: no usable cache or update.txt unreadable - forcing manifest rescan" "INFO"
    }

    if (-not $needsRescan) {
        return @{
            CoreVersion = $cache.coreVersion
            Modules     = @($cache.modules)
            Source      = "$($cache.source) (cached)"
        }
    }

    $fresh = Invoke-CscManifestScan
    $cacheObj = [PSCustomObject]@{
        updateTxtHash    = $currentHash
        lastFullScanTime = (Get-Date).ToString('o')
        coreVersion      = $fresh.CoreVersion
        modules          = $fresh.Modules
        source           = $fresh.Source
    }
    Save-CscInfoCache $cacheObj

    return $fresh
}
