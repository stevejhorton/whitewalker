# CPR RC2 state, cooldown, and flare-stamp utilities.
# Depends on: Main.Configuration.ps1 for state paths and cooldown settings.

# ----------------------- Utility: State & Cooldowns ---------------------------
if (-not (Test-Path $StateRoot)) { New-Item -Path $StateRoot -ItemType Directory -Force | Out-Null }

function Rescan-InCooldown {
    return In-Cooldown 'rescan' $RescanCooldownMinutes
}

function To-Hashtable($obj) {
  if ($null -eq $obj) { return $null }
  if ($obj -is [System.Collections.IDictionary]) { return $obj }
  if ($obj -is [System.Management.Automation.PSCustomObject]) {
    $ht = @{}
    foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = To-Hashtable $p.Value }
    return $ht
  }
  if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
    $arr = @()
    foreach ($i in $obj) { $arr += ,(To-Hashtable $i) }
    return $arr
  }
  return $obj
}

function Get-State {
  if (Test-Path $StateFile) {
    try {
      $s = Get-Content $StateFile -Raw | ConvertFrom-Json
      if ($s.lastFlare) { $s.lastFlare = To-Hashtable $s.lastFlare }
      return $s
    } catch { }
  }
  [PSCustomObject]@{ lastFlare = @{}; lastRescan = '' }
}
function Save-State($obj) {
  try { $obj | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8 } catch { }
}
$global:_state = Get-State

# per-run de-dupe (ensure hashtable)
if (-not ($global:flareHistory -is [hashtable])) { $global:flareHistory = @{} } else { $global:flareHistory.Clear() }

function In-Cooldown([string]$key, [int]$minutes) {
  try {
    if (-not $global:_state.lastFlare) { return $false }
    if (-not ($global:_state.lastFlare -is [hashtable])) { $global:_state.lastFlare = To-Hashtable $global:_state.lastFlare }
    $stamp = $global:_state.lastFlare[$key]
    if (-not $stamp) { return $false }
    $when = [datetime]::Parse($stamp)
    return ((Get-Date) -lt $when.AddMinutes($minutes))
  } catch { return $false }
}
# Network state flares - these update currentState in state.json.
# Action flares (e.g. captive_portal_browser) do NOT update currentState.
$script:StateFlares = @('on_prem','user_tun','mgmt_tun','off_prem_no_vpn','captive_portal','off_prem_untrusted_ssid')

function Set-FlareStamp([string]$key) {
  if (-not $global:_state.lastFlare) {
    $global:_state | Add-Member -NotePropertyName lastFlare -NotePropertyValue @{} -Force
  } elseif (-not ($global:_state.lastFlare -is [hashtable])) {
    $global:_state.lastFlare = To-Hashtable $global:_state.lastFlare
  }
  $global:_state.lastFlare[$key] = (Get-Date).ToString('o')

  # Update currentState for state-determining flares only
  if ($script:StateFlares -contains $key) {
    if (-not ($global:_state.PSObject.Properties.Name -contains 'currentState')) {
      $global:_state | Add-Member -NotePropertyName currentState -NotePropertyValue '' -Force
      $global:_state | Add-Member -NotePropertyName currentStateTime -NotePropertyValue '' -Force
    }
    $global:_state.currentState     = $key
    $global:_state.currentStateTime = (Get-Date).ToString('o')
    Write-Log "State: currentState updated to '$key'" "DEBUG"
  }

  Save-State $global:_state
}

