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
$script:StateFlares = @('on_prem','user_tun','mgmt_tun','off_prem_no_vpn','captive_portal','no_net_transient','vpn_connecting','cpr_error')

# ---- Exit convention: exit_reason = <reason>:<state> (docs/EXIT_REASON_AND_FLARE_DESIGN.md) ----
# <state> is the connection path at exit and is the same word as the state flare sent for it.
# A <reason> never contains a state word. Every run ends with exactly one state flare.
$script:CprExitStates = @('on_prem','user_tun','mgmt_tun','off_prem_no_vpn','vpn_connecting','captive_portal','no_net_transient','cpr_error')

function Get-CprExitType {
  # Live connection path now (never state.json): tunnel flavor -> on_prem (DC reachable AND trusted path) -> off_prem_no_vpn.
  # Fail-soft: anything that throws or is unknown resolves to off_prem_no_vpn.
  param($NetworkInfo)
  try {
    $f = Get-VpnTunnelFlavor
    if ($f -eq 'user_tun' -or $f -eq 'mgmt_tun') { return $f }
  } catch { }
  try {
    if ($NetworkInfo -and (Test-DC -hostname $DC_FQDN) -and (Test-SsidTrusted -NetworkInfo $NetworkInfo)) { return 'on_prem' }
  } catch { }
  return 'off_prem_no_vpn'
}

function Set-CprRunExit {
  # The ONLY place $script:exitReason is assigned (a Pester scan enforces this).
  # -State omitted => derived from the live path (ISE / remediation exits).
  param(
    [Parameter(Mandatory)][string]$Reason,
    [string]$State,
    $NetworkInfo
  )
  if ($Reason -match ':') { $Reason = ($Reason -split ':')[0] }
  if (-not $State) { $State = Get-CprExitType -NetworkInfo $NetworkInfo }
  if ($State -notin $script:CprExitStates) { $State = 'cpr_error' }
  $script:exitReason = "${Reason}:${State}"
}

function Get-CprExitState([string]$ExitReason) {
  # State part of an exit reason (text after the LAST colon), or '' when absent/unknown.
  if (-not $ExitReason -or $ExitReason -notmatch ':') { return '' }
  $st = ($ExitReason -split ':')[-1]
  if ($st -in $script:CprExitStates) { return $st }
  return ''
}

function Get-CprExitReasonPart([string]$ExitReason) {
  # Reason part (before the first colon of the reason:state pair).
  if (-not $ExitReason) { return '' }
  return ($ExitReason -split ':')[0]
}

function Send-CprExitFlare {
  # Called once from the run's finally block. Send-FlareEvent already de-dupes per tag per run.
  param([string]$ExitReason)
  $st = Get-CprExitState $ExitReason
  if (-not $st) { return }
  try { Send-FlareEvent $st } catch { Write-Log "exit flare '$st' failed: $_" "WARN" }
}

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

