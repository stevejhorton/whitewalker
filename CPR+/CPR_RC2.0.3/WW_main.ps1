# CPR+ v3.14.0_RC2.0.3 - WW_main.ps1 (keep in sync with $ver in main\Main.Configuration.ps1; a test enforces it)
#Requires -RunAsAdministrator
param(
  [switch]$WWDebug,
  [switch]$WWTrace,
  [switch]$WhatIf
)

<#
  White Walker CPR RC2 experimental decomposition line.
  Version: 3.14.0_RC2.0.3 (see line 1; the log prints the same version and a build= fingerprint)
  Seeded from CPR_3.14_RC1.25; behavior is intended to remain unchanged.

  Dot-source order is significant: configuration and shared utilities load first,
  followed by state/flare/network/captive-portal/VPN/SSID/update libraries, then
  the orchestration entry.
#>

# Runtime helper scripts remain top-level in this phase.
. "C:\ProgramData\WhiteWalker\WW_csc_client_info.ps1"
. "C:\ProgramData\WhiteWalker\WW_tee.ps1"

$mainRoot = Join-Path $PSScriptRoot 'main'
$mainFiles = @(
  'Main.Common.ps1',
  'Main.Configuration.ps1',
  'Main.Logging.ps1',
  'Main.State.ps1',
  'Main.FlareGun.ps1',
  'Main.Network.ps1',
  'Main.CaptivePortal.ps1',
  'Main.VpnState.ps1',
  'Main.SsidChange.ps1',
  'Main.SelfUpdate.ps1',
  'Main.TeeFlag.ps1',
  'Main.Entry.ps1'
)
foreach ($mainFile in $mainFiles) {
  . (Join-Path $mainRoot $mainFile)
}

if ($MyInvocation.InvocationName -ne '.') {
  Invoke-WhiteWalkerMain
}
