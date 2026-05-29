[CmdletBinding()]
param(
  [switch]$add,
  [switch]$rm
)

$hostsPath = Join-Path $env:WINDIR "System32\drivers\etc\hosts"
$ip = "127.0.0.1"

$beginMarker = "# BEGIN OptumUHG corpvpnsvcs sinkhole (managed)"
$endMarker   = "# END OptumUHG corpvpnsvcs sinkhole (managed)"

$Hostnames = @(
  "vpn.bc.corpvpnsvcs.com"
  "mn.bc.corpvpnsvcs.com"
  "ctc.bc.corpvpnsvcs.com"
  "ctc-21.bc.corpvpnsvcs.com"
  "ctc-22.bc.corpvpnsvcs.com"
  "ctc-23.bc.corpvpnsvcs.com"
  "ctc-24.bc.corpvpnsvcs.com"
  "ctc-25.bc.corpvpnsvcs.com"
  "ctc-26.bc.corpvpnsvcs.com"
  "ctc-27.bc.corpvpnsvcs.com"
  "elr.bc.corpvpnsvcs.com"
  "elr-21.bc.corpvpnsvcs.com"
  "elr-22.bc.corpvpnsvcs.com"
  "elr-23.bc.corpvpnsvcs.com"
  "elr-24.bc.corpvpnsvcs.com"
  "elr-25.bc.corpvpnsvcs.com"
  "elr-26.bc.corpvpnsvcs.com"
  "elr-27.bc.corpvpnsvcs.com"
  "ply.bc.corpvpnsvcs.com"
  "ply-21.bc.corpvpnsvcs.com"
  "ply-22.bc.corpvpnsvcs.com"
  "ply-23.bc.corpvpnsvcs.com"
  "ply-24.bc.corpvpnsvcs.com"
  "ply-25.bc.corpvpnsvcs.com"
  "ply-26.bc.corpvpnsvcs.com"
  "ply-27.bc.corpvpnsvcs.com"
  "ii757-1.bc.corpvpnsvcs.com"
  "ii757-2.bc.corpvpnsvcs.com"
  "ii747-1.bc.corpvpnsvcs.com"
  "ii747-2.bc.corpvpnsvcs.com"
  "ir777-1.bc.corpvpnsvcs.com"
  "ir777-2.bc.corpvpnsvcs.com"
  "ii550-1.bc.corpvpnsvcs.com"
  "ii550-2.bc.corpvpnsvcs.com"
  "ii554-1.bc.corpvpnsvcs.com"
  "ii554-2.bc.corpvpnsvcs.com"
  "ph518-1.bc.corpvpnsvcs.com"
  "ph518-2.bc.corpvpnsvcs.com"
)

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-ManagedBlock([string[]]$lines) {
  $out = New-Object System.Collections.Generic.List[string]
  $inBlock = $false

  foreach ($line in $lines) {
    if ($line -eq $beginMarker) { $inBlock = $true; continue }
    if ($line -eq $endMarker)   { $inBlock = $false; continue }
    if (-not $inBlock) { [void]$out.Add($line) }
  }

  return ,$out.ToArray()
}

function Write-HostsFileAtomic([string]$path, [string[]]$content) {
  # Preserve original attributes if possible
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  $originalAttributes = $item.Attributes

  # If read-only, clear it so replace/write succeeds
  if ($item.Attributes -band [IO.FileAttributes]::ReadOnly) {
    $item.Attributes = ($item.Attributes -bxor [IO.FileAttributes]::ReadOnly)
  }

  $tmp = Join-Path ([IO.Path]::GetDirectoryName($path)) ("hosts.tmp.{0}" -f ([guid]::NewGuid().ToString("N")))

  try {
    # Write temp file first
    Set-Content -LiteralPath $tmp -Value $content -Encoding ASCII -Force

    # Replace (more reliable than writing in-place)
    Move-Item -LiteralPath $tmp -Destination $path -Force
  }
  finally {
    # Clean up tmp if something failed before Move-Item
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

    # Best-effort: restore attributes (including ReadOnly if it was set)
    try {
      (Get-Item -LiteralPath $path -Force).Attributes = $originalAttributes
    } catch { }
  }
}

if (($add -and $rm) -or (-not $add -and -not $rm)) { throw "Specify exactly one flag: -add OR -rm" }
if (-not (Test-IsAdmin)) { throw "Run elevated as Administrator to modify: $hostsPath" }
if (-not (Test-Path -LiteralPath $hostsPath)) { throw "Hosts file not found at: $hostsPath" }

$lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop

if ($rm) {
  $filtered = Remove-ManagedBlock -lines $lines
  if ($filtered.Count -ne $lines.Count) {
    Write-HostsFileAtomic -path $hostsPath -content $filtered
    Write-Host "Removed managed corpvpnsvcs sinkhole block from hosts."
  } else {
    Write-Host "No managed corpvpnsvcs sinkhole block found (nothing to remove)."
  }
  exit 0
}

if ($add) {
  $filtered = Remove-ManagedBlock -lines $lines

  if ($filtered.Count -gt 0 -and $filtered[-1].Trim().Length -ne 0) {
    $filtered += ""
  }

  $block = New-Object System.Collections.Generic.List[string]
  [void]$block.Add($beginMarker)
  foreach ($h in $Hostnames) {
    [void]$block.Add(("{0}`t{1}`t# managed" -f $ip, $h))
  }
  [void]$block.Add($endMarker)

  $newContent = $filtered + $block.ToArray()

  Write-HostsFileAtomic -path $hostsPath -content $newContent
  Write-Host "Added/updated managed corpvpnsvcs sinkhole block with $($Hostnames.Count) entries."
}
