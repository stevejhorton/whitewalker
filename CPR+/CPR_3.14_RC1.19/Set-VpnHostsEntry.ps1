#Requires -RunAsAdministrator
<#
.SYNOPSIS
  VPN Headend Sinkhole Manager
  Version: 2.0.2
  Author: steve.horton@optum.com
  Date: 09-Apr-2026

.DESCRIPTION
  Adds or removes 127.0.0.1 sinkhole entries for all corp VPN headend FQDNs
  in the Windows hosts file. Called by WW_main.ps1 via CPR framework.

  -add : Sync config from DC share if cache is stale, then check AD allow groups.
         Members of any allow group are exempt - flag removed, exits clean.
         All others get sinkhole entries applied.
  -rm  : Remove sinkhole block unconditionally. No sync, no group check.

  Config files live on DC share and are cached locally.
  Version header + AES256 hash comparison prevents unnecessary pulls.
  This script is fully independent of WW_main.ps1.

  Config file format (first line is version, remaining lines are entries):
    version:09Apr26
    entry1
    entry2
    ...

  v2.0.1 fixes: atomic hosts write (Move-Item -> File::Replace), notification ArgumentList pipe escaping
  v2.0.2 fixes: swap File::Replace for Copy-Item+Delete - Replace() rejects Join-Path resolved paths
#>

[CmdletBinding()]
param(
    [switch]$add,
    [switch]$rm
)

# =============================================================================
# Configuration - change these vars, not the logic below
# =============================================================================

# How long to trust the local cache before re-checking the DC share (hours)
$max_cache_hrs = 24

# DC share containing the config files
$RemoteConfigDir = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN\CPR"

# Remote config file names
$RemoteAllowGroupsFile  = Join-Path $RemoteConfigDir "allowgroups.cfg"
$RemoteHostsSinkFile    = Join-Path $RemoteConfigDir "hostsinkhole.cfg"

# Local cache paths
$LocalCacheDir          = "C:\ProgramData\WhiteWalker"
$LocalAllowGroupsFile   = Join-Path $LocalCacheDir "allowgroups.cfg"
$LocalHostsSinkFile     = Join-Path $LocalCacheDir "hostsinkhole.cfg"
$SyncFlagFile           = Join-Path $LocalCacheDir "blackhole_sync.flag"

# Flag file to remove if user is exempt (keeps WW_main state clean)
$BlackholeFlagFile      = Join-Path $LocalCacheDir "vpn_blocked.flag"

# Log file
$LogFile                = Join-Path $LocalCacheDir "Set-VpnHostsEntry.log"

# Hosts file
$HostsPath              = Join-Path $env:WINDIR "System32\drivers\etc\hosts"

# Sinkhole IP
$SinkholeIP             = "127.0.0.1"

# Block markers
$BeginMarker            = "# BEGIN OptumUHG corpvpnsvcs sinkhole (managed)"
$EndMarker              = "# END OptumUHG corpvpnsvcs sinkhole (managed)"

# Hardcoded fallbacks - used ONLY if local cache is missing/corrupt AND share unreachable
$FallbackAllowGroups = @(
    "on_prem_vpn_allow"
)

$FallbackHostnames = @(
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

# =============================================================================
# Logging
# =============================================================================
function Write-SVLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts [$Level] [Set-VpnHostsEntry] $Message"
    Write-Host $line
    try {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

# =============================================================================
# Config Sync
# =============================================================================
function Get-FileVersion {
    # Reads the version: line from a config file. Returns $null if not found.
    param([string]$Path)
    try {
        $firstLine = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
        if ($firstLine -match '^version:(.+)$') {
            return $matches[1].Trim()
        }
    } catch { }
    return $null
}

function Get-FileHashSHA256 {
    param([string]$Path)
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Sync-ConfigFile {
    # Syncs a single config file from remote to local.
    # Returns $true if local file is good to use (synced or already current).
    param(
        [string]$RemotePath,
        [string]$LocalPath
    )

    # Does remote file exist?
    if (-not (Test-Path -LiteralPath $RemotePath)) {
        Write-SVLog "Remote config not found: $RemotePath - using local cache" "WARN"
        return (Test-Path -LiteralPath $LocalPath)
    }

    # Compare versions first (fast check)
    $remoteVersion = Get-FileVersion -Path $RemotePath
    $localVersion  = Get-FileVersion -Path $LocalPath

    Write-SVLog "$(Split-Path $LocalPath -Leaf) - local:$localVersion remote:$remoteVersion" "DEBUG"

    if ($remoteVersion -and $localVersion -and ($remoteVersion -eq $localVersion)) {
        Write-SVLog "$(Split-Path $LocalPath -Leaf) version match ($remoteVersion) - no pull needed" "DEBUG"
        return $true
    }

    # Version mismatch (or one is missing) - hash compare to confirm actual difference
    $remoteHash = Get-FileHashSHA256 -Path $RemotePath
    $localHash  = Get-FileHashSHA256 -Path $LocalPath

    if ($remoteHash -and $localHash -and ($remoteHash -eq $localHash)) {
        Write-SVLog "$(Split-Path $LocalPath -Leaf) hash match - no pull needed (version tag drifted)" "DEBUG"
        return $true
    }

    # Hashes differ or local missing - pull the file
    try {
        Copy-Item -LiteralPath $RemotePath -Destination $LocalPath -Force -ErrorAction Stop
        Write-SVLog "$(Split-Path $LocalPath -Leaf) updated from share (remote version: $remoteVersion)" "INFO"
        return $true
    } catch {
        Write-SVLog "Failed to pull $(Split-Path $LocalPath -Leaf) from share: $_" "WARN"
        return (Test-Path -LiteralPath $LocalPath)  # Fall back to whatever local we have
    }
}

function Invoke-ConfigSync {
    # Checks cache age and syncs both config files if stale.
    # Only runs on -add. Skipped entirely on -rm.

    # Check sync flag age
    if (Test-Path $SyncFlagFile) {
        try {
            $lastSync = [datetime]::Parse((Get-Content $SyncFlagFile -Raw).Trim())
            $ageHours = ((Get-Date) - $lastSync).TotalHours
            if ($ageHours -lt $max_cache_hrs) {
                Write-SVLog "Config cache fresh ($([math]::Round($ageHours,1))h old, max ${max_cache_hrs}h) - skipping sync" "DEBUG"
                return
            }
            Write-SVLog "Config cache stale ($([math]::Round($ageHours,1))h old) - syncing from share" "INFO"
        } catch {
            Write-SVLog "Could not read sync flag - forcing sync" "WARN"
        }
    } else {
        Write-SVLog "No sync flag found - first run, syncing from share" "INFO"
    }

    # Check share reachability before attempting copies
    if (-not (Test-Path -LiteralPath $RemoteConfigDir)) {
        Write-SVLog "DC share unreachable: $RemoteConfigDir - using local cache" "WARN"
        return
    }

    # Sync both files
    $agOK = Sync-ConfigFile -RemotePath $RemoteAllowGroupsFile -LocalPath $LocalAllowGroupsFile
    $hsOK = Sync-ConfigFile -RemotePath $RemoteHostsSinkFile   -LocalPath $LocalHostsSinkFile

    # Update sync flag regardless (prevents hammering the share on every run if one file is missing)
    try {
        Set-Content -Path $SyncFlagFile -Value (Get-Date).ToString('o') -Encoding UTF8 -Force
        Write-SVLog "Sync flag updated" "DEBUG"
    } catch {
        Write-SVLog "Could not update sync flag: $_" "WARN"
    }

    if ($agOK -and $hsOK) {
        Write-SVLog "Config sync complete" "INFO"
    } else {
        Write-SVLog "Config sync partial - one or more files using local cache" "WARN"
    }
}

# =============================================================================
# Config Loader
# =============================================================================
function Read-ConfigFile {
    # Reads a config file, skipping the version: line and blank/comment lines.
    # Returns array of entries, or $null if file unreadable.
    param([string]$Path)
    try {
        $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
        return @($lines | Where-Object {
            $_ -notmatch '^version:' -and
            $_.Trim().Length -gt 0 -and
            -not $_.TrimStart().StartsWith('#')
        })
    } catch {
        Write-SVLog "Could not read config file $Path : $_" "WARN"
        return $null
    }
}

function Get-AllowGroups {
    $entries = Read-ConfigFile -Path $LocalAllowGroupsFile
    if ($entries -and $entries.Count -gt 0) {
        Write-SVLog "Loaded $($entries.Count) allow group(s) from local cache" "DEBUG"
        return $entries
    }
    Write-SVLog "Using fallback allow groups ($($FallbackAllowGroups.Count) entries)" "WARN"
    return $FallbackAllowGroups
}

function Get-SinkholeHostnames {
    $entries = Read-ConfigFile -Path $LocalHostsSinkFile
    if ($entries -and $entries.Count -gt 0) {
        Write-SVLog "Loaded $($entries.Count) sinkhole hostname(s) from local cache" "DEBUG"
        return $entries
    }
    Write-SVLog "Using fallback sinkhole hostnames ($($FallbackHostnames.Count) entries)" "WARN"
    return $FallbackHostnames
}

# =============================================================================
# AD Group Membership Check
# =============================================================================
function Test-UserInAllowGroup {
    param([string[]]$AllowGroups)

    try {
        $loggedOnUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName

        if ([string]::IsNullOrEmpty($loggedOnUser)) {
            Write-SVLog "No interactive user detected - skipping AD group check" "WARN"
            return $false
        }

        $username = $loggedOnUser.Split('\')[1]
        Write-SVLog "Checking AD allow group membership for: $username" "INFO"

        $principal = New-Object System.Security.Principal.WindowsPrincipal($username)

        foreach ($allowGroup in $AllowGroups) {
            $isMember = $principal.IsInRole($allowGroup)
            if ($isMember) {
                Write-SVLog "EXEMPT: $username is member of allow group '$allowGroup'" "INFO"
                return $true
            } else {
                Write-SVLog "$allowGroup = NOT_A_MEMBER" "DEBUG"
            }
        }

        Write-SVLog "NOT EXEMPT: $username is not in any allow group - sinkhole applies" "INFO"
        return $false

    } catch {
        Write-SVLog "AD group check failed: $_ - applying sinkhole (fail closed)" "WARN"
        return $false
    }
}

# =============================================================================
# Hosts File Functions
# =============================================================================
function Remove-ManagedBlock {
    param([string[]]$Lines)
    $out     = New-Object System.Collections.Generic.List[string]
    $inBlock = $false

    foreach ($line in $Lines) {
        if ($line -eq $BeginMarker) { $inBlock = $true;  continue }
        if ($line -eq $EndMarker)   { $inBlock = $false; continue }
        if (-not $inBlock) { [void]$out.Add($line) }
    }

    return ,$out.ToArray()
}

function Write-HostsFileAtomic {
    param([string]$Path, [string[]]$Content)

    $item               = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $originalAttributes = $item.Attributes

    if ($item.Attributes -band [IO.FileAttributes]::ReadOnly) {
        $item.Attributes = ($item.Attributes -bxor [IO.FileAttributes]::ReadOnly)
    }

    $tmp = Join-Path ([IO.Path]::GetDirectoryName($Path)) ("hosts.tmp.{0}" -f ([guid]::NewGuid().ToString("N")))

    try {
        Set-Content -LiteralPath $tmp -Value $Content -Encoding ASCII -Force -ErrorAction Stop

        # FIX v2.0.2: Use Copy-Item -Force to overwrite the destination, then delete the tmp.
        # Move-Item -Force throws a non-terminating IOException on System32\drivers\etc\hosts
        # (silently swallowed - hosts file never updated despite "success" log).
        # File::Replace() was tried in v2.0.1 but rejects Join-Path resolved paths on some systems.
        # Copy-Item -Force correctly overwrites an existing file and has no such restriction.
        Copy-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue

    } finally {
        # Safety net: clean up tmp if Copy-Item itself threw
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
        try { (Get-Item -LiteralPath $Path -Force).Attributes = $originalAttributes } catch { }
    }
}

# =============================================================================
# Main
# =============================================================================

if (($add -and $rm) -or (-not $add -and -not $rm)) {
    throw "Specify exactly one flag: -add OR -rm"
}

if (-not (Test-Path -LiteralPath $HostsPath)) {
    throw "Hosts file not found at: $HostsPath"
}

Write-SVLog "Starting v2.0.2 - action=$(if ($add) { 'add' } else { 'rm' })"

# -rm: unconditional - no sync, no group check, just strip and go
if ($rm) {
    $lines    = Get-Content -LiteralPath $HostsPath -ErrorAction Stop
    $filtered = Remove-ManagedBlock -Lines $lines
    if ($filtered.Count -ne $lines.Count) {
        Write-HostsFileAtomic -Path $HostsPath -Content $filtered
        Write-SVLog "Removed managed corpvpnsvcs sinkhole block" "INFO"
    } else {
        Write-SVLog "No managed sinkhole block found - nothing to remove" "INFO"
    }
    exit 0
}

# -add: sync config, load data, check groups, apply if needed
if ($add) {

    # Sync config files from DC share if cache is stale
    Invoke-ConfigSync

    # Load allow groups and hostnames from local cache (or fallback)
    $AllowGroups = Get-AllowGroups
    $Hostnames   = Get-SinkholeHostnames

    Write-SVLog "Using $($AllowGroups.Count) allow group(s), $($Hostnames.Count) sinkhole hostname(s)" "INFO"

    # AD group check - exempt users exit here
    if (Test-UserInAllowGroup -AllowGroups $AllowGroups) {
        Write-SVLog "User exempt - removing flag file and exiting without applying sinkhole" "INFO"
        if (Test-Path $BlackholeFlagFile) {
            try {
                Remove-Item $BlackholeFlagFile -Force -ErrorAction Stop
                Write-SVLog "Removed blackhole flag: $BlackholeFlagFile" "INFO"
            } catch {
                Write-SVLog "Could not remove flag file: $_" "WARN"
            }
        }
        exit 0
    }

    # Not exempt - apply sinkhole block
    $lines    = Get-Content -LiteralPath $HostsPath -ErrorAction Stop
    $filtered = Remove-ManagedBlock -Lines $lines

    # Blank line separator before block
    if ($filtered.Count -gt 0 -and $filtered[-1].Trim().Length -ne 0) {
        $filtered += ""
    }

    $block = New-Object System.Collections.Generic.List[string]
    [void]$block.Add($BeginMarker)
    foreach ($h in $Hostnames) {
        [void]$block.Add(("{0}`t{1}`t# managed" -f $SinkholeIP, $h))
    }
    [void]$block.Add($EndMarker)

    $newContent = $filtered + $block.ToArray()
    Write-HostsFileAtomic -Path $HostsPath -Content $newContent
    Write-SVLog "Applied sinkhole block - $($Hostnames.Count) headend entries added" "INFO"

    # Notify the user via Event ID 800 -> WW_notify.ps1 (USER context)
    # Runs as SYSTEM so we write to event log and let the watcher handle display
    try {
        $notifyPayload = "NOTIFY:toast|title=VPN Disabled On This Network|body=You are connected directly to the corporate network. VPN is not required here and has been disabled to improve performance and battery life.|duration=12"

        # FIX v2.0.1: ArgumentList MUST be a single quoted string, not an array.
        # Pipe characters in the NOTIFY payload are mishandled as shell pipes when passed as an array,
        # causing eventcreate.exe to silently fail. Matches fix applied to WW_main.ps1 Send-WwNotification
        # in commit 81a97de. Added -PassThru to capture and log the exit code.
        $proc = Start-Process -FilePath "eventcreate.exe" `
            -ArgumentList "/T INFORMATION /ID 800 /L APPLICATION /SO WhiteWalkerFlareGun /D `"$notifyPayload`"" `
            -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
        if ($proc.ExitCode -eq 0) {
            Write-SVLog "User notification queued (Event ID 800)" "INFO"
        } else {
            Write-SVLog "Notification event write FAILED (ExitCode: $($proc.ExitCode)) - payload: $notifyPayload" "WARN"
        }
    } catch {
        Write-SVLog "Could not queue user notification: $_" "WARN"
    }

    exit 0
}
