#Requires -RunAsAdministrator
<#
.SYNOPSIS
WW_xml_vault.ps1
Version: 1.0.5
Author: steve.horton@optum.com (with AI assist)
Purpose: XmlVault subsystem - offline VPN XML backup and island self-heal
Triggered by: Task Scheduler watching for WhiteWalkerFlareGun Event IDs 801 (sync) and 802 (restore)
Runs as: SYSTEM

.DESCRIPTION
XmlVault maintains a local backup vault of VPN profile XMLs synced from the NETLOGON share.
When a bad headend-pushed XML strands an endpoint (island scenario), XmlVault can restore
a known-good XML from the vault, allowing VPN reconnection.

Changes in 1.0.5:
   - Added -Force switch (sync mode only). Bypasses the 24h cooldown for a manual/
     tech-triggered sync, e.g. from admin\Invoke-WhiteWalkerAction.ps1. Additive and
     backward compatible - default behavior (switch absent) is unchanged.

Sync mode (Event ID 801 or direct call without -Restore):
   - Detects dev_vpn.txt flag to determine DEV vs PROD environment
   - Looks for dev_-prefixed XMLs on share in DEV mode
   - Copies all XMLs to local vault, stripping dev_ prefix on copy
   - Cooldown-gated (24h) to avoid hammering the share - override with -Force
   - Logs dev/prod detection
   - NOTE: XSD schema validation disabled (schema namespace issues TBD)

Restore mode (Event ID 802, -Restore switch, or xml_restore.flag file):
   - User-accessible flag: C:\Windows\Temp\xml_restore.flag
   - Reads target XML name from HKLM:\SYSTEM\UHG\DSM VPN registry value
   - Copies vault copy to VPN client profile directory
   - Cleans up flag files and writes restore-complete flag

Task Scheduler Configuration:
   Trigger: Event Log
     Log: Application
     Source: WhiteWalkerFlareGun
     Event IDs: 801 (sync), 802 (restore)
   Action: Program
     Program: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
     Arguments: -NoProfile -NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass
                -File "C:\ProgramData\WhiteWalker\WW_xml_vault.ps1"
   Settings:
     Run whether user is logged on or not: CHECKED
     Run with highest privileges: CHECKED
     User account: SYSTEM
#>

param(
    [switch]$Restore,   # if present: restore mode. absent: sync/auto mode.
    [switch]$Force      # sync mode only: bypass the 24h cooldown. Default behavior (absent) is unchanged.
)

# ------------------------------- Config ---------------------------------------
$LogPath             = "C:\ProgramData\WhiteWalker\logs\white_walker.xml_vault.log"
$VaultDir            = "C:\ProgramData\WhiteWalker\xml_vault"
$XsdPath             = "C:\ProgramData\WhiteWalker\AnyConnectProfile.xsd"
$CooldownFlag        = "C:\ProgramData\WhiteWalker\xml_vault_sync.flag"
$CooldownHours       = 24
$RestoreFlag         = "C:\Windows\Temp\xml_restore.flag"
$RestoreCompleteFlag = "C:\Windows\Temp\xml_restore.flag.completed"
$DevFlag             = "C:\Windows\UHGLogs\dev_vpn.txt"   # mirrors More-Sense exactly
$RemoteBase          = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN"
$AnyConnectProfileDir   = "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\"
$SecureClientProfileDir = "C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile\"
$RegPath             = "HKLM:\SYSTEM\UHG\DSM"

$LogRotationMaxBytes = 1MB
$LogRotationKeep     = 5

# XML file list - mirrors More-Sense $xml_files array exactly
$XmlFiles = @(
    "uhg_always_on.xml",
    "uhg_always_on_elevated.xml",
    "uhg_always_on_exception.xml",
    "uhg_always_on_exception_elevated.xml",
    "uhg_smartcard_exception.xml",
    "uhg_smartcard_exception_elevated.xml",
    "uhgprofile.xml"
)

# ------------------------------- Logging --------------------------------------
function Invoke-XmlVaultLogRotation {
    if (-not (Test-Path $LogPath)) { return }
    $size = (Get-Item $LogPath -ErrorAction SilentlyContinue).Length
    if ($size -lt $LogRotationMaxBytes) { return }

    $oldest = "$LogPath.$LogRotationKeep"
    if (Test-Path $oldest) { Remove-Item $oldest -Force -ErrorAction SilentlyContinue }

    for ($i = ($LogRotationKeep - 1); $i -ge 1; $i--) {
        $src = "$LogPath.$i"
        $dst = "$LogPath.$($i + 1)"
        if (Test-Path $src) { Rename-Item $src $dst -Force -ErrorAction SilentlyContinue }
    }

    Rename-Item $LogPath "$LogPath.1" -Force -ErrorAction SilentlyContinue
}

function Initialize-XmlVaultLogger {
    Invoke-XmlVaultLogRotation
    $dir = Split-Path -Parent $LogPath
    if (-not (Test-Path $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force | Out-Null } catch { }
    }
    if (-not (Test-Path $LogPath)) {
        try { New-Item -Path $LogPath -ItemType File -Force | Out-Null } catch { }
    }
}

function Write-VaultLog {
    param([Parameter(Mandatory=$true)][string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
    $logLine = "$ts [XML-VAULT] [$Level] $Message"
    try {
        Add-Content -Path $LogPath -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

# ------------------------------- Tee Telemetry ---------------------------------
function Initialize-XmlVaultTelemetry {
    # Sets the standalone telemetry gates and RESOLVES the WW_tee.ps1 path, but
    # deliberately does NOT dot-source it: dot-sourcing inside this function
    # would load Write-TeeLog into the function's own local scope, which is
    # discarded the moment the function returns, leaving every later
    # Invoke-XmlVaultTelemetry call to silently bail out on its
    # Get-Command Write-TeeLog guard. The caller dot-sources the returned path
    # at script scope so Write-TeeLog survives for the life of the process.
    try {
        # XmlVault runs standalone (launched by Task Scheduler as its own SYSTEM
        # process, never inheriting WW_main.ps1's scope), so Write-TeeLog's
        # $HaystackEnabled/$TeeEnabled/$TeeEventsFile gates are never set unless
        # this process sets them itself. Hardcoded here to match the same
        # literal values WW_main.ps1 and other standalone helpers (e.g.
        # WW_cap_portal_runner_base.ps1) use today, and set BEFORE WW_tee.ps1 is
        # dot-sourced so the very first Write-TeeLog call can fire.
        $global:HaystackEnabled = $true
        $global:TeeEnabled      = $true
        $global:TeeEventsFile   = "C:\ProgramData\WhiteWalker\WW_tee_events.psd1"

        $resolvedTeePath = Join-Path (Split-Path -Parent $PSCommandPath) "WW_tee.ps1"
        if (Test-Path -LiteralPath $resolvedTeePath) {
            return $resolvedTeePath
        }

        Write-VaultLog "XmlVault: WW_tee.ps1 not found - telemetry disabled for this run" "WARN"
        return $null
    } catch {
        Write-VaultLog "XmlVault: failed to resolve WW_tee.ps1 - telemetry disabled for this run" "WARN"
        return $null
    }
}

function Confirm-XmlVaultTelemetry {
    # Truthful post-load status: only claim telemetry is initialized when
    # Write-TeeLog is actually visible to Invoke-XmlVaultTelemetry.
    if (Get-Command Write-TeeLog -ErrorAction SilentlyContinue) {
        Write-VaultLog "XmlVault: WW_tee loaded for lifecycle telemetry (Write-TeeLog available)" "DEBUG"
        return $true
    }

    Write-VaultLog "XmlVault: Write-TeeLog unavailable after telemetry init - telemetry disabled for this run" "WARN"
    return $false
}

function Invoke-XmlVaultTelemetry {
    param(
        [Parameter(Mandatory=$true)][string]$Tag,
        [Parameter(Mandatory=$true)][string]$Mode,
        [Parameter(Mandatory=$true)][string]$Status,
        [string]$Source,
        [string]$Reason,
        [string]$ProfileName,
        [int]$ProfileCount = -1
    )

    try {
        if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) { return }

        $data = @{
            mode   = $Mode
            status = $Status
        }

        if (-not [string]::IsNullOrWhiteSpace($Source))      { $data.source = $Source }
        if (-not [string]::IsNullOrWhiteSpace($Reason))      { $data.reason = $Reason }
        if (-not [string]::IsNullOrWhiteSpace($ProfileName)) { $data.profile_name = $ProfileName }
        if ($ProfileCount -ge 0)                              { $data.profile_count = $ProfileCount }

        # -PassThru so a silently dropped event (disabled switches, a tag
        # missing from a stale deployed profile, or a hard queue-write error)
        # is logged truthfully instead of looking identical to a success.
        $result = Write-TeeLog $Tag $data -PassThru

        if ($null -eq $result) {
            return
        }

        switch ($result.Reason) {
            'queued' {
                Write-VaultLog "XmlVault: tee telemetry queued (reason=queued) for tag '$Tag' -> $($result.QueueFile)" "DEBUG"
            }
            'tag_not_in_profile' {
                Write-VaultLog "XmlVault: tee telemetry dropped (reason=tag_not_in_profile) for tag '$Tag' - tag not in active WW_tee_events.psd1 profile" "WARN"
            }
            'haystack_disabled' {
                Write-VaultLog "XmlVault: tee telemetry dropped (reason=haystack_disabled) for tag '$Tag' - haystack disabled" "WARN"
            }
            'tee_disabled' {
                Write-VaultLog "XmlVault: tee telemetry dropped (reason=tee_disabled) for tag '$Tag' - tee disabled" "WARN"
            }
            'error' {
                Write-VaultLog "XmlVault: tee telemetry failed (reason=error) for tag '$Tag': $($result.Error)" "WARN"
            }
            default {
                Write-VaultLog "XmlVault: tee telemetry result (reason=$($result.Reason)) for tag '$Tag'" "DEBUG"
            }
        }
    } catch {
        Write-VaultLog "XmlVault: tee telemetry failed for tag '$Tag' (non-fatal)" "WARN"
    }
}

# ------------------------------- Env Detection --------------------------------
function Get-XmlVaultEnv {
    # Mirrors More-Sense set_env_val() exactly:
    # if dev_vpn.txt exists -> AOVPN-DEV, else -> AOVPN-PROD
    if (Test-Path -Path $DevFlag) {
        return "AOVPN-DEV"
    }
    return "AOVPN-PROD"
}

function Get-XmlVaultIsoTimestamp {
    param([datetime]$DateTime = (Get-Date))
    return $DateTime.ToUniversalTime().ToString("o")
}

function ConvertTo-XmlVaultDateTimeOrNull {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($Value, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function New-XmlVaultStateObject {
    param([object]$InputState)

    $state = [ordered]@{
        lastSynced                      = $null
        lastChecked                     = $null
        result                          = $null
        remoteCount                     = $null
        localCount                      = $null
        userProfile                     = $null
        activeProfileRemoteLength       = $null
        activeProfileRemoteLastWriteTimeUtc = $null
        lastRestore                     = $null
        lastRestoreResult               = $null
        lastRestoreSource               = $null
        lastRestoreVaultLength          = $null
        lastRestoreVaultLastWriteTimeUtc = $null
    }

    if ($InputState) {
        foreach ($prop in @($state.Keys)) {
            if ($null -ne $InputState.$prop) {
                $state[$prop] = $InputState.$prop
            }
        }
    }

    return [pscustomobject]$state
}

function Get-XmlVaultState {
    $defaultState = New-XmlVaultStateObject

    if (-not (Test-Path -LiteralPath $CooldownFlag)) {
        return $defaultState
    }

    try {
        $raw = (Get-Content -LiteralPath $CooldownFlag -Raw -ErrorAction Stop).Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $defaultState
        }

        try {
            $json = $raw | ConvertFrom-Json -ErrorAction Stop
            return New-XmlVaultStateObject -InputState $json
        } catch {
            # Backward compatibility: legacy plain ISO timestamp flag.
            $legacy = [datetime]::MinValue
            if ([datetime]::TryParse($raw, [ref]$legacy)) {
                return New-XmlVaultStateObject -InputState @{
                    lastSynced = (Get-XmlVaultIsoTimestamp -DateTime $legacy)
                    result     = "legacy_timestamp"
                }
            }

            Write-VaultLog "XmlVault: malformed sync flag content - forcing full sync evaluation path" "WARN"
            return $defaultState
        }
    } catch {
        Write-VaultLog "XmlVault: failed to read sync flag - forcing full sync evaluation path" "WARN"
        return $defaultState
    }
}

function Write-XmlVaultState {
    param([Parameter(Mandatory=$true)][object]$State)

    $tmpPath = "$CooldownFlag.tmp"
    try {
        $payload = New-XmlVaultStateObject -InputState $State
        $json = $payload | ConvertTo-Json -Depth 6
        Set-Content -LiteralPath $tmpPath -Value $json -Encoding UTF8 -Force -ErrorAction Stop
        Move-Item -LiteralPath $tmpPath -Destination $CooldownFlag -Force -ErrorAction Stop
        return $true
    } catch {
        try { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue } catch { }
        Write-VaultLog "XmlVault: could not persist sync state (non-fatal)" "WARN"
        return $false
    }
}

function Update-XmlVaultState {
    param(
        [hashtable]$Updates,
        [switch]$UpdateLastSynced
    )

    $state = New-XmlVaultStateObject -InputState (Get-XmlVaultState)
    if ($Updates) {
        foreach ($key in $Updates.Keys) {
            $state | Add-Member -MemberType NoteProperty -Name $key -Value $Updates[$key] -Force
        }
    }

    if ($UpdateLastSynced) {
        $state.lastSynced = Get-XmlVaultIsoTimestamp
    }

    Write-XmlVaultState -State $state | Out-Null
    return $state
}

function Normalize-XmlVaultProfileName {
    param([string]$ProfileValue)

    if ([string]::IsNullOrWhiteSpace($ProfileValue)) {
        return $null
    }

    $raw = $ProfileValue.Trim()
    if ($raw -match '[\\/]' -or $raw -match '\.\.') {
        return $null
    }

    $name = [System.IO.Path]::GetFileName($raw)
    if ([string]::IsNullOrWhiteSpace($name)) {
        return $null
    }

    if (-not $name.EndsWith(".xml", [System.StringComparison]::OrdinalIgnoreCase)) {
        $name = "$name.xml"
    }

    if ($name -notmatch '^[A-Za-z0-9._-]+\.xml$') {
        return $null
    }

    return $name
}

function Get-XmlVaultActiveProfileName {
    try {
        $raw = (Get-ItemProperty -Path $RegPath -ErrorAction Stop).VPN
    } catch {
        Write-VaultLog "XmlVault: could not read registry VPN value for active profile" "WARN"
        return $null
    }

    $normalized = Normalize-XmlVaultProfileName -ProfileValue $raw
    if (-not $normalized) {
        Write-VaultLog "XmlVault: registry VPN value cannot be normalized safely" "WARN"
        return $null
    }

    return $normalized
}

function Get-XmlVaultRemoteFileName {
    param(
        [Parameter(Mandatory=$true)][string]$ProfileName,
        [Parameter(Mandatory=$true)][string]$VaultEnv
    )

    if ($VaultEnv -eq "AOVPN-DEV") {
        return "dev_$ProfileName"
    }

    return $ProfileName
}

function Get-XmlVaultConfiguredRemoteCount {
    param(
        [Parameter(Mandatory=$true)][string]$RemoteDir,
        [Parameter(Mandatory=$true)][string]$VaultEnv
    )

    $count = 0
    foreach ($filename in $XmlFiles) {
        $remoteFile = Get-XmlVaultRemoteFileName -ProfileName $filename -VaultEnv $VaultEnv
        $remotePath = Join-Path $RemoteDir $remoteFile
        if (Test-Path -LiteralPath $remotePath) {
            $count++
        }
    }
    return $count
}

function Get-XmlVaultConfiguredLocalCount {
    $count = 0
    foreach ($filename in $XmlFiles) {
        if (Test-Path -LiteralPath (Join-Path $VaultDir $filename)) {
            $count++
        }
    }
    return $count
}

function Get-XmlVaultRemoteProfileMetadata {
    param(
        [Parameter(Mandatory=$true)][string]$RemoteDir,
        [Parameter(Mandatory=$true)][string]$VaultEnv,
        [Parameter(Mandatory=$true)][string]$ProfileName
    )

    $remoteFile = Get-XmlVaultRemoteFileName -ProfileName $ProfileName -VaultEnv $VaultEnv
    $remotePath = Join-Path $RemoteDir $remoteFile

    if (-not (Test-Path -LiteralPath $remotePath)) {
        return [pscustomobject]@{
            IsReliable       = $false
            RemotePath       = $remotePath
            RemoteName       = $remoteFile
            Reason           = "missing_remote_profile"
            Length           = $null
            LastWriteTimeUtc = $null
        }
    }

    try {
        $item = Get-Item -LiteralPath $remotePath -ErrorAction Stop
        return [pscustomobject]@{
            IsReliable       = $true
            RemotePath       = $remotePath
            RemoteName       = $remoteFile
            Reason           = $null
            Length           = [int64]$item.Length
            LastWriteTimeUtc = $item.LastWriteTimeUtc
        }
    } catch {
        return [pscustomobject]@{
            IsReliable       = $false
            RemotePath       = $remotePath
            RemoteName       = $remoteFile
            Reason           = "remote_metadata_unavailable"
            Length           = $null
            LastWriteTimeUtc = $null
        }
    }
}

function Ensure-XmlVaultDirectory {
    if (-not (Test-Path -LiteralPath $VaultDir)) {
        try {
            New-Item -Path $VaultDir -ItemType Directory -Force | Out-Null
            Write-VaultLog "XmlVault: created vault dir $VaultDir" "INFO"
        } catch {
            Write-VaultLog "XmlVault: failed to create vault dir $VaultDir" "ERROR"
            Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'sync' -Status 'failed' -Source 'local_vault' -Reason 'vault_create_failed'
            return $false
        }
    }

    try {
        $acl = Get-Acl $VaultDir
        $acl.SetAccessRuleProtection($true, $false)
        $systemSid = [System.Security.Principal.SecurityIdentifier]"S-1-5-18"
        $adminsSid = [System.Security.Principal.SecurityIdentifier]"S-1-5-32-544"
        $rights    = [System.Security.AccessControl.FileSystemRights]::FullControl
        $inherit   = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        $propagate = [System.Security.AccessControl.PropagationFlags]::None
        $allow     = [System.Security.AccessControl.AccessControlType]::Allow
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($systemSid, $rights, $inherit, $propagate, $allow))
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($adminsSid, $rights, $inherit, $propagate, $allow))
        Set-Acl -Path $VaultDir -AclObject $acl -ErrorAction Stop
        Write-VaultLog "XmlVault: vault ACL set (SYSTEM + Administrators only)" "INFO"
    } catch {
        Write-VaultLog "XmlVault: could not set vault ACL - continuing in degraded mode" "WARN"
    }

    return $true
}

function Test-XmlVaultMetadataMatch {
    param(
        [Parameter(Mandatory=$true)][object]$State,
        [Parameter(Mandatory=$true)][string]$ProfileName,
        [Parameter(Mandatory=$true)][object]$RemoteMetadata
    )

    if (-not $RemoteMetadata.IsReliable) { return $false }
    if ($State.userProfile -ine $ProfileName) { return $false }
    if ($null -eq $State.activeProfileRemoteLength) { return $false }
    if ($null -eq $State.activeProfileRemoteLastWriteTimeUtc) { return $false }

    $stateLength = 0L
    if (-not [int64]::TryParse([string]$State.activeProfileRemoteLength, [ref]$stateLength)) {
        return $false
    }

    $stateTime = ConvertTo-XmlVaultDateTimeOrNull -Value [string]$State.activeProfileRemoteLastWriteTimeUtc
    if (-not $stateTime) { return $false }

    return ($stateLength -eq [int64]$RemoteMetadata.Length) -and
           ((Get-XmlVaultIsoTimestamp -DateTime $stateTime) -eq (Get-XmlVaultIsoTimestamp -DateTime $RemoteMetadata.LastWriteTimeUtc))
}

function Invoke-XmlVaultFullSync {
    param(
        [Parameter(Mandatory=$true)][string]$RemoteDir,
        [Parameter(Mandatory=$true)][string]$VaultEnv,
        [Parameter(Mandatory=$true)][int]$RemoteCount,
        [Parameter(Mandatory=$true)][int]$LocalCount,
        [string]$UserProfile,
        [string]$Reason = "full_sync_requested"
    )

    if (-not (Ensure-XmlVaultDirectory)) {
        Update-XmlVaultState -Updates @{
            lastChecked = Get-XmlVaultIsoTimestamp
            result      = "full_sync_failed_vault_create"
            remoteCount = $RemoteCount
            localCount  = $LocalCount
            userProfile = $UserProfile
        } | Out-Null
        return
    }

    $copied = 0
    $failed = 0

    foreach ($filename in $XmlFiles) {
        $remoteFilename = Get-XmlVaultRemoteFileName -ProfileName $filename -VaultEnv $VaultEnv
        $remotePath = Join-Path $RemoteDir $remoteFilename
        $vaultPath = Join-Path $VaultDir $filename

        if (-not (Test-Path -LiteralPath $remotePath)) {
            Write-VaultLog "XmlVault: $remoteFilename not found on share - skipping" "INFO"
            Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'sync' -Status 'failed' -Source 'netlogon' -Reason 'missing_source_on_share' -ProfileName $filename
            $failed++
            continue
        }

        try {
            Copy-Item -LiteralPath $remotePath -Destination $vaultPath -Force -ErrorAction Stop
            if ($VaultEnv -eq "AOVPN-DEV") {
                Write-VaultLog "XmlVault: $remoteFilename copied to vault as $filename (dev_ prefix stripped)" "INFO"
            } else {
                Write-VaultLog "XmlVault: $filename copied to vault" "INFO"
            }
            $copied++
        } catch {
            Write-VaultLog "XmlVault: $remoteFilename copy failed" "WARN"
            Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'sync' -Status 'failed' -Source 'netlogon' -Reason 'sync_copy_failed' -ProfileName $filename
            $failed++
        }
    }

    $result = "synced_full"
    if ($failed -gt 0 -and $copied -gt 0) {
        $result = "synced_full_partial"
    } elseif ($failed -gt 0 -and $copied -eq 0) {
        $result = "full_sync_failed"
    }

    $metadataLength = $null
    $metadataTime = $null
    if ($UserProfile) {
        $meta = Get-XmlVaultRemoteProfileMetadata -RemoteDir $RemoteDir -VaultEnv $VaultEnv -ProfileName $UserProfile
        if ($meta.IsReliable) {
            $metadataLength = $meta.Length
            $metadataTime = Get-XmlVaultIsoTimestamp -DateTime $meta.LastWriteTimeUtc
        }
    }

    $stateUpdate = @{
        lastChecked                     = Get-XmlVaultIsoTimestamp
        result                          = $result
        remoteCount                     = $RemoteCount
        localCount                      = (Get-XmlVaultConfiguredLocalCount)
        userProfile                     = $UserProfile
        activeProfileRemoteLength       = $metadataLength
        activeProfileRemoteLastWriteTimeUtc = $metadataTime
    }

    if ($copied -gt 0) {
        Update-XmlVaultState -Updates $stateUpdate -UpdateLastSynced | Out-Null
    } else {
        Update-XmlVaultState -Updates $stateUpdate | Out-Null
    }

    Write-VaultLog ("XmlVault: full sync complete - copied={0} failed={1}" -f $copied, $failed) "INFO"
    if ($failed -gt 0) {
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'sync' -Status 'failed' -Source 'netlogon' -Reason 'full_sync_failed' -ProfileCount $failed
    } else {
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'sync' -Status 'completed' -Source 'netlogon' -Reason 'full_sync_completed' -ProfileCount $copied
    }
}

function Invoke-XmlVaultTargetedProfileSync {
    param(
        [Parameter(Mandatory=$true)][string]$RemoteDir,
        [Parameter(Mandatory=$true)][string]$VaultEnv,
        [Parameter(Mandatory=$true)][string]$ProfileName,
        [Parameter(Mandatory=$true)][object]$RemoteMetadata,
        [Parameter(Mandatory=$true)][int]$RemoteCount,
        [Parameter(Mandatory=$true)][int]$LocalCount
    )

    if (-not (Ensure-XmlVaultDirectory)) {
        Update-XmlVaultState -Updates @{
            lastChecked = Get-XmlVaultIsoTimestamp
            result      = "targeted_sync_failed_vault_create"
            remoteCount = $RemoteCount
            localCount  = $LocalCount
            userProfile = $ProfileName
        } | Out-Null
        return
    }

    if (-not $RemoteMetadata.IsReliable) {
        Invoke-XmlVaultFullSync -RemoteDir $RemoteDir -VaultEnv $VaultEnv -RemoteCount $RemoteCount -LocalCount $LocalCount -UserProfile $ProfileName -Reason "active_profile_metadata_unavailable"
        return
    }

    $vaultPath = Join-Path $VaultDir $ProfileName
    try {
        Copy-Item -LiteralPath $RemoteMetadata.RemotePath -Destination $vaultPath -Force -ErrorAction Stop
        Write-VaultLog "XmlVault: targeted sync copied active profile $ProfileName" "INFO"
        Update-XmlVaultState -Updates @{
            lastChecked                     = Get-XmlVaultIsoTimestamp
            result                          = "synced_targeted"
            remoteCount                     = $RemoteCount
            localCount                      = (Get-XmlVaultConfiguredLocalCount)
            userProfile                     = $ProfileName
            activeProfileRemoteLength       = [int64]$RemoteMetadata.Length
            activeProfileRemoteLastWriteTimeUtc = (Get-XmlVaultIsoTimestamp -DateTime $RemoteMetadata.LastWriteTimeUtc)
        } -UpdateLastSynced | Out-Null

        Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'sync' -Status 'completed' -Source 'netlogon' -Reason 'targeted_sync_completed' -ProfileName $ProfileName -ProfileCount 1
    } catch {
        Write-VaultLog "XmlVault: targeted sync copy failed for active profile" "WARN"
        Update-XmlVaultState -Updates @{
            lastChecked = Get-XmlVaultIsoTimestamp
            result      = "targeted_sync_failed"
            remoteCount = $RemoteCount
            localCount  = (Get-XmlVaultConfiguredLocalCount)
            userProfile = $ProfileName
        } | Out-Null
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'sync' -Status 'failed' -Source 'netlogon' -Reason 'targeted_sync_failed' -ProfileName $ProfileName -ProfileCount 1
    }
}

# ------------------------------- SYNC MODE ------------------------------------
function Invoke-XmlVaultSync {
    param(
        [switch]$Force   # bypass cooldown check - for manual/tech-triggered runs only
    )

    Write-VaultLog "===== XmlVault Sync Starting =====" "INFO"

    $state = Get-XmlVaultState
    $lastSynced = ConvertTo-XmlVaultDateTimeOrNull -Value [string]$state.lastSynced
    if ($lastSynced -and -not $Force) {
        $ageHours = ((Get-Date) - $lastSynced).TotalHours
        if ($ageHours -lt $CooldownHours) {
            Write-VaultLog ("XmlVault: sync cooldown active ({0:N1}h old) - skipping NETLOGON work" -f $ageHours) "DEBUG"
            Update-XmlVaultState -Updates @{
                lastChecked = Get-XmlVaultIsoTimestamp
                result      = "skipped_cooldown"
            } | Out-Null
            Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'sync' -Status 'skipped' -Source 'netlogon' -Reason 'sync_cooldown_active'
            return
        }
        Write-VaultLog ("XmlVault: cooldown expired ({0:N1}h old) - evaluating sync" -f $ageHours) "INFO"
    } elseif ($lastSynced -and $Force) {
        Write-VaultLog "XmlVault: -Force specified - bypassing sync cooldown" "INFO"
    }

    $vaultEnv = Get-XmlVaultEnv
    $RemoteDir = "$RemoteBase\$vaultEnv"
    Write-VaultLog "XmlVault: env=$vaultEnv (flag_path=$DevFlag)" "INFO"
    Write-VaultLog "XmlVault: remote_dir=$RemoteDir" "INFO"

    if (-not (Test-Path -LiteralPath $RemoteDir -ErrorAction SilentlyContinue)) {
        Write-VaultLog "XmlVault: share unreachable - deferring sync (lastSynced unchanged)" "WARN"
        Update-XmlVaultState -Updates @{
            lastChecked = Get-XmlVaultIsoTimestamp
            result      = "deferred_share_unreachable"
        } | Out-Null
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'sync' -Status 'deferred' -Source 'netlogon' -Reason 'share_unreachable'
        return
    }

    $remoteCount = Get-XmlVaultConfiguredRemoteCount -RemoteDir $RemoteDir -VaultEnv $vaultEnv
    $localCount = Get-XmlVaultConfiguredLocalCount
    Write-VaultLog ("XmlVault: configured profile counts remote={0} local={1}" -f $remoteCount, $localCount) "INFO"

    if ($remoteCount -ne $localCount) {
        Invoke-XmlVaultFullSync -RemoteDir $RemoteDir -VaultEnv $vaultEnv -RemoteCount $remoteCount -LocalCount $localCount -UserProfile (Get-XmlVaultActiveProfileName) -Reason "count_mismatch"
        Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
        return
    }

    if ($remoteCount -le 0) {
        Invoke-XmlVaultFullSync -RemoteDir $RemoteDir -VaultEnv $vaultEnv -RemoteCount $remoteCount -LocalCount $localCount -UserProfile (Get-XmlVaultActiveProfileName) -Reason "zero_remote_count"
        Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
        return
    }

    $activeProfile = Get-XmlVaultActiveProfileName
    if (-not $activeProfile) {
        Invoke-XmlVaultFullSync -RemoteDir $RemoteDir -VaultEnv $vaultEnv -RemoteCount $remoteCount -LocalCount $localCount -Reason "active_profile_unresolved"
        Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
        return
    }

    if ($XmlFiles -notcontains $activeProfile) {
        Write-VaultLog "XmlVault: active profile is not in configured vault list - falling back to full sync" "WARN"
        Invoke-XmlVaultFullSync -RemoteDir $RemoteDir -VaultEnv $vaultEnv -RemoteCount $remoteCount -LocalCount $localCount -UserProfile $activeProfile -Reason "active_profile_not_configured"
        Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
        return
    }

    $remoteMeta = Get-XmlVaultRemoteProfileMetadata -RemoteDir $RemoteDir -VaultEnv $vaultEnv -ProfileName $activeProfile
    if (-not $remoteMeta.IsReliable) {
        Write-VaultLog "XmlVault: active profile metadata unavailable - falling back to full sync" "WARN"
        Invoke-XmlVaultFullSync -RemoteDir $RemoteDir -VaultEnv $vaultEnv -RemoteCount $remoteCount -LocalCount $localCount -UserProfile $activeProfile -Reason "active_profile_metadata_unavailable"
        Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
        return
    }

    $vaultTargetPath = Join-Path $VaultDir $activeProfile
    $stateMetaMatches = Test-XmlVaultMetadataMatch -State $state -ProfileName $activeProfile -RemoteMetadata $remoteMeta
    $targetExists = Test-Path -LiteralPath $vaultTargetPath

    if ($stateMetaMatches -and $targetExists) {
        Write-VaultLog "XmlVault: active profile metadata unchanged and local target exists - skipping copy" "INFO"
        Update-XmlVaultState -Updates @{
            lastChecked                     = Get-XmlVaultIsoTimestamp
            result                          = "skipped_metadata_match"
            remoteCount                     = $remoteCount
            localCount                      = $localCount
            userProfile                     = $activeProfile
            activeProfileRemoteLength       = [int64]$remoteMeta.Length
            activeProfileRemoteLastWriteTimeUtc = (Get-XmlVaultIsoTimestamp -DateTime $remoteMeta.LastWriteTimeUtc)
        } | Out-Null
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'sync' -Status 'skipped' -Source 'netlogon' -Reason 'metadata_match_no_copy' -ProfileName $activeProfile -ProfileCount $remoteCount
        Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
        return
    }

    Invoke-XmlVaultTargetedProfileSync -RemoteDir $RemoteDir -VaultEnv $vaultEnv -ProfileName $activeProfile -RemoteMetadata $remoteMeta -RemoteCount $remoteCount -LocalCount $localCount
    Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
}

# ------------------------------- RESTORE MODE ---------------------------------
function Remove-XmlVaultStaleManagedProfiles {
    param(
        [Parameter(Mandatory=$true)][string]$ClientDir,
        [Parameter(Mandatory=$true)][string]$SelectedProfileName
    )

    $result = [ordered]@{
        Success      = $true
        RemovedCount = 0
        MissingCount = 0
        FailedCount  = 0
        ErrorReason  = $null
    }

    try {
        $managedFiles = @(Get-ChildItem -LiteralPath $VaultDir -File -Filter '*.xml' -ErrorAction Stop)
    } catch {
        $result.Success = $false
        $result.ErrorReason = 'restore_cleanup_enumeration_failed'
        Write-VaultLog "XmlVault: could not enumerate vault XML files for cleanup: $($_.Exception.Message)" "ERROR"
        return [pscustomobject]$result
    }

    $managedNames = @($managedFiles | ForEach-Object { $_.Name })
    Write-VaultLog "XmlVault: cleanup plan - managed vault XMLs: $($managedNames -join ', ')" "INFO"

    try {
        $clientFiles = @(Get-ChildItem -LiteralPath $ClientDir -File -ErrorAction Stop)
    } catch {
        $result.Success = $false
        $result.ErrorReason = 'restore_cleanup_enumeration_failed'
        Write-VaultLog "XmlVault: could not enumerate client profile files for cleanup: $($_.Exception.Message)" "ERROR"
        return [pscustomobject]$result
    }

    foreach ($managedName in $managedNames) {
        if ([string]::Equals($managedName, $SelectedProfileName, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $staleFiles = @($clientFiles | Where-Object {
            [string]::Equals($_.Name, $managedName, [System.StringComparison]::OrdinalIgnoreCase)
        })

        if ($staleFiles.Count -eq 0) {
            $result.MissingCount++
            Write-VaultLog "XmlVault: cleanup stale managed profile not present: $managedName" "WARN"
            continue
        }

        foreach ($staleFile in $staleFiles) {
            try {
                Remove-Item -LiteralPath $staleFile.FullName -Force -ErrorAction Stop
                $result.RemovedCount++
                Write-VaultLog "XmlVault: cleanup removed stale managed profile: $($staleFile.Name)" "INFO"
            } catch {
                $result.Success = $false
                $result.FailedCount++
                $result.ErrorReason = 'restore_cleanup_failed'
                Write-VaultLog "XmlVault: cleanup failed removing stale managed profile '$($staleFile.Name)': $($_.Exception.Message)" "ERROR"
            }
        }
    }

    return [pscustomobject]$result
}

function Invoke-XmlVaultRestore {
    Write-VaultLog "===== XmlVault Restore Starting =====" "INFO"

    # 1. Check restore flag exists (belt-and-suspenders - TS fires when WW_main saw it, but be safe)
    if (-not (Test-Path $RestoreFlag)) {
        Write-VaultLog "XmlVault: restore flag not present ($RestoreFlag) - nothing to restore" "DEBUG"
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'restore_flag_missing'
        Update-XmlVaultState -Updates @{
            lastChecked      = Get-XmlVaultIsoTimestamp
            result           = "restore_failed_missing_flag"
            lastRestore      = Get-XmlVaultIsoTimestamp
            lastRestoreResult = "restore_failed_missing_flag"
            lastRestoreSource = "local_vault"
        } | Out-Null
        return
    }

    # 2. Detect client dir (Secure Client wins over AnyConnect)
    $clientDir = $null
    if (Test-Path $SecureClientProfileDir) {
        $clientDir = $SecureClientProfileDir
        Write-VaultLog "XmlVault: using Cisco Secure Client profile dir: $clientDir" "INFO"
    } elseif (Test-Path $AnyConnectProfileDir) {
        $clientDir = $AnyConnectProfileDir
        Write-VaultLog "XmlVault: using AnyConnect profile dir: $clientDir" "INFO"
    } else {
        Write-VaultLog "XmlVault: neither Secure Client nor AnyConnect profile dir found - cannot restore" "ERROR"
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'profile_dir_not_found'
        Update-XmlVaultState -Updates @{
            lastChecked       = Get-XmlVaultIsoTimestamp
            result            = "restore_failed_profile_dir_not_found"
            lastRestore       = Get-XmlVaultIsoTimestamp
            lastRestoreResult = "restore_failed_profile_dir_not_found"
            lastRestoreSource = "local_vault"
        } | Out-Null
        return
    }

    # 3. Get target XML name from registry
    $xmlName = Get-XmlVaultActiveProfileName
    if (-not $xmlName) {
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'profile_name_missing'
        Update-XmlVaultState -Updates @{
            lastChecked       = Get-XmlVaultIsoTimestamp
            result            = "restore_failed_profile_name_missing"
            lastRestore       = Get-XmlVaultIsoTimestamp
            lastRestoreResult = "restore_failed_profile_name_missing"
            lastRestoreSource = "local_vault"
        } | Out-Null
        return
    }

    Write-VaultLog "XmlVault: target XML from registry: $xmlName" "INFO"

    # 4. Dev flag check - mirrors More-Sense behavior:
    #    if dev flag exists -> prepend dev_ to vault lookup name, write to client dir as prod name
    $vaultEnv = Get-XmlVaultEnv
    $vaultLookupName = $xmlName
    $destFileName    = $xmlName
    $restoreSource = "local_vault_prod"

    if ($vaultEnv -eq "AOVPN-DEV") {
        $vaultLookupName = "dev_$xmlName"
        $restoreSource = "local_vault_dev"
        # destFileName stays as $xmlName (strip dev_ prefix on destination)
        Write-VaultLog "XmlVault: DEV mode - vault lookup: $vaultLookupName  dest: $destFileName (dev_ prefix stripped)" "INFO"
    } else {
        Write-VaultLog "XmlVault: PROD mode - vault lookup and dest: $xmlName" "INFO"
    }

    # 5. Locate vault copy
    $vaultPath = Join-Path $VaultDir $vaultLookupName

    if (-not (Test-Path $vaultPath)) {
        if ($vaultEnv -eq "AOVPN-DEV") {
            # Fall back to prod copy if dev copy not present in vault
            $fallbackPath = Join-Path $VaultDir $xmlName
            if (Test-Path $fallbackPath) {
                Write-VaultLog "XmlVault: dev vault copy not found, falling back to prod copy: $xmlName" "WARN"
                $vaultPath = $fallbackPath
                $restoreSource = "local_vault_dev_fallback_prod"
            } else {
                Write-VaultLog "XmlVault: vault copy of $vaultLookupName (and fallback $xmlName) not found - cannot restore" "ERROR"
                Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'vault_copy_not_found' -ProfileName $destFileName
                Update-XmlVaultState -Updates @{
                    lastChecked       = Get-XmlVaultIsoTimestamp
                    result            = "restore_failed_vault_copy_not_found"
                    userProfile       = $destFileName
                    lastRestore       = Get-XmlVaultIsoTimestamp
                    lastRestoreResult = "restore_failed_vault_copy_not_found"
                    lastRestoreSource = $restoreSource
                } | Out-Null
                return
            }
        } else {
            Write-VaultLog "XmlVault: vault copy of $vaultLookupName not found - cannot restore" "ERROR"
            Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'vault_copy_not_found' -ProfileName $destFileName
            Update-XmlVaultState -Updates @{
                lastChecked       = Get-XmlVaultIsoTimestamp
                result            = "restore_failed_vault_copy_not_found"
                userProfile       = $destFileName
                lastRestore       = Get-XmlVaultIsoTimestamp
                lastRestoreResult = "restore_failed_vault_copy_not_found"
                lastRestoreSource = $restoreSource
            } | Out-Null
            return
        }
    }

    Write-VaultLog "XmlVault: vault copy found: $vaultPath" "INFO"

    # 6. Copy vault copy to client profile dir
    $destPath = Join-Path $clientDir $destFileName
    try {
        Copy-Item -LiteralPath $vaultPath -Destination $destPath -Force -ErrorAction Stop
        Write-VaultLog "XmlVault: restored $vaultPath -> $destPath" "INFO"
    } catch {
        Write-VaultLog "XmlVault: restore copy failed" "ERROR"
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'restore_copy_failed' -ProfileName $destFileName
        Update-XmlVaultState -Updates @{
            lastChecked       = Get-XmlVaultIsoTimestamp
            result            = "restore_failed_copy"
            userProfile       = $destFileName
            lastRestore       = Get-XmlVaultIsoTimestamp
            lastRestoreResult = "restore_failed_copy"
            lastRestoreSource = $restoreSource
        } | Out-Null
        return
    }

    # Verify the copy landed
    if (-not (Test-Path $destPath)) {
        Write-VaultLog "XmlVault: [!!] restored file not found at $destPath after copy - verify permissions" "ERROR"
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'restore_verification_failed_missing_destination' -ProfileName $destFileName
        Update-XmlVaultState -Updates @{
            lastChecked       = Get-XmlVaultIsoTimestamp
            result            = "restore_failed_verification"
            userProfile       = $destFileName
            lastRestore       = Get-XmlVaultIsoTimestamp
            lastRestoreResult = "restore_failed_verification"
            lastRestoreSource = $restoreSource
        } | Out-Null
        return
    }

    Write-VaultLog "XmlVault: restore destination verified OK ($destPath); beginning managed-profile cleanup" "INFO"

    $cleanupResult = Remove-XmlVaultStaleManagedProfiles -ClientDir $clientDir -SelectedProfileName $destFileName
    if (-not $cleanupResult.Success) {
        $cleanupReason = if ($cleanupResult.ErrorReason) { $cleanupResult.ErrorReason } else { 'restore_cleanup_failed' }
        Write-VaultLog "XmlVault: restore incomplete - stale managed profile cleanup failed (reason=$cleanupReason, failed=$($cleanupResult.FailedCount))" "ERROR"
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason $cleanupReason -ProfileName $destFileName
        Update-XmlVaultState -Updates @{
            lastChecked       = Get-XmlVaultIsoTimestamp
            result            = $cleanupReason
            userProfile       = $destFileName
            lastRestore       = Get-XmlVaultIsoTimestamp
            lastRestoreResult = $cleanupReason
            lastRestoreSource = $restoreSource
        } | Out-Null
        return
    }

    $vaultItem = Get-Item -LiteralPath $vaultPath -ErrorAction SilentlyContinue
    Update-XmlVaultState -Updates @{
        lastChecked                     = Get-XmlVaultIsoTimestamp
        result                          = "restore_verified"
        userProfile                     = $destFileName
        lastRestore                     = Get-XmlVaultIsoTimestamp
        lastRestoreResult               = "restore_verified"
        lastRestoreSource               = $restoreSource
        lastRestoreVaultLength          = if ($vaultItem) { [int64]$vaultItem.Length } else { $null }
        lastRestoreVaultLastWriteTimeUtc = if ($vaultItem) { Get-XmlVaultIsoTimestamp -DateTime $vaultItem.LastWriteTimeUtc } else { $null }
    } | Out-Null

    Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified' -ProfileName $destFileName -ProfileCount 1
    Invoke-XmlVaultTelemetry -Tag 'xml_vault_restore' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified' -ProfileName $destFileName

    # 7. Remove restore flag
    try {
        Remove-Item $RestoreFlag -Force -ErrorAction SilentlyContinue
        Write-VaultLog "XmlVault: restore flag removed ($RestoreFlag)" "DEBUG"
    } catch {
        Write-VaultLog "XmlVault: could not remove restore flag" "WARN"
    }

    # Write restore-complete flag
    try {
        (Get-Date -Format "o") | Set-Content $RestoreCompleteFlag -Encoding UTF8 -Force
        Write-VaultLog "XmlVault: restore complete flag written: $RestoreCompleteFlag" "INFO"
    } catch {
        Write-VaultLog "XmlVault: could not write restore complete flag" "WARN"
    }

    Write-VaultLog "===== XmlVault Restore Complete =====" "INFO"
}

# ================================= MAIN =======================================

Initialize-XmlVaultLogger

# --- BEGIN XmlVault standalone telemetry bootstrap (script scope) ---
# WW_tee.ps1 MUST be dot-sourced here, at script scope, not inside
# Initialize-XmlVaultTelemetry: a function-local dot-source discards
# Write-TeeLog as soon as the function returns, which silently disabled every
# XmlVault telemetry call. Loading it here keeps Write-TeeLog visible to
# Invoke-XmlVaultTelemetry for the whole run, while staying fail-soft.
$teePath = Initialize-XmlVaultTelemetry
if ($teePath) {
    try {
        . $teePath
    } catch {
        Write-VaultLog "XmlVault: failed to load WW_tee.ps1 - telemetry disabled for this run" "WARN"
    }
}
$null = Confirm-XmlVaultTelemetry
# --- END XmlVault standalone telemetry bootstrap ---

$bar = ('=' * 80)
Write-VaultLog $bar "INFO"
Write-VaultLog "XmlVault v1.0.5 Starting" "INFO"
Write-VaultLog ("User: {0}" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) "INFO"

# XmlVault's own FlareGun trigger IDs. 801 = sync, 802 = restore. Captive-portal
# FlareGun events (777/778) and every other WhiteWalker event ID are NOT XmlVault
# triggers and must never be interpreted as a sync/restore cause.
$XmlVaultSyncEventId    = 801
$XmlVaultRestoreEventId = 802
$XmlVaultTriggerEventIds = @($XmlVaultSyncEventId, $XmlVaultRestoreEventId)

# Determine mode: explicit -Restore switch takes precedence, then check for flag file, then read triggering event
$mode = "sync"
$modeReason = ""
$modeTelemetryReason = "default_sync"

if ($Restore) {
    $mode = "restore"
    $modeReason = "(-Restore switch)"
    $modeTelemetryReason = "explicit_restore_switch"
    Write-VaultLog "XmlVault: mode=restore $modeReason" "INFO"
} elseif (Test-Path $RestoreFlag) {
    $mode = "restore"
    $modeReason = "(xml_restore.flag present at $RestoreFlag)"
    $modeTelemetryReason = "restore_flag_present"
    Write-VaultLog "XmlVault: mode=restore $modeReason" "INFO"
} else {
    # Check triggering event (when launched by Task Scheduler) to distinguish 801 vs 802.
    # ONLY XmlVault's own trigger IDs count. The provider WhiteWalkerFlareGun also
    # carries unrelated captive-portal flares (777/778) and other WhiteWalker events;
    # reading the newest provider event of ANY ID made XmlVault report a captive
    # portal flare as its sync trigger. The query is now filtered by ID.
    try {
        $triggerEvent = Get-WinEvent -FilterHashtable @{
            LogName      = 'Application'
            ProviderName = 'WhiteWalkerFlareGun'
            Id           = $XmlVaultTriggerEventIds
        } -MaxEvents 1 -ErrorAction Stop

        Write-VaultLog ("XmlVault: triggering event ID={0} time={1}" -f $triggerEvent.Id, $triggerEvent.TimeCreated) "DEBUG"

        if ($triggerEvent.Id -eq $XmlVaultRestoreEventId) {
            $mode = "restore"
            $modeReason = "(Event ID $XmlVaultRestoreEventId)"
            $modeTelemetryReason = "event_id_$XmlVaultRestoreEventId"
            Write-VaultLog "XmlVault: mode=restore $modeReason" "INFO"
        } else {
            $modeTelemetryReason = ("event_id_{0}" -f $triggerEvent.Id)
            Write-VaultLog ("XmlVault: mode=sync (Event ID {0})" -f $triggerEvent.Id) "INFO"
        }
    } catch {
        $modeTelemetryReason = "no_trigger_event_default_sync"
        Write-VaultLog "XmlVault: no XmlVault trigger event (ID $($XmlVaultTriggerEventIds -join '/')) found - defaulting to sync mode" "DEBUG"
    }
}

if ($mode -eq "restore") {
    Invoke-XmlVaultTelemetry -Tag 'xml_vault_triggered' -Mode 'restore' -Status 'started' -Source 'local_vault' -Reason $modeTelemetryReason
    Invoke-XmlVaultRestore
} else {
    Invoke-XmlVaultTelemetry -Tag 'xml_vault_triggered' -Mode 'sync' -Status 'started' -Source 'netlogon' -Reason $modeTelemetryReason -ProfileCount $XmlFiles.Count
    Invoke-XmlVaultSync -Force:$Force
}

Write-VaultLog "XmlVault Exiting" "INFO"
Write-VaultLog $bar "INFO"

exit 0
