#Requires -RunAsAdministrator
<#
.SYNOPSIS
WW_xml_vault.ps1
Version: 1.0.3
Author: steve.horton@optum.com (with AI assist)
Purpose: XmlVault subsystem - offline VPN XML backup and island self-heal
Triggered by: Task Scheduler watching for WhiteWalkerFlareGun Event IDs 801 (sync) and 802 (restore)
Runs as: SYSTEM

.DESCRIPTION
XmlVault maintains a local backup vault of VPN profile XMLs synced from the NETLOGON share.
When a bad headend-pushed XML strands an endpoint (island scenario), XmlVault can restore
a known-good XML from the vault, allowing VPN reconnection.

Sync mode (Event ID 801 or direct call without -Restore):
   - Detects dev_vpn.txt flag to determine DEV vs PROD environment
   - Looks for dev_-prefixed XMLs on share in DEV mode
   - Copies all XMLs to local vault, stripping dev_ prefix on copy
   - Cooldown-gated (24h) to avoid hammering the share
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
    [switch]$Restore    # if present: restore mode. absent: sync/auto mode.
)

# ------------------------------- Config ---------------------------------------
$LogPath             = "C:\ProgramData\WhiteWalker\white_walker.xml_vault.log"
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

# ------------------------------- Env Detection --------------------------------
function Get-XmlVaultEnv {
    # Mirrors More-Sense set_env_val() exactly:
    # if dev_vpn.txt exists -> AOVPN-DEV, else -> AOVPN-PROD
    if (Test-Path -Path $DevFlag) {
        return "AOVPN-DEV"
    }
    return "AOVPN-PROD"
}

# ------------------------------- SYNC MODE ------------------------------------
function Invoke-XmlVaultSync {
    Write-VaultLog "===== XmlVault Sync Starting =====" "INFO"

    # 1. Cooldown check
    if (Test-Path $CooldownFlag) {
        try {
            $lastSync = [datetime]::Parse((Get-Content $CooldownFlag -Raw).Trim())
            $ageHours = ((Get-Date) - $lastSync).TotalHours
            if ($ageHours -lt $CooldownHours) {
                Write-VaultLog ("XmlVault: sync cooldown active ({0:N1}h old) - skipping" -f $ageHours) "DEBUG"
                return
            }
            Write-VaultLog ("XmlVault: cooldown expired ({0:N1}h old) - proceeding with sync" -f $ageHours) "INFO"
        } catch {
            Write-VaultLog "XmlVault: could not read cooldown flag - proceeding with sync" "WARN"
        }
    }

    # 2. Determine env and build remote dir
    $vaultEnv = Get-XmlVaultEnv
    $RemoteDir = "$RemoteBase\$vaultEnv"
    Write-VaultLog "XmlVault: env=$vaultEnv (flag_path=$DevFlag)" "INFO"
    Write-VaultLog "XmlVault: remote_dir=$RemoteDir" "INFO"

    # 3. Share reachability - do NOT update cooldown flag on failure so next run retries
    if (-not (Test-Path -LiteralPath $RemoteDir -ErrorAction SilentlyContinue)) {
        Write-VaultLog "XmlVault: share unreachable ($RemoteDir) - skipping sync (cooldown NOT updated)" "WARN"
        return
    }

    # 4. Vault dir creation with restricted ACL (SYSTEM + Administrators only)
    if (-not (Test-Path $VaultDir)) {
        try {
            New-Item -Path $VaultDir -ItemType Directory -Force | Out-Null
            Write-VaultLog "XmlVault: created vault dir $VaultDir" "INFO"
        } catch {
            Write-VaultLog "XmlVault: failed to create vault dir ${VaultDir}: $_" "ERROR"
            return
        }
    }

    try {
        $acl = Get-Acl $VaultDir
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, remove inherited rules
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
        Write-VaultLog "XmlVault: could not set vault ACL: $_ - continuing in degraded mode" "WARN"
    }

    # 5. Per-XML sync loop
    $synced  = 0
    $skipped = 0

    foreach ($filename in $XmlFiles) {
        # Determine remote filename based on dev/prod environment
        $remoteFilename = $filename
        if ($vaultEnv -eq "AOVPN-DEV") {
            $remoteFilename = "dev_$filename"
        }
        
        $remotePath = Join-Path $RemoteDir $remoteFilename
        $vaultPath  = Join-Path $VaultDir $filename  # Always store with plain name (stripped of dev_ prefix)

        # Remote file existence check
        if (-not (Test-Path -LiteralPath $remotePath)) {
            Write-VaultLog "XmlVault: $remoteFilename not found on share - skipping" "INFO"
            $skipped++
            continue
        }

        # Copy without validation (headend is trusted to validate)
        try {
            Copy-Item -LiteralPath $remotePath -Destination $vaultPath -Force -ErrorAction Stop
            if ($vaultEnv -eq "AOVPN-DEV") {
                Write-VaultLog "XmlVault: $remoteFilename copied to vault as $filename (dev_ prefix stripped)" "INFO"
            } else {
                Write-VaultLog "XmlVault: $filename copied to vault" "INFO"
            }
            $synced++
        } catch {
            Write-VaultLog "XmlVault: $remoteFilename copy failed: $_" "WARN"
            $skipped++
        }
    }

    # 6. Write cooldown flag (only after successful share contact)
    try {
        (Get-Date -Format "o") | Set-Content $CooldownFlag -Encoding UTF8 -Force
        Write-VaultLog "XmlVault: cooldown flag updated" "DEBUG"
    } catch {
        Write-VaultLog "XmlVault: could not write cooldown flag: $_" "WARN"
    }

    Write-VaultLog ("XmlVault: sync complete - synced={0} skipped={1}" -f $synced, $skipped) "INFO"

    # 7. Post-sync: check if dev flag exists
    if (Test-Path -Path $DevFlag) {
        Write-VaultLog "XmlVault: DEV flag present at $DevFlag (dev mode active)" "INFO"
    } else {
        Write-VaultLog "XmlVault: DEV flag not present at $DevFlag (PROD mode active)" "INFO"
    }

    Write-VaultLog "===== XmlVault Sync Complete =====" "INFO"
}

# ------------------------------- RESTORE MODE ---------------------------------
function Invoke-XmlVaultRestore {
    Write-VaultLog "===== XmlVault Restore Starting =====" "INFO"

    # 1. Check restore flag exists (belt-and-suspenders - TS fires when WW_main saw it, but be safe)
    if (-not (Test-Path $RestoreFlag)) {
        Write-VaultLog "XmlVault: restore flag not present ($RestoreFlag) - nothing to restore" "DEBUG"
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
        return
    }

    # 3. Get target XML name from registry
    $xmlName = $null
    try {
        $xmlName = (Get-ItemProperty -Path $RegPath -ErrorAction Stop).VPN
    } catch {
        Write-VaultLog "XmlVault: could not read registry at ${RegPath}: $_" "ERROR"
        return
    }

    if ([string]::IsNullOrWhiteSpace($xmlName)) {
        Write-VaultLog "XmlVault: registry VPN value is null/empty at $RegPath - cannot restore" "ERROR"
        return
    }

    # Ensure .xml extension
    if (-not $xmlName.EndsWith(".xml", [System.StringComparison]::OrdinalIgnoreCase)) {
        $xmlName = "$xmlName.xml"
    }

    Write-VaultLog "XmlVault: target XML from registry: $xmlName" "INFO"

    # 4. Dev flag check - mirrors More-Sense behavior:
    #    if dev flag exists -> prepend dev_ to vault lookup name, write to client dir as prod name
    $vaultEnv = Get-XmlVaultEnv
    $vaultLookupName = $xmlName
    $destFileName    = $xmlName

    if ($vaultEnv -eq "AOVPN-DEV") {
        $vaultLookupName = "dev_$xmlName"
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
            } else {
                Write-VaultLog "XmlVault: vault copy of $vaultLookupName (and fallback $xmlName) not found - cannot restore" "ERROR"
                return
            }
        } else {
            Write-VaultLog "XmlVault: vault copy of $vaultLookupName not found - cannot restore" "ERROR"
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
        Write-VaultLog "XmlVault: restore copy failed: $_" "ERROR"
        return
    }

    # Verify the copy landed
    if (-not (Test-Path $destPath)) {
        Write-VaultLog "XmlVault: [!!] restored file not found at $destPath after copy - verify permissions" "ERROR"
        return
    }

    Write-VaultLog "XmlVault: restore verified OK ($destPath)" "INFO"

    # 7. Remove restore flag
    try {
        Remove-Item $RestoreFlag -Force -ErrorAction SilentlyContinue
        Write-VaultLog "XmlVault: restore flag removed ($RestoreFlag)" "DEBUG"
    } catch {
        Write-VaultLog "XmlVault: could not remove restore flag: $_" "WARN"
    }

    # Write restore-complete flag
    try {
        (Get-Date -Format "o") | Set-Content $RestoreCompleteFlag -Encoding UTF8 -Force
        Write-VaultLog "XmlVault: restore complete flag written: $RestoreCompleteFlag" "INFO"
    } catch {
        Write-VaultLog "XmlVault: could not write restore complete flag: $_" "WARN"
    }

    Write-VaultLog "===== XmlVault Restore Complete =====" "INFO"
}

# ================================= MAIN =======================================

Initialize-XmlVaultLogger

$bar = ('=' * 80)
Write-VaultLog $bar "INFO"
Write-VaultLog "XmlVault v1.0.3 Starting" "INFO"
Write-VaultLog ("User: {0}" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) "INFO"

# Determine mode: explicit -Restore switch takes precedence, then check for flag file, then read triggering event
$mode = "sync"
$modeReason = ""

if ($Restore) {
    $mode = "restore"
    $modeReason = "(-Restore switch)"
    Write-VaultLog "XmlVault: mode=restore $modeReason" "INFO"
} elseif (Test-Path $RestoreFlag) {
    $mode = "restore"
    $modeReason = "(xml_restore.flag present at $RestoreFlag)"
    Write-VaultLog "XmlVault: mode=restore $modeReason" "INFO"
} else {
    # Check triggering event (when launched by Task Scheduler) to distinguish 801 vs 802
    try {
        $triggerEvent = Get-WinEvent -FilterHashtable @{
            LogName      = 'Application'
            ProviderName = 'WhiteWalkerFlareGun'
        } -MaxEvents 1 -ErrorAction Stop

        Write-VaultLog ("XmlVault: triggering event ID={0} time={1}" -f $triggerEvent.Id, $triggerEvent.TimeCreated) "DEBUG"

        if ($triggerEvent.Id -eq 802) {
            $mode = "restore"
            $modeReason = "(Event ID 802)"
            Write-VaultLog "XmlVault: mode=restore $modeReason" "INFO"
        } else {
            Write-VaultLog ("XmlVault: mode=sync (Event ID {0})" -f $triggerEvent.Id) "INFO"
        }
    } catch {
        Write-VaultLog "XmlVault: no triggering event found - defaulting to sync mode" "DEBUG"
    }
}

if ($mode -eq "restore") {
    Invoke-XmlVaultRestore
} else {
    Invoke-XmlVaultSync
}

Write-VaultLog "XmlVault Exiting" "INFO"
Write-VaultLog $bar "INFO"

exit 0
