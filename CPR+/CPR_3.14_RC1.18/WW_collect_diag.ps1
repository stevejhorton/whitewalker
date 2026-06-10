#Requires -RunAsAdministrator
<#
.SYNOPSIS
WhiteWalker Deep Diagnostics Collector

.DESCRIPTION
Version: 1.0.0
Author: steve.horton@optum.com
Date: 31-Oct-2025

Purpose: Collect comprehensive system diagnostics for troubleshooting
Triggered by: Task Scheduler on WhiteWalker event log message (ID TBD)

Collects:
- System uptime and boot time
- Hardware platform info (manufacturer, model, BIOS)
- OS version and build
- Network adapter details (all adapters, not just active)
- VPN client version and state history
- User context (username, domain, group memberships if available)
- Recent network events from event log
- Cisco client installation details
- Performance counters (optional)

Output: Single timestamped log file in C:\ProgramData\WhiteWalker\diagnostics\
#>

# Configuration
$DiagVersion = "1.0.0"
$DiagLogDir = "C:\ProgramData\WhiteWalker\diagnostics"
$DiagLogFile = Join-Path $DiagLogDir "diag_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$MaxDiagLogs = 10  # Keep only last 10 diagnostic logs

# Initialize diagnostic logging
function Initialize-DiagLogger {
    if (-not (Test-Path $DiagLogDir)) {
        try {
            New-Item -Path $DiagLogDir -ItemType Directory -Force | Out-Null
        } catch {
            Write-Host "ERROR: Cannot create diagnostics directory $DiagLogDir - $_"
            exit 1
        }
    }
    
    # Cleanup old diagnostic logs
    try {
        $oldLogs = Get-ChildItem -Path $DiagLogDir -Filter "diag_*.log" -File |
                   Sort-Object LastWriteTime -Descending |
                   Select-Object -Skip $MaxDiagLogs
        
        if ($oldLogs) {
            $oldLogs | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch { }
    
    try {
        New-Item -Path $DiagLogFile -ItemType File -Force | Out-Null
    } catch {
        Write-Host "WARNING: Cannot create diagnostic log file $DiagLogFile - $_"
    }
}

function Write-DiagLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
    $logLine = "$ts [$Level] $Message"
    
    try {
        Add-Content -Path $DiagLogFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
    
    # Also output to console for real-time visibility
    Write-Host $logLine
}

function Write-DiagSection {
    param([string]$Title)
    
    $bar = ("=" * 80)
    Write-DiagLog $bar
    Write-DiagLog $Title
    Write-DiagLog $bar
}

function Get-SystemUptime {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $lastBoot = $os.LastBootUpTime
        $uptime = (Get-Date) - $lastBoot
        
        return @{
            LastBootTime = $lastBoot.ToString("yyyy-MM-dd HH:mm:ss")
            Uptime = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
            UptimeSeconds = [math]::Round($uptime.TotalSeconds)
        }
    } catch {
        Write-DiagLog "Error getting system uptime: $_" "WARN"
        return @{
            LastBootTime = "Unknown"
            Uptime = "Unknown"
            UptimeSeconds = 0
        }
    }
}

function Get-HardwarePlatform {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $baseboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
        
        return @{
            Manufacturer = $cs.Manufacturer
            Model = $cs.Model
            SerialNumber = $bios.SerialNumber
            BIOSVersion = $bios.SMBIOSBIOSVersion
            BIOSDate = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
            SystemFamily = $cs.SystemFamily
            SystemSKU = $cs.SystemSKUNumber
            BaseboardProduct = if ($baseboard) { $baseboard.Product } else { "Unknown" }
            TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            ProcessorCount = $cs.NumberOfProcessors
            LogicalProcessors = $cs.NumberOfLogicalProcessors
        }
    } catch {
        Write-DiagLog "Error getting hardware platform: $_" "WARN"
        return @{
            Manufacturer = "Unknown"
            Model = "Unknown"
            SerialNumber = "Unknown"
        }
    }
}

function Get-OSDetails {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        
        return @{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            Architecture = $os.OSArchitecture
            InstallDate = $os.InstallDate.ToString("yyyy-MM-dd HH:mm:ss")
            RegisteredUser = $os.RegisteredUser
            Organization = $os.Organization
            Locale = $os.Locale
            TimeZone = (Get-TimeZone).DisplayName
        }
    } catch {
        Write-DiagLog "Error getting OS details: $_" "WARN"
        return @{
            Caption = "Unknown"
            Version = "Unknown"
        }
    }
}

function Get-NetworkAdapterDetails {
    # Get ALL network adapters (not just active ones)
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop
        
        $adapterInfo = @()
        foreach ($adapter in $adapters) {
            try {
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                
                $info = @{
                    Name = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    MacAddress = $adapter.MacAddress
                    MediaType = $adapter.MediaType
                    LinkSpeed = $adapter.LinkSpeed
                    Virtual = $adapter.Virtual
                    IPv4Address = if ($ipConfig -and $ipConfig.IPv4Address) { $ipConfig.IPv4Address.IPAddress } else { "N/A" }
                    IPv4Gateway = if ($ipConfig -and $ipConfig.IPv4DefaultGateway) { $ipConfig.IPv4DefaultGateway.NextHop } else { "N/A" }
                    DNSServers = if ($ipConfig) { 
                        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                        if ($dns) { $dns.ServerAddresses -join ', ' } else { "N/A" }
                    } else { "N/A" }
                }
                
                $adapterInfo += $info
            } catch {
                Write-DiagLog "Error getting details for adapter $($adapter.Name): $_" "DEBUG"
            }
        }
        
        return $adapterInfo
    } catch {
        Write-DiagLog "Error enumerating network adapters: $_" "WARN"
        return @()
    }
}

function Get-CiscoClientDetails {
    try {
        # Find Cisco installation
        $cands = @('HKLM:\SOFTWARE\Cisco\Cisco Secure Client','HKLM:\SOFTWARE\WOW6432Node\Cisco\Cisco Secure Client')
        $ciscoPath = $null
        $ciscoVersion = "Unknown"
        
        foreach ($key in $cands) {
            try {
                $val = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($val) {
                    if ($val.InstallPathWithSlash) {
                        $ciscoPath = $val.InstallPathWithSlash.TrimEnd('\')
                    }
                    if ($val.Version) {
                        $ciscoVersion = $val.Version
                    }
                    break
                }
            } catch { }
        }
        
        if (-not $ciscoPath) {
            foreach ($p in @('C:\Program Files\Cisco\Cisco Secure Client','C:\Program Files (x86)\Cisco\Cisco Secure Client')) {
                if (Test-Path $p) { 
                    $ciscoPath = $p
                    break
                }
            }
        }
        
        $vpncliPath = if ($ciscoPath) { Join-Path $ciscoPath "vpncli.exe" } else { $null }
        $posturecliPath = if ($ciscoPath) { Join-Path $ciscoPath "posturecli.exe" } else { $null }
        
        $vpncliExists = if ($vpncliPath) { Test-Path $vpncliPath } else { $false }
        $posturecliExists = if ($posturecliPath) { Test-Path $posturecliPath } else { $false }
        
        # Get VPN state if available
        $vpnState = "N/A"
        if ($vpncliExists) {
            try {
                $stateOutput = & $vpncliPath state 2>$null | Out-String
                # Use LAST >> state: line (first line contains stale data)
                $stateMatches = [regex]::Matches($stateOutput, '(?im)^\s*>>\s*state:\s*(\w+)\s*$')
                if ($stateMatches.Count -gt 0) {
                    $vpnState = $stateMatches[$stateMatches.Count - 1].Groups[1].Value
                } else {
                    $vpnState = "Unknown"
                }
            } catch { }
        }
        
        # Check for Cisco services
        $ciscoServices = @()
        try {
            $services = Get-Service -Name "csc_*","Cisco*" -ErrorAction SilentlyContinue
            foreach ($svc in $services) {
                $ciscoServices += @{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = $svc.Status
                    StartType = $svc.StartType
                }
            }
        } catch { }
        
        return @{
            InstallPath = if ($ciscoPath) { $ciscoPath } else { "Not Found" }
            Version = $ciscoVersion
            VPNCLIExists = $vpncliExists
            PostureCLIExists = $posturecliExists
            CurrentVPNState = $vpnState
            Services = $ciscoServices
        }
    } catch {
        Write-DiagLog "Error getting Cisco client details: $_" "WARN"
        return @{
            InstallPath = "Error"
            Version = "Unknown"
        }
    }
}

function Get-UserContext {
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        
        $userInfo = @{
            Username = $currentUser.Name
            AuthenticationType = $currentUser.AuthenticationType
            IsSystem = $currentUser.IsSystem
            IsGuest = $currentUser.IsGuest
            IsAuthenticated = $currentUser.IsAuthenticated
        }
        
        # Try to get domain info
        try {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
            $userInfo.Domain = $domain.Name
            $userInfo.DomainController = $domain.PdcRoleOwner.Name
        } catch {
            $userInfo.Domain = "Not domain-joined or error"
            $userInfo.DomainController = "N/A"
        }
        
        # Try to get group memberships (may fail if not running as user)
        try {
            $groups = $currentUser.Groups | ForEach-Object {
                try {
                    $_.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $_.Value
                }
            }
            $userInfo.GroupCount = $groups.Count
            $userInfo.Groups = $groups -join '; '
        } catch {
            $userInfo.GroupCount = 0
            $userInfo.Groups = "Unable to enumerate (running as SYSTEM)"
        }
        
        return $userInfo
    } catch {
        Write-DiagLog "Error getting user context: $_" "WARN"
        return @{
            Username = "Unknown"
        }
    }
}

function Get-RecentNetworkEvents {
    # Get recent network-related events from event logs
    try {
        $events = @()
        
        # Get recent WhiteWalker events
        try {
            $wwEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                ProviderName = 'WhiteWalker','WhiteWalkerTrigger'
            } -MaxEvents 20 -ErrorAction SilentlyContinue
            
            foreach ($event in $wwEvents) {
                $events += @{
                    TimeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    Source = $event.ProviderName
                    EventID = $event.Id
                    Level = $event.LevelDisplayName
                    Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                }
            }
        } catch { }
        
        # Get recent DHCP events
        try {
            $dhcpEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Microsoft-Windows-Dhcp-Client'
            } -MaxEvents 10 -ErrorAction SilentlyContinue
            
            foreach ($event in $dhcpEvents) {
                $events += @{
                    TimeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    Source = "DHCP-Client"
                    EventID = $event.Id
                    Level = $event.LevelDisplayName
                    Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                }
            }
        } catch { }
        
        # Get recent network profile changes
        try {
            $netEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Microsoft-Windows-NetworkProfile'
            } -MaxEvents 10 -ErrorAction SilentlyContinue
            
            foreach ($event in $netEvents) {
                $events += @{
                    TimeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    Source = "NetworkProfile"
                    EventID = $event.Id
                    Level = $event.LevelDisplayName
                    Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                }
            }
        } catch { }
        
        # Sort all events by time
        $events = $events | Sort-Object TimeCreated -Descending
        
        return $events
    } catch {
        Write-DiagLog "Error getting recent network events: $_" "WARN"
        return @()
    }
}

function Get-WiFiProfiles {
    # Get saved WiFi profiles
    try {
        $profiles = @()
        $netshOutput = netsh wlan show profiles 2>$null
        
        if ($netshOutput) {
            $profileLines = $netshOutput | Select-String "All User Profile\s+:\s+(.+)" -AllMatches
            
            foreach ($line in $profileLines) {
                $profileName = $line.Matches.Groups[1].Value.Trim()
                $profiles += $profileName
            }
        }
        
        return $profiles
    } catch {
        Write-DiagLog "Error getting WiFi profiles: $_" "WARN"
        return @()
    }
}

# ================================= MAIN =======================================

Initialize-DiagLogger

Write-DiagSection "WhiteWalker Deep Diagnostics Collection v$DiagVersion"
Write-DiagLog "Collection started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-DiagLog "Computer: $env:COMPUTERNAME"
Write-DiagLog "User: $env:USERNAME"
Write-DiagLog ""

# System Uptime
Write-DiagSection "SYSTEM UPTIME"
$uptime = Get-SystemUptime
Write-DiagLog "Last Boot Time: $($uptime.LastBootTime)"
Write-DiagLog "Uptime: $($uptime.Uptime) ($($uptime.UptimeSeconds) seconds)"
Write-DiagLog ""

# Hardware Platform
Write-DiagSection "HARDWARE PLATFORM"
$hw = Get-HardwarePlatform
Write-DiagLog "Manufacturer: $($hw.Manufacturer)"
Write-DiagLog "Model: $($hw.Model)"
Write-DiagLog "Serial Number: $($hw.SerialNumber)"
Write-DiagLog "System Family: $($hw.SystemFamily)"
Write-DiagLog "System SKU: $($hw.SystemSKU)"
Write-DiagLog "Baseboard: $($hw.BaseboardProduct)"
Write-DiagLog "BIOS Version: $($hw.BIOSVersion)"
Write-DiagLog "BIOS Date: $($hw.BIOSDate)"
Write-DiagLog "Total Memory: $($hw.TotalMemoryGB) GB"
Write-DiagLog "Processors: $($hw.ProcessorCount) physical, $($hw.LogicalProcessors) logical"
Write-DiagLog ""

# Operating System
Write-DiagSection "OPERATING SYSTEM"
$os = Get-OSDetails
Write-DiagLog "OS: $($os.Caption)"
Write-DiagLog "Version: $($os.Version)"
Write-DiagLog "Build: $($os.BuildNumber)"
Write-DiagLog "Architecture: $($os.Architecture)"
Write-DiagLog "Install Date: $($os.InstallDate)"
Write-DiagLog "Registered User: $($os.RegisteredUser)"
Write-DiagLog "Organization: $($os.Organization)"
Write-DiagLog "Time Zone: $($os.TimeZone)"
Write-DiagLog ""

# User Context
Write-DiagSection "USER CONTEXT"
$user = Get-UserContext
Write-DiagLog "Username: $($user.Username)"
Write-DiagLog "Authentication Type: $($user.AuthenticationType)"
Write-DiagLog "Is System: $($user.IsSystem)"
Write-DiagLog "Is Authenticated: $($user.IsAuthenticated)"
Write-DiagLog "Domain: $($user.Domain)"
Write-DiagLog "Domain Controller: $($user.DomainController)"
Write-DiagLog "Group Memberships: $($user.GroupCount) groups"
if ($user.Groups -and $user.Groups.Length -lt 500) {
    Write-DiagLog "Groups: $($user.Groups)"
}
Write-DiagLog ""

# Cisco Client Details
Write-DiagSection "CISCO SECURE CLIENT"
$cisco = Get-CiscoClientDetails
Write-DiagLog "Install Path: $($cisco.InstallPath)"
Write-DiagLog "Version: $($cisco.Version)"
Write-DiagLog "vpncli.exe exists: $($cisco.VPNCLIExists)"
Write-DiagLog "posturecli.exe exists: $($cisco.PostureCLIExists)"
Write-DiagLog "Current VPN State: $($cisco.CurrentVPNState)"
Write-DiagLog ""
Write-DiagLog "Cisco Services:"
foreach ($svc in $cisco.Services) {
    Write-DiagLog "  - $($svc.DisplayName) ($($svc.Name)): $($svc.Status) / $($svc.StartType)"
}
Write-DiagLog ""

# Network Adapters
Write-DiagSection "NETWORK ADAPTERS"
$adapters = Get-NetworkAdapterDetails
Write-DiagLog "Total Adapters: $($adapters.Count)"
Write-DiagLog ""
foreach ($adapter in $adapters) {
    Write-DiagLog "Adapter: $($adapter.Name)"
    Write-DiagLog "  Description: $($adapter.InterfaceDescription)"
    Write-DiagLog "  Status: $($adapter.Status)"
    Write-DiagLog "  MAC: $($adapter.MacAddress)"
    Write-DiagLog "  Media: $($adapter.MediaType)"
    Write-DiagLog "  Speed: $($adapter.LinkSpeed)"
    Write-DiagLog "  Virtual: $($adapter.Virtual)"
    Write-DiagLog "  IPv4: $($adapter.IPv4Address)"
    Write-DiagLog "  Gateway: $($adapter.IPv4Gateway)"
    Write-DiagLog "  DNS: $($adapter.DNSServers)"
    Write-DiagLog ""
}

# WiFi Profiles
Write-DiagSection "SAVED WIFI PROFILES"
$wifiProfiles = Get-WiFiProfiles
if ($wifiProfiles.Count -gt 0) {
    Write-DiagLog "Found $($wifiProfiles.Count) saved WiFi profiles:"
    foreach ($profile in $wifiProfiles) {
        Write-DiagLog "  - $profile"
    }
} else {
    Write-DiagLog "No saved WiFi profiles found"
}
Write-DiagLog ""

# Recent Network Events
Write-DiagSection "RECENT NETWORK EVENTS (Last 40 events)"
$events = Get-RecentNetworkEvents
if ($events.Count -gt 0) {
    foreach ($event in $events) {
        Write-DiagLog "[$($event.TimeCreated)] $($event.Source) ID:$($event.EventID) ($($event.Level))"
        Write-DiagLog "  $($event.Message)"
        Write-DiagLog ""
    }
} else {
    Write-DiagLog "No recent network events found"
}

# Summary
Write-DiagSection "DIAGNOSTIC COLLECTION COMPLETE"
Write-DiagLog "Collection completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-DiagLog "Log file: $DiagLogFile"
Write-DiagLog "Log size: $([math]::Round((Get-Item $DiagLogFile).Length / 1KB, 2)) KB"
Write-DiagLog ""
Write-DiagLog "This diagnostic log can be shared with Optum VPN SLO team for troubleshooting."

exit 0
