# CPR RC2 network, connectivity, redirect, and walled-garden checks.
# Depends on: Main.Logging.ps1 and Main.Configuration.ps1.

# ---------------------- Connectivity & Redirect Checks -----------------------
function Get-WlanSsidForAdapter {
    <#
    .SYNOPSIS
    Return the SSID reported by 'netsh wlan show interfaces' for a given WiFi adapter.

    .DESCRIPTION
    netsh remains the SSID source of truth (more reliable than Get-NetConnectionProfile).
    When more than one WLAN interface is present, the output is split into per-interface
    blocks (each block starts with a 'Name : <alias>' line) and only the block belonging
    to $AdapterName is parsed. If no per-interface block can be matched (single adapter,
    or unexpected output shape) the whole output is parsed - preserving pre-RC1.24 behavior.

    The "SSID is not an IP address" guard is preserved: a VPN/virtual interface can make
    netsh echo an IP address in the SSID position, which must never be treated as an SSID.
    Returns "N/A" when no valid SSID can be determined.
    #>
    param([string]$AdapterName = "")

    try {
        $netshOutput = netsh wlan show interfaces 2>$null | Out-String
        if (-not $netshOutput) { return "N/A" }

        # Scope to this adapter's block when netsh reports multiple WLAN interfaces
        $block = $netshOutput
        if ($AdapterName -and ($netshOutput -match '(?m)^\s*Name\s*:')) {
            $blocks = [regex]::Split($netshOutput, '(?m)^(?=\s*Name\s*:)') | Where-Object { $_ -match '\S' }
            $scoped = $blocks | Where-Object {
                $_ -match "(?m)^\s*Name\s*:\s*$([regex]::Escape($AdapterName))\s*$"
            } | Select-Object -First 1
            if ($scoped) { $block = $scoped }
        }

        if ($block -notmatch '(?m)^\s*State\s*:\s*connected') {
            Write-Log "WiFi adapter '$AdapterName' present but not connected (State != connected)" "DEBUG"
            return "N/A"
        }

        if ($block -match '(?m)^\s*SSID\s*:\s*(.+)$') {
            $ssidCandidate = $matches[1].Trim()

            # Validate SSID is not an IP address (VPN interface bug)
            if ($ssidCandidate -and
                $ssidCandidate -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and
                $ssidCandidate -ne "Identifying..." -and
                $ssidCandidate.Length -gt 0) {
                Write-Log "WiFi SSID detected on '$AdapterName': $ssidCandidate" "DEBUG"
                return $ssidCandidate
            } else {
                Write-Log "SSID validation failed: '$ssidCandidate' - may be transient state or VPN interface" "DEBUG"
            }
        } else {
            Write-Log "WiFi connected but could not extract SSID from netsh output" "DEBUG"
        }
    } catch {
        Write-Log "Could not retrieve SSID via netsh wlan: $_" "DEBUG"
    }

    return "N/A"
}

function Get-CprAdapterClass {
    param($Adapter)

    if ($null -eq $Adapter) { return 'unknown' }
    $identity = @(
        [string]$Adapter.Name, [string]$Adapter.InterfaceDescription,
        [string]$Adapter.MediaType, [string]$Adapter.NdisPhysicalMedium
    ) -join ' '
    if ($identity -match '(?i)Cisco|AnyConnect|VPN|TAP|Tunnel|WAN Miniport') { return 'vpn' }
    if ($Adapter.Virtual -eq $true -or $identity -match '(?i)Virtual|Hyper-V|Loopback') { return 'virtual' }
    if ($identity -match '(?i)Wi-?Fi|Wireless|802\.11|Native 802\.11') { return 'wifi' }
    if ($identity -match '(?i)Ethernet|802\.3|\bLAN\b') { return 'ethernet' }
    return 'unknown'
}

function Get-CprNetworkFingerprint {
    param($NetworkInfo)
    if ($null -eq $NetworkInfo) { return '' }
    return (@(
        [string]$NetworkInfo.InterfaceIndex,
        [string]$NetworkInfo.InterfaceGuid,
        [string]$NetworkInfo.IPAddress,
        [string]$NetworkInfo.DefaultGateway,
        [string]$NetworkInfo.SSID,
        [string]$NetworkInfo.OperationalState
    ) -join '|').ToLowerInvariant()
}

function Get-NetworkInfo {
    <#
    .SYNOPSIS
    Gather network state for ALL active physical adapters (RC1.24).

    .DESCRIPTION
    Pre-RC1.24 this function did 'Select-Object -First 1' on the active physical adapters,
    so on a docked laptop with WiFi still enabled only one of Ethernet/WiFi was ever visible
    to CPR - the other adapter's IP/DNS/gateway/suffix data was silently dropped, and which
    one won depended on Get-NetAdapter enumeration order (not a stable ordering).

    Now every adapter matching the physical / non-virtual / non-VPN filter is enumerated and
    returned in .Adapters (one record per adapter, including that adapter's connection-specific
    DNS suffix from Get-DnsClient). The flat fields (ConnectionType/IPAddress/SSID/...) remain
    for backward compatibility with existing callers and describe the PRIMARY adapter.

    PRIMARY ADAPTER PRECEDENCE RULE (documented behavioral decision):
      1. The adapter owning the active IPv4 default route with the lowest total metric
         (route metric + interface metric) - i.e. the interface Windows actually routes over.
      2. If route information is unavailable/ambiguous (tie, or no default route found):
         prefer Ethernet over WiFi.
      3. If still ambiguous: the first adapter that has a usable IPv4 address.
      4. Otherwise: the first active adapter found (pre-RC1.24 behavior).

    DNSSuffixes is the deduplicated union of:
      - every active adapter's connection-specific DNS suffix (NEW in RC1.24),
      - the machine-wide suffix search list (Get-DnsClientGlobalSetting),
      - the primary domain suffix (IPGlobalProperties().DomainName).

    DHCP LEASE DURATION (RC1.24):
    Each adapter record also carries LeaseObtained / LeaseExpires (human readable,
    ipconfig /all style) and LeaseDurationSeconds (numeric, $null when the adapter has
    no DHCP lease - e.g. a statically configured NIC). A lease shorter than
    $DhcpLeaseShortWarnSeconds is logged as a WARN right here: abnormally short leases
    make the DHCP client renew constantly, which re-triggers CPR's network checks and
    looks like a CPR loop when the root cause is actually the DHCP scope/relay.
    The WARN is purely diagnostic - it never changes control flow.
    #>
    $snapshotStartedAt = Get-Date
    $ssidDiscoveryMs = 0
    $adapterEnumerationMs = 0
    $ipAddressMs = 0
    $gatewayMs = 0
    $dnsMs = 0
    $leaseMs = 0
    $netInfo = @{
        CapturedAt = $snapshotStartedAt.ToString('o')
        SSID = "N/A"
        InterfaceName = "N/A"
        InterfaceIndex = $null
        InterfaceGuid = ""
        AdapterIdentifier = ""
        AdapterClass = "unknown"
        OperationalState = "Unknown"
        IPAddress = "N/A"
        PrefixLength = $null
        SubnetMask = "N/A"
        DefaultGateway = "N/A"
        DNSServers = @()
        DNSSuffixes = @()
        MACAddress = "N/A"
        ConnectionType = "Unknown"
        ConnectionSpecificSuffix = "N/A"
        LeaseObtained            = "N/A"
        LeaseExpires             = "N/A"
        LeaseDurationSeconds     = $null
        Adapters = @()
        ActiveAdapterCount = 0
        MultipleActiveAdapters = $false
    }

    try {
        # Get active PHYSICAL network adapters only (exclude VPN virtual adapters)
        $adapterStartedAt = Get-Date
        $activeAdapters = @(Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            $_.Virtual -eq $false -and
            $_.InterfaceDescription -notmatch 'Cisco|VPN|TAP|Virtual|Tunnel|WAN Miniport|AnyConnect'
        })
        $adapterEnumerationMs = ((Get-Date) - $adapterStartedAt).TotalMilliseconds

        if ($activeAdapters.Count -gt 0) {
            # Default route table once - used for primary adapter selection (rule #1)
            $defaultRoutes = @()
            try {
                $defaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
            } catch { }

            # Filter at the provider. The former broad CIM query materialized every
            # adapter configuration before PowerShell filtered it and dominated cold
            # discovery on managed endpoints.
            $dhcpConfigs = @()
            $leaseStartedAt = Get-Date
            try {
                $dhcpConfigs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
                    -Filter 'IPEnabled = TRUE AND DHCPEnabled = TRUE' -ErrorAction SilentlyContinue)
            } catch {
                Write-Log "Could not query Win32_NetworkAdapterConfiguration for DHCP lease info: $_" "DEBUG"
            }
            $leaseMs = ((Get-Date) - $leaseStartedAt).TotalMilliseconds

            $adapterRecords = [System.Collections.Generic.List[object]]::new()
            $suffixList     = [System.Collections.Generic.List[string]]::new()

            foreach ($adapter in $activeAdapters) {
                $record = @{
                    InterfaceName            = $adapter.Name
                    InterfaceIndex           = $adapter.InterfaceIndex
                    InterfaceGuid            = [string]$adapter.InterfaceGuid
                    AdapterIdentifier        = if ($adapter.InterfaceGuid) { [string]$adapter.InterfaceGuid } else { [string]$adapter.InterfaceIndex }
                    AdapterClass             = Get-CprAdapterClass -Adapter $adapter
                    OperationalState         = [string]$adapter.Status
                    MACAddress               = $adapter.MacAddress
                    ConnectionType           = "Unknown"
                    SSID                     = "N/A"
                    IPAddress                = "N/A"
                    PrefixLength             = $null
                    SubnetMask               = "N/A"
                    DefaultGateway           = "N/A"
                    DNSServers               = @()
                    ConnectionSpecificSuffix = "N/A"
                    LeaseObtained            = "N/A"
                    LeaseExpires             = "N/A"
                    LeaseDurationSeconds     = $null
                    RouteMetric              = $null
                }

                # Determine connection type (name-match logic unchanged)
                if ($record.AdapterClass -eq 'wifi') {
                    $record.ConnectionType = "WiFi"
                    $ssidStartedAt = Get-Date
                    $record.SSID = Get-WlanSsidForAdapter -AdapterName $adapter.Name
                    $ssidDiscoveryMs += ((Get-Date) - $ssidStartedAt).TotalMilliseconds
                } elseif ($record.AdapterClass -eq 'ethernet') {
                    $record.ConnectionType = "Ethernet"
                }

                # Targeted cmdlets avoid Get-NetIPConfiguration's broad internal
                # adapter/CIM aggregation. Fail-soft behavior and safety gates remain.
                $ipStartedAt = Get-Date
                $ipv4 = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 `
                    -ErrorAction SilentlyContinue | Where-Object {
                        $_.IPAddress -and $_.IPAddress -notmatch '^127\.'
                    } | Select-Object -First 1
                $ipAddressMs += ((Get-Date) - $ipStartedAt).TotalMilliseconds
                if ($ipv4) {
                    $record.IPAddress  = $ipv4.IPAddress
                    $record.SubnetMask = $ipv4.PrefixLength
                    $record.PrefixLength = $ipv4.PrefixLength
                }

                $gwStartedAt = Get-Date
                $gw = $defaultRoutes | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex } |
                    Sort-Object RouteMetric | Select-Object -First 1
                if (-not $gw) {
                    try {
                        $gw = Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex `
                            -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                            Sort-Object RouteMetric | Select-Object -First 1
                    } catch { }
                }
                $gatewayMs += ((Get-Date) - $gwStartedAt).TotalMilliseconds
                if ($gw) { $record.DefaultGateway = $gw.NextHop }

                $dnsStartedAt = Get-Date
                $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex `
                    -AddressFamily IPv4 -ErrorAction SilentlyContinue
                $dnsMs += ((Get-Date) - $dnsStartedAt).TotalMilliseconds
                if ($dns -and $dns.ServerAddresses) { $record.DNSServers = @($dns.ServerAddresses) }

                # Per-adapter connection-specific DNS suffix (RC1.24 - previously never queried)
                try {
                    $dnsClient = Get-DnsClient -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($dnsClient -and -not [string]::IsNullOrWhiteSpace($dnsClient.ConnectionSpecificSuffix)) {
                        $connSuffix = $dnsClient.ConnectionSpecificSuffix.ToLower().Trim()
                        $record.ConnectionSpecificSuffix = $connSuffix
                        if ($suffixList -notcontains $connSuffix) { $suffixList.Add($connSuffix) | Out-Null }
                    }
                } catch {
                    Write-Log "Could not retrieve connection-specific suffix for $($adapter.Name): $_" "DEBUG"
                }

                # DHCP lease timing for this adapter (RC1.24).
                # Fail-soft: a statically configured adapter simply has no lease data.
                try {
                    $dhcpCfg = $dhcpConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex } | Select-Object -First 1
                    if ($dhcpCfg -and $dhcpCfg.DHCPLeaseObtained -and $dhcpCfg.DHCPLeaseExpires) {
                        $leaseObtained = [datetime]$dhcpCfg.DHCPLeaseObtained
                        $leaseExpires  = [datetime]$dhcpCfg.DHCPLeaseExpires
                        $leaseSeconds  = [int][math]::Round(($leaseExpires - $leaseObtained).TotalSeconds)

                        # ipconfig /all style timestamps so log output is familiar during triage
                        $record.LeaseObtained        = $leaseObtained.ToString('dddd, MMMM d, yyyy h:mm:ss tt')
                        $record.LeaseExpires         = $leaseExpires.ToString('dddd, MMMM d, yyyy h:mm:ss tt')
                        $record.LeaseDurationSeconds = $leaseSeconds

                        if ($leaseSeconds -lt $DhcpLeaseShortWarnSeconds) {
                            Write-Log ("DHCP lease on $($adapter.Name) is abnormally short (${leaseSeconds}s) - " +
                                       "possible DHCP scope/relay misconfiguration, may cause frequent renewal/CPR re-trigger") "WARN"
                        } else {
                            Write-Log "DHCP lease on $($adapter.Name): ${leaseSeconds}s (obtained $($record.LeaseObtained), expires $($record.LeaseExpires))" "DEBUG"
                        }
                    } else {
                        Write-Log "No DHCP lease data for $($adapter.Name) (static address or lease info unavailable)" "DEBUG"
                    }
                } catch {
                    Write-Log "Could not determine DHCP lease duration for $($adapter.Name): $_" "DEBUG"
                }

                # Default route metric for this adapter (primary selection rule #1)
                $route = $defaultRoutes | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex } | Select-Object -First 1
                if ($route) {
                    $metric = 0
                    try { $metric = [int]$route.RouteMetric } catch { }
                    try { $metric += [int]$route.InterfaceMetric } catch { }
                    $record.RouteMetric = $metric
                }

                $adapterRecords.Add($record) | Out-Null
            }

            $netInfo.Adapters               = @($adapterRecords)
            $netInfo.ActiveAdapterCount     = $adapterRecords.Count
            $netInfo.MultipleActiveAdapters = ($adapterRecords.Count -gt 1)

            if ($adapterRecords.Count -gt 1) {
                $summary = ($adapterRecords | ForEach-Object { "$($_.ConnectionType)/$($_.InterfaceName)" }) -join ', '
                Write-Log "Multiple active physical adapters detected ($($adapterRecords.Count)): $summary" "INFO"
            }

            # ---- Primary adapter selection (see precedence rule in help block) ----
            $primary = $null

            # Rule 1: adapter owning the active default route with the lowest total metric
            $routed = @($adapterRecords | Where-Object { $null -ne $_.RouteMetric } | Sort-Object { $_.RouteMetric })
            if ($routed.Count -eq 1) {
                $primary = $routed[0]
            } elseif ($routed.Count -gt 1 -and $routed[0].RouteMetric -lt $routed[1].RouteMetric) {
                $primary = $routed[0]
            }

            # Rule 2: route info ambiguous/unavailable - prefer Ethernet over WiFi
            if (-not $primary) {
                $candidates = if ($routed.Count -gt 1) { $routed } else { $adapterRecords }
                $primary = $candidates | Where-Object { $_.ConnectionType -eq 'Ethernet' } | Select-Object -First 1
                if (-not $primary) {
                    $primary = $candidates | Where-Object { $_.ConnectionType -eq 'WiFi' } | Select-Object -First 1
                }
            }

            # Rule 3: first adapter with a usable IPv4 address
            if (-not $primary) {
                $primary = $adapterRecords | Where-Object { $_.IPAddress -ne 'N/A' } | Select-Object -First 1
            }

            # Rule 4: first active adapter (pre-RC1.24 behavior)
            if (-not $primary) { $primary = $adapterRecords[0] }

            $netInfo.InterfaceName            = $primary.InterfaceName
            $netInfo.InterfaceIndex           = $primary.InterfaceIndex
            $netInfo.InterfaceGuid            = $primary.InterfaceGuid
            $netInfo.AdapterIdentifier        = $primary.AdapterIdentifier
            $netInfo.AdapterClass             = $primary.AdapterClass
            $netInfo.OperationalState         = $primary.OperationalState
            $netInfo.MACAddress               = $primary.MACAddress
            $netInfo.ConnectionType           = $primary.ConnectionType
            $netInfo.SSID                     = $primary.SSID
            $netInfo.IPAddress                = $primary.IPAddress
            $netInfo.SubnetMask               = $primary.SubnetMask
            $netInfo.PrefixLength              = $primary.PrefixLength
            $netInfo.DefaultGateway           = $primary.DefaultGateway
            $netInfo.DNSServers               = $primary.DNSServers
            $netInfo.ConnectionSpecificSuffix = $primary.ConnectionSpecificSuffix
            $netInfo.LeaseObtained            = $primary.LeaseObtained
            $netInfo.LeaseExpires             = $primary.LeaseExpires
            $netInfo.LeaseDurationSeconds     = $primary.LeaseDurationSeconds

            # DNS Search Suffixes: per-adapter connection-specific (above) + global list + domain
            try {
                # Method 1: Global DNS suffix search list (DHCP/GPO-pushed)
                $dnsGlobal = Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue
                if ($dnsGlobal -and $dnsGlobal.SuffixSearchList) {
                    foreach ($s in $dnsGlobal.SuffixSearchList) {
                        $clean = $s.ToLower().Trim()
                        if (-not [string]::IsNullOrWhiteSpace($clean) -and $suffixList -notcontains $clean) {
                            $suffixList.Add($clean) | Out-Null
                        }
                    }
                }
                # Method 2: Primary DNS suffix from computer domain membership
                try {
                    $primaryDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
                    if (-not [string]::IsNullOrWhiteSpace($primaryDomain)) {
                        $cleanPrimary = $primaryDomain.ToLower().Trim()
                        if ($cleanPrimary -notin @('(none)', 'none') -and $suffixList -notcontains $cleanPrimary) {
                            $suffixList.Add($cleanPrimary) | Out-Null
                        }
                    }
                } catch { }
                $netInfo.DNSSuffixes = @($suffixList | Select-Object -Unique)
            } catch {
                Write-Log "Could not retrieve DNS suffixes: $_" "DEBUG"
            }
        }
    } catch {
        Write-Log "Error gathering network info: $_" "WARN"
    }

    $netInfo.Fingerprint = Get-CprNetworkFingerprint -NetworkInfo $netInfo
    $snapshotElapsedMs = [math]::Round(((Get-Date) - $snapshotStartedAt).TotalMilliseconds)
    Write-Log ("phase_timing phase='network_context_snapshot' elapsed_ms={0} adapter_ip_gateway_ms={1} ssid_discovery_ms={2} adapter_count={3} adapter_enumeration_ms={4} ip_address_ms={5} gateway_ms={6} dns_ms={7} lease_ms={8}" -f `
        $snapshotElapsedMs, [math]::Round([math]::Max(0, $snapshotElapsedMs - $ssidDiscoveryMs)), `
        [math]::Round($ssidDiscoveryMs), $netInfo.ActiveAdapterCount, [math]::Round($adapterEnumerationMs), `
        [math]::Round($ipAddressMs), [math]::Round($gatewayMs), [math]::Round($dnsMs), [math]::Round($leaseMs)) "INFO"
    return $netInfo
}

function Test-CprNetworkSnapshotFresh {
    param($Snapshot, [int]$MaxAgeSeconds = $NetworkSnapshotMaxAgeSec)

    $result = [ordered]@{ Fresh = $false; Reason = 'missing_snapshot'; Fingerprint = ''; CheckedAt = (Get-Date).ToString('o') }
    if ($null -eq $Snapshot -or -not $Snapshot.CapturedAt -or $null -eq $Snapshot.InterfaceIndex) { return [pscustomobject]$result }
    try {
        if (((Get-Date) - [datetime]$Snapshot.CapturedAt).TotalSeconds -gt $MaxAgeSeconds) {
            $result.Reason = 'ttl_expired'; return [pscustomobject]$result
        }
    } catch { $result.Reason = 'invalid_capture_time'; return [pscustomobject]$result }

    try {
        $adapter = Get-NetAdapter -InterfaceIndex $Snapshot.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter -or $adapter.Status -ne 'Up') { $result.Reason = 'adapter_unavailable'; return [pscustomobject]$result }
        $ip = Get-NetIPAddress -InterfaceIndex $Snapshot.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^127\.' } | Select-Object -First 1
        $route = Get-NetRoute -InterfaceIndex $Snapshot.InterfaceIndex -DestinationPrefix '0.0.0.0/0' `
            -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
        $ssid = 'N/A'
        if ($Snapshot.AdapterClass -eq 'wifi') { $ssid = Get-WlanSsidForAdapter -AdapterName $adapter.Name }
        $probe = @{
            InterfaceIndex = $adapter.InterfaceIndex; InterfaceGuid = [string]$adapter.InterfaceGuid
            IPAddress = if ($ip) { [string]$ip.IPAddress } else { 'N/A' }
            DefaultGateway = if ($route) { [string]$route.NextHop } else { 'N/A' }
            SSID = $ssid; OperationalState = [string]$adapter.Status
        }
        $result.Fingerprint = Get-CprNetworkFingerprint -NetworkInfo $probe
        $result.Fresh = ($result.Fingerprint -eq [string]$Snapshot.Fingerprint)
        $result.Reason = if ($result.Fresh) { 'fingerprint_match' } else { 'fingerprint_changed' }
    } catch {
        $result.Reason = 'freshness_check_failed'
    }
    return [pscustomobject]$result
}

function Get-CprCurrentNetworkSnapshot {
    param($Snapshot, [switch]$Force)
    if (-not $Force) {
        $check = Test-CprNetworkSnapshotFresh -Snapshot $Snapshot
        Write-Log "network_snapshot_freshness fresh=$($check.Fresh) reason='$($check.Reason)' fingerprint='$($check.Fingerprint)'" "DEBUG"
        if ($check.Fresh) { return $Snapshot }
    }
    Write-Log "Network snapshot invalid or expired - rebuilding authoritative snapshot" "INFO"
    return Get-NetworkInfo
}

function Get-CprConnectionTelemetry {
    param($NetworkInfo)
    $result = [ordered]@{ connection_type = 'Unknown'; ssid = 'N/A' }
    if ($null -eq $NetworkInfo) { return [pscustomobject]$result }

    $usable = $NetworkInfo.IPAddress -and $NetworkInfo.IPAddress -ne 'N/A' -and
        $NetworkInfo.DefaultGateway -and $NetworkInfo.DefaultGateway -ne 'N/A'
    if (-not $usable) {
        $result.connection_type = 'NoNetwork'
    } elseif ($NetworkInfo.AdapterClass -eq 'wifi') {
        $result.connection_type = 'WiFi'
        if ($NetworkInfo.SSID -and $NetworkInfo.SSID -ne 'N/A') { $result.ssid = [string]$NetworkInfo.SSID }
    } elseif ($NetworkInfo.AdapterClass -eq 'ethernet') {
        $result.connection_type = 'Wired'
    }
    return [pscustomobject]$result
}

function Write-NetworkInfoToLog {
    param($NetworkInfo)
    
    Write-Log "=== Network Information ===" "INFO"
    Write-Log "  Connection Type: $($NetworkInfo.ConnectionType)" "INFO"
    Write-Log "  Interface: $($NetworkInfo.InterfaceName)" "INFO"
    if ($NetworkInfo.SSID -ne "N/A") {
        Write-Log "  SSID: $($NetworkInfo.SSID)" "INFO"
    }
    Write-Log "  IP Address: $($NetworkInfo.IPAddress)/$($NetworkInfo.SubnetMask)" "INFO"
    Write-Log "  Default Gateway: $($NetworkInfo.DefaultGateway)" "INFO"
    Write-Log "  MAC Address: $($NetworkInfo.MACAddress)" "INFO"
    if ($NetworkInfo.DNSServers.Count -gt 0) {
        Write-Log "  DNS Servers: $($NetworkInfo.DNSServers -join ', ')" "INFO"
    }
    if ($NetworkInfo.ConnectionSpecificSuffix -and $NetworkInfo.ConnectionSpecificSuffix -ne "N/A") {
        Write-Log "  Connection-Specific Suffix: $($NetworkInfo.ConnectionSpecificSuffix)" "INFO"
    }
    # RC1.24: DHCP lease timing, ipconfig /all style, for the primary adapter
    if ($null -ne $NetworkInfo.LeaseDurationSeconds) {
        Write-Log "  Lease Obtained. . . . . . . . . . : $($NetworkInfo.LeaseObtained)" "INFO"
        Write-Log "  Lease Expires . . . . . . . . . . : $($NetworkInfo.LeaseExpires)" "INFO"
        Write-Log "  Lease Duration (seconds). . . . . : $($NetworkInfo.LeaseDurationSeconds)" "INFO"
    }
    if ($NetworkInfo.DNSSuffixes -and $NetworkInfo.DNSSuffixes.Count -gt 0) {
        Write-Log "  DNS Suffixes: $($NetworkInfo.DNSSuffixes -join ', ')" "INFO"
    } else {
        Write-Log "  DNS Suffixes: (none discovered)" "DEBUG"
    }

    # RC1.24: log EVERY active physical adapter, not just the primary one, so techs/Splunk
    # can see "Ethernet up + WiFi up" simultaneously during triage. The primary-adapter
    # summary lines above are unchanged for existing log scanning/grep patterns.
    if ($NetworkInfo.Adapters -and $NetworkInfo.Adapters.Count -gt 0) {
        Write-Log "  Active adapters: $($NetworkInfo.Adapters.Count)" "INFO"
        foreach ($a in $NetworkInfo.Adapters) {
            $isPrimary = if ($a.InterfaceName -eq $NetworkInfo.InterfaceName) { " [PRIMARY]" } else { "" }
            $line = "  Adapter: $($a.ConnectionType) '$($a.InterfaceName)' ip=$($a.IPAddress)/$($a.SubnetMask) gw=$($a.DefaultGateway) mac=$($a.MACAddress) suffix=$($a.ConnectionSpecificSuffix)"
            if ($a.ConnectionType -eq "WiFi") { $line += " ssid=$($a.SSID)" }
            if ($a.DNSServers -and $a.DNSServers.Count -gt 0) { $line += " dns=$($a.DNSServers -join '|')" }
            if ($null -ne $a.LeaseDurationSeconds) {
                $line += " lease_obtained='$($a.LeaseObtained)' lease_expires='$($a.LeaseExpires)' lease_sec=$($a.LeaseDurationSeconds)"
            }
            Write-Log "$line$isPrimary" "INFO"
        }
    }
    Write-Log "===========================" "INFO"

    # RC1.16: Report MAC randomization mode for WiFi adapters
    # Modes 2 (daily) and 3 (per_connection) break captive portal re-auth - log as WARN
    if ($NetworkInfo.ConnectionType -eq "WiFi") {
        $macRand = Get-MacRandomizationState -MacAddress $NetworkInfo.MACAddress
        if ($macRand.ModeValue -ge 0) {
            $randMsg = "  MAC randomization: mode=$($macRand.RandomizationMode) (value=$($macRand.ModeValue))"
            if ($macRand.IsRisky) {
                Write-Log "$randMsg - RISKY: MAC changes between connections, captive portal re-auth will fail" "WARN"
            } elseif ($macRand.IsRandomized) {
                Write-Log "$randMsg - same MAC per SSID, portal-safe" "INFO"
            } else {
                Write-Log "$randMsg - permanent MAC, portal-safe" "DEBUG"
            }
        }
    }
}

function Get-MacRandomizationState {
    <#
    .SYNOPSIS
    Detect MAC randomization by inspecting the second hex digit of the MAC address.

    .DESCRIPTION
    The second hex character of a MAC encodes bits 1-0 of the first octet:
      Bit 1 = locally administered (set by OS when randomizing)
      Bit 0 = multicast (always 0 for unicast NICs)

    Second char in {2,6,A,E} => locally administered unicast => randomized.
    No registry traversal required - the MAC itself is the ground truth.

    Returns a hashtable with:
      ModeValue         - 1 if randomized, 0 if not, -1 if MAC unavailable
      RandomizationMode - "randomized" | "disabled" | "unknown"
      IsRandomized      - $true if any randomization detected
      IsRisky           - $true if randomized (mode unknown - treat as risky)
    #>
    param(
        [string]$MacAddress = ""
    )

    $result = @{
        ModeValue         = -1
        RandomizationMode = "unknown"
        IsRandomized      = $false
        IsRisky           = $false
    }

    try {
        if ([string]::IsNullOrEmpty($MacAddress)) {
            Write-Log "MacRandState: no MAC address provided" "DEBUG"
            return $result
        }

        $mac        = $MacAddress.ToUpper().Trim()
        $secondChar = $mac[1].ToString()
        $isRand     = $secondChar -in @('2','6','A','E')

        $result.ModeValue         = if ($isRand) { 1 } else { 0 }
        $result.IsRandomized      = $isRand
        $result.IsRisky           = $isRand   # specific mode unknown - any randomization is portal-risky
        $result.RandomizationMode = if ($isRand) { "randomized" } else { "disabled" }

        Write-Log "MacRandState: MAC=$mac second-char='$secondChar' randomized=$isRand" "DEBUG"

    } catch {
        Write-Log "MacRandState: error: $_" "DEBUG"
    }

    return $result
}

function Test-DefaultGateway {
    try {
        $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Select-Object -First 1).NextHop
        if ($gw -and (Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return $true
        }
    } catch { }
    return $false
}

function Clear-StaleFlagFiles {
    <#
    .SYNOPSIS
    Remove stale flag files that might block execution
    
    .DESCRIPTION
    ER6: Flag files can become stale if cap_portal_runner crashes or system reboots
    while remediation is in progress. This function checks file age and removes
    flags older than threshold (default 15 minutes).
    
    Prevents scenario where stale flags block WhiteWalker from running until manual cleanup.
    #>
    param([int]$StaleThresholdMinutes = 15)
    
    $flagFiles = @(
        $FlagFile,                # portal_complete.flag
        $InterruptFile,           # network_interrupt.flag
        $RemediationStateFile,    # cap_portal_remediation_active.flag
        $CaptiveFailureFlag,      # captive_failure.flag
        $UserPromptedFlag,        # user_prompted.flag (ER6: was blocking execution)
        "C:\ProgramData\WhiteWalker\dns_chicken_egg_issue.flag"
    )
    
    $now = Get-Date
    $removedCount = 0
    
    foreach ($flagPath in $flagFiles) {
        if (Test-Path $flagPath) {
            try {
                $fileInfo = Get-Item $flagPath -ErrorAction Stop
                $age = ($now - $fileInfo.LastWriteTime).TotalMinutes
                
                if ($age -gt $StaleThresholdMinutes) {
                    Remove-Item $flagPath -Force -ErrorAction Stop
                    Write-Log "Removed stale flag file (age: $([math]::Round($age))min): $(Split-Path $flagPath -Leaf)" "INFO"
                    $removedCount++
                } else {
                    Write-Log "Flag file present but fresh (age: $([math]::Round($age))min): $(Split-Path $flagPath -Leaf)" "DEBUG"
                }
            } catch {
                Write-Log "Error checking/removing flag file $flagPath : $_" "WARN"
            }
        }
    }
    
    if ($removedCount -gt 0) {
        Write-Log "Cleaned up $removedCount stale flag file(s)" "INFO"
    } else {
        Write-Log "No stale flag files found" "DEBUG"
    }
}

function Test-DefaultGateway {
  try {
    $gateways = Get-NetIPConfiguration |
      Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } |
      ForEach-Object { $_.IPv4DefaultGateway.NextHop } |
      Select-Object -Unique
    foreach ($gw in $gateways) {
      if (Test-Connection -ComputerName $gw -Count 1 -Quiet) { return $true }
    }
  } catch { }
  return $false
}

function Test-WalledGarden {
    <#
    .SYNOPSIS
    Detect DNS-blocking walled-garden captive portals.
    
    .DESCRIPTION
    Walled-garden portals (Wyndham, Marriott, etc.) block ALL DNS before user authenticates.
    Unlike redirect-based portals, they never return a Location header.
    
    Signature:
      1. Device has a valid IP and default gateway (not APIPA)
      2. Default gateway is reachable via ping (local L3 works)
      3. DNS resolution fails (not timeout - instant NXDOMAIN/unreachable)
    
    This is distinct from a genuinely broken network because the gateway IS pingable.
    A broken network has no gateway or an unreachable gateway.
    
    Called when: gateway.optum.com unreachable AND enroll.cisco.com DNS fails AND VPN disconnected.

    .PARAMETER PrimaryGateway
    The default gateway already resolved for the primary adapter in THIS run
    (Get-NetInfo / $networkInfo.DefaultGateway). This is preferred over the local
    route-table lookup: the route table can still hold a stale/virtual/Cisco
    default route (observed on xfinitywifi: route table said 10.10.69.1 while the
    live Wi-Fi gateway was 172.20.20.1), which made this test ping the wrong hop
    and report a genuine outage. The route-table lookup is used only when no
    usable adapter gateway is supplied.

    .NOTE
    This test is FALLBACK/supporting evidence only. The empirical
    gateway.optum.com preflight is the authoritative network-state probe.
    #>
    param([string]$PrimaryGateway = "")

    $result = @{
        IsWalledGarden = $false
        GatewayIP      = $null
        Reason         = "unknown"
        GatewaySource  = "route_table"
    }
    
    try {
        # Step 1: Resolve the gateway to test - adapter gateway first, route table second
        $gw = $null
        $routeGw = $null
        try {
            $routeGw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                        Sort-Object RouteMetric |
                        Select-Object -First 1).NextHop
        } catch {
            Write-Log "WalledGarden: route-table default gateway lookup failed: $_" "DEBUG"
        }

        if (-not [string]::IsNullOrWhiteSpace($PrimaryGateway) -and
            $PrimaryGateway -ne '0.0.0.0' -and $PrimaryGateway -ne 'N/A') {
            $gw = $PrimaryGateway
            $result.GatewaySource = "adapter"
            Write-Log "WalledGarden: using supplied primary adapter gateway $gw (route table reported '$routeGw')" "DEBUG"
            if ($routeGw -and $routeGw -ne $gw) {
                Write-Log "WalledGarden: route-table gateway '$routeGw' DISAGREES with primary adapter gateway '$gw' - trusting the adapter gateway from this run" "WARN"
            }
        } else {
            $gw = $routeGw
            $result.GatewaySource = "route_table"
            Write-Log "WalledGarden: no usable primary adapter gateway supplied - falling back to route-table gateway '$gw'" "DEBUG"
        }

        if (-not $gw -or $gw -eq '0.0.0.0') {
            $result.Reason = "no_default_gateway"
            Write-Log "WalledGarden: no default gateway found - not a walled garden" "DEBUG"
            return $result
        }
        
        $result.GatewayIP = $gw
        Write-Log "WalledGarden: default gateway is $gw (source=$($result.GatewaySource)) - testing reachability..." "DEBUG"
        
        # Step 2: Ping the gateway - if reachable, local L3 is working
        $gwPing = Test-Connection -ComputerName $gw -Count 2 -Quiet -ErrorAction SilentlyContinue
        if (-not $gwPing) {
            $result.Reason = "gateway_unreachable"
            Write-Log "WalledGarden: gateway $gw not pingable - genuine connectivity problem, not walled garden" "DEBUG"
            return $result
        }
        
        Write-Log "WalledGarden: gateway $gw IS reachable - local L3 works" "DEBUG"
        
        # Step 3: Test DNS resolution - walled gardens block DNS entirely
        # Use .NET directly for speed and to capture the specific failure mode
        $dnsBlocked = $false
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses("enroll.cisco.com")
            # DNS worked - not a walled garden (or portal is transparent to DNS)
            Write-Log "WalledGarden: DNS resolution succeeded for enroll.cisco.com - not a walled garden" "DEBUG"
            $result.Reason = "dns_works"
            return $result
        } catch {
            $dnsErr = $_.Exception.Message
            Write-Log "WalledGarden: DNS resolution failed for enroll.cisco.com: $dnsErr" "DEBUG"
            $dnsBlocked = $true
        }
        
        if ($dnsBlocked) {
            # Gateway reachable + DNS blocked = walled garden
            $result.IsWalledGarden = $true
            $result.Reason = "gateway_up_dns_blocked"
            Write-Log "WalledGarden: CONFIRMED - gateway $gw reachable but DNS blocked = walled-garden captive portal" "WARN"
        }
        
    } catch {
        Write-Log "WalledGarden: detection error: $_" "DEBUG"
        $result.Reason = "detection_error"
    }
    
    return $result
}

function Test-PlausibleLocalNetwork {
    <#
    .SYNOPSIS
    STRICT gate: decide whether the box genuinely has a usable local network.

    .DESCRIPTION
    Used when the empirical gateway.optum.com preflight came back inconclusive
    (timeout/unreachable/DNS failure). "Inconclusive" is NOT the same as "the
    network is genuinely broken": a valid non-APIPA IP plus a real default
    gateway means L2/L3/DHCP all worked and something above that layer is
    intercepting or blocking us - a captive portal is the most likely cause.

    RC2.1 made this strict after live evidence showed Main suspecting a captive
    portal, firing Event 778 and launching Base with NO Wi-Fi and no usable
    adapter at all ("No active non-VPN adapter with a default gateway found",
    "ssid left empty"). A captive-portal handoff now requires ALL of:

      * an active non-VPN physical adapter (ConnectionType resolved);
      * a non-empty IPv4 that is not APIPA, loopback or 0.0.0.0;
      * a valid non-zero default gateway tied to that adapter;
      * for a Wi-Fi path, a currently connected SSID. Wired may have no SSID,
        but still needs a valid adapter/IP/gateway.

    Anything else => no captive-portal handoff, no Event 778, no Event 777,
    normal no-network fail-soft result.

    Returns a hashtable with IsPlausible/Ip/Gateway/Ssid/ConnectionType/Reason.
    Never throws.
    #>
    param($NetworkInfo)

    $result = @{ IsPlausible = $false; Ip = ""; Gateway = ""; Ssid = ""; ConnectionType = ""; Reason = "no_network_info" }

    try {
        if (-not $NetworkInfo) { return $result }

        $ip = [string]$NetworkInfo.IPAddress
        $gw = [string]$NetworkInfo.DefaultGateway
        # Get-NetworkInfo placeholders ("N/A"/"Unknown"/"none") mean "not
        # determined" and must never be read as real data. Normalized inline so
        # this gate stays self-contained and independently testable.
        $placeholders = @('n/a', 'na', 'unknown', 'none', '(none)', 'not connected', 'disconnected')
        $connectionType = [string]$NetworkInfo.ConnectionType
        if ($placeholders -contains $connectionType.Trim().ToLowerInvariant()) { $connectionType = "" } else { $connectionType = $connectionType.Trim() }
        $ssid = [string]$NetworkInfo.SSID
        if ($placeholders -contains $ssid.Trim().ToLowerInvariant()) { $ssid = "" } else { $ssid = $ssid.Trim() }

        # IPAddress may carry a /prefix suffix (e.g. 172.20.20.20/24)
        if ($ip -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ip = $matches[1] } else { $ip = "" }

        $result.Ip = $ip
        $result.Gateway = $gw
        $result.Ssid = $ssid
        $result.ConnectionType = $connectionType

        # An adapter that never resolved to WiFi/Ethernet is not an active
        # non-VPN physical adapter. ConnectionType is only trusted when the
        # caller actually supplied one, so legacy callers are unaffected.
        if (($null -ne $NetworkInfo.ConnectionType) -and [string]::IsNullOrWhiteSpace($connectionType)) {
            $result.Reason = "no_active_adapter"
            return $result
        }

        if ([string]::IsNullOrWhiteSpace($ip)) {
            $result.Reason = "no_ip"
            return $result
        }
        if ($ip -like '169.254.*') {
            $result.Reason = "apipa_ip"
            return $result
        }
        if ($ip -like '127.*' -or $ip -eq '0.0.0.0') {
            $result.Reason = "invalid_ip"
            return $result
        }
        if ([string]::IsNullOrWhiteSpace($gw) -or $gw -eq '0.0.0.0' -or $gw -eq 'N/A') {
            $result.Reason = "no_default_gateway"
            return $result
        }
        if ($connectionType -eq 'WiFi' -and [string]::IsNullOrWhiteSpace($ssid)) {
            # Radio on but not associated (or radio off): no connected SSID means
            # there is no wireless network to be captive-portalled by.
            $result.Reason = "wifi_no_connected_ssid"
            return $result
        }

        $result.IsPlausible = $true
        $result.Reason = "valid_ip_and_gateway"
    } catch {
        $result.Reason = "evaluation_error"
    }

    return $result
}

function Test-MacRandomization {
    <#
    .SYNOPSIS
    Detect Windows 11 MAC randomization on reconnect to same SSID.
    
    .DESCRIPTION
    Windows 11 uses random hardware addresses per-network by default.
    On reconnect, the MAC may change. Hotel portals authenticate by MAC,
    so a MAC change = portal treats device as new unauthenticated client.
    This is a silent failure mode - user thinks they authenticated but
    the portal doesn't recognize them on reconnect.
    
    Logs a WARNING when MAC differs from last seen on this SSID.
    Does not block execution - informational only.
    #>
    param(
        [string]$CurrentSsid,
        [string]$CurrentMac
    )
    
    if (-not $CurrentSsid -or $CurrentSsid -eq "N/A") { return }
    if (-not $CurrentMac -or $CurrentMac -eq "N/A") { return }
    
    try {
        # Cache file stores JSON: { "SSID": "MAC" }
        $macCache = @{}
        if (Test-Path $MacCacheFile) {
            try {
                $raw = Get-Content $MacCacheFile -Raw -ErrorAction Stop
                $loaded = $raw | ConvertFrom-Json
                foreach ($prop in $loaded.PSObject.Properties) {
                    $macCache[$prop.Name] = $prop.Value
                }
            } catch {
                Write-Log "MacRandomization: could not read MAC cache: $_" "DEBUG"
            }
        }
        
        $normalizedSsid = $CurrentSsid.Trim()
        $normalizedMac  = $CurrentMac.ToUpper().Trim()
        
        if ($macCache.ContainsKey($normalizedSsid)) {
            $lastMac = $macCache[$normalizedSsid].ToUpper().Trim()
            if ($lastMac -ne $normalizedMac) {
                Write-Log "MAC RANDOMIZATION DETECTED on SSID '$normalizedSsid': was $lastMac now $normalizedMac" "WARN"
                Write-Log "MAC change may invalidate captive portal session - portal authenticates by MAC" "WARN"
                Write-Log "Recommendation: Disable random hardware addresses for this SSID in Windows WiFi settings" "WARN"
            } else {
                Write-Log "MacRandomization: MAC unchanged for SSID '$normalizedSsid' ($normalizedMac)" "DEBUG"
            }
        } else {
            Write-Log "MacRandomization: first seen MAC for SSID '$normalizedSsid': $normalizedMac" "DEBUG"
        }
        
        # Update cache
        $macCache[$normalizedSsid] = $normalizedMac
        $macCache | ConvertTo-Json -Depth 2 | Set-Content -Path $MacCacheFile -Encoding UTF8 -Force
        
    } catch {
        Write-Log "MacRandomization: check failed: $_" "DEBUG"
    }
}

function Test-DC { 
    param([string]$hostname = $DC_FQDN)
    
    # Ping the DC, then confirm via DNS suffix.
    # Stale VPN routes can make DC pingable from any network - suffixes don't lie.
    # If ANY non-corporate suffix is found, we're off-prem.
    try {
        if ($TestDC_DiagnosticMode) { Write-Log "=== TEST-DC START (Diagnostic Mode) ===" "INFO" }
        if ($TestDC_DiagnosticMode) { Write-Log "Testing DC hostname: $hostname" "DEBUG" }

        $pingResult = Test-Connection -ComputerName $hostname -Count 1 -Quiet -ErrorAction Stop
        if ($TestDC_DiagnosticMode) { Write-Log "DC Ping result: $pingResult" "DEBUG" }
        if (-not $pingResult) {
            if ($TestDC_DiagnosticMode) {
                Write-Log "DC not reachable - returning off-prem" "DEBUG"
                Write-Log "=== TEST-DC END (result=FALSE) ===" "INFO"
            } else {
                Write-Log "Test-DC: host=$hostname  ping=False  corp_suffixes=(none)  non_corp=(none)  result=False" "INFO"
            }
            return $false
        }
        
        try {
            $corpSuffixes = @('ms.ds.uhc.com', 'ds.uhc.com', 'uhc.com')
            $foundSuffixes = @()

            # Method 1: Get DNS suffix search list (the clean way - no regex!)
            if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Starting Method 1: Get-DnsClientGlobalSetting" "DEBUG" }
            try {
                $dnsGlobal = Get-DnsClientGlobalSetting -ErrorAction Stop
                if ($dnsGlobal.SuffixSearchList) {
                    if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Method 1 returned list:" "DEBUG" }
                    foreach ($suffix in $dnsGlobal.SuffixSearchList) {
                        $cleanSuffix = $suffix.ToLower().Trim()
                        if ($TestDC_DiagnosticMode) { Write-Log "  [SUFFIX-METHOD1] Found: '$cleanSuffix'" "DEBUG" }
                        $foundSuffixes += $cleanSuffix
                    }
                } else {
                    if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Method 1: SuffixSearchList is empty/null" "DEBUG" }
                }
            } catch {
                if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Method 1 FAILED: $_" "DEBUG" }
            }

            # Method 2: Get primary DNS suffix (computer's domain membership)
            if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Starting Method 2: IPGlobalProperties.DomainName" "DEBUG" }
            try {
                $primary = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
                if (-not [string]::IsNullOrWhiteSpace($primary)) {
                    $cleanPrimary = $primary.ToLower().Trim()
                    if ($cleanPrimary -in @('(none)', 'none')) {
                        if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Method 2 ignored placeholder DomainName: '$cleanPrimary'" "DEBUG" }
                    } else {
                        if ($TestDC_DiagnosticMode) { Write-Log "  [SUFFIX-METHOD2] Found: '$cleanPrimary'" "DEBUG" }
                        $foundSuffixes += $cleanPrimary
                    }
                } else {
                    if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Method 2: DomainName is empty/null" "DEBUG" }
                }
            } catch {
                if ($TestDC_DiagnosticMode) { Write-Log "[SUFFIX-COLLECTION] Method 2 FAILED: $_" "DEBUG" }
            }

            # Remove duplicates and blanks
            $foundSuffixes = $foundSuffixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

            if ($TestDC_DiagnosticMode) {
                Add-LogLine ""
                Write-Log "--- DNS SUFFIX DIAGNOSTIC REPORT (Test-DC) ---" "INFO"
                Write-Log "DC Hostname Tested: $hostname" "INFO"
                Write-Log "DC Reachable: $pingResult" "INFO"
                Write-Log "Total Suffixes Found: $($foundSuffixes.Count)" "INFO"
                Write-Log "Suffixes (comma-separated): $($foundSuffixes -join ',')" "INFO"
                if ($foundSuffixes.Count -gt 0) {
                    Write-Log "Suffixes (detailed list):" "INFO"
                    for ($i = 0; $i -lt $foundSuffixes.Count; $i++) {
                        Write-Log "  [$($i+1)] '$($foundSuffixes[$i])'" "INFO"
                    }
                }
                Write-Log "Corporate Suffixes List: $($corpSuffixes -join ',')" "INFO"
                Add-LogLine ""
            }

            if (-not $foundSuffixes) {
                Write-Log "[WARN] RESULT: DC ping succeeded but NO DNS suffixes found - cannot confirm on-prem" "WARN"
                if ($TestDC_DiagnosticMode) {
                    Write-Log "--- RETURNING: FALSE (off-prem assumed) ---" "INFO"
                    Write-Log "=== TEST-DC END (result=FALSE, no suffixes) ===" "INFO"
                } else {
                    Write-Log "Test-DC: host=$hostname  ping=$pingResult  corp_suffixes=(none)  non_corp=(none)  result=False" "INFO"
                }
                return $false
            }

            # Check if we have ONLY corporate suffixes (no ISP/public WiFi suffixes)
            # On-prem: only corp suffixes present
            # VPN from home: corp suffixes + ISP suffix (comcast.net, att.net, etc.)
            $corpSuffixCount = 0
            $corpSuffixList  = @()
            $nonCorpSuffixes = @()

            if ($TestDC_DiagnosticMode) {
                Add-LogLine ""
                Write-Log "SUFFIX CLASSIFICATION ANALYSIS:" "INFO"
                Write-Log "-------------------------------------------------------------" "INFO"
            }
            foreach ($found in $foundSuffixes) {
                $isCorp = $false
                foreach ($corp in $corpSuffixes) {
                    # Exact match or subdomain (e.g., "foo.uhc.com" matches "uhc.com")
                    if ($found -eq $corp -or $found -like "*.$corp") {
                        $isCorp = $true
                        $corpSuffixCount++
                        $corpSuffixList += $found
                        if ($TestDC_DiagnosticMode) { Write-Log "  [OK] CORPORATE: '$found' matches pattern '$corp'" "INFO" }
                        break
                    }
                }
                if (-not $isCorp) {
                    $nonCorpSuffixes += $found
                    if ($TestDC_DiagnosticMode) { Write-Log "  [!!] NON-CORPORATE: '$found' (does NOT match any trusted pattern)" "INFO" }
                }
            }

            if ($TestDC_DiagnosticMode) {
                Write-Log "-------------------------------------------------------------" "INFO"
                Write-Log "Corporate suffixes found: $corpSuffixCount" "INFO"
                Write-Log "Non-corporate suffixes found: $($nonCorpSuffixes.Count)" "INFO"
                if ($nonCorpSuffixes.Count -gt 0) {
                    Write-Log "Non-corporate list: $($nonCorpSuffixes -join ',')" "INFO"
                }
                Add-LogLine ""
            }

            # Must have at least one corporate suffix
            if ($corpSuffixCount -eq 0) {
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                Write-Log "[!!] UNTRUSTED SUFFIX DETECTED - DC REACHABLE BUT ON-PREM DENIED" "ERROR"
                Write-Log "[!!] No corporate DNS suffixes found. Found: $($foundSuffixes -join ', ')" "ERROR"
                Write-Log "[!!] Check NIC DNS suffix config on this machine." "ERROR"
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                if ($TestDC_DiagnosticMode) {
                    Write-Log "--- RETURNING: FALSE (no corporate suffixes) ---" "INFO"
                    Write-Log "=== TEST-DC END (result=FALSE, no corp suffixes) ===" "INFO"
                } else {
                    Write-Log "Test-DC: host=$hostname  ping=$pingResult  corp_suffixes=(none)  non_corp=$($nonCorpSuffixes -join ',')  result=False" "INFO"
                }
                return $false
            }

            # Must have ONLY corporate suffixes (no ISP/public suffixes)
            if ($nonCorpSuffixes.Count -gt 0) {
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                Write-Log "[!!] UNTRUSTED SUFFIX DETECTED - DC REACHABLE BUT ON-PREM DENIED" "ERROR"
                Write-Log "[!!] Non-corporate suffix(es) present: $($nonCorpSuffixes -join ', ')" "ERROR"
                Write-Log "[!!] Corporate suffixes also found - likely VPN from off-prem, or hardcoded suffix on NIC." "ERROR"
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                if ($TestDC_DiagnosticMode) {
                    Write-Log "--- RETURNING: FALSE (non-corporate suffixes + corporate) ---" "INFO"
                    Write-Log "--- DIAGNOSIS: Likely VPN from off-prem home network ---" "INFO"
                    Write-Log "=== TEST-DC END (result=FALSE, mixed suffixes) ===" "INFO"
                } else {
                    $corpStr = if ($corpSuffixList) { $corpSuffixList -join ',' } else { '(none)' }
                    Write-Log "Test-DC: host=$hostname  ping=$pingResult  corp_suffixes=$corpStr  non_corp=$($nonCorpSuffixes -join ',')  result=False" "INFO"
                }
                return $false
            }

            if ($TestDC_DiagnosticMode) {
                Write-Log "[OK] SUCCESS: DC reachable with ONLY corporate DNS suffixes ($($foundSuffixes -join ', ')) - on-prem confirmed" "DEBUG"
                Write-Log "--- RETURNING: TRUE (on-prem confirmed) ---" "INFO"
                Write-Log "=== TEST-DC END (result=TRUE, on-prem) ===" "INFO"
            } else {
                Write-Log "Test-DC: host=$hostname  ping=$pingResult  corp_suffixes=$($foundSuffixes -join ',')  non_corp=0  result=True" "INFO"
            }
            return $true
            
        } catch {
            # Suffix check failed - fall through and trust the ping
            Write-Log "[WARN] Could not validate DNS suffixes: $_" "WARN"
            Write-Log "Falling back to trusting DC ping result: TRUE" "DEBUG"
            if ($TestDC_DiagnosticMode) {
                Write-Log "--- RETURNING: TRUE (fallback to ping, suffix check failed) ---" "INFO"
                Write-Log "=== TEST-DC END (result=TRUE, fallback) ===" "INFO"
            } else {
                Write-Log "Test-DC: host=$hostname  ping=$pingResult  corp_suffixes=(error)  non_corp=(error)  result=True (fallback)" "INFO"
            }
            return $true
        }
        
    } catch { 
        Write-Log "Test-DC outer exception: $_" "ERROR"
        if ($TestDC_DiagnosticMode) {
            Write-Log "--- RETURNING: FALSE (outer exception) ---" "INFO"
            Write-Log "=== TEST-DC END (result=FALSE, exception) ===" "INFO"
        } else {
            Write-Log "Test-DC: host=$hostname  result=False (outer exception)" "INFO"
        }
        return $false 
    }
}

# RC1: Primary network gate function
function Get-CapPreflightUrlDetails {
    <#
    Protocol/FQDN/port breakdown of a preflight redirect target. Shared by the
    preflight classifier and the FlareGun dispatch context so Main and Base
    describe the same redirect with the same fields. Fail-soft: an unparsable
    URL yields empty parts, never an exception.
    #>
    param([string]$Url = "")

    $details = @{ protocol = ''; fqdn = ''; port = '' }
    if ([string]::IsNullOrWhiteSpace($Url)) { return $details }
    try {
        $uri = [Uri]$Url
        $details.protocol = $uri.Scheme
        $details.fqdn     = $uri.Host
        $details.port     = if ($uri.IsDefaultPort) {
            switch ($uri.Scheme.ToLowerInvariant()) {
                'http'  { '80' }
                'https' { '443' }
                default { '' }
            }
        } else { [string]$uri.Port }
    } catch { }
    return $details
}

function Resolve-CapPreflightClassification {
    <#
    THE control-plane contract, in one place:
      * HTTP 200/404 with no Location            -> online      (ONLINE)
      * ANY 2xx/3xx WITH a Location header       -> redirect    (REDIRECT)
        (ISE answers with a non-standard HTTP 200 + Location)
      * anything else / timeout / DNS / transport-> unreachable (INCONCLUSIVE)
    INCONCLUSIVE means "we do not know yet" - never "online" and never proof
    that no captive portal exists. Cisco EventID 301 / WebView2 plays no part
    in this decision; it is optional corroboration only.
    #>
    param([Parameter(Mandatory)]$Result)

    $code = 0
    [void][int]::TryParse([string]$Result.http_status, [ref]$code)

    if ($Result.redirect_url -and $code -ge 200 -and $code -lt 400) {
        $Result.status         = 'redirect'
        $Result.classification = 'REDIRECT'
        $Result.reason         = if ($code -ge 300) { 'http_3xx_location' } else { 'http_2xx_with_location' }
    } elseif ([string]$Result.http_status -in @('200', '404')) {
        $Result.status         = 'online'
        $Result.classification = 'ONLINE'
        $Result.reason         = 'no_redirect'
    } else {
        $Result.status         = 'unreachable'
        $Result.classification = 'INCONCLUSIVE'
        if (-not $Result.reason) { $Result.reason = 'unexpected_http_status' }
    }

    if ($Result.redirect_url) {
        $parts = Get-CapPreflightUrlDetails -Url $Result.redirect_url
        $Result.protocol = $parts.protocol
        $Result.fqdn     = $parts.fqdn
        $Result.port     = $parts.port
        $Result.redirect_type = Get-RedirectType -RedirectUrl $Result.redirect_url
    }

    return $Result
}

function Wait-CprNetworkReady {
    <#
    .SYNOPSIS
    Bounded network-settle gate fired immediately BEFORE the authoritative
    preflight (RC2.2, Required D).

    .DESCRIPTION
    Live evidence (xfinitywifi): enroll.cisco.com redirected at 23:29:34 but
    the authoritative gateway.optum.com preflight fired at 23:29:39 and timed
    out INCONCLUSIVE at 23:29:47 - the path simply was not usable yet.

    A longer FIXED sleep was explicitly rejected: it would tax every healthy
    run, including ISE_EMPLOYEE/WLANi03, with latency it does not need. This
    gate instead polls two CHEAP readiness signals and returns the MOMENT one
    is observed:

      gateway_reachable - ICMP echo to the default gateway (ARP/L2 usable)
      dns_resolved      - DNS resolution of the preflight host

    The total wait is hard-capped by -MaxWaitMs; on expiry the caller probes
    ANYWAY and the run records signal='not_confirmed'. Nothing here can block:
    every probe is wrapped and a failure is simply "not ready yet".

    Returns a hashtable: Ready, Signal, WaitedMs, Attempts.
    #>
    param(
        [string]$GatewayAddress = '',
        [string]$ProbeHost = '',
        [int]$MaxWaitMs = 0,
        [int]$PollIntervalMs = 0,
        [int]$GatewayTimeoutMs = 0,
        [int]$DnsTimeoutMs = 0,
        [switch]$Disabled
    )

    if ($MaxWaitMs -le 0)        { $MaxWaitMs        = if ($NetworkReadyMaxWaitMs)        { $NetworkReadyMaxWaitMs }        else { 8000 } }
    if ($PollIntervalMs -le 0)   { $PollIntervalMs   = if ($NetworkReadyPollIntervalMs)   { $NetworkReadyPollIntervalMs }   else { 500 } }
    if ($GatewayTimeoutMs -le 0) { $GatewayTimeoutMs = if ($NetworkReadyGatewayTimeoutMs) { $NetworkReadyGatewayTimeoutMs } else { 750 } }
    if ($DnsTimeoutMs -le 0)     { $DnsTimeoutMs     = if ($NetworkReadyDnsTimeoutMs)     { $NetworkReadyDnsTimeoutMs }     else { 1500 } }

    $result = @{ Ready = $false; Signal = 'not_confirmed'; WaitedMs = 0; Attempts = 0 }

    if ($Disabled) {
        $result.Signal = 'disabled'
        return $result
    }

    $gateway = ConvertTo-CprReadyAddress $GatewayAddress
    $probe   = ConvertTo-CprReadyHost $ProbeHost
    if (-not $gateway -and -not $probe) {
        $result.Signal = 'no_signals_available'
        return $result
    }

    $startedAt = Get-Date
    while ($true) {
        $result.Attempts++

        try {
            if ($gateway -and (Test-CprGatewayReachable -Address $gateway -TimeoutMs $GatewayTimeoutMs)) {
                $result.Ready = $true
                $result.Signal = 'gateway_reachable'
                break
            }
        } catch { }

        try {
            if ($probe -and (Test-CprDnsResolvable -HostName $probe -TimeoutMs $DnsTimeoutMs)) {
                $result.Ready = $true
                $result.Signal = 'dns_resolved'
                break
            }
        } catch { }

        $elapsedMs = ((Get-Date) - $startedAt).TotalMilliseconds
        if ($elapsedMs + $PollIntervalMs -ge $MaxWaitMs) { break }
        Start-Sleep -Milliseconds $PollIntervalMs
    }

    $result.WaitedMs = [math]::Round(((Get-Date) - $startedAt).TotalMilliseconds)
    return $result
}

function ConvertTo-CprReadyAddress {
    # Normalizes a gateway value; Get-NetworkInfo uses placeholders for "none".
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $text = $Value.Trim()
    if (@('n/a', 'unknown', 'none', '0.0.0.0') -contains $text.ToLowerInvariant()) { return '' }
    return $text
}

function ConvertTo-CprReadyHost {
    # Accepts a URL or a bare hostname and returns the host to resolve.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $text = $Value.Trim()
    try {
        $uri = $null
        if ([System.Uri]::TryCreate($text, [System.UriKind]::Absolute, [ref]$uri) -and $uri) { return $uri.Host }
    } catch { }
    return $text
}

function Test-CprGatewayReachable {
    # Cheap L2/L3 liveness signal. Never throws; any failure is "not ready".
    param([string]$Address, [int]$TimeoutMs = 750)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $ping = $null
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($Address, $TimeoutMs)
        return ($null -ne $reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    } catch {
        return $false
    } finally {
        if ($ping) { try { $ping.Dispose() } catch { } }
    }
}

function Test-CprDnsResolvable {
    # Cheap name-resolution signal for the authoritative preflight host.
    param([string]$HostName, [int]$TimeoutMs = 1500)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($HostName)
        if (-not $task.Wait($TimeoutMs)) { return $false }
        return ($null -ne $task.Result -and $task.Result.Count -gt 0)
    } catch {
        return $false
    }
}

function Get-NwCheckResult {
    # Hits gateway.optum.com (blocked in ISE/WLC posture redirect ACL).
    # THE authoritative, empirical network-state probe. One call yields the
    # state AND the redirect in a single step:
    #   Status = "online"      -> 200/404 with no Location, network is clean
    #   Status = "redirect"    -> any 2xx/3xx WITH Location, RedirectUrl routes
    #                             the workflow (ISE answers 200 + Location)
    #   Status = "unreachable" -> INCONCLUSIVE: timeout/DNS/transport failure or
    #                             an unexpected status. NOT proof of "no portal".
    param(
        [string]$Url = $NewPreflightURL,
        [int]$Attempt = 1
    )

    Write-Log "RC1 nwcheck preflight: GET $Url" "INFO"

    $started = Get-Date
    $result = [ordered]@{
        observation_time = $started.ToString('o')
        probe_url        = $Url
        status           = 'unreachable'
        classification   = 'INCONCLUSIVE'
        http_status      = ''
        redirect_url     = ''
        redirect_type    = ''
        protocol         = ''
        fqdn             = ''
        port             = ''
        duration_ms      = 0
        attempt          = $Attempt
        reason           = ''
        error_message    = ''
    }

    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 8000

        $response = $request.GetResponse()
        $result.http_status  = [string][int]$response.StatusCode
        $result.redirect_url = [string]$response.Headers['Location']
        $response.Close()

        $result = Resolve-CapPreflightClassification -Result $result
    } catch [System.Net.WebException] {
        # HttpWebRequest throws WebException for non-2xx responses (including 404).
        # Must inspect the exception's response object to get the real status code.
        $exResponse = $_.Exception.Response
        if ($exResponse) {
            $statusCode = [int]$exResponse.StatusCode
            $result.http_status  = [string]$statusCode
            $result.redirect_url = [string]$exResponse.Headers['Location']

            if ($statusCode -eq 404 -and -not $result.redirect_url) {
                # Read response body to confirm this is gateway.optum.com's known 404
                # and not a captive portal or DNS hijack also returning 404
                try {
                    $stream = $exResponse.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $body = $reader.ReadToEnd()
                    $reader.Close()
                } catch {
                    $body = ""
                }
                $exResponse.Close()

                if ($body -match '"no Route matched with those values"') {
                    $result.status         = 'online'
                    $result.classification = 'ONLINE'
                    $result.reason         = 'gateway_404_signature'
                } else {
                    $result.status         = 'unreachable'
                    $result.classification = 'INCONCLUSIVE'
                    $result.reason         = 'http_404_body_signature_mismatch'
                    Write-Log "preflight: body=$body" "DEBUG"
                }
            } else {
                $exResponse.Close()
                $result = Resolve-CapPreflightClassification -Result $result
            }
        } else {
            $result.reason        = 'transport_failure'
            $result.error_message = [string]$_.Exception.Message
        }
    } catch {
        $result.reason        = 'transport_failure'
        $result.error_message = [string]$_.Exception.Message
    }

    $result.duration_ms = [math]::Round(((Get-Date) - $started).TotalMilliseconds)

    switch ($result.status) {
        'online' {
            Write-Log "preflight: HTTP $($result.http_status) from $Url - network is online (reason=$($result.reason))" "INFO"
        }
        'redirect' {
            Write-Log "preflight: HTTP $($result.http_status) redirect to $($result.redirect_url) - restricted access (captive/ISE, reason=$($result.reason))" "WARN"
        }
        default {
            $detail = if ($result.error_message) { $result.error_message } else { $result.reason }
            Write-Log "preflight: INCONCLUSIVE - $detail" "WARN"
        }
    }

    # Preserve the authoritative preflight for the FlareGun dispatch context so
    # 777/778 can carry it even from a branch that no longer has $nwCheck in scope.
    try { $global:LastCapPreflightResult = [PSCustomObject]$result } catch { }

    return [PSCustomObject]@{
        Status           = $result.status
        Classification   = $result.classification
        RedirectUrl      = $(if ($result.redirect_url) { $result.redirect_url } else { $null })
        RedirectType     = $result.redirect_type
        HttpStatus       = $result.http_status
        Protocol         = $result.protocol
        Fqdn             = $result.fqdn
        Port             = $result.port
        DurationMs       = $result.duration_ms
        Attempt          = $result.attempt
        ProbeUrl         = $result.probe_url
        ObservationTime  = $result.observation_time
        Reason           = $result.reason
        ErrorMessage     = $result.error_message
    }
}

function Test-InternetAccess-Legacy {
    # LEGACY: Google 204 check (currently passes even with ISE redirect due to blank ACL)
    param([string]$Url = $LegacyPreflightURL)
    
    Write-Log "Pre-flight check (LEGACY): Testing $Url" "INFO"
    
    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 3000
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $response.Close()
        
        if ($statusCode -eq 204) {
            Write-Log "Pre-flight PASSED (LEGACY): Received 204 from Google" "INFO"
            return $true
        }
        
        Write-Log "Pre-flight FAILED (LEGACY): Status $statusCode" "WARN"
        return $false
        
    } catch {
        Write-Log "Pre-flight FAILED (LEGACY): $_" "WARN"
        return $false
    }
}

function Test-CaptivePortalCleared {
    # Used by cap_portal_runner poll loop to confirm portal has been accepted
    if ($UseNewPreflight) {
        $result = Get-NwCheckResult
        return ($result.Status -eq "online")
    } else {
        return Test-InternetAccess-Legacy
    }
}

function Test-Redirect { 
    param([string]$Url = "http://captive.apple.com/hotspot-detect.html")
    
    Write-Log "Testing for redirect: trying $Url"
  
  $redirectInfo = @{
    IsRedirect = $false
    RedirectUrl = $null
    Method = $null
  }
  
  try {
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 4000
    $response = $request.GetResponse()
    $statusCode = [int]$response.StatusCode
    $location = $response.Headers['Location']
    $response.Close()
    
    # ISE can return 200 with Location header OR standard 3xx redirects
    # Check for Location header on any 2xx or 3xx response
    if ($statusCode -ge 200 -and $statusCode -lt 400 -and $location) {
      Write-Log "REDIRECT DETECTED: HTTP $statusCode with Location header - $Url redirected to: $location"
      $redirectInfo.IsRedirect = $true
      $redirectInfo.RedirectUrl = $location
      $redirectInfo.Method = "HTTP"
      return $redirectInfo
    } else {
      Write-Log "No HTTP redirect: $Url returned status $statusCode (Location: $location)"
    }
  } catch { 
    # When AllowAutoRedirect=false, redirects throw exceptions - check if exception contains redirect
    if ($_.Exception.Response) {
      $statusCode = [int]$_.Exception.Response.StatusCode
      $location = $_.Exception.Response.Headers['Location']
      
      # Check for Location header on any 2xx or 3xx response in exception
      if ($statusCode -ge 200 -and $statusCode -lt 400 -and $location) {
        Write-Log "REDIRECT DETECTED (via exception): HTTP $statusCode with Location - $Url redirected to: $location"
        $redirectInfo.IsRedirect = $true
        $redirectInfo.RedirectUrl = $location
        $redirectInfo.Method = "HTTP"
        return $redirectInfo
      }
    }
    Write-Log "HTTP redirect check error for $Url (may be captive or blocked): $_" 
  }
  
  try {
    Write-Log "Attempting fallback content check for meta refresh on $Url"
    $resp = Invoke-WebRequest -Uri $Url -TimeoutSec 5
    if ($resp.StatusCode -eq 200) {
      $content = $resp.Content
      
      # Try multiple meta refresh patterns
      $metaPatterns = @(
        '<meta\s+http-equiv\s*=\s*["'']refresh["'']\s+content\s*=\s*["''][^"'']*?url\s*=\s*([^"''\s>]+)[^>]*>',
        '<meta\s+http-equiv\s*=\s*["'']refresh["'']\s+content\s*=\s*["''][^"'']*?url\s*=\s*["'']([^"'']+)["''][^>]*>',
        '<meta\s+content\s*=\s*["''][^"'']*?url\s*=\s*([^"''\s>;]+)[^>]*?\s+http-equiv\s*=\s*["'']refresh["''][^>]*>',
        '<meta\s+content\s*=\s*["''][^"'']*?url\s*=\s*["'']([^"'']+)["''][^>]*?\s+http-equiv\s*=\s*["'']refresh["''][^>]*>'
      )
      
      $metaRedirectUrl = $null
      foreach ($pattern in $metaPatterns) {
        if ($content -match $pattern) {
          $metaRedirectUrl = $matches[1]
          Write-Log "META REFRESH PATTERN MATCHED: $pattern"
          break
        }
      }
      
      if ($metaRedirectUrl) {
        Write-Log "REDIRECT DETECTED: Meta refresh - $Url redirected to: $metaRedirectUrl"
        $redirectInfo.IsRedirect = $true
        $redirectInfo.RedirectUrl = $metaRedirectUrl
        $redirectInfo.Method = "META"
        return $redirectInfo
      }
      
      if ($content -match '(<meta[^>]*http-equiv\s*=\s*["'']refresh["''][^>]*>)') {
        $fullMetaTag = $matches[1]
        Write-Log "REDIRECT DETECTED: Meta refresh found but couldn't extract URL. Full tag: $fullMetaTag"
        $redirectInfo.IsRedirect = $true
        $redirectInfo.RedirectUrl = "UNKNOWN"
        $redirectInfo.Method = "META_UNKNOWN"
        return $redirectInfo
      }
      
      Write-Log "No meta refresh redirect found in $Url content"
    }
  } catch { 
    Write-Log "Fallback content check failed for ${Url}: $_" 
  }
  
  Write-Log "No redirect detected from $Url"
  return $redirectInfo
}

function Test-RedirectToGateway {
    # Gateway redirect test (fallback method)
    Write-Log "Attempting gateway redirect test (fallback method)"
    
    try {
        $gateways = Get-NetIPConfiguration |
            Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } |
            ForEach-Object { $_.IPv4DefaultGateway.NextHop } |
            Select-Object -Unique
        
        foreach ($gw in $gateways) {
            Write-Log "Testing redirect via gateway: http://$gw"
            
            try {
                $request = [System.Net.HttpWebRequest]::Create("http://$gw")
                $request.AllowAutoRedirect = $false
                $request.Timeout = 4000
                
                $response = $request.GetResponse()
                $statusCode = [int]$response.StatusCode
                $location = $response.Headers['Location']
                $response.Close()
                
                if ($statusCode -ge 300 -and $statusCode -lt 400 -and $location) {
                    # Check if this is just HTTP -> HTTPS upgrade on same IP (not a captive portal)
                    try {
                        $redirectUri = [System.Uri]$location
                        $redirectHost = $redirectUri.Host.Trim('[]')  # Remove IPv6 brackets if present
                        
                        if ($redirectHost -eq $gw) {
                            Write-Log "Gateway redirect is HTTP -> HTTPS upgrade on same IP ($gw) - not a captive portal" "DEBUG"
                            continue  # Try next gateway or exit loop
                        }
                    } catch {
                        Write-Log "Could not parse redirect URL $location - treating as captive portal" "DEBUG"
                    }
                    
                    # Redirect to different host = likely captive portal
                    Write-Log "REDIRECT DETECTED via gateway: HTTP $statusCode - http://$gw redirected to: $location"
                    return @{
                        IsRedirect = $true
                        RedirectUrl = $location
                        Method = "GATEWAY_HTTP"
                    }
                } elseif ($statusCode -eq 200) {
                    try {
                        $resp = Invoke-WebRequest -Uri "http://$gw" -TimeoutSec 5
                        $content = $resp.Content.ToLower()
                        
                        #if ($content -match "login|captive|portal|authentication|accept.*terms|click.*continue") {
                        if ($content -match "captive|portal|authentication|accept.*terms|click.*continue") {
                            Write-Log "REDIRECT DETECTED: Gateway returned captive portal page"
                            return @{
                                IsRedirect = $true
                                RedirectUrl = "http://$gw"
                                Method = "GATEWAY_CAPTIVE_PAGE"
                            }
                        }
                    } catch {
                        Write-Log "Gateway page content check failed: $_" "DEBUG"
                    }
                }
                
                Write-Log "Gateway $gw returned status $statusCode with no redirect or captive indicators"
                
            } catch {
                Write-Log "Gateway redirect test failed for $gw : $_" "DEBUG"
            }
        }
    } catch {
        Write-Log "Gateway redirect test error: $_" "DEBUG"
    }
    
    Write-Log "No redirect detected via gateway method"
    return @{
        IsRedirect = $false
        RedirectUrl = $null
        Method = $null
    }
}

function Get-RedirectType {
    param([string]$RedirectUrl)
    
    if (-not $RedirectUrl -or $RedirectUrl -eq "UNKNOWN") {
        return "UNKNOWN"
    }
    
    $url = $RedirectUrl.ToLower()
    
    if ($url -match "isepsn") {
        Write-Log "ISE Employee Network detected in redirect URL: $RedirectUrl"
        return "ISE_EMPLOYEE"
    }
    elseif ($url -match "isegst") {
        Write-Log "ISE Guest Network detected in redirect URL: $RedirectUrl"
        return "ISE_GUEST"
    }
    else {
        Write-Log "Non-ISE captive portal detected in redirect URL: $RedirectUrl"
        return "NON_ISE"
    }
}
