# RC2.0.3 fast network probe: .NET/registry replacement for the slow NetTCPIP/DnsClient cmdlets.
# Contract: same record shape as the legacy path, parity check catches differences, legacy stays
# the default and the fallback.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $path = Join-Path $script:Root 'main\Main.Network.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    foreach ($n in 'Get-CprAdapterClass','Get-CprNetworkFingerprint','Test-CprPhysicalNic','ConvertFrom-CprLeaseEpoch',
                   'ConvertTo-CprAdapterRecordFast','Get-NetworkInfoFast','Compare-CprNetworkInfo','Get-NetworkInfo') {
        $fn = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $script:Logged = @()
    function Write-Log { param($Message, $Level) $script:Logged += "[$Level] $Message" }
    function Get-WlanSsidForAdapter { param($AdapterName) 'TestSsid' }
    function Get-CprGlobalDnsSuffixes { @('uhc.com','ms.ds.uhc.com') }
    function Get-CprDhcpLeaseFromRegistry { param($Guid) [pscustomobject]@{ Obtained = 1761912109; Terminates = 1761912109 + 86400 } }
    $script:DhcpLeaseShortWarnSeconds = 300

    function script:New-Nic {
        param($Name='Wi-Fi', $Desc='Intel(R) Wi-Fi 6E AX211 160MHz', $Type='Wireless80211', $Ip='10.10.69.217', $Gw='10.10.69.1', $Dhcp=$true)
        [pscustomobject]@{ Name=$Name; Description=$Desc; Type=$Type; Id='{AAAA-1111}'; Index=12; IsDhcp=$Dhcp; Mac='F4-A4-75-A8-95-2B'
            IPv4=$Ip; PrefixLength=24; Gateways=@($Gw); Dns=@('10.10.69.1'); DnsSuffix='Horton.LAN' }
    }
}

Describe 'Test-CprPhysicalNic' {
    It 'excludes the same adapters the legacy filter does' {
        Test-CprPhysicalNic (New-Nic) | Should -BeTrue
        Test-CprPhysicalNic (New-Nic -Desc 'Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter') | Should -BeFalse
        Test-CprPhysicalNic (New-Nic -Desc 'Hyper-V Virtual Ethernet Adapter') | Should -BeFalse
        Test-CprPhysicalNic (New-Nic -Desc 'WAN Miniport (IP)') | Should -BeFalse
        Test-CprPhysicalNic (New-Nic -Type 'Tunnel') | Should -BeFalse
    }
}

Describe 'ConvertFrom-CprLeaseEpoch' {
    It 'converts unix seconds to local time and rejects junk' {
        (ConvertFrom-CprLeaseEpoch 1761912109).ToUniversalTime().ToString('o') | Should -Match '^2025-10-31T'
        ConvertFrom-CprLeaseEpoch $null | Should -BeNullOrEmpty
        ConvertFrom-CprLeaseEpoch 0 | Should -BeNullOrEmpty
    }
    It 'handles a REG_DWORD that arrives as a negative signed int' {
        (ConvertFrom-CprLeaseEpoch (-1)) | Should -Not -BeNullOrEmpty
    }
}

Describe 'ConvertTo-CprAdapterRecordFast' {
    It 'builds a wifi record with the legacy field names and values' {
        $r = ConvertTo-CprAdapterRecordFast -Nic (New-Nic) -Lease ([pscustomobject]@{ Obtained = 1761912109; Terminates = 1761912109 + 86400 }) -Ssid 'cia_van'
        $r.InterfaceName | Should -Be 'Wi-Fi'; $r.AdapterClass | Should -Be 'wifi'; $r.ConnectionType | Should -Be 'WiFi'
        $r.SSID | Should -Be 'cia_van'; $r.IPAddress | Should -Be '10.10.69.217'; $r.PrefixLength | Should -Be 24; $r.SubnetMask | Should -Be 24
        $r.DefaultGateway | Should -Be '10.10.69.1'; $r.ConnectionSpecificSuffix | Should -BeExactly 'horton.lan'
        $r.LeaseDurationSeconds | Should -Be 86400; $r.OperationalState | Should -Be 'Up'; $r.InterfaceGuid | Should -Be '{AAAA-1111}'
    }
    It 'builds an ethernet record, no SSID, no lease for a static address' {
        $r = ConvertTo-CprAdapterRecordFast -Nic (New-Nic -Name 'Ethernet' -Desc 'Realtek PCIe GbE Family Controller' -Type 'Ethernet' -Dhcp $false)
        $r.AdapterClass | Should -Be 'ethernet'; $r.ConnectionType | Should -Be 'Ethernet'; $r.SSID | Should -Be 'N/A'
        $r.LeaseObtained | Should -Be 'N/A'; $r.LeaseDurationSeconds | Should -BeNullOrEmpty
    }
    It 'uses N/A for a NIC with no IPv4 or gateway' {
        $n = New-Nic; $n.IPv4 = $null; $n.Gateways = @()
        $r = ConvertTo-CprAdapterRecordFast -Nic $n
        $r.IPAddress | Should -Be 'N/A'; $r.DefaultGateway | Should -Be 'N/A'
    }
}

Describe 'Get-NetworkInfoFast' {
    BeforeEach { $script:Logged = @() }
    It 'returns the legacy shape for exactly one active adapter' {
        $n = Get-NetworkInfoFast -Nics @(New-Nic)
        $n.ActiveAdapterCount | Should -Be 1; $n.MultipleActiveAdapters | Should -BeFalse
        $n.IPAddress | Should -Be '10.10.69.217'; $n.SSID | Should -Be 'TestSsid'
        $n.DNSSuffixes | Should -Contain 'horton.lan'; $n.DNSSuffixes | Should -Contain 'uhc.com'
        $n.Fingerprint | Should -Match '^12\|\{aaaa-1111\}\|10\.10\.69\.217\|10\.10\.69\.1\|testssid\|up$'
        @($n.Adapters).Count | Should -Be 1
    }
    It 'returns $null (caller falls back) for zero or several active adapters' {
        Get-NetworkInfoFast -Nics @() | Should -BeNullOrEmpty
        Get-NetworkInfoFast -Nics @((New-Nic), (New-Nic -Name 'Ethernet' -Type 'Ethernet' -Desc 'Realtek GbE')) | Should -BeNullOrEmpty
    }
    It 'ignores VPN and virtual adapters when counting' {
        $n = Get-NetworkInfoFast -Nics @((New-Nic), (New-Nic -Name 'Cisco' -Desc 'Cisco AnyConnect Virtual Miniport'))
        $n.ActiveAdapterCount | Should -Be 1
    }
    It 'reuses an SSID handed in instead of probing again' {
        $n = Get-NetworkInfoFast -Nics @(New-Nic) -SsidByName @{ 'Wi-Fi' = 'from_legacy' }
        $n.SSID | Should -Be 'from_legacy'
    }
    It 'logs the lease line only when asked' {
        $null = Get-NetworkInfoFast -Nics @(New-Nic)
        $script:Logged.Count | Should -Be 0
        $null = Get-NetworkInfoFast -Nics @(New-Nic) -LogDetails
        ($script:Logged -join ' ') | Should -Match 'DHCP lease on Wi-Fi: 86400s'
    }
}

Describe 'Compare-CprNetworkInfo' {
    It 'reports no differences for identical results (case-insensitive)' {
        $a = Get-NetworkInfoFast -Nics @(New-Nic); $b = Get-NetworkInfoFast -Nics @(New-Nic)
        $b.SSID = 'TESTSSID'
        @(Compare-CprNetworkInfo -Fast $a -Legacy $b).Count | Should -Be 0
    }
    It 'names the field that differs' {
        $a = Get-NetworkInfoFast -Nics @(New-Nic); $b = Get-NetworkInfoFast -Nics @(New-Nic)
        $b.DefaultGateway = '10.10.69.254'
        $d = @(Compare-CprNetworkInfo -Fast $a -Legacy $b)
        $d.Count | Should -Be 1; $d[0] | Should -Match "^DefaultGateway\(fast='10\.10\.69\.1' legacy='10\.10\.69\.254'\)"
    }
    It 'tolerates a 2 s lease-duration difference but not more' {
        $a = Get-NetworkInfoFast -Nics @(New-Nic); $b = Get-NetworkInfoFast -Nics @(New-Nic)
        $b.LeaseDurationSeconds = $a.LeaseDurationSeconds + 2
        @(Compare-CprNetworkInfo -Fast $a -Legacy $b).Count | Should -Be 0
        $b.LeaseDurationSeconds = $a.LeaseDurationSeconds + 60
        @(Compare-CprNetworkInfo -Fast $a -Legacy $b).Count | Should -Be 1
    }
}

Describe 'Get-NetworkInfo mode switch' {
    BeforeEach {
        $script:Logged = @(); $script:LegacyCalls = 0
        Remove-Variable NetProbeMode -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable NetProbeMode -Scope Global -ErrorAction SilentlyContinue
        function Get-NetworkInfoLegacy { $script:LegacyCalls++; $x = Get-NetworkInfoFast -Nics @(New-Nic); $x }
        function Get-CprNicSnapshot { ,@(New-Nic) }
    }
    It 'is legacy when NetProbeMode is not defined (existing tests and callers unchanged)' {
        $r = Get-NetworkInfo
        $script:LegacyCalls | Should -Be 1; $script:Logged.Count | Should -Be 0
    }
    It 'parity mode returns the legacy result and logs ok' {
        $script:NetProbeMode = 'parity'
        $r = Get-NetworkInfo
        $script:LegacyCalls | Should -Be 1
        ($script:Logged -join ' ') | Should -Match 'net_probe_parity=ok fast_ms='
    }
    It 'parity mode logs DIFF as a WARN when the fast result disagrees' {
        $script:NetProbeMode = 'parity'
        function Get-NetworkInfoLegacy { $script:LegacyCalls++; $x = Get-NetworkInfoFast -Nics @(New-Nic); $x.IPAddress = '10.9.9.9'; $x }
        $null = Get-NetworkInfo
        ($script:Logged -join ' ') | Should -Match '\[WARN\] net_probe_parity=DIFF .*IPAddress'
    }
    It 'fast mode skips legacy entirely for one adapter' {
        $script:NetProbeMode = 'fast'
        $r = Get-NetworkInfo
        $script:LegacyCalls | Should -Be 0; $r.IPAddress | Should -Be '10.10.69.217'
        ($script:Logged -join ' ') | Should -Match "probe='fast'"
    }
    It 'fast mode falls back to legacy for several adapters and on error' {
        $script:NetProbeMode = 'fast'
        function Get-CprNicSnapshot { ,@((New-Nic), (New-Nic -Name 'Ethernet' -Type 'Ethernet' -Desc 'Realtek GbE')) }
        $null = Get-NetworkInfo
        $script:LegacyCalls | Should -Be 1
        function Get-CprNicSnapshot { throw 'boom' }
        $null = Get-NetworkInfo
        $script:LegacyCalls | Should -Be 2
        ($script:Logged -join ' ') | Should -Match 'net_probe fast failed'
    }
}

Describe 'config' {
    It 'ships in parity mode for the soak' {
        (Get-Content (Join-Path $script:Root 'main\Main.Configuration.ps1') -Raw) | Should -Match '(?m)^\$NetProbeMode\s*=\s*"parity"'
    }
}
