# RC2.0.4 ZPA awareness: preflight host resolving into $ZpaNetworks => one zpa_detected tee row; no state change.
function global:Get-CprFunctionSource {
    param([string]$Path, [string[]]$Names)
    $errors = $null; $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Failed to parse $Path" }
    $found = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Names -contains $n.Name }, $true)
    return (($found | ForEach-Object { $_.Extent.Text }) -join "`n`n")
}
BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    $script:entry = Get-Content (Join-Path $script:root 'main/Main.Entry.ps1') -Raw
    function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') }
    function global:ConvertTo-TelemetryValue { param($v) "$v" }
    Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.Network.ps1') -Names @('Test-CprIpInCidr','Get-CprZpaSignal','Write-CprZpaSignal'))
    $global:ZpaDetectEnabled = $true; $global:ZpaNetworks = @('100.64.0.0/10'); $global:ZpaResolveTimeoutMs = 1500
    $global:NewPreflightURL = 'https://gateway.optum.com'
}
Describe 'Test-CprIpInCidr' {
    It 'matches the whole 100.64.0.0/10 range and nothing outside it' {
        foreach ($ip in '100.64.0.0','100.64.1.7','100.100.5.5','100.127.255.255') { Test-CprIpInCidr -Ip $ip -Cidr '100.64.0.0/10' | Should -BeTrue }
        foreach ($ip in '100.63.255.255','100.128.0.0','10.1.1.1','172.20.1.1','192.168.1.1') { Test-CprIpInCidr -Ip $ip -Cidr '100.64.0.0/10' | Should -BeFalse }
    }
    It 'handles /32, /0, /8 and rejects malformed input without throwing' {
        Test-CprIpInCidr -Ip '10.1.2.3' -Cidr '10.1.2.3/32' | Should -BeTrue
        Test-CprIpInCidr -Ip '10.1.2.4' -Cidr '10.1.2.3/32' | Should -BeFalse
        Test-CprIpInCidr -Ip '8.8.8.8' -Cidr '0.0.0.0/0' | Should -BeTrue
        Test-CprIpInCidr -Ip '10.9.9.9' -Cidr '10.0.0.0/8' | Should -BeTrue
        foreach ($bad in @('x','10.0.0.0','10.0.0.0/40','')) { Test-CprIpInCidr -Ip '10.1.1.1' -Cidr $bad | Should -BeFalse }
        Test-CprIpInCidr -Ip 'notanip' -Cidr '10.0.0.0/8' | Should -BeFalse
    }
}
Describe 'Get-CprZpaSignal' {
    It 'flags an address inside any configured ZPA net (IP literal resolves to itself)' {
        $r = Get-CprZpaSignal -HostName '100.64.12.9' -Networks @('172.30.0.0/16','100.64.0.0/10')
        $r.Zpa | Should -BeTrue; $r.MatchedNet | Should -Be '100.64.0.0/10'; $r.ResolvedIp | Should -Be '100.64.12.9'
        (Get-CprZpaSignal -HostName '172.30.4.4' -Networks @('172.30.0.0/16','100.64.0.0/10')).MatchedNet | Should -Be '172.30.0.0/16'
    }
    It 'does not flag corporate or public answers, and fails closed on bad input' {
        (Get-CprZpaSignal -HostName '10.20.30.40' -Networks @('100.64.0.0/10')).Zpa | Should -BeFalse
        (Get-CprZpaSignal -HostName '' -Networks @('100.64.0.0/10')).Zpa | Should -BeFalse
        (Get-CprZpaSignal -HostName '100.64.1.1' -Networks @()).Zpa | Should -BeFalse
    }
}
Describe 'Write-CprZpaSignal' {
    BeforeEach { $global:rows = @(); function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data) $global:rows += ,@($Tag, $Data) } }
    It 'writes one zpa_detected row when the host resolves into the pool, and nothing otherwise' {
        Mock Get-CprZpaSignal { [pscustomobject]@{ Zpa = $true; ResolvedIp = '100.64.2.2'; MatchedNet = '100.64.0.0/10'; Host = $HostName } }
        Write-CprZpaSignal -NetworkInfo ([pscustomobject]@{ SSID = 'HomeNet'; ConnectionType = 'WiFi' }) -SsidTrusted 'False' -ResultingState 'off_prem_no_vpn'
        $global:rows.Count | Should -Be 1
        $global:rows[0][0] | Should -Be 'zpa_detected'
        $global:rows[0][1].resolved_ip | Should -Be '100.64.2.2'
        $global:rows[0][1].gw_host | Should -Be 'gateway.optum.com'
        $global:rows[0][1].resulting_state | Should -Be 'off_prem_no_vpn'
        $global:rows = @()
        Mock Get-CprZpaSignal { [pscustomobject]@{ Zpa = $false; ResolvedIp = '10.1.1.1'; MatchedNet = ''; Host = $HostName } }
        Write-CprZpaSignal -NetworkInfo ([pscustomobject]@{ SSID = 'WLANi03'; ConnectionType = 'WiFi' }) -ResultingState 'on_prem'
        $global:rows.Count | Should -Be 0
    }
    It 'is off when ZpaDetectEnabled is false' {
        Mock Get-CprZpaSignal { throw 'must not be called' }
        $global:ZpaDetectEnabled = $false
        try { { Write-CprZpaSignal -NetworkInfo ([pscustomobject]@{ SSID = 'x' }) } | Should -Not -Throw; $global:rows.Count | Should -Be 0 } finally { $global:ZpaDetectEnabled = $true }
    }
}
Describe 'wiring' {
    It 'calls Write-CprZpaSignal only in the two DC-reachable no-VPN exits, before the flare, and adds no new state' {
        ([regex]::Matches($script:entry, 'Write-CprZpaSignal')).Count | Should -Be 2
        $a = $script:entry.IndexOf('Write-CprZpaSignal'); $b = $script:entry.IndexOf("Send-FlareEvent 'on_prem'", $a)
        $b | Should -BeGreaterThan $a
        $script:entry | Should -Not -Match "State 'zpa"
    }
}
AfterAll {
    foreach ($f in 'Write-TeeLog','Write-Log','ConvertTo-TelemetryValue') { Remove-Item "function:global:$f" -ErrorAction SilentlyContinue }
    Remove-Variable -Name rows -Scope Global -ErrorAction SilentlyContinue
}
