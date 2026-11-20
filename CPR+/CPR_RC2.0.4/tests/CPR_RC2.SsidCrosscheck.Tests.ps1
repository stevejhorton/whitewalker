# RC2.0.4: stale-SSID cross-check (netsh vs WLAN-AutoConfig 8001) in Main, and the base runner's "user left the portal network" guard.
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
    $script:runnerPath = Join-Path $script:root 'WW_cap_portal_runner_base.ps1'
    $script:runnerSource = Get-Content $script:runnerPath -Raw
    function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') }
    function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') }
    function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data) $global:teeRows += ,@($Tag, $Data) }
    function global:Get-WinEvent { param($FilterHashtable, $MaxEvents, $ErrorAction) }
    Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.Network.ps1') -Names @('Get-CprWlanConnectEvent','Resolve-CprWlanSsid','Get-WlanSsidForAdapter'))
    Invoke-Expression (Get-CprFunctionSource -Path $script:runnerPath -Names @('Get-BaseCapWlanEventSsid','Test-BaseCapNetworkChanged'))
    function script:New-WlanEvent($guid, $ssid, $secondsAgo) {
        $xml = "<Event><EventData><Data Name='InterfaceGuid'>{$guid}</Data><Data Name='SSID'>$ssid</Data></EventData></Event>"
        $o = [pscustomobject]@{ TimeCreated = (Get-Date).AddSeconds(-$secondsAgo); Xml = $xml }
        $o | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml } -Force
        $o
    }
    $global:SsidCrosscheckEnabled = $true; $global:SsidCrosscheckMaxAgeSec = 900
}
Describe 'Get-CprWlanConnectEvent' {
    It 'returns the newest 8001 for the matching interface GUID and ignores other interfaces' {
        $g = 'aaaaaaaa-0000-0000-0000-000000000001'
        Mock Get-WinEvent { @((New-WlanEvent 'bbbbbbbb-0000-0000-0000-000000000002' 'Other' 5), (New-WlanEvent $g 'M3000-AB94' 20), (New-WlanEvent $g 'DeltaSkyClub' 300)) }
        $r = Get-CprWlanConnectEvent -InterfaceGuid "{$g}"
        $r.Ssid | Should -Be 'M3000-AB94'
        ((Get-Date) - $r.Time).TotalSeconds | Should -BeLessThan 60
    }
    It 'returns $null when there is no event, no GUID, or the log read fails' {
        Mock Get-WinEvent { throw 'NoMatchingEventsFound' }
        Get-CprWlanConnectEvent -InterfaceGuid 'cccccccc-0000-0000-0000-000000000003' | Should -BeNullOrEmpty
        Get-CprWlanConnectEvent -InterfaceGuid '' | Should -BeNullOrEmpty
    }
}
Describe 'Resolve-CprWlanSsid' {
    BeforeEach { $global:teeRows = @() }
    It 'keeps the netsh SSID when the event agrees, and writes no tee row' {
        Mock Get-CprWlanConnectEvent { [pscustomobject]@{ Ssid = 'HomeNet'; Time = (Get-Date).AddSeconds(-30); Guid = 'x' } }
        Resolve-CprWlanSsid -NetshSsid 'HomeNet' -InterfaceGuid 'g1' | Should -Be 'HomeNet'
        $global:teeRows.Count | Should -Be 0
    }
    It 'uses the event SSID when netsh disagrees (stale after a roam) and writes one ssid_crosscheck_override row' {
        Mock Get-CprWlanConnectEvent { [pscustomobject]@{ Ssid = 'M3000-AB94'; Time = (Get-Date).AddSeconds(-12); Guid = 'x' } }
        Resolve-CprWlanSsid -NetshSsid 'DeltaSkyClub' -InterfaceGuid 'g2' -AdapterName 'Wi-Fi' | Should -Be 'M3000-AB94'
        $global:teeRows.Count | Should -Be 1
        $global:teeRows[0][0] | Should -Be 'ssid_crosscheck_override'
        $global:teeRows[0][1].ssid | Should -Be 'M3000-AB94'
        $global:teeRows[0][1].netsh_ssid | Should -Be 'DeltaSkyClub'
        $global:teeRows[0][1].ssid_source | Should -Be 'event_8001'
    }
    It 'falls back to netsh with no event, no GUID, a blank netsh SSID, or the feature off' {
        Mock Get-CprWlanConnectEvent { $null }
        Resolve-CprWlanSsid -NetshSsid 'A' -InterfaceGuid 'g3' | Should -Be 'A'
        Mock Get-CprWlanConnectEvent { [pscustomobject]@{ Ssid = 'B'; Time = (Get-Date); Guid = 'x' } }
        Resolve-CprWlanSsid -NetshSsid 'A' -InterfaceGuid '' | Should -Be 'A'
        Resolve-CprWlanSsid -NetshSsid '' -InterfaceGuid 'g3' | Should -Be ''
        $global:SsidCrosscheckEnabled = $false
        try { Resolve-CprWlanSsid -NetshSsid 'A' -InterfaceGuid 'g3' | Should -Be 'A' } finally { $global:SsidCrosscheckEnabled = $true }
        $global:teeRows.Count | Should -Be 0
    }
    It 'never throws if the event lookup does' {
        Mock Get-CprWlanConnectEvent { throw 'boom' }
        { Resolve-CprWlanSsid -NetshSsid 'A' -InterfaceGuid 'g4' } | Should -Not -Throw
        Resolve-CprWlanSsid -NetshSsid 'A' -InterfaceGuid 'g4' | Should -Be 'A'
    }
}
Describe 'Get-WlanSsidForAdapter hands the netsh GUID to the cross-check' {
    It 'passes the interface GUID from the netsh block and returns the resolved SSID' {
        function global:netsh {
            "    Name                   : Wi-Fi`n    GUID                   : 11111111-2222-3333-4444-555555555555`n    State                  : connected`n    SSID                   : DeltaSkyClub`n    BSSID                  : aa:bb:cc:dd:ee:ff`n"
        }
        Mock Resolve-CprWlanSsid { 'M3000-AB94' }
        Get-WlanSsidForAdapter -AdapterName 'Wi-Fi' | Should -Be 'M3000-AB94'
        Should -Invoke Resolve-CprWlanSsid -Times 1 -ParameterFilter { $InterfaceGuid -eq '11111111-2222-3333-4444-555555555555' -and $NetshSsid -eq 'DeltaSkyClub' }
        Remove-Item function:global:netsh -ErrorAction SilentlyContinue
    }
}
Describe 'Test-BaseCapNetworkChanged' {
    It 'flags a different gateway, a different SSID, or a different adapter; ignores empty values' {
        $disp = @{ ssid = 'DeltaSkyClub'; gw = '10.0.0.1' }; $start = @{ ssid = 'DeltaSkyClub'; gw = '10.0.0.1'; interface_guid = 'g1' }
        (Test-BaseCapNetworkChanged -DispatchContext $disp -StartContext $start -CurrentContext @{ ssid = 'DeltaSkyClub'; gw = '10.0.0.1'; interface_guid = 'g1' }).Changed | Should -BeFalse
        $r = Test-BaseCapNetworkChanged -DispatchContext $disp -StartContext $start -CurrentContext @{ ssid = 'M3000-AB94'; gw = '192.168.144.1'; interface_guid = 'g1' }
        $r.Changed | Should -BeTrue; $r.Reason | Should -Be 'gateway_changed'; $r.OldSsid | Should -Be 'DeltaSkyClub'; $r.NewSsid | Should -Be 'M3000-AB94'
        (Test-BaseCapNetworkChanged -DispatchContext $disp -StartContext $null -CurrentContext @{ ssid = 'M3000-AB94'; gw = ''; interface_guid = '' }).Reason | Should -Be 'ssid_changed'
        (Test-BaseCapNetworkChanged -DispatchContext @{ ssid = ''; gw = '' } -StartContext @{ ssid = 'X'; gw = '1.1.1.1'; interface_guid = 'g1' } -CurrentContext @{ ssid = 'X'; gw = '1.1.1.1'; interface_guid = 'g2' }).Reason | Should -Be 'adapter_changed'
    }
    It 'a lease that merely arrived late (empty old gateway, same SSID) is NOT a change' {
        (Test-BaseCapNetworkChanged -DispatchContext @{ ssid = 'DeltaSkyClub'; gw = '' } -StartContext @{ ssid = 'DeltaSkyClub'; gw = ''; interface_guid = 'g1' } -CurrentContext @{ ssid = 'DeltaSkyClub'; gw = '10.0.0.1'; interface_guid = 'g1' }).Changed | Should -BeFalse
        (Test-BaseCapNetworkChanged -DispatchContext $null -StartContext $null -CurrentContext $null).Changed | Should -BeFalse
    }
    It 'SSID comparison is case-insensitive' {
        (Test-BaseCapNetworkChanged -DispatchContext @{ ssid = 'HomeNet'; gw = '' } -StartContext $null -CurrentContext @{ ssid = 'homenet'; gw = ''; interface_guid = '' }).Changed | Should -BeFalse
    }
}
Describe 'Get-BaseCapWlanEventSsid' {
    It 'returns the SSID of the newest matching 8001 and $null on a read failure' {
        $g = 'dddddddd-0000-0000-0000-000000000004'
        Mock Get-WinEvent { @((New-WlanEvent $g 'M3000-AB94' 8)) }
        (Get-BaseCapWlanEventSsid -InterfaceGuid "{$g}").Ssid | Should -Be 'M3000-AB94'
        Mock Get-WinEvent { throw 'x' }
        Get-BaseCapWlanEventSsid -InterfaceGuid $g | Should -BeNullOrEmpty
    }
}
Describe 'base runner wiring' {
    It 'checks for a network change before reporting native_resolution, abandons without the timeout/escalation block, and keeps the passed row for the unchanged case' {
        $src = $script:runnerSource
        $i = $src.IndexOf('Test-BaseCapNetworkChanged -DispatchContext $dispatchContext')
        $j = $src.IndexOf('Write-CompletionFlag -Status "SUCCESS_NATIVE"')
        $i | Should -BeGreaterThan 0; $j | Should -BeGreaterThan $i
        $src | Should -Match "-Reason 'network_changed_before_portal_cleared'"
        $src | Should -Match 'if \(-not \$observed -and -not \$networkChangedAbandon\)'
        $src | Should -Match 'Write-CompletionFlag -Status "NETWORK_CHANGED"'
    }
    It 'cross-checks the SSID inside Get-BaseCapNetworkContext' {
        (Get-CprFunctionSource -Path $script:runnerPath -Names @('Get-BaseCapNetworkContext')) | Should -Match 'Get-BaseCapWlanEventSsid'
    }
}
AfterAll {
    foreach ($f in 'Write-Log','Write-BaseCapLog','Write-TeeLog','Get-WinEvent','netsh') { Remove-Item "function:global:$f" -ErrorAction SilentlyContinue }
    Remove-Variable -Name teeRows -Scope Global -ErrorAction SilentlyContinue
}
