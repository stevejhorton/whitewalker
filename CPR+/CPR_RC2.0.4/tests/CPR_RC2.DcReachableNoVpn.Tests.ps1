# RC2.0.4: DC reachable with no VPN (Zscaler ZPA etc.) => state.json dcReachableNoVpn; HayStack drain and self-update treat it as reachable (60 min).
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
    Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $script:root 'haystack_action.ps1') -Names @('Get-CurrentNetworkState','Test-SyslogReachable'))
    Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.State.ps1') -Names @('Set-FlareStamp'))
    function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') }
    function global:To-Hashtable { param($o) $h = @{}; $o.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value }; $h }
    function global:Save-State { param($s) }
    $script:StateFlares = @('on_prem','user_tun','mgmt_tun','off_prem_no_vpn','captive_portal','no_net_transient','vpn_connecting','cpr_error')
    $script:selfUpdate = Get-Content (Join-Path $script:root 'main/Main.SelfUpdate.ps1') -Raw
    $script:entry = Get-Content (Join-Path $script:root 'main/Main.Entry.ps1') -Raw
}
Describe 'HayStack drain gate' {
    BeforeAll {
    function Set-St($state, $dc, $minutesAgo) {
        $o = @{ currentState = $state; currentStateTime = (Get-Date).AddMinutes(-$minutesAgo).ToString('o') }
        if ($null -ne $dc) { $o.dcReachableNoVpn = $dc }
        ($o | ConvertTo-Json) | Set-Content $script:WwStateFile
    }
    }
    BeforeEach { $script:WwStateFile = Join-Path $TestDrive 'state.json' }
    It 'still true for on_prem / user_tun / mgmt_tun and false for other states without the marker' {
        foreach ($s in 'on_prem','user_tun','mgmt_tun') { Set-St $s $null 0; Test-SyslogReachable | Should -BeTrue }
        foreach ($s in 'off_prem_no_vpn','captive_portal','no_net_transient','vpn_connecting') { Set-St $s $null 0; Test-SyslogReachable | Should -BeFalse }
    }
    It 'true for off_prem_no_vpn with a fresh dcReachableNoVpn marker, false when stale, false-marked, or on another state' {
        Set-St 'off_prem_no_vpn' $true 5;   Test-SyslogReachable | Should -BeTrue
        Set-St 'off_prem_no_vpn' $true 59;  Test-SyslogReachable | Should -BeTrue
        Set-St 'off_prem_no_vpn' $true 61;  Test-SyslogReachable | Should -BeFalse
        Set-St 'off_prem_no_vpn' $false 5;  Test-SyslogReachable | Should -BeFalse
        Set-St 'captive_portal'  $true 5;   Test-SyslogReachable | Should -BeFalse
    }
    It 'is false (not an error) with no state file or garbage in it' {
        Remove-Item $script:WwStateFile -ErrorAction SilentlyContinue; Test-SyslogReachable | Should -BeFalse
        'not json' | Set-Content $script:WwStateFile; Test-SyslogReachable | Should -BeFalse
    }
}
Describe 'Set-FlareStamp writes the marker' {
    BeforeEach { $global:_state = [pscustomobject]@{ lastFlare = @{} } }
    It 'true only for on_prem / off_prem_no_vpn in a run that took the DC-reachable no-VPN branch' {
        $script:DcReachableNoVpn = $true
        Set-FlareStamp 'off_prem_no_vpn'; $global:_state.dcReachableNoVpn | Should -BeTrue
        Set-FlareStamp 'captive_portal';  $global:_state.dcReachableNoVpn | Should -BeFalse
        $script:DcReachableNoVpn = $false
        Set-FlareStamp 'off_prem_no_vpn'; $global:_state.dcReachableNoVpn | Should -BeFalse
    }
}
Describe 'wiring' {
    It 'self-update honors the marker, and Entry sets the flag in both DC-reachable exits before the flare' {
        $script:selfUpdate | Should -Match 'dcReachableNoVpn'
        $script:selfUpdate | Should -Match 'goodStates -notcontains \$lastState -and -not \$dcNoVpnOk'
        ([regex]::Matches($script:entry, '\$script:DcReachableNoVpn = \$true')).Count | Should -Be 2
    }
}
AfterAll { foreach ($f in 'Write-Log','To-Hashtable','Save-State') { Remove-Item "function:global:$f" -ErrorAction SilentlyContinue }; Remove-Variable -Name _state -Scope Global -ErrorAction SilentlyContinue }
