# RC2.0.3: first Connecting/Reconnecting sighting in a run does one record-only portal probe (non-always-on browser auth).
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
    $script:vpnPath = Join-Path $script:root 'main/Main.VpnState.ps1'
    $script:vpnSource = Get-Content $script:vpnPath -Raw
    function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') }
    function global:ConvertTo-TelemetryValue { param($v) "$v" }
    function global:Get-CaptivePortalNetworkContext { @{ ssid = 'MUSC'; ip = '10.1.1.5'; gw = '10.1.1.1'; dns = '8.8.8.8' } }
    function global:Get-CaptivePortalRedirectTelemetry { param([string]$RedirectUrl) [ordered]@{ url = $RedirectUrl; port = '443'; protocol = 'https'; fqdn = 'portal.musc.edu' } }
    function global:Get-CprPortalUrlFields { param([string]$Url) @{ portal_host = 'portal.musc.edu' } }
    Invoke-Expression (Get-CprFunctionSource -Path $script:vpnPath -Names @('Invoke-CprConnectingPortalProbe'))
    $global:NewPreflightURL = 'https://gateway.optum.com'; $global:PreflightConnectingTimeoutMs = 3000; $global:PreflightProbeWhileConnecting = $true
}
Describe 'Invoke-CprConnectingPortalProbe' {
    BeforeEach { $script:ConnectingProbeDone = $false; $global:rows = @(); function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data) $global:rows += ,@($Tag, $Data) } }
    It 'writes one cap_portal_redirect row (connecting_probe) on a redirect, once per run' {
        function global:Get-NwCheckResult { param($Url, $TimeoutMs) [pscustomobject]@{ Status = 'redirect'; RedirectUrl = 'https://portal.musc.edu/login' } }
        Invoke-CprConnectingPortalProbe -VpnState 'Connecting'
        Invoke-CprConnectingPortalProbe -VpnState 'Connecting'
        $global:rows.Count | Should -Be 1
        $global:rows[0][0] | Should -Be 'cap_portal_redirect'
        $global:rows[0][1].detection_source | Should -Be 'connecting_probe'
        $global:rows[0][1].fqdn | Should -Be 'portal.musc.edu'
        $global:rows[0][1].vpn_state | Should -Be 'Connecting'
    }
    It 'writes nothing when the probe is online or fails, and never throws' {
        function global:Get-NwCheckResult { param($Url, $TimeoutMs) throw 'boom' }
        { Invoke-CprConnectingPortalProbe -VpnState 'Connecting' } | Should -Not -Throw
        $script:ConnectingProbeDone = $false
        function global:Get-NwCheckResult { param($Url, $TimeoutMs) [pscustomobject]@{ Status = 'online'; RedirectUrl = '' } }
        Invoke-CprConnectingPortalProbe -VpnState 'Connecting'
        $global:rows.Count | Should -Be 0
    }
    It 'is wired into the stabilize loop before the intermediate-state wait, and never opens a browser' {
        $i = $script:vpnSource.IndexOf('Invoke-CprConnectingPortalProbe -VpnState $state')
        $j = $script:vpnSource.IndexOf('(will force disconnect after')
        $i | Should -BeGreaterThan 0; $j | Should -BeGreaterThan $i
        (Get-CprFunctionSource -Path $script:vpnPath -Names @('Invoke-CprConnectingPortalProbe')) | Should -Not -Match 'Send-FlareEvent|Start-Process'
    }
}
AfterAll {
    foreach ($f in 'Get-NwCheckResult','Write-TeeLog','Write-Log','ConvertTo-TelemetryValue','Get-CaptivePortalNetworkContext','Get-CaptivePortalRedirectTelemetry','Get-CprPortalUrlFields') {
        Remove-Item "function:global:$f" -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name rows -Scope Global -ErrorAction SilentlyContinue
}
