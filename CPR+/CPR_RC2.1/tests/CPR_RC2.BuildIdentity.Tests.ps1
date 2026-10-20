Describe 'CPR build identity' {
    BeforeAll { $script:root = Split-Path -Parent $PSScriptRoot }

    It 'puts the same version on line 1 of WW_main.ps1 as $ver in the config' {
        $ver = (Select-String -Path (Join-Path $root 'main\Main.Configuration.ps1') -Pattern '^\$ver\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
        (Get-Content (Join-Path $root 'WW_main.ps1') -TotalCount 1) | Should -Match ([regex]::Escape("v$ver"))
    }

    It 'fingerprints main + WW_main, and changes when a file changes' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.Logging.ps1'), [ref]$null, [ref]$null)
        $def = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CprBuildFingerprint' }, $true)[0]
        . ([scriptblock]::Create($def.Extent.Text))
        $main = Join-Path $TestDrive 'main'; New-Item -ItemType Directory $main | Out-Null
        Set-Content (Join-Path $TestDrive 'WW_main.ps1') 'a'; Set-Content (Join-Path $main 'Main.A.ps1') 'b'
        $script:CprBuildFingerprint = $null
        $one = Get-CprBuildFingerprint -MainDir $main
        $one | Should -Match '^[0-9a-f]{12} files=2$'
        $script:CprBuildFingerprint = $null
        (Get-CprBuildFingerprint -MainDir $main) | Should -Be $one
        Add-Content (Join-Path $main 'Main.A.ps1') 'changed'
        $script:CprBuildFingerprint = $null
        (Get-CprBuildFingerprint -MainDir $main) | Should -Not -Be $one
    }

    It 'shows the real CPR version in the action console header and menu' {
        $ver = (Select-String -Path (Join-Path $root 'main\Main.Configuration.ps1') -Pattern '^\$ver\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
        $src = Get-Content (Join-Path $root 'admin\Invoke-WhiteWalkerAction.ps1') -Raw
        $src | Should -Match ([regex]::Escape("CPR version: $ver"))
        $src | Should -Match 'Get-WWCprVersion'
    }
}

Describe 'Uninstall removes everything' {
    BeforeAll {
        $inst = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($inst, [ref]$null, [ref]$null)
        $want = 'Remove-InstallDirectory'
        $d = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $want }, $true)[0]
        . ([scriptblock]::Create($d.Extent.Text))
        function Write-InstallLog { param($m, $l) }
    }
    It 'deletes the whole install dir including logs' {
        $script:MainScriptDeployDir = Join-Path $TestDrive 'WhiteWalker'
        New-Item -ItemType Directory -Path (Join-Path $script:MainScriptDeployDir 'logs') -Force | Out-Null
        Set-Content (Join-Path $script:MainScriptDeployDir 'logs\x.log') 'x'
        Set-Content (Join-Path $script:MainScriptDeployDir 'WW_main.ps1') 'x'
        Remove-InstallDirectory | Should -BeTrue
        Test-Path $script:MainScriptDeployDir | Should -BeFalse
    }
    It 'uninstall no longer preserves logs or diagnostics, and returns a failure code when incomplete' {
        $src = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1') -Raw
        $src | Should -Not -Match 'preserve diagnostics'
        $src | Should -Match 'ExitCodeUninstallIncomplete'
        $src | Should -Match 'Remove-CprTaskFolder'
    }
}

Describe 'Connected VPN short-circuits the unreachable branch' {
    BeforeAll { $script:entry = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.Entry.ps1') -Raw }
    It 'exits on a Connected VPN before testing enroll.cisco.com' {
        $exit = $entry.IndexOf('skipping enroll.cisco.com and captive-portal checks')
        $test = $entry.IndexOf('$enrollResult = Test-Redirect -Url $ISERedirectTestURL')
        $exit | Should -BeGreaterThan 0
        $exit | Should -BeLessThan $test
    }
    It 'does not re-probe a VPN that stayed Connected' {
        $entry | Should -Match 'not \$reprobedOnNetworkChange -and -not \$vpnStayedConnected'
    }
}


Describe 'End-of-run network re-check' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        . ([scriptblock]::Create((Get-Content (Join-Path $root 'main\Main.Network.ps1') -Raw)))
        $script:entry = Get-Content (Join-Path $root 'main\Main.Entry.ps1') -Raw
    }
    BeforeEach {
        $script:EndRunRecheckEnabled = $true; $script:EndRunRerunMax = 2; $script:EndRunRerunWindowSec = 60
        $script:EndRunRerunDelaySec = 3; $script:CprTaskFolder = '\CPR\'; $script:WhatIf = $false
        $script:EndRunRerunStateFile = Join-Path $TestDrive 'rerun.txt'
        function Write-Log { param($m,$l) }
        function Write-TeeLog { param($a,$f) $script:teeSeen = @{ a = $a; f = $f } }
        Mock Request-CprRerun { $true }
    }
    It 'reports no change and does not re-run when the fingerprint matches' {
        $ni = [pscustomobject]@{ SSID='A'; IPAddress='1.1.1.1'; DefaultGateway='1.1.1.254'; InterfaceIndex=1; InterfaceGuid='g'; OperationalState='Up' }
        Mock Get-NetworkInfo { $ni }
        (Invoke-EndRunNetworkRecheck -Baseline $ni).Changed | Should -BeFalse
        Should -Invoke Request-CprRerun -Times 0
    }
    It 'detects a flip, tees it and requests one re-run' {
        $old = [pscustomobject]@{ SSID='SNAFU'; IPAddress='1.1.1.1'; DefaultGateway='1.1.1.254'; InterfaceIndex=1; InterfaceGuid='g'; OperationalState='Up' }
        $new = [pscustomobject]@{ SSID='cia_van'; IPAddress='2.2.2.2'; DefaultGateway='2.2.2.254'; InterfaceIndex=1; InterfaceGuid='g'; OperationalState='Up' }
        Mock Get-NetworkInfo { $new }
        $r = Invoke-EndRunNetworkRecheck -Baseline $old
        $r.Changed | Should -BeTrue
        $r.Rerun | Should -BeTrue
        $script:teeSeen.a | Should -Be 'network_changed_during_run'
    }
    It 'caps chained re-runs' {
        (Test-RerunAllowed) | Should -BeTrue
        (Test-RerunAllowed) | Should -BeTrue
        (Test-RerunAllowed) | Should -BeFalse
    }
    It 'runs before the maintenance stage' {
        $entry.IndexOf('Invoke-EndRunNetworkRecheck') | Should -BeLessThan $entry.IndexOf('Invoke-MaintenanceStage -ExitReason')
    }
}
