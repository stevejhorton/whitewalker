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
