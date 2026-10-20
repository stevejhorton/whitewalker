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
}
