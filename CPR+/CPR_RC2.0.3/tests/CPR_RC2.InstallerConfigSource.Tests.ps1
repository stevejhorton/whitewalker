# The installer must not carry its own copies of the version, the CPR task folder or the default
# tee level (RC2.0.3). It reads them from main\Main.Configuration.ps1 as text via
# Get-CprConfigLiteral, with NO fallback (a package without its configuration is broken).
# haystack.ps1 reads the task folder from the same file and keeps a fallback only because it must
# keep running on a box where the file cannot be read; a test pins that fallback to the config value.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:InstallPath = Join-Path $script:Root 'install.ps1'
    $script:ConfigPath  = Join-Path $script:Root 'main\Main.Configuration.ps1'

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:InstallPath, [ref]$tokens, [ref]$errors)
    $fn  = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CprConfigLiteral' }, $true) | Select-Object -First 1
    $script:FnText = $fn.Extent.Text
    Invoke-Expression $script:FnText
}

Describe 'Get-CprConfigLiteral' {
    BeforeEach { $script:Cfg = Join-Path $TestDrive 'cfg.ps1' }

    It 'reads double-quoted, single-quoted and integer literals, ignoring spacing and trailing comments' {
        @('$ver                    = "3.14.0_RC9.9.9"', "`$Single = 'x y'", '$Num          = 7      # a comment', '$CprTaskFolder = "\CPR\"') | Set-Content $script:Cfg
        Get-CprConfigLiteral -Name 'ver' -Path $script:Cfg | Should -Be '3.14.0_RC9.9.9'
        Get-CprConfigLiteral -Name 'Single' -Path $script:Cfg | Should -Be 'x y'
        Get-CprConfigLiteral -Name 'Num' -Path $script:Cfg | Should -Be '7'
        Get-CprConfigLiteral -Name 'CprTaskFolder' -Path $script:Cfg | Should -Be '\CPR\'
    }
    It 'does not match a longer variable name that merely starts with the same letters' {
        '$TeeDefaultLevelOther = 9' | Set-Content $script:Cfg
        { Get-CprConfigLiteral -Name 'TeeDefaultLevel' -Path $script:Cfg } | Should -Throw
    }
    It 'throws (no silent default) when the name is missing or the file is not there' {
        '$other = 1' | Set-Content $script:Cfg
        { Get-CprConfigLiteral -Name 'ver' -Path $script:Cfg } | Should -Throw '*Cannot find*'
        { Get-CprConfigLiteral -Name 'ver' -Path (Join-Path $TestDrive 'nope.ps1') } | Should -Throw '*package is incomplete*'
    }
}

Describe 'install.ps1 and haystack.ps1 parse cleanly' {
    It 'has no PowerShell syntax errors (a bad message string once slipped into the reader)' -ForEach @(@{ F = 'install.ps1' }, @{ F = 'haystack.ps1' }) {
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root $F), [ref]$tokens, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0 -Because (@($errors | ForEach-Object { $_.Message }) -join '; ')
    }
}

Describe 'the installer takes its constants from the configuration' {
    BeforeAll {
        $script:Inst = Get-Content -LiteralPath $script:InstallPath -Raw
        $script:Cfg  = Get-Content -LiteralPath $script:ConfigPath -Raw
    }
    It 'defines none of them as a literal' {
        $script:Inst | Should -Not -Match '(?m)^\$WW_Version\s*=\s*"'
        $script:Inst | Should -Not -Match '(?m)^\$CprTaskFolder\s*=\s*"'
        $script:Inst | Should -Not -Match '(?m)^\$TeeDefaultLevel\s*=\s*\d'
    }
    It 'reads all three through Get-CprConfigLiteral' {
        $script:Inst | Should -Match "\`$CprVersionFull\s*=\s*Get-CprConfigLiteral -Name 'ver'"
        $script:Inst | Should -Match "\`$CprTaskFolder\s*=\s*Get-CprConfigLiteral -Name 'CprTaskFolder'"
        $script:Inst | Should -Match "\`$TeeDefaultLevel\s*=\s*\[int\]\(Get-CprConfigLiteral -Name 'TeeDefaultLevel'\)"
    }
    It 'the configuration defines each one as a literal the reader can parse, and the values are sane' {
        $ver = Get-CprConfigLiteral -Name 'ver' -Path $script:ConfigPath
        $ver | Should -Match '^\d+\.\d+\.\d+_RC\d+(\.\d+)*$'
        ($ver -replace '^.*_', '') | Should -Match '^RC\d+(\.\d+)*$'
        Get-CprConfigLiteral -Name 'CprTaskFolder' -Path $script:ConfigPath | Should -Be '\CPR\'
        [int](Get-CprConfigLiteral -Name 'TeeDefaultLevel' -Path $script:ConfigPath) | Should -BeGreaterOrEqual 0
    }
    It 'every other script that carries the task folder keeps it pinned to the configuration value' {
        $cfgFolder = Get-CprConfigLiteral -Name 'CprTaskFolder' -Path $script:ConfigPath
        $hs = (Select-String -Path (Join-Path $script:Root 'haystack.ps1') -Pattern '^\$TsTaskPath\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
        $hs | Should -Be $cfgFolder
        (Get-Content (Join-Path $script:Root 'haystack.ps1') -Raw) | Should -Match 'CprTaskFolder'
    }
}
