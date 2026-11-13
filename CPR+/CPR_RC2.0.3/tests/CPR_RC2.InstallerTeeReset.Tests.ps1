# Every install/upgrade writes the default tee level and clears the previous tee state (RC2.0.3):
# revert stamp, cpr_tee_<1-5>[_keep].flag, tee_assign sync/try flags. Other files stay.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'install.ps1'), [ref]$tokens, [ref]$errors)
    $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Clear-TeeInstallState' }, $true) | Select-Object -First 1
    $fn | Should -Not -BeNullOrEmpty
    Invoke-Expression $fn.Extent.Text
    function Write-InstallLog { param($Message, $Level) }
}

Describe 'Clear-TeeInstallState' {
    BeforeEach {
        $script:Flags = Join-Path $TestDrive 'flags'
        $script:Data  = Join-Path $TestDrive 'data'
        New-Item -ItemType Directory -Path $script:Flags, $script:Data -Force | Out-Null
        $script:Stamp = Join-Path $script:Data 'tee_level_revert.json'
        $script:Sync  = Join-Path $script:Data 'tee_assign_sync.flag'
        $script:Try   = Join-Path $script:Data 'tee_assign_try.flag'
        foreach ($f in @($script:Stamp, $script:Sync, $script:Try)) { Set-Content $f 'x' }
    }

    It 'removes the revert stamp, the plain and keep tee flags and the assign sync/try flags' {
        foreach ($n in 'cpr_tee_3.flag', 'cpr_tee_5_keep.flag') { Set-Content (Join-Path $script:Flags $n) '' }
        $r = @(Clear-TeeInstallState -FlagDir $script:Flags -RevertFile $script:Stamp -SyncFlag $script:Sync -TryFlag $script:Try)
        $r.Count | Should -Be 5
        foreach ($p in @($script:Stamp, $script:Sync, $script:Try, (Join-Path $script:Flags 'cpr_tee_3.flag'), (Join-Path $script:Flags 'cpr_tee_5_keep.flag'))) {
            Test-Path -LiteralPath $p | Should -BeFalse
        }
    }

    It 'leaves .failed tee flags, self-update flags, out-of-range names and unrelated files alone' {
        $keep = 'cpr_tee_3.flag.failed', 'cpr_update_dev_tee_5.flag', 'cpr_tee_9.flag', 'cpr_tee_0.flag', 'other.txt'
        foreach ($n in $keep) { Set-Content (Join-Path $script:Flags $n) '' }
        Clear-TeeInstallState -FlagDir $script:Flags -RevertFile $script:Stamp -SyncFlag $script:Sync -TryFlag $script:Try | Out-Null
        foreach ($n in $keep) { Test-Path -LiteralPath (Join-Path $script:Flags $n) | Should -BeTrue -Because $n }
    }

    It 'does nothing and does not throw when none of it exists' {
        $r = @(Clear-TeeInstallState -FlagDir (Join-Path $TestDrive 'nope') -RevertFile (Join-Path $TestDrive 'a.json') -SyncFlag (Join-Path $TestDrive 'b.flag') -TryFlag (Join-Path $TestDrive 'c.flag'))
        $r.Count | Should -Be 0
    }
}

Describe 'install.ps1 tee reset wiring' {
    BeforeAll {
        $script:Inst = Get-Content -LiteralPath (Join-Path $script:Root 'install.ps1') -Raw
        $script:Cfg  = Get-Content -LiteralPath (Join-Path $script:Root 'main\Main.Configuration.ps1') -Raw
    }
    It 'reads the four paths from the configuration, which defines each as a literal' {
        foreach ($n in 'TeeFlagDir', 'TeeRevertStateFile', 'TeeAssignSyncFlag', 'TeeAssignTryFlag') {
            $script:Inst | Should -Match "Get-CprConfigLiteral -Name '$n'"
            $script:Cfg  | Should -Match ('(?m)^\$' + $n + '\s*=\s*"[^"]+"')
            $script:Inst | Should -Not -Match ('(?m)^\$' + $n + '\s*=\s*"')
        }
    }
    It 'clears the old state before writing the default level, inside Update-TeeProfile' {
        $i = $script:Inst.IndexOf('function Update-TeeProfile')
        $body = $script:Inst.Substring($i)
        $body.IndexOf('@(Clear-TeeInstallState)') | Should -BeGreaterThan 0
        $body.IndexOf('@(Clear-TeeInstallState)') | Should -BeLessThan $body.IndexOf('Set-CprTeeLevel -Level $level')
    }
}
