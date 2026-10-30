# TEMPORARY: delete with WW_migrate_legacy_tasks.ps1 when the migration is retired.
Describe 'CPR task folder consistency' {
    BeforeAll { $script:root = Split-Path -Parent $PSScriptRoot }

    It 'installer reads the task folder from Main.Configuration.ps1; haystack.ps1 falls back to the same value' {
        $inst = Get-Content (Join-Path $root 'install.ps1') -Raw
        $inst | Should -Match "\`$CprTaskFolder\s*=\s*Get-CprConfigLiteral -Name 'CprTaskFolder'"
        $inst | Should -Not -Match '(?m)^\$CprTaskFolder\s*=\s*"'
        $c = (Select-String -Path (Join-Path $root 'main\Main.Configuration.ps1') -Pattern '^\$CprTaskFolder\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
        $h = (Select-String -Path (Join-Path $root 'haystack.ps1') -Pattern '^\$TsTaskPath\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
        $c | Should -Be '\CPR\'
        $h | Should -Be $c
    }
    It 'installer registers every task XML under the CPR folder' {
        $src = Get-Content (Join-Path $root 'install.ps1') -Raw
        ([regex]::Matches($src, 'TaskPath = "\\"; Path = "\$ScriptRoot')).Count | Should -Be 0
        ([regex]::Matches($src, 'TaskPath = \$CprTaskFolder; Path = "\$ScriptRoot')).Count | Should -Be 8
    }
}

Describe 'Legacy task migration' {
    BeforeAll {
        # Non-Windows runs: Pester's Mock needs the ScheduledTasks cmdlets to exist.
        foreach ($c in 'Get-ScheduledTask', 'Unregister-ScheduledTask') {
            if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { Set-Item "function:global:$c" { param($TaskName, $TaskPath, $InputObject, $Confirm, $ErrorAction) } }
        }
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'WW_migrate_legacy_tasks.ps1')
    }
    BeforeEach {
        $script:MigLogPath  = Join-Path $TestDrive 'mig.log'
        $script:MigFlagPath = Join-Path $TestDrive 'mig.done'
        Remove-Item $script:MigLogPath, $script:MigFlagPath -ErrorAction SilentlyContinue
        $script:tasks = Join-Path $TestDrive 'Tasks'
        Remove-Item $script:tasks -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path (Join-Path $script:tasks 'HayStack') -Force | Out-Null
        Set-Content (Join-Path $script:tasks 'WW_main') 'x'
        Set-Content (Join-Path $script:tasks 'HayStack\HayStack_Monitor') 'x'
        Mock Unregister-ScheduledTask {
            param($TaskName, $TaskPath, $Confirm, $ErrorAction)
            $rel = (($TaskPath.Trim('\')), $TaskName | Where-Object { $_ }) -join '\'
            Remove-Item (Join-Path $script:tasks $rel) -Force
        }
        Mock Remove-EmptyTaskFolder { }
    }

    It 'removes legacy tasks, logs, and writes the done-flag' {
        $r = Invoke-LegacyTaskMigration -TasksRoot $script:tasks
        $r.Ran | Should -BeTrue
        $r.Removed.Count | Should -Be 2 -Because ("Removed=[$($r.Removed -join ',')] Failed=[$($r.Failed -join ',')] log: " + (Get-Content $script:MigLogPath -Raw -ErrorAction SilentlyContinue))
        Test-Path (Join-Path $script:tasks 'WW_main') | Should -BeFalse
        Test-Path $script:MigFlagPath | Should -BeTrue
        (Get-Content $script:MigLogPath -Raw) | Should -Match 'removed legacy task \\WW_main'
    }
    It 'skips quietly when the flag exists and nothing legacy is left' {
        Set-Content $script:MigFlagPath '{}'
        Remove-Item (Join-Path $script:tasks 'WW_main'), (Join-Path $script:tasks 'HayStack\HayStack_Monitor')
        $r = Invoke-LegacyTaskMigration -TasksRoot $script:tasks
        $r.Ran | Should -BeFalse
        $r.Reason | Should -Be 'flag_present'
        Should -Invoke Unregister-ScheduledTask -Times 0 -Exactly
        Test-Path $script:MigLogPath | Should -BeFalse
    }
    It 'runs again when the flag exists but legacy tasks reappeared' {
        Set-Content $script:MigFlagPath '{}'
        $r = Invoke-LegacyTaskMigration -TasksRoot $script:tasks
        $r.Ran | Should -BeTrue
        (Get-Content $script:MigLogPath -Raw) | Should -Match 'reappeared'
    }
    It 'does nothing when the pivot is off' {
        $r = Invoke-LegacyTaskMigration -TasksRoot $script:tasks -Enabled $false
        $r.Ran | Should -BeFalse
        $r.Reason | Should -Be 'pivot_off'
        Should -Invoke Unregister-ScheduledTask -Times 0 -Exactly
    }
    It 'does not write the flag when a removal fails' {
        Mock Unregister-ScheduledTask { throw 'nope' }
        $r = Invoke-LegacyTaskMigration -TasksRoot $script:tasks
        $r.Failed.Count | Should -Be 2
        $r.Reason | Should -Be 'incomplete'
        Test-Path $script:MigFlagPath | Should -BeFalse
    }
    It 'reads the pivot from the config and defaults to on' {
        $cfg = Join-Path $TestDrive 'cfg.ps1'
        Set-Content $cfg '$LegacyTaskMigrationEnabled = $false   # off'
        Get-MigrationPivot -ConfigPath $cfg | Should -BeFalse
        Set-Content $cfg '$LegacyTaskMigrationEnabled = $true'
        Get-MigrationPivot -ConfigPath $cfg | Should -BeTrue
        Get-MigrationPivot -ConfigPath (Join-Path $TestDrive 'missing.ps1') | Should -BeTrue
    }
}
