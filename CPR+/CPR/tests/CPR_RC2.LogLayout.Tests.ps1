BeforeAll {
    $ReleaseRoot = Split-Path -Parent $PSScriptRoot
    $Installer = Get-Content -LiteralPath (Join-Path $ReleaseRoot 'install.ps1') -Raw
}

Describe 'CPR RC2 consolidated log layout' {
    It 'defines the deployed logs directory and creates it during installation' {
        $Installer | Should -Match '\$LogDir\s*=\s*"C:\\ProgramData\\WhiteWalker\\logs"'
        $Installer | Should -Match '\$directories\s*=\s*@\(\$MainScriptDeployDir.*\$LogDir'
    }

    It 'mirrors the WW_main library directory required by the deployed loader' {
        $Installer | Should -Match 'Source = "\$ScriptRoot\\main";\s+Dest = "C:\\ProgramData\\WhiteWalker\\main"'
    }

    It 'keeps every runtime log stream beneath the deployed logs directory' {
        $expectedPaths = @(
            'logs\white_walker.main.log',
            'logs\white_walker_install.log',
            'logs\white_walker.cap_portal.log',
            'logs\white_walker.cap_portal_base.log',
            'logs\white_walker.flaregun_system.log',
            'logs\white_walker.flaregun_user.log',
            'logs\white_walker.xml_vault.log',
            'logs\WW_notify.log',
            'logs\haystack_syslog_queue.jsonl'
        )

        $source = Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -File -Include '*.ps1' |
            Where-Object { $_.FullName -notmatch '[/\\](code_)?archive[/\\]' -and $_.FullName -notmatch '[/\\]steve_to_review[/\\]' } |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw } |
            Join-String -Separator "`n"

        foreach ($path in $expectedPaths) {
            $source | Should -Match ([regex]::Escape($path))
        }
    }

    It 'has no old flat ProgramData log or queue literals outside historical archives' {
        $sourceFiles = Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -File -Include '*.ps1' |
            Where-Object { $_.FullName -notmatch '[/\\](code_)?archive[/\\]' -and $_.FullName -notmatch '[/\\]steve_to_review[/\\]' }
        $oldFlatPaths = 'C:\\ProgramData\\WhiteWalker\\(?!logs\\)[^"''\s]+\.(?:log|jsonl)'

        foreach ($file in $sourceFiles) {
            (Get-Content -LiteralPath $file.FullName -Raw) | Should -Not -Match $oldFlatPaths
        }
    }

    It 'keeps the phase-1 WW_main loader as the scheduled task entry point' {
        $mainTask = Get-Content -LiteralPath (Join-Path $ReleaseRoot 'triggers/WW_main.xml') -Raw
        $mainTask | Should -Match 'C:\\ProgramData\\WhiteWalker\\WW_main\.ps1'
    }
}
