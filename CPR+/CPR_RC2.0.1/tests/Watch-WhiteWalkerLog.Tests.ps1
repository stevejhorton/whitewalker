$script:ReleaseRoot = Split-Path -Parent $PSScriptRoot
$script:WatcherPath = Join-Path $script:ReleaseRoot 'admin\Watch-WhiteWalkerLog.ps1'

Describe 'Watch-WhiteWalkerLog' {
    BeforeAll {
        $watchPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'admin\Watch-WhiteWalkerLog.ps1'
        $rootPath = Split-Path -Parent $PSScriptRoot
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($watchPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
        . $watchPath
        $readme = Get-Content (Join-Path $rootPath 'logs/README.md') -Raw
        $script:WatcherPath = $watchPath
    }

    It 'parses without PowerShell syntax errors' {
        $parseErrors | Should -BeNullOrEmpty
    }

    It 'matches every log file documented in the authoritative inventory' {
        $documented = [regex]::Matches($readme, '(?m)^\| `([^`]+)` \|') |
            ForEach-Object { $_.Groups[1].Value }
        $actual = Get-WWLogInventory | ForEach-Object File
        $documented.Count | Should -Be $actual.Count
        foreach ($file in $actual) { $documented | Should -Contain $file }
    }

    It 'is deployed via the RC2 installer mirrored admin/ subdirectory' {
        $installer = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1') -Raw
        $installer | Should -Match 'Source = "\$ScriptRoot\\admin";\s+Dest = "C:\\ProgramData\\WhiteWalker\\admin";\s+Label = "admin"'
        $installer | Should -Not -Match 'Name = "Watch-WhiteWalkerLog\.ps1"'
    }

    It 'classifies the formats emitted by CPR log writers' {
        Get-WWLogSeverity '2026-10-11 12:00:00.000 +00:00 [WW] [ERROR] failed' | Should -Be 'Error'
        Get-WWLogSeverity '2026-10-11 12:00:00.000 [WARN] [WW_notify] retrying' | Should -Be 'Warning'
        Get-WWLogSeverity '2026-10-11 12:00:00.000 [INFO] [WW_notify] started' | Should -Be 'Info'
        Get-WWLogSeverity '{"EvtTime":"2026-10-11T12:00:00Z","action":"cap_portal_redirect"}' | Should -Be 'Plain'
    }

    It 'renders JSONL telemetry as a compact summary' {
        $summary = ConvertFrom-WWJsonLine '{"EvtTime":"2026-10-11T12:00:00Z","action":"cap_portal_redirect","machine":"PC1","user":"u"}'
        $summary | Should -Be '2026-10-11T12:00:00.000Z action=cap_portal_redirect machine=PC1 user=u'
    }

    It 'filters case-insensitively without treating keywords as regular expressions' {
        Test-WWLogFilter 'machine=AB-123 action=connected' 'ab-123' | Should -BeTrue
        Test-WWLogFilter 'value [x]' '[x]' | Should -BeTrue
        Test-WWLogFilter 'machine=AB-123' 'missing' | Should -BeFalse
    }

    It 'rejects an invalid stream through parameter validation' {
        { & $script:WatcherPath -Stream NotAStream -Last 1 } | Should -Throw
    }

    It 'skips an empty or whitespace-only line without throwing or producing output' {
        { Write-WWLogLine '' } | Should -Not -Throw
        { Write-WWLogLine '   ' } | Should -Not -Throw
        Mock Write-Host { } -ParameterFilter { $Object -ne $null }
        Write-WWLogLine ''
        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'still renders and classifies a real non-empty line as before' {
        Mock Write-Host { }
        Write-WWLogLine '2026-10-11 12:00:00.000 [ERROR] [WW] boom' -Source 'Main'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '[Main] 2026-10-11 12:00:00.000 [ERROR] [WW] boom' -and $ForegroundColor -eq 'Red'
        }
    }

    It 'silently skips a trailing blank line when tailing a log so the stream does not crash' {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        try {
            $logFile = Join-Path $tempDir 'white_walker.main.log'
            Set-Content -LiteralPath $logFile -Value @(
                '2026-10-11 12:00:00.000 [INFO] [WW] started'
                ''
            )
            $script:WhiteWalkerLogRoot = $tempDir
            Mock Write-Host { }
            { Show-WWLogStream -Definition (Get-WWLogDefinition 'Main') -Count 10 -Match $null } | Should -Not -Throw
            Should -Invoke Write-Host -Times 1 -Exactly
        } finally {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# =============================================================================
# RC2.2 Required F - byte-offset tailer and Invoke console integration
# =============================================================================
Describe 'Watch-WhiteWalkerLog byte-offset tailer' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'admin/Watch-WhiteWalkerLog.ps1')
    }

    BeforeEach {
        $script:tailDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:tailDir -Force | Out-Null
        $script:tailLog = Join-Path $script:tailDir 'white_walker.main.log'
        Set-Content -LiteralPath $script:tailLog -Value "line one`nline two" -NoNewline
    }

    AfterEach {
        Remove-Item -LiteralPath $script:tailDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'reads only appended bytes and never re-spools the whole log' {
        $first = Read-WWLogTail -Path $script:tailLog -Offset 0
        $first.Event | Should -Be 'append'
        $first.Lines | Should -Contain 'line one'

        # No change at all -> nothing is replayed.
        $idle = Read-WWLogTail -Path $script:tailLog -Offset $first.Offset
        $idle.Event | Should -Be 'none'
        $idle.Lines.Count | Should -Be 0
        $idle.Offset | Should -Be $first.Offset

        Add-Content -LiteralPath $script:tailLog -Value "`nline three"
        $next = Read-WWLogTail -Path $script:tailLog -Offset $first.Offset
        $next.Event | Should -Be 'append'
        ($next.Lines -join '|') | Should -Match 'line three'
        ($next.Lines -join '|') | Should -Not -Match 'line one'
        $next.Offset | Should -BeGreaterThan $first.Offset
    }

    It 'detects rotation (renamed to .1 and recreated) and resets deliberately, once' {
        $first = Read-WWLogTail -Path $script:tailLog -Offset 0
        Move-Item -LiteralPath $script:tailLog -Destination ($script:tailLog + '.1') -Force
        Set-Content -LiteralPath $script:tailLog -Value "fresh" -NoNewline

        $rotated = Read-WWLogTail -Path $script:tailLog -Offset $first.Offset
        $rotated.Event | Should -Be 'rotated'
        $rotated.Lines | Should -Contain 'fresh'
        $rotated.Lines | Should -Not -Contain 'line one'

        # The reset happens exactly once - the next poll is quiet.
        $after = Read-WWLogTail -Path $script:tailLog -Offset $rotated.Offset
        $after.Event | Should -Be 'none'
        $after.Lines.Count | Should -Be 0
    }

    It 'detects in-place truncation and resets without replaying history' {
        $first = Read-WWLogTail -Path $script:tailLog -Offset 0
        Set-Content -LiteralPath $script:tailLog -Value "tiny" -NoNewline

        $truncated = Read-WWLogTail -Path $script:tailLog -Offset $first.Offset
        $truncated.Event | Should -Be 'truncated'
        $truncated.Lines | Should -Contain 'tiny'
        $truncated.Offset | Should -BeLessThan $first.Offset
    }

    It 'holds its offset while the file is briefly missing mid-rotation' {
        $first = Read-WWLogTail -Path $script:tailLog -Offset 0
        Remove-Item -LiteralPath $script:tailLog -Force
        $missing = Read-WWLogTail -Path $script:tailLog -Offset $first.Offset
        $missing.Event  | Should -Be 'missing'
        $missing.Offset | Should -Be $first.Offset
        $missing.Lines.Count | Should -Be 0
    }

    It 'tracks position by byte offset, not by line count' {
        $watcher = Get-Content $script:WatcherPath -Raw
        $watcher | Should -Match '\[int64\]\$Offset'
        $watcher | Should -Match 'SeekOrigin\]::Begin'
        $watcher | Should -Match '\[System\.IO\.FileShare\]::ReadWrite -bor \[System\.IO\.FileShare\]::Delete'
    }

    It 'exits the follow loop on Q or Esc using a NON-BLOCKING key check' {
        $watcher = Get-Content $script:WatcherPath -Raw
        $watcher | Should -Match 'KeyAvailable'
        $watcher | Should -Not -Match 'ReadKey\(\)\s*$'
        $exit = (Get-Command Test-WWExitKeyPressed).ScriptBlock.ToString()
        $exit | Should -Match '\[ConsoleKey\]::Q'
        $exit | Should -Match '\[ConsoleKey\]::Escape'
        $exit | Should -Match 'ReadKey\(\$true\)'
    }

    It 'returns from the follow loop as soon as the exit key is reported' {
        # Shadow the key check in this scope; Show-WWLogStream resolves it from
        # the caller's scope, so the loop sees Q/Esc on its first check.
        function Test-WWExitKeyPressed { return $true }
        $definition = Get-WWLogInventory | Where-Object { $_.Name -eq 'Main' }
        $script:WhiteWalkerLogRoot = $script:tailDir
        $elapsed = Measure-Command {
            Show-WWLogStream -Definition $definition -Count 5 -Follow -AllowExitKey -MaxIterations 20
        }
        # It returned on the exit key, not by exhausting 20 x 500ms iterations.
        $elapsed.TotalSeconds | Should -BeLessThan 5
    }
}

Describe 'Invoke-WhiteWalkerAction Watch integration' {
    BeforeAll {
        $script:consolePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'admin/Invoke-WhiteWalkerAction.ps1'
        $script:consoleSource = Get-Content $script:consolePath -Raw
    }

    It 'parses without PowerShell syntax errors' {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:consolePath, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'offers a Watch menu entry that returns to the menu on Q or Esc' {
        $script:consoleSource | Should -Match 'W\. Watch a WhiteWalker log'
        $script:consoleSource | Should -Match "\{ \`$_ -in @\('W', 'w'\) \}"
    }

    It 'runs the existing standalone watcher IN-PROCESS rather than duplicating it' {
        $script:consoleSource | Should -Match "Join-Path \`$PSScriptRoot 'Watch-WhiteWalkerLog\.ps1'"
        $script:consoleSource | Should -Match '\.\s+\$watcher'
        $script:consoleSource | Should -Match 'Show-WWLogStream -Definition \$definition'
        $script:consoleSource | Should -Not -Match 'Start-Process[^\r\n]*Watch-WhiteWalkerLog'
    }

    It 'lets the tech pick the stream, sourced from the watcher inventory' {
        $script:consoleSource | Should -Match 'Get-WWLogInventory'
        foreach ($stream in @('Main', 'CapPortal', 'CapPortalBase', 'FlareGunUser', 'XmlVault', 'Haystack', 'AdminActions')) {
            $script:consoleSource | Should -Match ("'" + $stream + "'")
        }
        $script:consoleSource | Should -Match 'Get-WWLogPath \$definition'
    }

    It 'fails soft when the chosen log does not exist yet' {
        $fn = [regex]::Match($script:consoleSource, '(?s)function Invoke-WWWatchLog \{.*?\n\}').Value
        $fn | Should -Match 'Test-Path -LiteralPath \$path -PathType Leaf'
        $fn | Should -Match 'returned to menu'
        $fn | Should -Not -Match 'throw'
    }

    It 'logs the action to the admin actions log like every other action' {
        $script:consoleSource | Should -Match "Invoke-WWAction -Name 'WatchLog'"
        $script:consoleSource | Should -Match 'Write-WWAdminLog "WatchLog: tailing'
        $script:consoleSource | Should -Match 'Write-WWAdminLog "WatchLog: stopped tailing'
    }
}
