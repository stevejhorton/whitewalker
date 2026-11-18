BeforeAll {
    $scriptPath = "$PSScriptRoot/install.ps1"
    $content = Get-Content -LiteralPath $scriptPath -Raw
    $start = $content.IndexOf('function Write-InstallResultEvent')
    $end = $content.IndexOf('function Drain-PendingInstallEvents')
    $funcContent = $content.Substring($start, $end - $start)
    Invoke-Expression $funcContent

    if (-not (Get-Command Write-InstallLog -ErrorAction SilentlyContinue)) {
        function Write-InstallLog { param([string]$Message, [string]$Level = "INFO") }
    }
}

Describe 'Write-InstallResultEvent payload' {
    BeforeEach {
        $script:WW_Version = 'RC1.25'
        $script:MainScriptDeployDir = Join-Path $TestDrive 'WhiteWalker'
        $script:InstallResultQueueFile = Join-Path $script:MainScriptDeployDir 'haystack_syslog_queue.jsonl'
        $script:PendingInstallEventDir = Join-Path $TestDrive 'WhiteWalkerPending'
        New-Item -Path $script:MainScriptDeployDir -ItemType Directory -Force | Out-Null
        Remove-Item -LiteralPath $script:InstallResultQueueFile -Force -ErrorAction SilentlyContinue
        Mock Write-InstallLog {}
    }

    It 'includes EvtTime and required fields for <Action>' -TestCases @(
        @{ Action = 'install'; EventAction = 'cpr_install_result'; ExitCode = 0; Reason = 'ok' }
        @{ Action = 'uninstall'; EventAction = 'cpr_uninstall_result'; ExitCode = 9; Reason = 'failed uninstall' }
    ) {
        param($Action, $EventAction, $ExitCode, $Reason)

        Write-InstallResultEvent -Action $Action -ExitCode $ExitCode -Reason $Reason

        $script:CapturedEntry = (Get-Content -LiteralPath $script:InstallResultQueueFile | Select-Object -Last 1).Trim()
        $script:CapturedEntry | Should -Not -BeNullOrEmpty
        $tsMatch = [regex]::Match($script:CapturedEntry, '"ts":"([^"]+)"')
        $tsMatch.Success | Should -BeTrue
        $tsIso = $tsMatch.Groups[1].Value
        $entry = $script:CapturedEntry | ConvertFrom-Json
        $payload = $entry.payload

        $payload | Should -Match ([regex]::Escape(('action="{0}"' -f $EventAction)))
        $payload | Should -Match ([regex]::Escape(('exit_code="{0}"' -f $ExitCode)))
        $payload | Should -Match ([regex]::Escape(('reason="{0}"' -f $Reason)))
        $payload | Should -Match ([regex]::Escape(('version="{0}"' -f $script:WW_Version)))
        $payload | Should -Match 'machine="[^"]*"'

        $evtTimeMatch = [regex]::Match($payload, 'EvtTime="([^"]+)"')
        $evtTimeMatch.Success | Should -BeTrue
        $evtTimeIso = $evtTimeMatch.Groups[1].Value
        { [datetime]::Parse($evtTimeIso) } | Should -Not -Throw

        $tsIso | Should -Be $evtTimeIso
    }
}

Describe 'Install manifest - HayStack schema files' {
    BeforeAll {
        $scriptPath = "$PSScriptRoot/install.ps1"
        $content = Get-Content -LiteralPath $scriptPath -Raw

        $sfStart = $content.IndexOf('$ScriptFiles = @(')
        $sfEndRel = $content.Substring($sfStart).IndexOf("`n)`n")
        $scriptFilesBlock = $content.Substring($sfStart, $sfEndRel + 2)

        $schemaStart = $content.IndexOf('$SchemaFiles = @(')
        $schemaEndRel = $content.Substring($schemaStart).IndexOf("`n)`n")
        $schemaFilesBlock = $content.Substring($schemaStart, $schemaEndRel + 2)

        $ScriptRoot = $PSScriptRoot
        $DiagDir = Join-Path $TestDrive 'diagnostics'
        Invoke-Expression $scriptFilesBlock
        Invoke-Expression $schemaFilesBlock
        $script:ScriptFiles = $ScriptFiles
        $script:SchemaFiles = $SchemaFiles
    }

    It 'includes WW_haystack_schema.ps1 in $ScriptFiles' {
        $entry = $script:ScriptFiles | Where-Object { $_.Name -eq 'WW_haystack_schema.ps1' }
        $entry | Should -Not -BeNullOrEmpty
    }

    It 'includes haystack_msg_schema.psd1 in $SchemaFiles' {
        $entry = $script:SchemaFiles | Where-Object { $_.Name -eq 'haystack_msg_schema.psd1' }
        $entry | Should -Not -BeNullOrEmpty
        $entry.Source | Should -Match 'support_files'
    }

    It 'WW_haystack_schema.ps1 source file actually exists on disk' {
        $entry = $script:ScriptFiles | Where-Object { $_.Name -eq 'WW_haystack_schema.ps1' }
        Test-Path -LiteralPath $entry.Source | Should -BeTrue
    }

    It 'haystack_msg_schema.psd1 source file actually exists on disk' {
        $entry = $script:SchemaFiles | Where-Object { $_.Name -eq 'haystack_msg_schema.psd1' }
        Test-Path -LiteralPath $entry.Source | Should -BeTrue
    }

    It 'includes the Defender needle preview diagnostic and its source exists' {
        $entry = $script:ScriptFiles | Where-Object { $_.Name -eq 'New-DefenderNeedlePreview.ps1' }
        $entry | Should -Not -BeNullOrEmpty
        $entry.Dest | Should -Match 'diagnostics'
        Test-Path -LiteralPath $entry.Source | Should -BeTrue
    }
}

Describe 'Remove-StaleFlagFiles Defender state' {
    BeforeAll {
        $scriptPath = "$PSScriptRoot/install.ps1"
        $content = Get-Content -LiteralPath $scriptPath -Raw
        $start = $content.IndexOf('function Remove-StaleFlagFiles')
        $end = $content.IndexOf('function Ensure-Directories')
        Invoke-Expression $content.Substring($start, $end - $start)
    }

    BeforeEach {
        $script:MainScriptDeployDir = Join-Path $TestDrive 'WhiteWalker'
        $script:DefenderDir = Join-Path $script:MainScriptDeployDir 'defender_flags'
        New-Item -Path $script:DefenderDir -ItemType Directory -Force | Out-Null
        '{}' | Set-Content -LiteralPath (Join-Path $script:DefenderDir 'WebView2_FW_Allow.flag')
        Mock Write-InstallLog {}
    }

    It 'removes the Defender flag directory even when no flat flag exists' {
        Remove-StaleFlagFiles

        Test-Path -LiteralPath $script:DefenderDir | Should -BeFalse
    }
}

# =============================================================================
# RC1.25 - required runtime helper deployment
# =============================================================================
Describe 'Install manifest - RC1.25 required runtime helpers' {
    BeforeAll {
        $scriptPath = "$PSScriptRoot/install.ps1"
        $content = Get-Content -LiteralPath $scriptPath -Raw

        $schemaStart = $content.IndexOf('$SchemaFiles = @(')
        $schemaEndRel = $content.Substring($schemaStart).IndexOf("`n)`n")
        $schemaFilesBlock = $content.Substring($schemaStart, $schemaEndRel + 2)

        $helperStart = $content.IndexOf('$RequiredRuntimeHelpers = @(')
        $helperEndRel = $content.Substring($helperStart).IndexOf("`n)`n")
        $helperBlock = $content.Substring($helperStart, $helperEndRel + 2)

        $ScriptRoot = $PSScriptRoot
        $MainScriptDeployDir = Join-Path $TestDrive 'WhiteWalker'
        $SupportFilesDeployDir = Join-Path $MainScriptDeployDir 'support_files'
        Invoke-Expression $schemaFilesBlock
        Invoke-Expression $helperBlock
        $script:SchemaFiles = $SchemaFiles
        $script:RequiredRuntimeHelpers = $RequiredRuntimeHelpers
        $script:SupportFilesDeployDir = $SupportFilesDeployDir
        $script:rawSource = $content
    }

    It 'deploys haystack_msg_schema.psd1 to support_files (where Get-HaystackMsgSchema looks first)' {
        $dests = @($script:SchemaFiles |
            Where-Object { $_.Name -eq 'haystack_msg_schema.psd1' } |
            ForEach-Object { $_.Dest })

        $dests | Should -Contain $script:SupportFilesDeployDir
    }

    It 'requires <Name> at runtime' -TestCases @(
        @{ Name = 'WW_tee.ps1' }
        @{ Name = 'WW_haystack_schema.ps1' }
        @{ Name = 'WW_tee_events.psd1' }
        @{ Name = 'WW_tee_master.psd1' }
        @{ Name = 'WW_set_tee_level.ps1' }
        @{ Name = 'haystack_msg_schema.psd1' }
    ) {
        param($Name)
        $entry = $script:RequiredRuntimeHelpers | Where-Object { $_.Name -eq $Name }
        $entry | Should -Not -BeNullOrEmpty
        $entry.Path | Should -Not -BeNullOrEmpty
    }

    It 'validates required helpers during Test-Installation (warn, never blocking)' {
        $script:rawSource | Should -Match 'function Test-RequiredHelperDeployment'
        $validateIndex = $script:rawSource.IndexOf('function Test-Installation')
        $script:rawSource.IndexOf('Test-RequiredHelperDeployment', $validateIndex) | Should -BeGreaterThan $validateIndex
    }

    It 'stamps the RC1.25 version' {
        $script:rawSource | Should -Match '\$WW_Version\s*=\s*"RC1\.25"'
    }

    It 'does not deploy install.ps1 to the WhiteWalker root' {
        $script:ScriptFiles | Where-Object {
            $_.Name -eq 'install.ps1' -and $_.Dest -eq $script:MainScriptDeployDir
        } | Should -BeNullOrEmpty
    }

    It 'uses support_files as the only install.ps1 deployment destination' {
        $script:rawSource | Should -Match 'Join-Path \$SupportFilesDeployDir "install\.ps1"'
        $script:rawSource | Should -Not -Match 'Join-Path \$MainScriptDeployDir "install\.ps1"'
    }
}

Describe 'RC1.25 stale root install.ps1 cleanup' {
    BeforeAll {
        $content = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install.ps1') -Raw
        $start = $content.IndexOf('function Remove-OldScripts')
        $end = $content.IndexOf('function Remove-StaleFlagFiles')
        Invoke-Expression $content.Substring($start, $end - $start)
    }

    BeforeEach {
        $script:MainScriptDeployDir = Join-Path $TestDrive 'WhiteWalker'
        $script:CapPortalDeployDir = $script:MainScriptDeployDir
        New-Item -Path $script:MainScriptDeployDir -ItemType Directory -Force | Out-Null
        'stale' | Set-Content -LiteralPath (Join-Path $script:MainScriptDeployDir 'install.ps1')
        New-Item -Path (Join-Path $script:MainScriptDeployDir 'support_files') -ItemType Directory -Force | Out-Null
        'intended' | Set-Content -LiteralPath (Join-Path $script:MainScriptDeployDir 'support_files/install.ps1')
        Mock Write-InstallLog {}
    }

    It 'removes only the stale root copy and preserves support_files/install.ps1' {
        Remove-OldScripts

        Test-Path -LiteralPath (Join-Path $script:MainScriptDeployDir 'install.ps1') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:MainScriptDeployDir 'support_files/install.ps1') | Should -BeTrue
    }
}
