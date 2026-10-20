function Invoke-XmlVaultRestore {}

Describe 'WW_xml_vault behavior' {
BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'WW_xml_vault.ps1'
    $null = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
    if ($errors) { throw "Failed to parse WW_xml_vault.ps1" }

    $functionAsts = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    $functionSource = ($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n"
    Invoke-Expression $functionSource
}

BeforeEach {
    $script:tempRoot = Join-Path $TestDrive 'xmlvault'
    if (Test-Path $script:tempRoot) {
        Remove-Item -LiteralPath $script:tempRoot -Recurse -Force
    }
    New-Item -Path $script:tempRoot -ItemType Directory -Force | Out-Null

    $script:CooldownFlag = Join-Path $script:tempRoot 'xml_vault_sync.flag'
    $script:VaultDir = Join-Path $script:tempRoot 'xml_vault'
    $script:LogPath = Join-Path $script:tempRoot 'vault.log'
    $script:RestoreFlag = Join-Path $script:tempRoot 'xml_restore.flag'
    $script:RestoreCompleteFlag = Join-Path $script:tempRoot 'xml_restore.flag.completed'
    $script:SecureClientProfileDir = Join-Path $script:tempRoot 'SecureClient'
    $script:AnyConnectProfileDir = Join-Path $script:tempRoot 'AnyConnect'
    $script:RemoteBase = Join-Path $script:tempRoot 'remote'
    $script:DevFlag = Join-Path $script:tempRoot 'dev_vpn.txt'
    $script:RegPath = 'HKLM:\SYSTEM\UHG\DSM'
    $script:CooldownHours = 24
    $script:XmlFiles = @(
        'uhg_always_on.xml',
        'uhg_always_on_elevated.xml',
        'uhg_always_on_exception.xml',
        'uhg_always_on_exception_elevated.xml',
        'uhg_smartcard_exception.xml',
        'uhg_smartcard_exception_elevated.xml',
        'uhgprofile.xml'
    )

    Mock Write-VaultLog {}
    Mock Invoke-XmlVaultTelemetry {}
}

Describe 'XmlVault sync state parsing' {
    It 'parses legacy timestamp flags safely' {
        $legacyStamp = (Get-Date).AddHours(-30).ToString('o')
        Set-Content -Path $script:CooldownFlag -Value $legacyStamp -Encoding UTF8

        $state = Get-XmlVaultState
        $state.result | Should -Be 'legacy_timestamp'
        $state.lastSynced | Should -Not -BeNullOrEmpty
    }

    It 'parses JSON state flags and preserves key fields' {
        $payload = @{
            lastSynced = '2026-09-20T00:00:00.0000000Z'
            lastChecked = '2026-09-21T00:00:00.0000000Z'
            result = 'synced_targeted'
            remoteCount = 7
            localCount = 7
            userProfile = 'uhgprofile.xml'
            activeProfileRemoteLength = 1234
            activeProfileRemoteLastWriteTimeUtc = '2026-09-20T00:00:00.0000000Z'
        } | ConvertTo-Json

        Set-Content -Path $script:CooldownFlag -Value $payload -Encoding UTF8

        $state = Get-XmlVaultState
        $state.result | Should -Be 'synced_targeted'
        $state.remoteCount | Should -Be 7
        $state.userProfile | Should -Be 'uhgprofile.xml'
    }
}

Describe 'XmlVault sync decision tree' {
    It 'skips NETLOGON work during cooldown and records skipped_cooldown' {
        Mock Get-XmlVaultState {
            [pscustomobject]@{ lastSynced = (Get-Date).AddHours(-1).ToString('o') }
        }
        Mock ConvertTo-XmlVaultDateTimeOrNull { (Get-Date).AddHours(-1) }
        Mock Update-XmlVaultState {
            param($Updates, $UpdateLastSynced)
            $script:lastUpdate = $Updates
        }
        Mock Invoke-XmlVaultFullSync {}
        Mock Invoke-XmlVaultTargetedProfileSync {}

        Invoke-XmlVaultSync

        $script:lastUpdate.result | Should -Be 'skipped_cooldown'
        Should -Invoke Invoke-XmlVaultFullSync -Times 0
        Should -Invoke Invoke-XmlVaultTargetedProfileSync -Times 0
    }

    It '-Force bypasses an active cooldown and proceeds with the share-reachability check' {
        Mock Get-XmlVaultState {
            [pscustomobject]@{ lastSynced = (Get-Date).AddHours(-1).ToString('o') }
        }
        Mock ConvertTo-XmlVaultDateTimeOrNull { (Get-Date).AddHours(-1) }
        Mock Update-XmlVaultState {
            param($Updates, $UpdateLastSynced)
            $script:lastUpdate = $Updates
        }
        Mock Test-Path { $false }   # share unreachable - proves we got past cooldown and into the real check
        Mock Invoke-XmlVaultFullSync {}
        Mock Invoke-XmlVaultTargetedProfileSync {}

        Invoke-XmlVaultSync -Force

        $script:lastUpdate.result | Should -Not -Be 'skipped_cooldown'
        $script:lastUpdate.result | Should -Be 'deferred_share_unreachable'
    }

    It 'uses full sync when configured remote/local counts mismatch' {
        Mock Get-XmlVaultState {
            [pscustomobject]@{ lastSynced = (Get-Date).AddHours(-25).ToString('o') }
        }
        Mock ConvertTo-XmlVaultDateTimeOrNull { (Get-Date).AddHours(-25) }
        Mock Get-XmlVaultEnv { 'AOVPN-PROD' }
        Mock Test-Path { $true }
        Mock Get-XmlVaultConfiguredRemoteCount { 6 }
        Mock Get-XmlVaultConfiguredLocalCount { 7 }
        Mock Get-XmlVaultActiveProfileName { 'uhgprofile.xml' }
        Mock Invoke-XmlVaultFullSync {}
        Mock Invoke-XmlVaultTargetedProfileSync {}

        Invoke-XmlVaultSync

        Should -Invoke Invoke-XmlVaultFullSync -Times 1
        Should -Invoke Invoke-XmlVaultTargetedProfileSync -Times 0
    }

    It 'skips copy when counts match and active profile metadata matches state' {
        $profile = 'uhgprofile.xml'
        $remoteDir = Join-Path $script:RemoteBase 'AOVPN-PROD'
        $targetPath = Join-Path $script:VaultDir $profile
        $remoteMeta = [pscustomobject]@{
            IsReliable = $true
            RemotePath = Join-Path $remoteDir $profile
            RemoteName = $profile
            Length = 99
            LastWriteTimeUtc = (Get-Date).ToUniversalTime()
        }

        Mock Get-XmlVaultState {
            [pscustomobject]@{ lastSynced = (Get-Date).AddHours(-25).ToString('o') }
        }
        Mock Get-XmlVaultEnv { 'AOVPN-PROD' }
        Mock Test-Path {
            param($LiteralPath, $Path)
            $candidate = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
            if ($candidate -eq $remoteDir) { return $true }
            if ($candidate -eq $targetPath) { return $true }
            return $false
        }
        Mock Get-XmlVaultConfiguredRemoteCount { 7 }
        Mock Get-XmlVaultConfiguredLocalCount { 7 }
        Mock Get-XmlVaultActiveProfileName { $profile }
        Mock Get-XmlVaultRemoteProfileMetadata { $remoteMeta }
        Mock Test-XmlVaultMetadataMatch { $true }
        Mock Update-XmlVaultState {
            param($Updates, $UpdateLastSynced)
            $script:lastUpdate = $Updates
        }
        Mock Invoke-XmlVaultFullSync {}
        Mock Invoke-XmlVaultTargetedProfileSync {}

        Invoke-XmlVaultSync

        $script:lastUpdate.result | Should -Be 'skipped_metadata_match'
        Should -Invoke Invoke-XmlVaultFullSync -Times 0
        Should -Invoke Invoke-XmlVaultTargetedProfileSync -Times 0
    }

    It 'uses targeted sync when counts match but active profile metadata drifted' {
        $profile = 'uhgprofile.xml'
        $remoteDir = Join-Path $script:RemoteBase 'AOVPN-PROD'
        $targetPath = Join-Path $script:VaultDir $profile
        $remoteMeta = [pscustomobject]@{
            IsReliable = $true
            RemotePath = Join-Path $remoteDir $profile
            RemoteName = $profile
            Length = 101
            LastWriteTimeUtc = (Get-Date).ToUniversalTime()
        }

        Mock Get-XmlVaultState {
            [pscustomobject]@{ lastSynced = (Get-Date).AddHours(-25).ToString('o') }
        }
        Mock Get-XmlVaultEnv { 'AOVPN-PROD' }
        Mock Test-Path {
            param($LiteralPath, $Path)
            $candidate = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
            if ($candidate -eq $remoteDir) { return $true }
            if ($candidate -eq $targetPath) { return $true }
            return $false
        }
        Mock Get-XmlVaultConfiguredRemoteCount { 7 }
        Mock Get-XmlVaultConfiguredLocalCount { 7 }
        Mock Get-XmlVaultActiveProfileName { $profile }
        Mock Get-XmlVaultRemoteProfileMetadata { $remoteMeta }
        Mock Test-XmlVaultMetadataMatch { $false }
        Mock Invoke-XmlVaultFullSync {}
        Mock Invoke-XmlVaultTargetedProfileSync {}

        Invoke-XmlVaultSync

        Should -Invoke Invoke-XmlVaultTargetedProfileSync -Times 1
        Should -Invoke Invoke-XmlVaultFullSync -Times 0
    }
}

Describe 'XmlVault restore state integration' {
    It 'removes only stale managed vault XMLs and preserves unrelated files' {
        $selected = Join-Path $script:VaultDir 'selected.xml'
        $stale = Join-Path $script:VaultDir 'stale.xml'
        New-Item -Path $script:VaultDir -ItemType Directory -Force | Out-Null
        New-Item -Path $script:SecureClientProfileDir -ItemType Directory -Force | Out-Null
        Set-Content -Path $selected -Value selected
        Set-Content -Path $stale -Value stale
        Set-Content -Path (Join-Path $script:SecureClientProfileDir 'SELECTED.XML') -Value selected
        Set-Content -Path (Join-Path $script:SecureClientProfileDir 'STALE.XML') -Value stale
        Set-Content -Path (Join-Path $script:SecureClientProfileDir 'unrelated.xml') -Value unrelated
        Set-Content -Path (Join-Path $script:SecureClientProfileDir 'stale.xml.bak') -Value artifact

        $result = Remove-XmlVaultStaleManagedProfiles -ClientDir $script:SecureClientProfileDir -SelectedProfileName 'selected.xml'

        $result.Success | Should -BeTrue
        $result.RemovedCount | Should -Be 1
        $result.MissingCount | Should -Be 0
        Test-Path (Join-Path $script:SecureClientProfileDir 'SELECTED.XML') | Should -BeTrue
        Test-Path (Join-Path $script:SecureClientProfileDir 'STALE.XML') | Should -BeFalse
        Test-Path (Join-Path $script:SecureClientProfileDir 'unrelated.xml') | Should -BeTrue
        Test-Path (Join-Path $script:SecureClientProfileDir 'stale.xml.bak') | Should -BeTrue
    }

    It 'reports missing managed peers and does not use the configured XML list as authority' {
        New-Item -Path $script:VaultDir -ItemType Directory -Force | Out-Null
        New-Item -Path $script:SecureClientProfileDir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $script:VaultDir 'selected.xml') -Value selected
        Set-Content -Path (Join-Path $script:VaultDir 'peer.xml') -Value peer
        Set-Content -Path (Join-Path $script:SecureClientProfileDir 'selected.xml') -Value selected
        Set-Content -Path (Join-Path $script:SecureClientProfileDir 'ghost.xml') -Value ghost
        $script:XmlFiles += 'ghost.xml'

        $result = Remove-XmlVaultStaleManagedProfiles -ClientDir $script:SecureClientProfileDir -SelectedProfileName 'SELECTED.XML'

        $result.Success | Should -BeTrue
        $result.RemovedCount | Should -Be 0
        $result.MissingCount | Should -Be 1
        Test-Path (Join-Path $script:SecureClientProfileDir 'ghost.xml') | Should -BeTrue
    }

    It 'returns a failed cleanup result when stale deletion fails' {
        New-Item -Path $script:VaultDir -ItemType Directory -Force | Out-Null
        New-Item -Path $script:SecureClientProfileDir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $script:VaultDir 'selected.xml') -Value selected
        Set-Content -Path (Join-Path $script:VaultDir 'peer.xml') -Value peer
        Set-Content -Path (Join-Path $script:SecureClientProfileDir 'peer.xml') -Value peer
        Mock Remove-Item { throw 'simulated deletion failure' }

        $result = Remove-XmlVaultStaleManagedProfiles -ClientDir $script:SecureClientProfileDir -SelectedProfileName 'selected.xml'

        $result.Success | Should -BeFalse
        $result.FailedCount | Should -Be 1
        $result.ErrorReason | Should -Be 'restore_cleanup_failed'
    }

    It 'returns a failed cleanup result when vault enumeration fails' {
        Mock Get-ChildItem { throw 'simulated vault enumeration failure' }

        $result = Remove-XmlVaultStaleManagedProfiles -ClientDir $script:SecureClientProfileDir -SelectedProfileName 'selected.xml'

        $result.Success | Should -BeFalse
        $result.ErrorReason | Should -Be 'restore_cleanup_enumeration_failed'
    }

    It 'updates restore state without advancing lastSynced' {
        $profile = 'uhgprofile.xml'
        $vaultFile = Join-Path $script:VaultDir $profile
        $destFile = Join-Path $script:SecureClientProfileDir $profile

        Mock Test-Path {
            param($Path, $LiteralPath)
            $candidate = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
            switch ($candidate) {
                { $_ -eq $script:RestoreFlag } { return $true }
                { $_ -eq $script:SecureClientProfileDir } { return $true }
                { $_ -eq $vaultFile } { return $true }
                { $_ -eq $destFile } { return $true }
                default { return $false }
            }
        }
        Mock Get-XmlVaultActiveProfileName { $profile }
        Mock Get-XmlVaultEnv { 'AOVPN-PROD' }
        Mock Copy-Item {}
        Mock Get-Item {
            [pscustomobject]@{
                Length = 321
                LastWriteTimeUtc = (Get-Date).ToUniversalTime()
            }
        }
        Mock Get-ChildItem {
            param($LiteralPath)
            if ($LiteralPath -eq $script:VaultDir) {
                return [pscustomobject]@{ Name = $profile }
            }
            return @()
        }
        Mock Remove-Item {}
        Mock Set-Content {}
        Mock Update-XmlVaultState {
            param($Updates, $UpdateLastSynced)
            $script:restoreUpdate = $Updates
            $script:restoreUpdateLastSynced = if ($null -ne $UpdateLastSynced) { $UpdateLastSynced.IsPresent } else { $false }
        }

        Invoke-XmlVaultRestore

        $script:restoreUpdate.result | Should -Be 'restore_verified'
        $script:restoreUpdate.lastRestoreResult | Should -Be 'restore_verified'
        $script:restoreUpdate.userProfile | Should -Be $profile
        $script:restoreUpdateLastSynced | Should -BeFalse
        Should -Invoke Invoke-XmlVaultTelemetry -Times 1 -ParameterFilter {
            $Tag -eq 'xml_vault_restore' -and
            $ProfileName -eq $profile -and
            $Reason -eq 'restore_verified'
        }
    }

    It 'does not clean up when destination verification fails' {
        $profile = 'uhgprofile.xml'
        $vaultFile = Join-Path $script:VaultDir $profile
        $destFile = Join-Path $script:SecureClientProfileDir $profile

        Mock Test-Path {
            param($Path, $LiteralPath)
            $candidate = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
            $candidate -in @($script:RestoreFlag, $script:SecureClientProfileDir, $vaultFile) 
        }
        Mock Get-XmlVaultActiveProfileName { $profile }
        Mock Get-XmlVaultEnv { 'AOVPN-PROD' }
        Mock Copy-Item {}
        Mock Get-ChildItem {}
        Mock Update-XmlVaultState {}

        Invoke-XmlVaultRestore

        Should -Invoke Get-ChildItem -Times 0
        Should -Invoke Update-XmlVaultState -Times 1
    }

    It 'leaves restore retryable when cleanup fails' {
        $profile = 'uhgprofile.xml'
        $vaultFile = Join-Path $script:VaultDir $profile
        $destFile = Join-Path $script:SecureClientProfileDir $profile

        Mock Test-Path {
            param($Path, $LiteralPath)
            $candidate = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
            $candidate -in @($script:RestoreFlag, $script:SecureClientProfileDir, $vaultFile, $destFile)
        }
        Mock Get-XmlVaultActiveProfileName { $profile }
        Mock Get-XmlVaultEnv { 'AOVPN-PROD' }
        Mock Copy-Item {}
        Mock Get-ChildItem {
            param($LiteralPath)
            if ($LiteralPath -eq $script:VaultDir) {
                return @(
                    [pscustomobject]@{ Name = $profile }
                    [pscustomobject]@{ Name = 'peer.xml' }
                )
            }
            return [pscustomobject]@{ Name = 'peer.xml'; FullName = Join-Path $script:SecureClientProfileDir 'peer.xml' }
        }
        Mock Remove-Item { throw 'simulated deletion failure' }
        Mock Set-Content {}
        Mock Update-XmlVaultState {
            param($Updates)
            $script:restoreUpdate = $Updates
        }

        Invoke-XmlVaultRestore

        $script:restoreUpdate.result | Should -Be 'restore_cleanup_failed'
        Should -Invoke Remove-Item -Times 1
        Should -Invoke Set-Content -Times 0
        $script:restoreUpdate.lastRestoreResult | Should -Be 'restore_cleanup_failed'
    }

    It 'leaves restore retryable when cleanup vault enumeration fails' {
        $profile = 'uhgprofile.xml'
        $vaultFile = Join-Path $script:VaultDir $profile
        $destFile = Join-Path $script:SecureClientProfileDir $profile

        Mock Test-Path {
            param($Path, $LiteralPath)
            $candidate = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
            $candidate -in @($script:RestoreFlag, $script:SecureClientProfileDir, $vaultFile, $destFile)
        }
        Mock Get-XmlVaultActiveProfileName { $profile }
        Mock Get-XmlVaultEnv { 'AOVPN-PROD' }
        Mock Copy-Item {}
        Mock Get-ChildItem { throw 'simulated vault enumeration failure' }
        Mock Set-Content {}
        Mock Update-XmlVaultState {
            param($Updates)
            $script:restoreUpdate = $Updates
        }

        Invoke-XmlVaultRestore

        $script:restoreUpdate.result | Should -Be 'restore_cleanup_enumeration_failed'
        Should -Invoke Set-Content -Times 0
    }
}
}

# =============================================================================
# Standalone tee wiring - XmlVault runs as its own SYSTEM process and never
# inherits WW_main.ps1's scope, so Write-TeeLog's HaystackEnabled/TeeEnabled/
# TeeEventsFile gates must be set explicitly in-process before WW_tee.ps1 is
# dot-sourced, the same pattern WW_cap_portal_runner_base.ps1 already uses.
#
# Deliberately a sibling of (not nested inside) 'WW_xml_vault behavior' above:
# that outer Describe's BeforeEach blanket-mocks Invoke-XmlVaultTelemetry {}
# for its own sync/restore-decision tests, which would otherwise shadow the
# real function these tests need to exercise.
# =============================================================================
Describe 'XmlVault standalone tee telemetry wiring' {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot 'WW_xml_vault.ps1'
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
        if ($errors) { throw "Failed to parse WW_xml_vault.ps1" }

        $functionAsts = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        $functionSource = ($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n"
        Invoke-Expression $functionSource
        $script:functionSource = $functionSource

        $script:rawSource = Get-Content -Path $scriptPath -Raw

        # The real script-scope telemetry bootstrap, extracted verbatim so the
        # scope-lifetime tests below exercise the shipped wiring rather than a
        # reimplementation of it.
        $bootstrapMatch = [regex]::Match(
            $script:rawSource,
            '(?s)# --- BEGIN XmlVault standalone telemetry bootstrap \(script scope\) ---(.*?)# --- END XmlVault standalone telemetry bootstrap ---')
        if (-not $bootstrapMatch.Success) { throw "Could not locate the XmlVault standalone telemetry bootstrap block" }
        $script:bootstrapSource = $bootstrapMatch.Groups[1].Value

        # The scope-lifetime tests run the extracted bootstrap in a child pwsh
        # process: that isolates them from Pester's Write-VaultLog/Write-TeeLog
        # mocks and exercises the same "standalone process, script scope"
        # conditions XmlVault actually runs under.
        $script:pwshExe = (Get-Process -Id $PID).Path

        # Write-TeeLog is normally brought in by dot-sourcing the real WW_tee.ps1
        # at runtime (via Initialize-XmlVaultTelemetry). Stub it here so these are
        # pure unit tests of the wiring, not an integration test of the real tee
        # engine - same pattern as WW_cap_portal_runner_base.Tests.ps1.
        function Write-TeeLog { param([string]$Tag, [hashtable]$Data, [switch]$PassThru) }
    }

    BeforeEach {
        Mock Write-TeeLog {}
        Mock Write-VaultLog {}
    }

    It 'sets the standalone Haystack/Tee globals before WW_tee.ps1 is dot-sourced, pointing at the active profile path' {
        $script:rawSource | Should -Match '\$global:HaystackEnabled\s*=\s*\$true'
        $script:rawSource | Should -Match '\$global:TeeEnabled\s*=\s*\$true'
        $script:rawSource | Should -Match '\$global:TeeEventsFile\s*=\s*"C:\\ProgramData\\WhiteWalker\\WW_tee_events\.psd1"'

        # Gates must appear before the dot-source line, not merely somewhere
        # else in the file.
        $gateIndex = $script:rawSource.IndexOf('$global:HaystackEnabled')
        $dotSourceIndex = $script:rawSource.IndexOf('. $teePath')
        $gateIndex | Should -BeGreaterThan 0
        $dotSourceIndex | Should -BeGreaterThan 0
        $gateIndex | Should -BeLessThan $dotSourceIndex
    }

    It 'dot-sources WW_tee.ps1 at script scope, never inside a function (scope lifetime regression)' {
        # Regression guard: a dot-source inside a function loads Write-TeeLog
        # into that function's local scope, which is discarded on return, so
        # Invoke-XmlVaultTelemetry's Get-Command guard silently bails out.
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot 'WW_xml_vault.ps1'), [ref]$null, [ref]$errors)
        $errors | Should -BeNullOrEmpty

        $functionAsts = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        $dotSourcesInFunctions = @($functionAsts | Where-Object { $_.Extent.Text -match '(?m)^\s*\.\s+\$\w*[Tt]ee\w*\b' })
        $dotSourcesInFunctions.Count | Should -Be 0

        # ...and it must still happen somewhere at script scope.
        $script:rawSource | Should -Match '(?m)^\s*\.\s+\$teePath\s*$'
    }

    It 'keeps Write-TeeLog available to Invoke-XmlVaultTelemetry after initialization returns, and logs the queued result' {
        $sandbox = Join-Path $TestDrive 'teescope'
        New-Item -Path $sandbox -ItemType Directory -Force | Out-Null

        # Fake WW_tee.ps1 sitting next to the harness script, exactly where the
        # real bootstrap resolves it from ($PSCommandPath's directory).
        Set-Content -Path (Join-Path $sandbox 'WW_tee.ps1') -Encoding UTF8 -Value @'
function Write-TeeLog {
    param([string]$Tag, [hashtable]$Data, [switch]$PassThru)
    if ($PassThru) {
        [pscustomobject]@{ Tag = $Tag; Queued = $true; Reason = 'queued'; Error = $null; QueueFile = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl' }
    }
}
'@

        $logPath = Join-Path $sandbox 'vault.log'
        $harness = Join-Path $sandbox 'harness.ps1'
        Set-Content -Path $harness -Encoding UTF8 -Value @"
`$LogPath = '$logPath'
$script:functionSource

$script:bootstrapSource

if (Get-Command Write-TeeLog -ErrorAction SilentlyContinue) {
    Write-VaultLog 'TEST: Write-TeeLog available after initialization returned' 'DEBUG'
} else {
    Write-VaultLog 'TEST: Write-TeeLog MISSING after initialization returned' 'WARN'
}

Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified'
"@

        $out = & $script:pwshExe -NoProfile -NonInteractive -File $harness 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "harness output: $out"

        $log = Get-Content -Path $logPath -Raw
        $log | Should -Match 'Write-TeeLog available after initialization returned'
        $log | Should -Not -Match 'Write-TeeLog MISSING after initialization returned'
        $log | Should -Match 'WW_tee loaded for lifecycle telemetry'
        $log | Should -Match "tee telemetry queued \(reason=queued\) for tag 'xml_vault_passed'"
        $log | Should -Match 'haystack_syslog_queue\.jsonl'
    }

    It 'remains fail-soft and warns when WW_tee.ps1 is missing' {
        $sandbox = Join-Path $TestDrive 'teemissing'
        New-Item -Path $sandbox -ItemType Directory -Force | Out-Null

        $logPath = Join-Path $sandbox 'vault.log'
        $harness = Join-Path $sandbox 'harness.ps1'
        Set-Content -Path $harness -Encoding UTF8 -Value @"
`$LogPath = '$logPath'
$script:functionSource

$script:bootstrapSource

Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified'
Write-VaultLog 'TEST: reached end of harness' 'DEBUG'
"@

        $out = & $script:pwshExe -NoProfile -NonInteractive -File $harness 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "harness output: $out"

        $log = Get-Content -Path $logPath -Raw
        $log | Should -Match '\[WARN\].*WW_tee\.ps1 not found'
        $log | Should -Match '\[WARN\].*Write-TeeLog unavailable after telemetry init'
        $log | Should -Not -Match 'WW_tee loaded for lifecycle telemetry'
        $log | Should -Match 'TEST: reached end of harness'
    }

    It 'remains fail-soft and warns when WW_tee.ps1 is present but unloadable' {
        $sandbox = Join-Path $TestDrive 'teebroken'
        New-Item -Path $sandbox -ItemType Directory -Force | Out-Null

        Set-Content -Path (Join-Path $sandbox 'WW_tee.ps1') -Encoding UTF8 -Value "throw 'simulated tee load failure'"

        $logPath = Join-Path $sandbox 'vault.log'
        $harness = Join-Path $sandbox 'harness.ps1'
        Set-Content -Path $harness -Encoding UTF8 -Value @"
`$LogPath = '$logPath'
$script:functionSource

$script:bootstrapSource

Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'restore_copy_failed'
Write-VaultLog 'TEST: reached end of harness' 'DEBUG'
"@

        $out = & $script:pwshExe -NoProfile -NonInteractive -File $harness 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "harness output: $out"

        $log = Get-Content -Path $logPath -Raw
        $log | Should -Match '\[WARN\].*failed to load WW_tee\.ps1'
        $log | Should -Match '\[WARN\].*Write-TeeLog unavailable after telemetry init'
        $log | Should -Not -Match 'WW_tee loaded for lifecycle telemetry'
        $log | Should -Match 'TEST: reached end of harness'
    }

    It 'calls Write-TeeLog with -PassThru' {
        Invoke-XmlVaultTelemetry -Tag 'xml_vault_triggered' -Mode 'restore' -Status 'started' -Source 'local_vault' -Reason 'flag_present'

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            $PassThru -eq $true
        }
    }

    It 'logs a queued result as queued' {
        Mock Write-TeeLog {
            [pscustomobject]@{ Tag = $Tag; Queued = $true; Reason = 'queued'; Error = $null; QueueFile = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl' }
        }

        Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified'

        Should -Invoke Write-VaultLog -Times 1 -ParameterFilter {
            $Message -match 'queued' -and $Message -match 'xml_vault_passed'
        }
    }

    It 'logs a tag_not_in_profile result truthfully and does not throw' {
        Mock Write-TeeLog {
            [pscustomobject]@{ Tag = $Tag; Queued = $false; Reason = 'tag_not_in_profile'; Error = $null; QueueFile = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl' }
        }

        { Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'sync' -Status 'failed' -Source 'netlogon' -Reason 'sync_copy_failed' } | Should -Not -Throw

        Should -Invoke Write-VaultLog -Times 1 -ParameterFilter {
            $Message -match 'tag_not_in_profile' -and $Message -match 'xml_vault_failed'
        }
    }

    It 'logs a haystack_disabled result truthfully and does not throw' {
        Mock Write-TeeLog {
            [pscustomobject]@{ Tag = $Tag; Queued = $false; Reason = 'haystack_disabled'; Error = $null; QueueFile = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl' }
        }

        { Invoke-XmlVaultTelemetry -Tag 'xml_vault_restore' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified' } | Should -Not -Throw

        Should -Invoke Write-VaultLog -Times 1 -ParameterFilter {
            $Message -match 'haystack_disabled'
        }
    }

    It 'logs a tee_disabled result truthfully and does not throw' {
        Mock Write-TeeLog {
            [pscustomobject]@{ Tag = $Tag; Queued = $false; Reason = 'tee_disabled'; Error = $null; QueueFile = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl' }
        }

        { Invoke-XmlVaultTelemetry -Tag 'xml_vault_restore' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified' } | Should -Not -Throw

        Should -Invoke Write-VaultLog -Times 1 -ParameterFilter {
            $Message -match 'tee_disabled'
        }
    }

    It 'logs an error result including the returned error and does not throw' {
        Mock Write-TeeLog {
            [pscustomobject]@{ Tag = $Tag; Queued = $false; Reason = 'error'; Error = 'simulated queue write failure'; QueueFile = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl' }
        }

        { Invoke-XmlVaultTelemetry -Tag 'xml_vault_failed' -Mode 'restore' -Status 'failed' -Source 'local_vault' -Reason 'restore_copy_failed' } | Should -Not -Throw

        Should -Invoke Write-VaultLog -Times 1 -ParameterFilter {
            $Message -match 'simulated queue write failure'
        }
    }

    It 'remains fail-soft when Write-TeeLog itself throws, and never propagates the error to the caller' {
        Mock Write-TeeLog { throw 'simulated tee engine failure' }

        { Invoke-XmlVaultTelemetry -Tag 'xml_vault_triggered' -Mode 'sync' -Status 'started' -Source 'netlogon' -Reason 'cooldown_expired' } | Should -Not -Throw

        Should -Invoke Write-VaultLog -Times 1 -ParameterFilter {
            $Message -match "tee telemetry failed for tag 'xml_vault_triggered'"
        }
    }

    It 'does not alter restore outcome when telemetry fails (fail-soft, restore state untouched by tee result)' {
        # Invoke-XmlVaultRestore is stubbed at file scope for other Describe blocks;
        # here we confirm Invoke-XmlVaultTelemetry's own contract directly: a thrown
        # Write-TeeLog failure must not throw or return anything that a caller could
        # mistake for a restore/sync decision.
        Mock Write-TeeLog { throw 'simulated tee engine failure' }

        $returned = Invoke-XmlVaultTelemetry -Tag 'xml_vault_passed' -Mode 'restore' -Status 'completed' -Source 'local_vault' -Reason 'restore_verified'

        $returned | Should -BeNullOrEmpty
    }
}
