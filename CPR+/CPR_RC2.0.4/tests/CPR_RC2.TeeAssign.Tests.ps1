# RC2.0.3 tee assignment from the share (tee_assign.cfg): parser, apply, and "still listed = extend" behavior.
# Behavior is exercised through the real Invoke-TeeLevelFlagCheck with Set-CprTeeLevel / the level reader stubbed.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $path = Join-Path $script:Root 'main\Main.TeeFlag.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    foreach ($n in 'Get-TeeAssignLevelFromLines','Sync-TeeAssignFile','Write-TeeRevertState','Read-TeeRevertState','Invoke-TeeLevelFlagCheck','Move-TeeFlagToFailed') {
        $fn = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($fn.Extent.Text))
    }
}

Describe 'Get-TeeAssignLevelFromLines' {
    BeforeAll {
        $script:cfg = @(
            'version:1', '# comment', '', '[tee3]', 'PCA-001', 'LAB-*   # lab boxes', '[tee5]', 'PCB-777', '[other]', 'PCZ-1', '[tee9]', 'PCY-1')
    }
    It 'returns the level of the section the host is listed in' { Get-TeeAssignLevelFromLines -Lines $cfg -ComputerName 'pca-001' | Should -Be 3 }
    It 'supports wildcards and trailing comments'               { Get-TeeAssignLevelFromLines -Lines $cfg -ComputerName 'LAB-42' | Should -Be 3 }
    It 'returns $null when the host is not listed'              { Get-TeeAssignLevelFromLines -Lines $cfg -ComputerName 'NOPE' | Should -BeNullOrEmpty }
    It 'ignores unknown sections and out-of-range tee sections' {
        Get-TeeAssignLevelFromLines -Lines $cfg -ComputerName 'PCZ-1' | Should -BeNullOrEmpty
        Get-TeeAssignLevelFromLines -Lines $cfg -ComputerName 'PCY-1' | Should -BeNullOrEmpty
    }
    It 'highest matching section wins' {
        Get-TeeAssignLevelFromLines -Lines @('[tee2]','LAB-*','[tee4]','LAB-42') -ComputerName 'LAB-42' | Should -Be 4
    }
    It 'never honors a wildcard-only line (it would match every host)' {
        Get-TeeAssignLevelFromLines -Lines @('[tee5]','*','??') -ComputerName 'ANY-PC' | Should -BeNullOrEmpty
    }
    It 'the shipped template assigns nobody' {
        $t = Get-Content (Join-Path $script:Root 'tee_assign.cfg')
        foreach ($h in 'EXAMPLE-PC-001','EXAMPLE-PC-002','LAB-1','ANYTHING') { Get-TeeAssignLevelFromLines -Lines $t -ComputerName $h | Should -BeNullOrEmpty }
        $t | Where-Object { $_ -match '^\[tee[1-5]\]$' } | Should -HaveCount 2
    }
    It 'handles an empty file' { Get-TeeAssignLevelFromLines -Lines @() -ComputerName 'X' | Should -BeNullOrEmpty }
}

Describe 'Invoke-TeeLevelFlagCheck with a share assignment' {
    BeforeEach {
        $script:Dir = Join-Path ([System.IO.Path]::GetTempPath()) ("teeassign_" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Dir | Out-Null
        $script:TeeFlagDir = $script:Dir; $script:TeeRevertStateFile = Join-Path $script:Dir 'revert.json'
        $script:TeeSetScript = Join-Path $script:Dir 'set.ps1'; Set-Content $script:TeeSetScript '# stub'
        $script:TeeMasterFile = Join-Path $script:Dir 'master.psd1'; Set-Content $script:TeeMasterFile '@{}'
        $script:TeeEventsFile = Join-Path $script:Dir 'active.psd1'
        $script:TeeFlagEnabled = $true; $script:TeeFlagRevertHours = 336; $script:TeeFlagCooldownMinutes = 10
        $script:TeeAssignExtendMinGapHours = 24; $script:TeeDefaultLevel = 1; $script:WhatIf = $false
        $script:Fresh = $true; $script:AssignLevel = 3; $script:Active = 1; $script:Set = @(); $script:Events = @(); $script:Logs = @()
        function global:Write-Log { param($Message, $Level) $script:Logs += "[$Level] $Message" }
        function global:Write-TeeLog { param($a, $b, [switch]$PassThru) }
        function global:Send-TeeLevelSetEvent { param($Level, $PreviousLevel, $Source, $Result, $Reason) $script:Events += "$Source/$Result/$Level" }
        function global:Send-TeeLevelInfoIfDue { }
        function global:Get-TeeAssignment { [pscustomobject]@{ Level = $script:AssignLevel; Fresh = $script:Fresh } }
        function global:Get-CprActiveTeeLevelInfo { param($ActivePath) [pscustomobject]@{ Level = $script:Active } }
        function global:Set-CprTeeLevel { param($Level, $MasterPath, $ActivePath, $GeneratedBy, $Reason) $script:Set += "$Level/$GeneratedBy"; $script:Active = $Level; [pscustomobject]@{ Success = $true } }
    }
    AfterEach {
        Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($f in 'Write-Log','Write-TeeLog','Send-TeeLevelSetEvent','Send-TeeLevelInfoIfDue','Get-TeeAssignment','Get-CprActiveTeeLevelInfo','Set-CprTeeLevel') { Remove-Item "function:global:$f" -ErrorAction SilentlyContinue }
    }
    It 'applies the listed level and writes a manifest-sourced revert stamp' {
        Invoke-TeeLevelFlagCheck
        $script:Set | Should -Be @('3/cpr_tee_assign')
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        $st.source | Should -Be 'manifest'; $st.set_level | Should -Be 3; $st.previous_level | Should -Be 1
        ([datetime]$st.expires_at) | Should -BeGreaterThan (Get-Date).AddHours(335)
    }
    It 'does nothing when the host is already at or above the listed level' {
        $script:Active = 4; Invoke-TeeLevelFlagCheck
        $script:Set.Count | Should -Be 0; Test-Path $script:TeeRevertStateFile | Should -BeFalse
    }
    It 'does nothing when the share was not read recently (Fresh = false)' {
        $script:Fresh = $false; Invoke-TeeLevelFlagCheck
        $script:Set.Count | Should -Be 0
    }
    It 'extends the revert time when the host is still listed and the stamp is older than the minimum gap' {
        $old = (Get-Date).AddDays(-3).AddHours(-1)   # applied 3 days ago -> expires in ~11 days
        @{ previous_level = 1; set_level = 3; applied_at = $old.ToString('o'); expires_at = $old.AddHours(336).ToString('o'); keep = $false; source = 'manifest' } |
            ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        $script:Active = 3; Invoke-TeeLevelFlagCheck
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        ([datetime]$st.expires_at) | Should -BeGreaterThan (Get-Date).AddHours(335)
        $st.previous_level | Should -Be 1
        $script:Events | Should -Contain 'manifest/extended/3'
        $script:Set.Count | Should -Be 0
    }
    It 'does not rewrite the stamp when it was extended recently' {
        $exp = (Get-Date).AddHours(336 - 2)
        @{ previous_level = 1; set_level = 3; applied_at = (Get-Date).ToString('o'); expires_at = $exp.ToString('o'); keep = $false; source = 'manifest' } | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        $script:Active = 3; Invoke-TeeLevelFlagCheck
        $script:Events.Count | Should -Be 0
    }
    It 'does NOT extend when the share was not read recently (offline), so the level reverts on schedule' {
        $old = (Get-Date).AddDays(-3)
        $orig = $old.AddHours(336).ToString('o')
        @{ previous_level = 1; set_level = 3; applied_at = $old.ToString('o'); expires_at = $orig; keep = $false; source = 'manifest' } | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        $script:Fresh = $false; $script:Active = 3; Invoke-TeeLevelFlagCheck
        ([datetime](Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json).expires_at) | Should -Be ([datetime]$orig)
    }
    It 'does NOT extend after the host was removed from the list; the existing stamp then reverts normally' {
        $old = (Get-Date).AddDays(-15)
        @{ previous_level = 1; set_level = 3; applied_at = $old.ToString('o'); expires_at = $old.AddHours(336).ToString('o'); keep = $false; source = 'manifest' } | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        $script:AssignLevel = $null; $script:Active = 3; Invoke-TeeLevelFlagCheck
        $script:Set | Should -Be @('1/cpr_tee_revert')
        Test-Path $script:TeeRevertStateFile | Should -BeFalse
    }
    It 'leaves a manual flag state alone (no source field)' {
        $old = (Get-Date).AddDays(-1)
        @{ previous_level = 1; set_level = 2; applied_at = $old.ToString('o'); expires_at = $old.AddHours(336).ToString('o'); keep = $false } | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        $script:Active = 2; Invoke-TeeLevelFlagCheck
        $script:Set.Count | Should -Be 0; $script:Events.Count | Should -Be 0
        (Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json).set_level | Should -Be 2
    }
    It 'moves a manifest host to a new level when the list changes, keeping the original previous level' {
        $old = (Get-Date).AddDays(-1)
        @{ previous_level = 1; set_level = 3; applied_at = $old.ToString('o'); expires_at = $old.AddHours(336).ToString('o'); keep = $false; source = 'manifest' } | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        $script:AssignLevel = 5; $script:Active = 3; Invoke-TeeLevelFlagCheck
        $script:Set | Should -Be @('5/cpr_tee_assign')
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        $st.set_level | Should -Be 5; $st.previous_level | Should -Be 1
    }
    It 'does not extend if someone changed the level meanwhile' {
        $old = (Get-Date).AddDays(-3)
        $orig = $old.AddHours(336).ToString('o')
        @{ previous_level = 1; set_level = 3; applied_at = $old.ToString('o'); expires_at = $orig; keep = $false; source = 'manifest' } | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        $script:Active = 4; Invoke-TeeLevelFlagCheck
        ([datetime](Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json).expires_at) | Should -Be ([datetime]$orig)
    }
}

Describe 'Sync-TeeAssignFile' {
    BeforeEach {
        $script:D = Join-Path ([System.IO.Path]::GetTempPath()) ("teesync_" + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $script:D | Out-Null
        $script:TeeAssignRemoteFile = Join-Path $script:D 'remote.cfg'; $script:TeeAssignFile = Join-Path $script:D 'local.cfg'
        $script:TeeAssignSyncFlag = Join-Path $script:D 'ok.flag'; $script:TeeAssignTryFlag = Join-Path $script:D 'try.flag'
        $script:TeeAssignSyncCooldownHours = 4; $script:TeeAssignRetryMinutes = 60; $script:TeeAssignFreshHours = 12
        $script:Reach = $true; $script:Probes = 0
        function global:Write-Log { param($Message, $Level) }
        function global:Test-ShareReachableFast { param($HostName, $TimeoutMs) $script:Probes++; $script:Reach }
    }
    AfterEach { Remove-Item $script:D -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item function:global:Write-Log, function:global:Test-ShareReachableFast -ErrorAction SilentlyContinue }
    It 'pulls the file, stamps success, and reports fresh' {
        Set-Content $script:TeeAssignRemoteFile "[tee3]`nPC1" -NoNewline
        Sync-TeeAssignFile | Should -BeTrue
        (Get-Content $script:TeeAssignFile -Raw) | Should -Be "[tee3]`nPC1"
        Test-Path $script:TeeAssignSyncFlag | Should -BeTrue
    }
    It 'skips the share while the last success is inside the cooldown' {
        (Get-Date).AddHours(-1).ToString('o') | Set-Content $script:TeeAssignSyncFlag
        Sync-TeeAssignFile | Should -BeTrue; $script:Probes | Should -Be 0
    }
    It 'reports NOT fresh when the share is unreachable and there was no recent success' {
        $script:Reach = $false
        Sync-TeeAssignFile | Should -BeFalse
    }
    It 'backs off after a failed attempt (no second probe inside the retry window)' {
        $script:Reach = $false; [void](Sync-TeeAssignFile); [void](Sync-TeeAssignFile)
        $script:Probes | Should -Be 1
    }
    It 'stays fresh for a while after the last success even when the share is down' {
        (Get-Date).AddHours(-6).ToString('o') | Set-Content $script:TeeAssignSyncFlag
        $script:Reach = $false
        Sync-TeeAssignFile | Should -BeTrue
    }
    It 'is not fresh once the last success is older than the fresh window' {
        (Get-Date).AddHours(-13).ToString('o') | Set-Content $script:TeeAssignSyncFlag
        $script:Reach = $false
        Sync-TeeAssignFile | Should -BeFalse
    }
}

Describe 'config and loader' {
    It 'config defines the assignment settings and the feature can be switched off' {
        $c = Get-Content (Join-Path $script:Root 'main\Main.Configuration.ps1') -Raw
        foreach ($v in 'TeeAssignEnabled','TeeAssignRemoteFile','TeeAssignFile','TeeAssignSyncFlag','TeeAssignTryFlag','TeeAssignSyncCooldownHours','TeeAssignRetryMinutes','TeeAssignFreshHours','TeeAssignExtendMinGapHours') {
            $c | Should -Match ('\$' + $v + '\s*=')
        }
    }
}
