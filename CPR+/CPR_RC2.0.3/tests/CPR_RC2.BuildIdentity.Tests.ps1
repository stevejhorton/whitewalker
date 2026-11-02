# Non-Windows runs (CI, Linux): Pester's Mock needs the command to exist.
BeforeAll {
    if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) { function global:Get-WinEvent { param($LogName, $FilterHashtable, $MaxEvents, $ErrorAction) } }
}

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

Describe 'Connected VPN short-circuits the unreachable branch' {
    BeforeAll { $script:entry = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.Entry.ps1') -Raw }
    It 'exits on a Connected VPN before testing enroll.cisco.com' {
        # A Connected VPN is settled by the connected-unreachable triage, which returns
        # before the enroll.cisco.com probe (d76e5cd replaced the old 'skipping ...' message).
        $exit = $entry.IndexOf('$vpnBeforeEnroll -eq "Connected"')
        $test = $entry.IndexOf('$enrollResult = Test-Redirect -Url $ISERedirectTestURL')
        $exit | Should -BeGreaterThan 0
        $exit | Should -BeLessThan $test
    }
    It 'does not re-probe a VPN that stayed Connected' {
        $entry | Should -Match 'not \$reprobedOnNetworkChange -and -not \$vpnStayedConnected'
    }
}


Describe 'End-of-run network re-check' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        . ([scriptblock]::Create((Get-Content (Join-Path $root 'main\Main.Network.ps1') -Raw)))
        $script:entry = Get-Content (Join-Path $root 'main\Main.Entry.ps1') -Raw
    }
    BeforeEach {
        $script:EndRunRecheckEnabled = $true; $script:EndRunRerunMax = 2; $script:EndRunRerunWindowSec = 60
        $script:EndRunRerunDelaySec = 5; $script:CprTaskFolder = '\CPR\'; $script:WhatIf = $false
        $script:EndRunRerunStateFile = Join-Path $TestDrive 'rerun.txt'
        Remove-Item -LiteralPath $script:EndRunRerunStateFile -ErrorAction SilentlyContinue   # TestDrive is shared by the Its in this block
        $script:base = [pscustomobject]@{ SSID='SNAFU'; IPAddress='1.1.1.1'; DefaultGateway='1.1.1.254'; InterfaceGuid='{g}'; AdapterClass='wifi' }
        function Write-Log { param($m,$l) }
        function Write-TeeLog { param($a,$f) $script:teeSeen = @{ a = $a; f = $f } }
        Mock Request-CprRerun { $true }
        $script:runAdapterSet = 'a'
        Mock Get-CprActivePhysicalSet { 'a' }
    }
    It 'no change: no re-run' {
        Mock Get-CprQuickNetworkProbe { [pscustomobject]@{ Found=$true; State='Up'; IPAddress='1.1.1.1'; DefaultGateway='1.1.1.254'; SSID='SNAFU' } }
        (Invoke-EndRunNetworkRecheck -Baseline $base).Changed | Should -BeFalse
        Should -Invoke Request-CprRerun -Times 0
    }
    It 'SSID flip alone triggers one re-run and a tee event' {
        Mock Get-CprQuickNetworkProbe { [pscustomobject]@{ Found=$true; State='Up'; IPAddress='1.1.1.1'; DefaultGateway='1.1.1.254'; SSID='cia_van' } }
        $r = Invoke-EndRunNetworkRecheck -Baseline $base
        $r.Changed | Should -BeTrue; $r.Rerun | Should -BeTrue
        $script:teeSeen.a | Should -Be 'network_changed_during_run'
    }
    It 'a different set of active physical adapters (dock/undock) triggers a re-run' {
        Mock Get-CprQuickNetworkProbe { [pscustomobject]@{ Found=$true; State='Up'; IPAddress='1.1.1.1'; DefaultGateway='1.1.1.254'; SSID='SNAFU' } }
        Mock Get-CprActivePhysicalSet { 'a,b' }
        $r = Invoke-EndRunNetworkRecheck -Baseline $base
        $r.Changed | Should -BeTrue; $r.Rerun | Should -BeTrue
    }
    It 'adapter gone or down counts as changed' {
        Mock Get-CprQuickNetworkProbe { [pscustomobject]@{ Found=$false; State='missing'; IPAddress='N/A'; DefaultGateway='N/A'; SSID='N/A' } }
        (Invoke-EndRunNetworkRecheck -Baseline $base).Changed | Should -BeTrue
    }
    It 'caps chained re-runs' {
        (Test-RerunAllowed) | Should -BeTrue
        (Test-RerunAllowed) | Should -BeTrue
        (Test-RerunAllowed) | Should -BeFalse
    }
    It 'is the last step: after the maintenance stage, before Write-RunEnd' {
        $m = $entry.IndexOf('Invoke-MaintenanceStage -ExitReason')
        $c = $entry.IndexOf('Invoke-EndRunNetworkRecheck')
        $e = $entry.IndexOf('Write-RunEnd $script:exitReason', $c)
        $c | Should -BeGreaterThan $m
        $e | Should -BeGreaterThan $c
    }
}

Describe 'Connected VPN is trusted on wake/jump' {
    It 'stale-guard is behind a pivot that defaults to trusting Connected' {
        $root = Split-Path -Parent $PSScriptRoot
        (Get-Content (Join-Path $root 'main\Main.Configuration.ps1') -Raw) | Should -Match '\$VpnConnectedTrustOnWakeJump\s*=\s*\$true'
        (Get-Content (Join-Path $root 'main\Main.Entry.ps1') -Raw) | Should -Match '\(\$earlyGate\.Wake -or \$earlyGate\.Jump\) -and -not \$VpnConnectedTrustOnWakeJump'
    }
}

Describe 'DHCP settle sleep ordering' {
    It 'a Connected VPN short-circuits before the post-DHCP sleep' {
        $e = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.Entry.ps1') -Raw
        $e.IndexOf('RC2.1 Connected short-circuit') | Should -BeLessThan $e.IndexOf('Start-Sleep -Seconds $initial_sleep')
    }
}

Describe 'Tee master and level tool' {
    BeforeAll {
        $script:root = Split-Path -Parent $PSScriptRoot
        $script:master = Join-Path $script:root 'WW_tee_master.psd1'
        . (Join-Path $script:root 'WW_set_tee_level.ps1')
        $script:codeTags = @(Get-ChildItem $script:root -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' } |
            ForEach-Object { [regex]::Matches((Get-Content $_.FullName -Raw), "Write-TeeLog\s+'([a-z0-9_]+)'") } |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    }
    It 'the tool has no param() block, so dot-sourcing it cannot overwrite the caller''s variables' {
        $text = Get-Content (Join-Path $script:root 'WW_set_tee_level.ps1') -Raw
        $text | Should -Not -Match '(?m)^(\[CmdletBinding\(\)\]\s*)?param\s*\('
        function Test-DotSourceKeepsLocals {
            param([string]$ToolPath)
            $activePath = 'C:\sentinel\active.psd1'; $masterPath = 'C:\sentinel\master.psd1'
            $level = 3; $reason = 'sentinel'; $generatedBy = 'sentinel'
            . $ToolPath
            return @($activePath, $masterPath, $level, $reason, $generatedBy)
        }
        $v = Test-DotSourceKeepsLocals -ToolPath (Join-Path $script:root 'WW_set_tee_level.ps1')
        $v[0] | Should -Be 'C:\sentinel\active.psd1'
        $v[1] | Should -Be 'C:\sentinel\master.psd1'
        $v[2] | Should -Be 3
        $v[3] | Should -Be 'sentinel'
        $v[4] | Should -Be 'sentinel'
    }
    It 'command-line use still works (-Level N -MasterPath -ActivePath) and rejects a bad level' {
        $out = Join-Path $TestDrive 'cli_active.psd1'
        $tool = Join-Path $script:root 'WW_set_tee_level.ps1'
        & $tool -Level 2 -MasterPath $script:master -ActivePath $out -Reason 'cli_test' | Out-Null
        (Import-PowerShellDataFile $out).Level | Should -Be 2
        (Import-PowerShellDataFile $out).Reason | Should -Be 'cli_test'
        Remove-Item $out -Force
        try { & $tool -Level 9 -MasterPath $script:master -ActivePath $out 2>$null | Out-Null } catch { }
        Test-Path $out | Should -BeFalse
    }
    It 'every tag the code emits is defined in the master (tag drift guard)' {
        $all = Get-CprTeeLevelProfile -Level 5 -MasterPath $script:master
        foreach ($t in $script:codeTags) {
            if ($t -eq 'not_a_real_tag') { continue }
            $all.Events.ContainsKey($t) | Should -BeTrue -Because "master is missing tag '$t'"
        }
    }
    It 'no tag is defined in two levels' {
        { Get-CprTeeLevelProfile -Level 5 -MasterPath $script:master } | Should -Not -Throw
    }
    It 'levels are cumulative: each level contains every tag of the level below' {
        $prev = @()
        foreach ($n in 0..5) {
            $tags = @((Get-CprTeeLevelProfile -Level $n -MasterPath $script:master).Events.Keys)
            foreach ($t in $prev) { $tags | Should -Contain $t }
            $prev = $tags
        }
    }
    It 'level 1 carries all captive-portal events and the tee_level_set event' {
        $l1 = Get-CprTeeLevelProfile -Level 1 -MasterPath $script:master
        foreach ($t in 'cap_portal_redirect','cap_portal_remediation_passed','cap_portal_remediation_failed','cap_portal_preflight_observation','cap_portal_webhelper_navigation','cap_portal_runner_result','captive_walled_garden','tee_level_set','cpr_self_update_passed','flare_dispatched','flare_failed','flare_suppressed','flare_runner_started','flare_runner_completed') {
            $l1.Events.ContainsKey($t) | Should -BeTrue -Because $t
        }
    }
    It 'generated text parses back with the same Level and tag count for every level' {
        foreach ($n in 0..5) {
            $lp = Get-CprTeeLevelProfile -Level $n -MasterPath $script:master
            $path = Join-Path $TestDrive "gen$n.psd1"
            Set-Content $path (ConvertTo-CprTeeProfileText -LevelProfile $lp) -Encoding UTF8
            $d = Import-PowerShellDataFile $path
            $d.Level | Should -Be $n
            @($d.Events.Keys).Count | Should -Be @($lp.Events.Keys).Count
        }
    }
    It 'Set-CprTeeLevel writes the active file, keeps a .bak, and reports the previous level' {
        $active = Join-Path $TestDrive 'active.psd1'
        (Set-CprTeeLevel -Level 2 -MasterPath $script:master -ActivePath $active).Success | Should -BeTrue
        $r = Set-CprTeeLevel -Level 4 -MasterPath $script:master -ActivePath $active
        $r.Success | Should -BeTrue
        $r.PreviousLevel | Should -Be 2
        (Get-CprActiveTeeLevelInfo -ActivePath $active).Level | Should -Be 4
        Test-Path "$active.bak" | Should -BeTrue
    }
    It 'a failure leaves the existing active profile untouched' {
        $active = Join-Path $TestDrive 'keep.psd1'
        Set-Content $active "@{ Level = 3; ProfileVersion = 'x'; Events = @{} }" -Encoding UTF8
        $before = Get-Content $active -Raw
        $r = Set-CprTeeLevel -Level 2 -MasterPath (Join-Path $TestDrive 'missing.psd1') -ActivePath $active
        $r.Success | Should -BeFalse
        (Get-Content $active -Raw) | Should -Be $before
    }
    It 'level 0 still carries the level reporting events (and nothing else)' {
        $l0 = Get-CprTeeLevelProfile -Level 0 -MasterPath $script:master
        @($l0.Events.Keys | Sort-Object) | Should -Be @('tee_level_info','tee_level_set')
    }
    It 'the generated header records who wrote the profile and why' {
        $active = Join-Path $TestDrive 'why.psd1'
        $null = Set-CprTeeLevel -Level 2 -MasterPath $script:master -ActivePath $active -GeneratedBy 'unit' -Reason 'because'
        $i = Get-CprActiveTeeLevelInfo -ActivePath $active
        $i.Reason | Should -Be 'because'
        $i.GeneratedBy | Should -Be 'unit'
        $i.TagCount | Should -BeGreaterThan 2
    }
    It 'Get-CprActiveTeeLevelInfo reads the Level marker and the Custom opt-out' {
        $p = Join-Path $TestDrive 'info.psd1'
        Set-Content $p "@{ Level = 5; ProfileVersion = 'v'; Custom = `$true; Events = @{} }" -Encoding UTF8
        $i = Get-CprActiveTeeLevelInfo -ActivePath $p
        $i.Level | Should -Be 5
        $i.Custom | Should -BeTrue
        (Get-CprActiveTeeLevelInfo -ActivePath (Join-Path $TestDrive 'nope.psd1')).Exists | Should -BeFalse
    }
}

Describe 'cpr_tee_<N>.flag handler' {
    BeforeAll {
        $script:root = Split-Path -Parent $PSScriptRoot
        . (Join-Path $script:root 'main\Main.TeeFlag.ps1')
    }
    BeforeEach {
        $script:flagDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:flagDir | Out-Null
        $script:TeeFlagEnabled = $true; $script:TeeFlagDir = $script:flagDir
        $script:TeeSetScript = Join-Path $script:root 'WW_set_tee_level.ps1'
        $script:TeeMasterFile = Join-Path $script:root 'WW_tee_master.psd1'
        $script:TeeEventsFile = Join-Path $script:flagDir 'active.psd1'
        $script:TeeRevertStateFile = Join-Path $script:flagDir 'revert.json'
        $script:TeeLevelInfoHours = 24; $script:TeeLevelInfoStampFile = Join-Path $script:flagDir 'info.stamp'
        $script:TeeDefaultLevel = 1; $script:TeeFlagCooldownMinutes = 10; $script:TeeFlagRevertHours = 336
        $script:TeeFlagFailedMaxAgeDays = 7; $script:WhatIf = $false
        $script:teeEvents = @()
        function Write-Log { param($m,$l) }
        function Write-TeeLog { param($Tag,$Data,[switch]$PassThru) $script:teeEvents += ,@{ Tag = $Tag; Data = $Data }; if ($PassThru) { [pscustomobject]@{ Queued = $true } } }
        . $script:TeeSetScript
        $null = Set-CprTeeLevel -Level 1 -MasterPath $script:TeeMasterFile -ActivePath $script:TeeEventsFile
    }
    It 'applies a valid flag, deletes it, records the previous level and tees the change' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_5.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 5
        Test-Path (Join-Path $script:flagDir 'cpr_tee_5.flag') | Should -BeFalse
        (Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json).previous_level | Should -Be 1
        @($script:teeEvents | Where-Object { $_.Tag -eq 'tee_level_set' -and $_.Data.result -eq 'applied' }).Count | Should -Be 1
    }
    It 'ignores file CONTENT: a flag with junk inside is treated the same' {
        Set-Content (Join-Path $script:flagDir 'cpr_tee_3.flag') '& calc.exe; level=99'
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 3
    }
    It 'renames an invalid flag name to .failed and changes nothing' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_9.flag') -ItemType File | Out-Null
        New-Item (Join-Path $script:flagDir 'cpr_tee_0.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 1
        Test-Path (Join-Path $script:flagDir 'cpr_tee_9.failed') | Should -BeTrue
        Test-Path (Join-Path $script:flagDir 'cpr_tee_0.failed') | Should -BeTrue
    }
    It 'with several flags the highest level wins and all are consumed' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_2.flag') -ItemType File | Out-Null
        New-Item (Join-Path $script:flagDir 'cpr_tee_4.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 4
        @(Get-ChildItem $script:flagDir -Filter 'cpr_tee_*.flag').Count | Should -Be 0
    }
    It 'cooldown: a second flag right after a change waits and is left in place' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_5.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        New-Item (Join-Path $script:flagDir 'cpr_tee_2.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 5
        Test-Path (Join-Path $script:flagDir 'cpr_tee_2.flag') | Should -BeTrue
    }
    It 'reverts to the previous level after the revert time and tees it' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_5.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        $st.expires_at = (Get-Date).AddHours(-1).ToString('o')
        $st | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 1
        Test-Path $script:TeeRevertStateFile | Should -BeFalse
        @($script:teeEvents | Where-Object { $_.Data.result -eq 'reverted' }).Count | Should -Be 1
    }
    It 'does not revert when someone else changed the level meanwhile' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_5.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        $null = Set-CprTeeLevel -Level 2 -MasterPath $script:TeeMasterFile -ActivePath $script:TeeEventsFile
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        $st.expires_at = (Get-Date).AddHours(-1).ToString('o')
        $st | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 2
    }
    It 'a _keep flag sets the level with NO revert, even long after' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_5_keep.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 5
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        $st.expires_at | Should -BeNullOrEmpty
        $st.applied_at = (Get-Date).AddDays(-60).ToString('o')
        $st | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 5
        @($script:teeEvents | Where-Object { $_.Data.reason -eq 'keep' }).Count | Should -Be 1
    }
    It 'a _keep flag cancels a pending revert and later flags revert to the kept level, not the old one' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_5.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        $st.applied_at = (Get-Date).AddHours(-1).ToString('o')
        $st | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        New-Item (Join-Path $script:flagDir 'cpr_tee_3_keep.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-CprActiveTeeLevelInfo -ActivePath $script:TeeEventsFile).Level | Should -Be 3
        (Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json).expires_at | Should -BeNullOrEmpty
        $st = Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json
        $st.applied_at = (Get-Date).AddHours(-1).ToString('o')
        $st | ConvertTo-Json | Set-Content $script:TeeRevertStateFile
        New-Item (Join-Path $script:flagDir 'cpr_tee_5.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json).previous_level | Should -Be 3
    }
    It 'at the same level the _keep flag wins over the plain flag' {
        New-Item (Join-Path $script:flagDir 'cpr_tee_4.flag') -ItemType File | Out-Null
        New-Item (Join-Path $script:flagDir 'cpr_tee_4_keep.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        (Get-Content $script:TeeRevertStateFile -Raw | ConvertFrom-Json).expires_at | Should -BeNullOrEmpty
    }
    It 'reports the effective level and reason (tee_level_info) once, then not again until it changes or 24h pass' {
        Invoke-TeeLevelFlagCheck
        @($script:teeEvents | Where-Object { $_.Tag -eq 'tee_level_info' }).Count | Should -Be 1
        Invoke-TeeLevelFlagCheck
        @($script:teeEvents | Where-Object { $_.Tag -eq 'tee_level_info' }).Count | Should -Be 1
        New-Item (Join-Path $script:flagDir 'cpr_tee_4.flag') -ItemType File | Out-Null
        Invoke-TeeLevelFlagCheck
        $infos = @($script:teeEvents | Where-Object { $_.Tag -eq 'tee_level_info' })
        $infos.Count | Should -Be 2
        $infos[1].Data.level | Should -Be '4'
        $infos[1].Data.reason | Should -Be 'flag'
        $infos[1].Data.revert_at | Should -Not -BeNullOrEmpty
    }
    It 'sweeps stale .failed flags but keeps fresh ones' {
        $old = New-Item (Join-Path $script:flagDir 'cpr_tee_5.failed') -ItemType File
        $old.LastWriteTime = (Get-Date).AddDays(-30)
        $new = New-Item (Join-Path $script:flagDir 'cpr_update_dev.failed') -ItemType File
        Invoke-TeeLevelFlagCheck
        Test-Path $old.FullName | Should -BeFalse
        Test-Path $new.FullName | Should -BeTrue
    }
    It 'is called from the run finally block, before the end-of-run recheck' {
        $e = Get-Content (Join-Path $script:root 'main\Main.Entry.ps1') -Raw
        $e.IndexOf('Invoke-TeeLevelFlagCheck') | Should -BeGreaterThan 0
        $e.IndexOf('Invoke-TeeLevelFlagCheck') | Should -BeLessThan $e.IndexOf('Invoke-EndRunNetworkRecheck')
        (Get-Content (Join-Path $script:root 'WW_main.ps1') -Raw) | Should -Match "Main\.TeeFlag\.ps1"
    }
}

Describe 'Installer tee profile handling' {
    BeforeAll {
        $script:inst = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1') -Raw
    }
    It 'deploys the master and the tool and regenerates the profile from them' {
        $inst | Should -Match 'WW_tee_master\.psd1'
        $inst | Should -Match 'WW_set_tee_level\.ps1'
        $inst | Should -Match 'function Update-TeeProfile'
        $inst | Should -Match 'Set-CprTeeLevel -Level \$level'
        $inst | Should -Not -Match 'Copy-TeeEventsIfMissing'
    }
    It 'honours the Custom opt-out and the default level' {
        $inst | Should -Match '\$info\.Custom'
        $inst | Should -Match "Get-CprConfigLiteral -Name 'TeeDefaultLevel' -Default"
        $inst | Should -Not -Match '(?m)^\$TeeDefaultLevel\s*=\s*\d'
    }
    It 'the default level has exactly one definition: the configuration (the installer reads it)' {
        $cfg = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.Configuration.ps1') -Raw
        $cfg | Should -Match '(?m)^\$TeeDefaultLevel\s*=\s*\d+'
    }
}

Describe 'Syslog path diagnostic' {
    BeforeAll {
        $script:root = Split-Path -Parent $PSScriptRoot
        $script:diag = Get-Content (Join-Path $script:root 'diagnostics\Test-CprSyslogPath.ps1') -Raw
    }
    It 'defaults the test machine name to CPR_TESTER' {
        $script:diag | Should -Match "MachineName\s*=\s*'CPR_TESTER'"
    }
    It 'indexes the resolved addresses safely (regression: a lone string made $ip[0] one character)' {
        $script:diag | Should -Match '\$ips\s*=\s*@\('
        $script:diag | Should -Match '\[string\]\$ips\[0\]'
        $script:diag | Should -Not -Match 'Find-NetRoute\s+-RemoteIPAddress\s+\$ip\['
    }
    It 'reads the same state file and reachable-state list as haystack_action.ps1' {
        $ha = Get-Content (Join-Path $script:root 'haystack_action.ps1') -Raw
        $ha | Should -Match 'C:\\Windows\\UHGLogs\\state\.json'
        $script:diag | Should -Match 'C:\\Windows\\UHGLogs\\state\.json'
        $script:diag | Should -Match "'on_prem',\s*'user_tun',\s*'mgmt_tun'"
    }
    It 'only sends a test message when -Send is given' {
        $script:diag | Should -Match 'if \(\$Send\)'
    }
    It 'builds the test payload in the production field order with EvtTime and a resolved user' {
        $script:diag | Should -Match 'action="needle_hit" machine="\{0\}" user="\{1\}" EvtTime="\{2\}"'
        $script:diag | Should -Match "Get-Date -Format 'o'"
        $script:diag | Should -Match 'Get-HaystackUserContext'
        $script:diag | Should -Match 'Test-HaystackMsgSchema'
    }
    It 'is wired into the console Quick Actions and WW_diagnostics.ps1 (read-only there)' {
        $console = Get-Content (Join-Path $script:root 'admin\Invoke-WhiteWalkerAction.ps1') -Raw
        $console | Should -Match "'5' \{ Invoke-WWAction -Name 'QuickAction:SyslogPathTest'"
        $console | Should -Match 'Test-CprSyslogPath\.ps1" -Send|Test-CprSyslogPath\.ps1 -Send|\$syslogTest -Send'
        $wd = Get-Content (Join-Path $script:root 'WW_diagnostics.ps1') -Raw
        $wd | Should -Match 'function Test-SyslogPathDiag'
        $wd | Should -Not -Match '\$tool\s+-Send'
    }
}


Describe 'Test tools follow the production message convention' {
    BeforeAll { $script:t = Join-Path (Split-Path -Parent $PSScriptRoot) 'tests' }
    It 'every raw test sender uses machine=CPR_TESTER and stamps EvtTime' -TestCases @(
        @{ f = 'TEST_send_syslog_msg_from_powershell_simple.ps1' },
        @{ f = 'TEST_send_syslog_msg.py' },
        @{ f = 'TEST_send_syslog_msg_from_bash_simple.sh' }
    ) {
        $c = Get-Content (Join-Path $script:t $f) -Raw
        $c | Should -Match 'CPR_TESTER'
        $c | Should -Match 'EvtTime'
        $c | Should -Not -Match 'action=test_shot'      # action is quoted like production
    }
    It 'Test-HayStackSyslog and the mock flow default MachineName to CPR_TESTER' -TestCases @(
        @{ f = 'Test-HayStackSyslog.ps1' }, @{ f = 'TEST_mock_cap_portal_flow.ps1' }
    ) {
        (Get-Content (Join-Path $script:t $f) -Raw) | Should -Match "\`$MachineName\s*=\s*'CPR_TESTER'"
    }
}

Describe 'Admin console log browser' {
    BeforeAll { $script:adm = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'admin\Invoke-WhiteWalkerAction.ps1') -Raw }
    It 'offers A (all files) in the Watch menu and routes it to the browser' {
        $script:adm | Should -Match "-in @\('A', 'a'\)\) \{ Invoke-WWBrowseLogs; return \}"
    }
    It 'lists logs\ and logs\spool, and offers tail, view and Notepad' {
        $script:adm | Should -Match "Join-Path \`$root 'spool'"
        $script:adm | Should -Match 'Show-WWLogStream -Definition \$def -Count 50'
        $script:adm | Should -Match "notepad\.exe"
    }
    It 'never writes to the files it browses' {
        $b = [regex]::Match($script:adm, 'function Invoke-WWBrowseLogs.*?function Invoke-WWWatchLog', 'Singleline').Value
        $b | Should -Not -Match 'Set-Content|Add-Content|Remove-Item|Out-File'
    }
}

Describe 'Self-update retry counter' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $script:su  = Get-Content (Join-Path $root 'main\Main.SelfUpdate.ps1') -Raw
        $script:cfg = Get-Content (Join-Path $root 'main\Main.Configuration.ps1') -Raw
    }
    It 'has a configurable attempt limit' {
        $script:cfg | Should -Match '\$SelfUpdateMaxAttempts\s*=\s*5'
    }
    It 'reads the count from the flag and treats junk as zero' {
        $script:su | Should -Match 'Get-Content -LiteralPath \$flagFile -Raw'
        $script:su | Should -Match '\[int\]::TryParse\(\$rawCount\.Trim\(\)'
        $script:su | Should -Match '\[math\]::Min\(\$parsedCount, \$maxAttempts\)'
    }
    It 'keeps the flag and records the count until the limit, then renames to .failed' {
        $script:su | Should -Match 'Set-Content -LiteralPath \$flagFile -Value \(\[string\]\$failedCount\)'
        $script:su | Should -Match '\$gaveUp\s*=\s*\(\$failedCount -ge \$maxAttempts\)'
        $script:su | Should -Match "if \(\`$gaveUp\) \{\s*Rename-Item -Path \`$flagFile"
    }
    It 'tees every attempt with attempt= and a retry_pending / gave_up status' {
        $script:su | Should -Match "'gave_up' \} else \{ 'retry_pending'"
        ([regex]::Matches($script:su, 'attempt\s*=\s*\[string\]')).Count | Should -BeGreaterOrEqual 3
    }
    It 'tells an unreachable share from a missing zip' {
        $script:su | Should -Match 'share_unreachable'
        $script:su | Should -Match 'Test-Path -LiteralPath \$SelfUpdateRemoteBase'
    }
    It 'adds no nested functions (only Get-SelfUpdateNetworkState is allowed)' {
        ([regex]::Matches($script:su, '(?m)^\s+function ')).Count | Should -Be 1
    }
}

Describe 'Syslog queue drain does not lose entries appended mid-drain' {
    BeforeAll {
        $src = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'haystack_action.ps1') -Raw
        $script:drain = [regex]::Match($src, 'function Drain-SyslogQueue.*?function Invoke-SyslogSend', 'Singleline').Value
    }
    It 'claims the queue by atomic rename and works on the claimed copy' {
        $script:drain | Should -Match '\$workFile\s*=\s*"\$SyslogQueueFile\.draining"'
        $script:drain | Should -Match 'Move-Item -LiteralPath \$SyslogQueueFile -Destination \$workFile'
        $script:drain | Should -Match 'Get-Content -LiteralPath \$workFile'
    }
    It 'never deletes or overwrites the live queue file' {
        $script:drain | Should -Not -Match 'Remove-Item[^\r\n]*\$SyslogQueueFile'
        $script:drain | Should -Not -Match 'Set-Content[^\r\n]*\$SyslogQueueFile'
    }
    It 'puts failed entries back by appending, then removes only the claimed file' {
        $script:drain | Should -Match 'Add-Content -LiteralPath \$SyslogQueueFile -Value \$keep'
        $script:drain | Should -Match 'Remove-Item -LiteralPath \$workFile'
    }
    It 'skips while another drain is active and recovers a stale claim' {
        $script:drain | Should -Match '\$claimAge -lt 5'
        $script:drain | Should -Match 'recovering a stale claimed queue'
    }
    It 'logs one line per sent entry with its action' {
        $script:drain | Should -Match 'SyslogQueue: sent action=\$sentAction'
    }
    It 'still ingests the spool first' {
        $script:drain.IndexOf('Import-SyslogSpool') | Should -BeLessThan $script:drain.IndexOf('$workFile')
    }
}

Describe 'Main log writer does not drop lines silently' {
    BeforeAll {
        $src = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.Logging.ps1') -Raw
        $script:fn = [regex]::Match($src, 'function Add-LogLine.*?function Write-Log', 'Singleline').Value
    }
    It 'retries more than 3 times through a transient lock' {
        $script:fn | Should -Match '\$i -le 6'
    }
    It 'leaves a trace in log_write_failures.txt when every try fails' {
        $script:fn | Should -Match 'log_write_failures\.txt'
        $script:fn | Should -Match 'run=\{1\}'
    }
}

Describe 'Combined update + tee flag' {
    BeforeAll {
        $script:su = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.SelfUpdate.ps1') -Raw
        $script:rx = [regex]::Match($script:su, "-match '(\^cpr_update_[^']+)'").Groups[1].Value
    }
    It 'uses one strict name pattern for the update flag' {
        $script:rx | Should -Be '^cpr_update_(dev|prod)(_tee_([1-5])(_keep)?)?\.flag$'
    }
    It 'accepts the plain and combined names' {
        foreach ($n in 'cpr_update_dev.flag', 'cpr_update_prod.flag', 'cpr_update_dev_tee_5.flag', 'cpr_update_prod_tee_2_keep.flag') {
            $n | Should -Match $script:rx
        }
    }
    It 'rejects bad names' {
        foreach ($n in 'cpr_update_dev_tee5.flag', 'cpr_update_dev_tee_6.flag', 'cpr_update_dev_tee_0.flag', 'cpr_update_dev_keep.flag', 'cpr_update_qa.flag', 'cpr_update_dev_tee_5_keep.flag.txt') {
            $n | Should -Not -Match $script:rx
        }
    }
    It 'renames invalid names to .failed instead of retrying them forever' {
        $script:su | Should -Match "-replace '\\\.flag\$', '\.failed'"
        $script:su | Should -Match 'invalid_flag_name'
    }
    It 'drops the tee flag only in the success branch, after the installer exit-code check' {
        $iExit = $script:su.IndexOf('installer_nonzero_exit')
        $iTee  = $script:su.IndexOf('cpr_tee_{0}{1}.flag')
        $iExit | Should -BeGreaterThan 0
        $iTee  | Should -BeGreaterThan $iExit
        $iTee  | Should -BeLessThan $script:su.IndexOf('} catch {', $iTee + 1)
    }
    It 'never lets a tee flag problem fail the update' {
        $script:su | Should -Match 'update succeeded but the tee flag could not be created'
    }
    It 'uninstall removes every cpr_update_*.flag' {
        (Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1') -Raw) | Should -Match "-Filter 'cpr_update_\*\.flag'"
    }
}

Describe 'vpncli calls are time-bounded' {
    BeforeAll {
        $script:root = Split-Path -Parent $PSScriptRoot
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:root 'main\Main.VpnState.ps1'), [ref]$null, [ref]$null)
        $def = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-VpnCliBounded' }, $true)[0]
        . ([scriptblock]::Create($def.Extent.Text))
        function Write-Log { param($m, $l) $script:logged += "$m" }
        $script:vpn_cmd = Join-Path $(if ($env:SystemRoot) { $env:SystemRoot } else { $TestDrive }) 'System32\cmd.exe'
        $script:VpnCliTimeoutSec = 8
        $script:VpnCliDisconnectTimeoutSec = 20
    }
    BeforeEach { $script:logged = @(); $script:VpnDisconnectsThisRun = 0 }

    It 'returns the stdout of a call that finishes in time' {
        $out = Invoke-VpnCliBounded -Arguments '/c echo state: Disconnected' -TimeoutSec 5
        $out | Should -Match 'state: Disconnected'
    }
    It 'kills a hung call, returns empty and logs vpncli_timeout' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $out = Invoke-VpnCliBounded -Arguments '/c ping -n 30 127.0.0.1 >nul' -TimeoutSec 1
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 6
        $out | Should -Be ''
        ($script:logged -join "`n") | Should -Match 'vpncli_timeout'
    }
    It 'counts disconnect calls for the run' {
        $null = Invoke-VpnCliBounded -Arguments 'disconnect' -TimeoutSec 5
        $script:VpnDisconnectsThisRun | Should -Be 1
    }
    It 'no main script calls vpncli directly any more' {
        $direct = Get-ChildItem (Join-Path $script:root 'main') -Filter *.ps1 | Select-String -Pattern '& \$vpn_cmd'
        @($direct).Count | Should -Be 0
    }
    It 'retry-disconnect only fires after WW itself cut the VPN, and is capped' {
        $src = Get-Content (Join-Path $script:root 'main\Main.VpnState.ps1') -Raw
        $src | Should -Match '\$script:VpnDisconnectsThisRun -gt 0'
        $src | Should -Match '\$script:VpnPostDisconnectRetries -lt \[int\]\$VpnPostDisconnectRetryMax'
    }
    It 'has config knobs for the timeouts and the retry cap' {
        $cfg = Get-Content (Join-Path $script:root 'main\Main.Configuration.ps1') -Raw
        foreach ($n in 'VpnCliTimeoutSec', 'VpnCliDisconnectTimeoutSec', 'VpnPostDisconnectRetryMax') { $cfg | Should -Match "\`$$n\s*=" }
    }
}

Describe 'Native redirect carries the same portal fields as the 301 row' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $src = Join-Path $root 'main\Main.CaptivePortal.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$null, [ref]$null)
        $want = 'Get-CprCiscoWebHelperQueryParameter', 'Get-CprCiscoWebHelperQueryParameterAny', 'Get-CprPortalUrlFields'
        foreach ($d in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $want }, $true)) {
            . ([scriptblock]::Create($d.Extent.Text))
        }
        $script:srcText = Get-Content $src -Raw
    }
    It 'extracts portal descriptors from a redirect URL' {
        $f = Get-CprPortalUrlFields -Url 'https://portal.example/login?ap_name=AP1&ap_mac=aa-bb&SIP=10.0.0.1&PSID=xyz&login_url=http%3A%2F%2Fa%2Fb&ORG=acme'
        $f.ap_name | Should -Be 'AP1'
        $f.ap_mac  | Should -Be 'aa-bb'
        $f.sip     | Should -Be '10.0.0.1'
        $f.psid    | Should -Be 'xyz'
        $f.login_url | Should -Be 'http://a/b'
        $f.org     | Should -Be 'acme'
    }
    It 'uses the cm alias for ap_mac, like the 301 parser' {
        (Get-CprPortalUrlFields -Url 'http://p/x?cm=11-22').ap_mac | Should -Be '11-22'
    }
    It 'leaves absent parameters empty and tolerates empty or junk input' {
        (Get-CprPortalUrlFields -Url 'http://p/x?a=b').ap_name | Should -Be ''
        (Get-CprPortalUrlFields -Url '').trace_id | Should -Be ''
        { Get-CprPortalUrlFields -Url 'not a url' } | Should -Not -Throw
    }
    It 'cap_portal_redirect tee in remediation merges the portal fields' {
        $srcText | Should -Match 'Get-CprPortalUrlFields -Url \(\[string\]\$RedirectUrl\)'
        $srcText | Should -Match 'detection_source = \$\(if \(\$accepted301Carried\)'
    }
    It 'tee master lists the new fields for cap_portal_redirect' {
        $m = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'WW_tee_master.psd1') -Raw
        $m | Should -Match "'reason','detection_source','protocol','fqdn','ap_name'"
    }
}

Describe 'Get-VpnState does not trust the management line when vpncli state is empty' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.VpnState.ps1'), [ref]$null, [ref]$null)
        foreach ($d in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-VpnState' }, $true)) { . ([scriptblock]::Create($d.Extent.Text)) }
        function Write-Log { param($m, $l) }
        function Write-DebugBlock { param($Label, $Text) }
        function Test-VpnPostureActive { $false }
        $script:WWDebug = $false
    }
    It 'returns Unknown when state is empty and stats only shows a Disconnected management line' {
        function Invoke-VpnCliBounded { param($Arguments, $TimeoutSec, $MaxAgeSec) if ($Arguments -eq 'stats') { "Management Connection State: Disconnected`n" } else { '' } }
        Get-VpnState | Should -Be 'Unknown'
    }
    It 'still returns Disconnected when state answers Disconnected' {
        function Invoke-VpnCliBounded { param($Arguments, $TimeoutSec, $MaxAgeSec) if ($Arguments -eq 'stats') { "Management Connection State: Disconnected`n" } else { "  >> state: Disconnected`n" } }
        Get-VpnState | Should -Be 'Disconnected'
    }
    It 'returns Connecting when state says so' {
        function Invoke-VpnCliBounded { param($Arguments, $TimeoutSec, $MaxAgeSec) if ($Arguments -eq 'stats') { '' } else { "  >> state: Connecting`n" } }
        Get-VpnState | Should -Be 'Connecting'
    }
}

Describe 'Posture activity makes a Disconnected vpncli read count as Connecting' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.VpnState.ps1'), [ref]$null, [ref]$null)
        foreach ($d in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Get-VpnState','Test-VpnPostureActive' }, $true)) { . ([scriptblock]::Create($d.Extent.Text)) }
        function Write-Log { param($m, $l) }
        function Write-DebugBlock { param($Label, $Text) }
        $script:WWDebug = $false
        $script:VpnPostureDetection = $true
        $script:VpnPostureLogName = 'Cisco Secure Client - Secure Firewall Posture'
        $script:VpnPostureActiveWindowSec = 15
        $script:VpnPostureScanProvider = 'csc_cscan'
        function Invoke-VpnCliBounded { param($Arguments, $TimeoutSec, $MaxAgeSec) if ($Arguments -eq 'stats') { '' } else { "  >> state: Disconnected`n" } }
    }
    It 'returns Connecting when state reads Disconnected and posture events are recent' {
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_cscan' } }
        Get-VpnState | Should -Be 'Connecting'
    }
    It 'returns Disconnected when the posture log is quiet' {
        Mock Get-WinEvent { $null }
        Get-VpnState | Should -Be 'Disconnected'
    }
    It 'is fail-soft when the log query throws, and honors the off switch' {
        Mock Get-WinEvent { throw 'no such log' }
        Test-VpnPostureActive | Should -BeFalse
        $script:VpnPostureDetection = $false
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'x' } }
        Test-VpnPostureActive | Should -BeFalse
        $script:VpnPostureDetection = $true
    }
    It 'never changes a Connected read' {
        function Invoke-VpnCliBounded { param($Arguments, $TimeoutSec, $MaxAgeSec) if ($Arguments -eq 'stats') { "Management Connection State: Connected`n" } else { "  >> state: Connected`n" } }
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_cscan' } }
        Get-VpnState | Should -Be 'Connected'
    }
}

Describe 'Posture marker distinguishes a HostScan scan from client connect activity' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.VpnState.ps1'), [ref]$null, [ref]$null)
        foreach ($d in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-VpnPostureActive' }, $true)) { . ([scriptblock]::Create($d.Extent.Text)) }
        $script:VpnPostureDetection = $true; $script:VpnPostureActiveWindowSec = 15
        $script:VpnPostureLogName = 'x'; $script:VpnPostureScanProvider = 'csc_cscan'
        $script:logged = @()
        function Write-Log { param($m, $l) $script:logged += $m }
    }
    BeforeEach { $script:logged = @() }
    It 'logs vpn_hostscan_posture_active only for the scanner provider' {
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_cscan' } }
        Test-VpnPostureActive | Should -BeTrue
        ($script:logged -join ' ') | Should -Match 'vpn_hostscan_posture_active'
    }
    It 'logs vpn_client_connect_activity when only other providers wrote' {
        Mock Get-WinEvent { if ($FilterHashtable.ProviderName) { $null } else { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_ciscod' } } }
        Test-VpnPostureActive | Should -BeTrue
        ($script:logged -join ' ') | Should -Match 'vpn_client_connect_activity'
        ($script:logged -join ' ') | Should -Not -Match 'vpn_hostscan_posture_active'
    }
}

Describe 'HostScan hold: never disconnect during a live scan, with a ceiling' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.VpnState.ps1'), [ref]$null, [ref]$null)
        foreach ($d in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Test-VpnHostscanHold','Invoke-VpnCliBounded' }, $true)) { . ([scriptblock]::Create($d.Extent.Text)) }
        function Write-Log { param($m, $l) }
        $script:VpnPostureDetection = $true; $script:VpnHostscanHold = $true
        $script:VpnHostscanSilentSec = 30; $script:VpnHostscanMaxWaitSec = 300
        $script:VpnPostureLogName = 'x'; $script:VpnPostureScanProvider = 'csc_cscan'
        $script:VpnHostscanEpisodeFile = Join-Path $TestDrive 'hold.txt'
        $script:VpnCliTimeoutSec = 8; $script:VpnCliDisconnectTimeoutSec = 20
        $script:VpnDisconnectsThisRun = 0
        $script:vpn_cmd = Join-Path $(if ($env:SystemRoot) { $env:SystemRoot } else { $TestDrive }) 'System32\cmd.exe'
    }
    BeforeEach { $script:VpnHostscanHoldActive = $false; Remove-Item $script:VpnHostscanEpisodeFile -ErrorAction SilentlyContinue; $script:VpnDisconnectsThisRun = 0 }
    It 'holds while scanner events are fresh and starts an episode' {
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_cscan' } }
        Test-VpnHostscanHold | Should -BeTrue
        $script:VpnHostscanHoldActive | Should -BeTrue
        Test-Path $script:VpnHostscanEpisodeFile | Should -BeTrue
    }
    It 'does not hold when the scanner is silent and clears the episode' {
        Set-Content $script:VpnHostscanEpisodeFile (Get-Date).ToString('o')
        Mock Get-WinEvent { $null }
        Test-VpnHostscanHold | Should -BeFalse
        Test-Path $script:VpnHostscanEpisodeFile | Should -BeFalse
    }
    It 'gives up after the ceiling even if the scanner is still writing' {
        Set-Content $script:VpnHostscanEpisodeFile (Get-Date).AddSeconds(-400).ToString('o')
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_cscan' } }
        Test-VpnHostscanHold | Should -BeFalse
    }
    It 'honors the off switch and is fail-soft' {
        $script:VpnHostscanHold = $false
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_cscan' } }
        Test-VpnHostscanHold | Should -BeFalse
        $script:VpnHostscanHold = $true
        Mock Get-WinEvent { throw 'boom' }
        Test-VpnHostscanHold | Should -BeFalse
    }
    It 'Invoke-VpnCliBounded skips disconnect during a hold and does not count it' {
        Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = Get-Date; ProviderName = 'csc_cscan' } }
        Invoke-VpnCliBounded -Arguments 'disconnect' | Should -Be ''
        $script:VpnDisconnectsThisRun | Should -Be 0
    }
    It 'static: stabilize returns early on a hold and the main flow exits cleanly' {
        $vs = Get-Content (Join-Path $root 'main\Main.VpnState.ps1') -Raw
        $en = Get-Content (Join-Path $root 'main\Main.Entry.ps1') -Raw
        $vs | Should -Match "Test-VpnHostscanHold -Where 'stabilize'"
        $en | Should -Match 'vpn_hostscan_posturing'
    }
}

Describe 'HayStack drain kick: end-of-run ship of queued install/update results' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.Entry.ps1'), [ref]$null, [ref]$null)
        foreach ($d in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-HaystackDrainKick' }, $true)) { . ([scriptblock]::Create($d.Extent.Text)) }
        function Write-Log { param($m, $l) }
        function Start-ScheduledTask { param($TaskPath, $TaskName, $ErrorAction) }
        function Get-ScheduledTask { param($TaskName, $ErrorAction) }
        function Start-Process { param($FilePath, $ArgumentList, $WindowStyle) }
        $script:HaystackActionScriptPath = Join-Path $TestDrive 'ha.ps1'
        $script:HaystackEnabled = $true; $script:HaystackDrainKick = $true; $script:WhatIf = $false
        $script:HaystackDrainQueueFile = Join-Path $TestDrive 'q.jsonl'
        $script:HaystackDrainPendingDir = Join-Path $TestDrive 'pending'
        $script:HaystackDrainTaskName = 'HayStack_Monitor'; $script:CprTaskFolder = '\CPR\'
        $script:StateFile = Join-Path $TestDrive 'state.json'
    }
    BeforeEach {
        Remove-Item $script:HaystackDrainQueueFile, $script:StateFile -ErrorAction SilentlyContinue
        Remove-Item $script:HaystackDrainPendingDir -Recurse -ErrorAction SilentlyContinue
    }
    It 'starts the task when the queue has content and the state can ship' {
        Set-Content $script:HaystackDrainQueueFile '{"x":1}'
        '{"currentState":"user_tun"}' | Set-Content $script:StateFile
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'HayStack_Monitor'; TaskPath = '\CPR\' } }
        Mock Start-ScheduledTask {}
        Invoke-HaystackDrainKick -CorpReachable $true
        Should -Invoke Start-ScheduledTask -Times 1
    }
    It 'falls back to running the action script when the task is not found'{
        Set-Content $script:HaystackDrainQueueFile '{"x":1}'
        Set-Content $script:HaystackActionScriptPath '#'
        '{"currentState":"user_tun"}' | Set-Content $script:StateFile
        Mock Get-ScheduledTask { $null }
        Mock Start-ScheduledTask { throw 'not found' }
        Mock Start-Process {}
        Invoke-HaystackDrainKick -CorpReachable $true
        Should -Invoke Get-ScheduledTask -Times 1
        Should -Invoke Start-Process -Times 1
    }
    It 'does nothing when the queue is empty' {
        '{"currentState":"on_prem"}' | Set-Content $script:StateFile
        Mock Start-ScheduledTask {}
        Invoke-HaystackDrainKick -CorpReachable $true
        Should -Invoke Start-ScheduledTask -Times 0
    }
    It 'does nothing when this run could not reach corp, even if state.json is stale user_tun' {
        Set-Content $script:HaystackDrainQueueFile '{"x":1}'
        '{"currentState":"user_tun"}' | Set-Content $script:StateFile
        Mock Start-ScheduledTask {}
        Mock Start-Process {}
        Invoke-HaystackDrainKick -CorpReachable $false
        Should -Invoke Start-Process -Times 0
        Should -Invoke Start-ScheduledTask -Times 0
    }
    It 'kicks for a pending-dir file when the queue file is absent' {
        New-Item -ItemType Directory $script:HaystackDrainPendingDir | Out-Null
        Set-Content (Join-Path $script:HaystackDrainPendingDir 'e.json') '{}'
        '{"currentState":"mgmt_tun"}' | Set-Content $script:StateFile
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'HayStack_Monitor'; TaskPath = '\CPR\' } }
        Mock Start-ScheduledTask {}
        Invoke-HaystackDrainKick -CorpReachable $true
        Should -Invoke Start-ScheduledTask -Times 1
    }
    It 'is fail-soft when the task start throws' {
        Set-Content $script:HaystackDrainQueueFile '{"x":1}'
        '{"currentState":"on_prem"}' | Set-Content $script:StateFile
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'HayStack_Monitor'; TaskPath = '\CPR\' } }
        Mock Start-ScheduledTask { throw 'nope' }
        Mock Start-Process {}
        { Invoke-HaystackDrainKick } | Should -Not -Throw
    }
    It 'static: maintenance stage calls the kick after self-update' {
        $en = Get-Content (Join-Path $root 'main\Main.Entry.ps1') -Raw
        $en | Should -Match '(?s)Invoke-SelfUpdate.*Invoke-HaystackDrainKick -CorpReachable \(\[bool\]\$shareOk\)'
    }
}

Describe 'HayStack reroll recreates a missing task even when the stamp is current' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $script:hsSrc = Get-Content (Join-Path $root 'haystack.ps1') -Raw
    }
    It 'Test-RerollNeeded checks task existence before trusting the stamp' {
        $script:hsSrc | Should -Match '(?s)function Test-RerollNeeded.*?Get-ScheduledTask -TaskName \$TsTaskName -TaskPath \$TsTaskPath.*?Get-RerollStampData'
        $script:hsSrc | Should -Match 'task not registered at'
    }
}

Describe 'Installer registers and validates HayStack_Monitor like every other task' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $script:inst = Get-Content (Join-Path $root 'install.ps1') -Raw
    }
    It 'defines Register-HaystackMonitorTask running haystack.ps1 -reroll -Force with a bounded wait and one retry' {
        $script:inst | Should -Match 'function Register-HaystackMonitorTask'
        $script:inst | Should -Match '-reroll -Force'
        $script:inst | Should -Match 'WaitForExit\(120000\)'
        $script:inst | Should -Match '\$attempt -le 2'
    }
    It 'calls it after Register-Tasks and before Test-Installation' {
        $script:inst | Should -Match '(?s)\$tasksOK = Register-Tasks.*\$null = Register-HaystackMonitorTask.*\$validated = Test-Installation'
    }
    It 'Test-Installation expects HayStack_Monitor in the CPR folder in addition to the XML tasks' {
        $script:inst | Should -Match '(?s)\$expectedTasks = @\(\$TaskXMLs\) \+ @\(@\{ Name = "HayStack_Monitor"; TaskPath = \$CprTaskFolder \}\)'
        $script:inst | Should -Match 'foreach \(\$task in \$expectedTasks\)'
    }
}
