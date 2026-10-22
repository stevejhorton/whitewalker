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
        $exit = $entry.IndexOf('skipping enroll.cisco.com and captive-portal checks')
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
        ($script:teeEvents | Where-Object { $_.Tag -eq 'tee_level_set' -and $_.Data.result -eq 'applied' }).Count | Should -Be 1
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
        ($script:teeEvents | Where-Object { $_.Data.result -eq 'reverted' }).Count | Should -Be 1
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
        ($script:teeEvents | Where-Object { $_.Data.reason -eq 'keep' }).Count | Should -Be 1
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
        $inst | Should -Match '\$TeeDefaultLevel\s*=\s*1'
    }
    It 'default level matches between installer and configuration' {
        $cfg = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\Main.Configuration.ps1') -Raw
        $cfg | Should -Match '\$TeeDefaultLevel\s*=\s*1'
    }
}
