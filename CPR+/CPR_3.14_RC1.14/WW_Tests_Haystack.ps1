BeforeAll {
    $scriptPath = "$PSScriptRoot/haystack.ps1"

    $content = Get-Content -LiteralPath $scriptPath -Raw
    $entryPointPattern = '(?ms)^# =+\r?\n# Entry Point'
    $preEntryPointContent = ($content -split $entryPointPattern)[0]
    $funcStart = $preEntryPointContent.IndexOf('function Write-HSLog')
    $funcContent = $preEntryPointContent.Substring($funcStart)
    Invoke-Expression $funcContent

    if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        function Register-ScheduledTask { param([string]$Xml, [string]$TaskName, [string]$TaskPath, [switch]$Force) }
    }
    if (-not (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue)) {
        function Unregister-ScheduledTask { param([string]$TaskName, [string]$TaskPath, [switch]$Confirm) }
    }
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        function Get-ScheduledTask { param([string]$TaskName, [string]$TaskPath) return $null }
    }

    $script:HaystackVersion = '1.0.0'
    $script:HaystackRerollCooldownMinutes = 60
    $script:LocalCacheDir = $TestDrive
    $script:LocalNeedlesFile = Join-Path $TestDrive 'needles.cfg'
    $script:LocalNeedlesFile_Local = Join-Path $TestDrive 'needles_local.cfg'
    $script:RerollStampFile = Join-Path $TestDrive 'haystack_reroll.stamp'
    $script:HaystackLogFile = Join-Path $TestDrive 'haystack.log'
    $script:HaystackLogMaxBytes = 1MB
    $script:HaystackLogKeep = 5
    $script:ActionScriptPath = Join-Path $TestDrive 'haystack_action.ps1'
    $script:TsTaskName = 'HayStack_Monitor'
    $script:TsTaskPath = '\HayStack\'
    $script:RemoteConfigDir = '\\fake\share\that\does\not\exist'
    $script:RemoteNeedlesFile = '\\fake\share\that\does\not\exist\needles.cfg'
}

Describe 'ConvertTo-XmlEscaped' {
    It 'escapes ampersand' {
        (ConvertTo-XmlEscaped -s '&') | Should -Be '&amp;'
    }

    It 'escapes less-than' {
        (ConvertTo-XmlEscaped -s '<') | Should -Be '&lt;'
    }

    It 'escapes greater-than' {
        (ConvertTo-XmlEscaped -s '>') | Should -Be '&gt;'
    }

    It 'escapes double quote' {
        (ConvertTo-XmlEscaped -s '"') | Should -Be '&quot;'
    }

    It 'escapes single quote' {
        (ConvertTo-XmlEscaped -s "'") | Should -Be '&apos;'
    }

    It 'escapes all XML special characters in one pass' {
        (ConvertTo-XmlEscaped -s '&<>"''') | Should -Be '&amp;&lt;&gt;&quot;&apos;'
    }

    It 'passes clean strings unchanged' {
        (ConvertTo-XmlEscaped -s 'HayStack_Label_1') | Should -Be 'HayStack_Label_1'
    }
}

Describe 'Read-NeedleFile' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }
    }

    Context 'NEEDLE type' {
        It 'parses valid NEEDLE lines including bare EventID XPath' {
            @(
                'version:1.0.0'
                'NEEDLE|Security|4624|*[System[(EventID=4624)]]|LoginHit'
                'NEEDLE|System|6005||BootHit'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share'

            $result.Count | Should -Be 2
            $result[0].Type | Should -Be 'NEEDLE'
            $result[0].LogName | Should -Be 'Security'
            $result[0].EventID | Should -Be '4624'
            $result[0].XPathFilter | Should -Be '*[System[(EventID=4624)]]'
            $result[0].Label | Should -Be 'LoginHit'
            $result[0].Source | Should -Be 'share'

            $result[1].LogName | Should -Be 'System'
            $result[1].EventID | Should -Be '6005'
            $result[1].XPathFilter | Should -Be ''
            $result[1].Label | Should -Be 'BootHit'
        }

        It 'skips comments blanks invalid formats and malformed NEEDLE entries with warnings' {
            @(
                ''
                '# comment'
                'version:1.0.0'
                'BAD|foo|bar'
                'NEEDLE|System|42|Only4Fields'
                'NEEDLE|System|abc||NonNumeric'
                'NEEDLE||42||EmptyLog'
                'NEEDLE|System|||EmptyEvent'
                'NEEDLE|System|42||'
                'NEEDLE|System|42||Label With Space'
                'NEEDLE|System|42||Label\Slash'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share'

            @($result).Count | Should -Be 0
            ($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' }).Count | Should -BeGreaterThan 0
            ($script:LogBuffer.Message -join ' ') | Should -Match 'unrecognized format'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'expected 5 pipe-delimited fields'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'is not numeric'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'LogName is empty'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'EventID is empty'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'Label is empty'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'contains invalid characters'
        }

        It 'returns empty array when file is missing' {
            $missing = Join-Path $TestDrive 'missing.cfg'
            $result = Read-NeedleFile -Path $missing -SourceTag 'share'
            @($result).Count | Should -Be 0
        }

        It 'logs parsed count for multiple valid NEEDLEs' {
            @(
                'NEEDLE|Application|1000||AppHit'
                'NEEDLE|System|6008||ShutdownHit'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $null = Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'Parsed 2 needle\(s\)'
        }
    }

    Context 'SESSION type' {
        It 'parses valid SESSION and accepts all valid StateChange values' {
            @(
                'SESSION|SessionLock|LockHit'
                'SESSION|SessionUnlock|UnlockHit'
                'SESSION|RemoteConnect|RemoteConnectHit'
                'SESSION|RemoteDisconnect|RemoteDisconnectHit'
                'SESSION|ConsoleConnect|ConsoleConnectHit'
                'SESSION|ConsoleDisconnect|ConsoleDisconnectHit'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'local'

            $result.Count | Should -Be 6
            ($result | ForEach-Object StateChange) | Should -Be @(
                'SessionLock','SessionUnlock','RemoteConnect','RemoteDisconnect','ConsoleConnect','ConsoleDisconnect'
            )
            ($result | ForEach-Object Type | Select-Object -Unique) | Should -Be 'SESSION'
            ($result | ForEach-Object Source | Select-Object -Unique) | Should -Be 'local'
        }

        It 'skips invalid SESSION lines with warnings and supports mixed NEEDLE plus SESSION' {
            @(
                'SESSION|BadState|BadStateHit'
                'SESSION|SessionLock'
                'SESSION||EmptyState'
                'SESSION|SessionUnlock|'
                'SESSION|SessionLock|Bad Label'
                'NEEDLE|System|6005||BootHit'
                'SESSION|SessionUnlock|UnlockHit'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share'

            $result.Count | Should -Be 2
            ($result.Type | Sort-Object) | Should -Be @('NEEDLE','SESSION')
            ($script:LogBuffer.Message -join ' ') | Should -Match 'SESSION StateChange'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'expected 3 pipe-delimited fields'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'SESSION Label is empty'
            ($script:LogBuffer.Message -join ' ') | Should -Match 'contains invalid characters'
        }
    }
}

Describe 'Merge-Needles' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }
    }

    It 'merges with local winning collisions and includes local-only/share-only needles' {
        $local = @(
            [pscustomobject]@{ Type='NEEDLE'; Label='Common'; Source='local' },
            [pscustomobject]@{ Type='SESSION'; Label='LocalOnly'; Source='local'; StateChange='SessionUnlock' }
        )
        $share = @(
            [pscustomobject]@{ Type='NEEDLE'; Label='Common'; Source='share' },
            [pscustomobject]@{ Type='NEEDLE'; Label='ShareOnly'; Source='share' }
        )

        $merged = Merge-Needles -ShareNeedles $share -LocalNeedles $local

        $merged.Count | Should -Be 3
        ($merged | Where-Object Label -eq 'Common').Source | Should -Be 'local'
        ($merged.Label -contains 'LocalOnly') | Should -BeTrue
        ($merged.Label -contains 'ShareOnly') | Should -BeTrue
    }

    It 'keeps first duplicate in local and share lists and logs collision count' {
        $local = @(
            [pscustomobject]@{ Type='NEEDLE'; Label='DupL'; Source='local' },
            [pscustomobject]@{ Type='NEEDLE'; Label='DupL'; Source='local' }
        )
        $share = @(
            [pscustomobject]@{ Type='NEEDLE'; Label='DupS'; Source='share' },
            [pscustomobject]@{ Type='NEEDLE'; Label='DupS'; Source='share' }
        )

        $merged = Merge-Needles -ShareNeedles $share -LocalNeedles $local

        $merged.Count | Should -Be 2
        @($merged | Where-Object Label -eq 'DupL').Count | Should -Be 1
        @($merged | Where-Object Label -eq 'DupS').Count | Should -Be 1
        ($script:LogBuffer.Message -join ' ') | Should -Match 'Duplicate label.*local'
        ($script:LogBuffer.Message -join ' ') | Should -Match 'Duplicate label.*share'
        ($script:LogBuffer.Message -join ' ') | Should -Match '2 collision\(s\) resolved'
    }

    It 'handles empty lists combinations' {
        $shareOnly = @([pscustomobject]@{ Type='NEEDLE'; Label='S1'; Source='share' })
        $localOnly = @([pscustomobject]@{ Type='SESSION'; Label='L1'; Source='local'; StateChange='SessionLock' })

        @(Merge-Needles -ShareNeedles $shareOnly -LocalNeedles @()).Count | Should -Be 1
        @(Merge-Needles -ShareNeedles @() -LocalNeedles $localOnly).Count | Should -Be 1
        @(Merge-Needles -ShareNeedles @() -LocalNeedles @()).Count | Should -Be 0
    }
}

Describe 'Build-EventTriggerXml' {
    It 'uses custom XPath as-is and embeds escaped QueryList in subscription' {
        $needle = [pscustomobject]@{ Type='NEEDLE'; LogName='Security'; EventID='4624'; XPathFilter='*[System[(EventID=4624) and (Level=0)]]'; Label='LogonTest' }
        $xml = Build-EventTriggerXml -Needle $needle

        $xml | Should -Match '<EventTrigger id="HayStack_LogonTest">'
        $xml | Should -Match '<Enabled>true</Enabled>'
        $xml | Should -Match '<Subscription>&lt;QueryList&gt;'
        $xml | Should -Match 'Path=&quot;Security&quot;'
        $xml | Should -Match '\*\[System\[\(EventID=4624\) and \(Level=0\)\]\]'
    }

    It 'falls back to bare EventID XPath when filter is empty' {
        $needle = [pscustomobject]@{ Type='NEEDLE'; LogName='System'; EventID='6005'; XPathFilter=''; Label='BootEvent' }
        $xml = Build-EventTriggerXml -Needle $needle

        $xml | Should -Match '\*\[System\[EventID=6005\]\]'
        $xml | Should -Match 'Query Id=&quot;0&quot; Path=&quot;System&quot;'
        $xml | Should -Match 'Select Path=&quot;System&quot;'
    }
}

Describe 'Build-SessionTriggerXml' {
    It 'builds session state change trigger XML without subscription/event trigger blocks' {
        $needle = [pscustomobject]@{ Type='SESSION'; StateChange='SessionUnlock'; Label='UnlockTest' }
        $xml = Build-SessionTriggerXml -Needle $needle

        $xml | Should -Match '<SessionStateChangeTrigger id="HayStack_UnlockTest">'
        $xml | Should -Match '<Enabled>true</Enabled>'
        $xml | Should -Match '<StateChange>SessionUnlock</StateChange>'
        $xml | Should -Not -Match '<Subscription>'
        $xml | Should -Not -Match '<EventTrigger'
    }

    It 'supports another valid state change value' {
        $needle = [pscustomobject]@{ Type='SESSION'; StateChange='ConsoleDisconnect'; Label='ConsoleDisc' }
        (Build-SessionTriggerXml -Needle $needle) | Should -Match '<StateChange>ConsoleDisconnect</StateChange>'
    }
}

Describe 'Build-HaystackTaskXml' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }
    }

    It 'returns null and logs warning for empty needle list' {
        $xml = Build-HaystackTaskXml -Needles @()
        $xml | Should -BeNullOrEmpty
        ($script:LogBuffer.Message -join ' ') | Should -Match 'merged needle list is empty'
    }

    It 'builds full task XML with event and session triggers and expected settings' {
        $needles = @(
            [pscustomobject]@{ Type='NEEDLE'; LogName='System'; EventID='6005'; XPathFilter=''; Label='BootNeedle'; Source='share' },
            [pscustomobject]@{ Type='SESSION'; StateChange='SessionUnlock'; Label='UnlockNeedle'; Source='local' }
        )

        $xml = Build-HaystackTaskXml -Needles $needles

        $xml | Should -Match '^<\?xml version="1\.0"'
        $xml | Should -Match '<EventTrigger id="HayStack_BootNeedle">'
        $xml | Should -Match '<SessionStateChangeTrigger id="HayStack_UnlockNeedle">'
        $xml | Should -Match '<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
        $xml | Should -Match '<ExecutionTimeLimit>PT2M</ExecutionTimeLimit>'
        $xml | Should -Match '<UserId>S-1-5-18</UserId>'
        $xml | Should -Match '<Hidden>true</Hidden>'
        $xml | Should -Match '<Description>HayStack Event Monitor - CPR subsystem v1\.0\.0\. 2 needle\(s\) active\.'
    }

    It 'routes NEEDLE-only lists to EventTrigger XML' {
        $needles = @(
            [pscustomobject]@{ Type='NEEDLE'; LogName='System'; EventID='6005'; XPathFilter=''; Label='BootNeedle'; Source='share' }
        )
        $xml = Build-HaystackTaskXml -Needles $needles
        $xml | Should -Match '<EventTrigger'
        $xml | Should -Not -Match '<SessionStateChangeTrigger'
    }

    It 'routes SESSION-only lists to SessionStateChangeTrigger XML' {
        $needles = @(
            [pscustomobject]@{ Type='SESSION'; StateChange='SessionUnlock'; Label='UnlockNeedle'; Source='local' }
        )
        $xml = Build-HaystackTaskXml -Needles $needles
        $xml | Should -Match '<SessionStateChangeTrigger'
        $xml | Should -Not -Match '<EventTrigger'
    }
}

Describe 'Test-RerollNeeded' {
    BeforeEach {
        $script:HaystackRerollCooldownMinutes = 60
        Remove-Item -Path $script:RerollStampFile -ErrorAction SilentlyContinue
        Remove-Item -Path $script:LocalNeedlesFile_Local -ErrorAction SilentlyContinue

        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }
    }

    It 'returns true when stamp file does not exist' {
        (Test-RerollNeeded) | Should -BeTrue
    }

    It 'returns false when within cooldown and local cfg unchanged' {
        @{ LastReroll=(Get-Date).ToString('o'); LocalCfgMtime=$null } | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8
        (Test-RerollNeeded) | Should -BeFalse
    }

    It 'returns true when cooldown has elapsed' {
        @{ LastReroll=(Get-Date).AddMinutes(-120).ToString('o'); LocalCfgMtime=$null } | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8
        (Test-RerollNeeded) | Should -BeTrue
    }

    It 'returns true when local cfg mtime changed since stamp' {
        'SESSION|SessionUnlock|UnlockHit' | Set-Content -Path $script:LocalNeedlesFile_Local -Encoding UTF8
        $oldMtime = (Get-Item $script:LocalNeedlesFile_Local).LastWriteTime.AddMinutes(-10).ToString('o')
        @{ LastReroll=(Get-Date).ToString('o'); LocalCfgMtime=$oldMtime } | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8
        (Test-RerollNeeded) | Should -BeTrue
    }

    It 'returns true when local cfg existed at last reroll but is now missing' {
        @{ LastReroll=(Get-Date).ToString('o'); LocalCfgMtime=(Get-Date).AddMinutes(-1).ToString('o') } | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8
        (Test-RerollNeeded) | Should -BeTrue
    }

    It 'respects cooldown when local cfg absent both before and now' {
        @{ LastReroll=(Get-Date).ToString('o'); LocalCfgMtime=$null } | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8
        (Test-RerollNeeded) | Should -BeFalse
    }

    It 'returns true when stamp is corrupt or unreadable' {
        'not-json' | Set-Content -Path $script:RerollStampFile -Encoding UTF8
        (Test-RerollNeeded) | Should -BeTrue
        ($script:LogBuffer.Message -join ' ') | Should -Match 'reroll'
    }
}

Describe 'Invoke-HaystackReroll' {
    BeforeEach {
        $script:LogBuffer = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }

        Set-Content -Path $script:ActionScriptPath -Value '# action stub' -Encoding UTF8
        Set-Content -Path $script:LocalNeedlesFile -Value 'NEEDLE|System|6005||BootHit' -Encoding UTF8
        Remove-Item -Path $script:LocalNeedlesFile_Local -ErrorAction SilentlyContinue

        Mock Get-ScheduledTask { $null }
        Mock Unregister-ScheduledTask { }
        Mock Register-ScheduledTask { }
    }

    Context '-reroll cooldown behavior' {
        It 'skips registration during active cooldown with no local cfg change' {
            @{ LastReroll=(Get-Date).ToString('o'); LocalCfgMtime=$null } | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8

            Invoke-HaystackReroll

            Should -Invoke Register-ScheduledTask -Times 0 -Exactly
            ($script:LogBuffer.Message -join ' ') | Should -Match 'cooldown active'
        }

        It 'registers task after cooldown elapsed' {
            @{ LastReroll=(Get-Date).AddMinutes(-120).ToString('o'); LocalCfgMtime=$null } | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8

            Invoke-HaystackReroll

            Should -Invoke Register-ScheduledTask -Times 1 -Exactly
        }
    }

    Context '-reroll -Force behavior' {
        It 'bypasses cooldown check, logs force message, and updates stamp' {
            $initialStamp = @{ LastReroll=(Get-Date).AddHours(-1).ToString('o'); LocalCfgMtime=$null }
            $initialStamp | ConvertTo-Json | Set-Content -Path $script:RerollStampFile -Encoding UTF8
            $before = (Get-Content -Path $script:RerollStampFile -Raw | ConvertFrom-Json).LastReroll

            Mock Test-RerollNeeded { $false }

            Invoke-HaystackReroll -Force

            Should -Invoke Test-RerollNeeded -Times 0 -Exactly
            Should -Invoke Register-ScheduledTask -Times 1 -Exactly
            ($script:LogBuffer.Message -join ' ') | Should -Match 'Force flag set - bypassing cooldown check'

            Test-Path $script:RerollStampFile | Should -BeTrue
            $after = (Get-Content -Path $script:RerollStampFile -Raw | ConvertFrom-Json).LastReroll
            $after | Should -Not -Be $before
        }

        It 'works with force when no stamp exists' {
            Remove-Item -Path $script:RerollStampFile -ErrorAction SilentlyContinue

            Invoke-HaystackReroll -Force

            Should -Invoke Register-ScheduledTask -Times 1 -Exactly
            Test-Path $script:RerollStampFile | Should -BeTrue
        }
    }
}
