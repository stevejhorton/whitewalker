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
    if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) {
        function Write-TeeLog { param([string]$Tag, [hashtable]$Data) }
    }

    $script:HaystackVersion = '1.0.0'
    $script:HaystackRerollCooldownMinutes = 60
    $script:HeartbeatIntervalMinutes = 30
    $script:HeartbeatRandomDelayMinutes = 10
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
            $result[0].ExtendedLogging | Should -Be '0'
            $result[0].Source | Should -Be 'share'

            $result[1].LogName | Should -Be 'System'
            $result[1].EventID | Should -Be '6005'
            $result[1].XPathFilter | Should -Be ''
            $result[1].Label | Should -Be 'BootHit'
            $result[1].ExtendedLogging | Should -Be '0'
        }

        It 'parses optional 6th NEEDLE field for extended logging and remains backward compatible' {
            @(
                'NEEDLE|Application|10000||Network_Connected|1'
                'NEEDLE|System|42||BasicHit|0'
                'NEEDLE|Security|4624||DefaultHit'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share'

            $result.Count | Should -Be 3
            $result[0].ExtendedLogging | Should -Be '1'
            $result[1].ExtendedLogging | Should -Be '0'
            $result[2].ExtendedLogging | Should -Be '0'
        }

        It 'accepts all/2 extended logging values and defaults invalid values to 0 with warning' {
            @(
                'NEEDLE|Application|10000||FullByWord|ALL'
                'NEEDLE|System|42||FullByNumber|2'
                'NEEDLE|Security|4624||InvalidMode|banana'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share'

            $result.Count | Should -Be 3
            $result[0].ExtendedLogging | Should -Be 'all'
            $result[1].ExtendedLogging | Should -Be '2'
            $result[2].ExtendedLogging | Should -Be '0'
            ($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match 'ExtendedLogging' }).Count | Should -BeGreaterThan 0
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
            ($script:LogBuffer.Message -join ' ') | Should -Match 'expected 5 or 6 pipe-delimited fields'
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

    Context 'DEFENDER type' {
        It 'parses a valid DEFENDER line with interval and extended logging' {
            'DEFENDER|V2 - MsWebView2 Any Out|6|WebView2_FW_Allow|all' |
                Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = @(Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'local')

            $result.Count | Should -Be 1
            $result[0].Type | Should -Be 'DEFENDER'
            $result[0].RuleNameMatch | Should -Be 'V2 - MsWebView2 Any Out'
            $result[0].IntervalHours | Should -Be 6
            $result[0].Label | Should -Be 'WebView2_FW_Allow'
            $result[0].ExtendedLogging | Should -Be 'all'
            $result[0].Source | Should -Be 'local'
        }

        It 'uses a null interval for empty or invalid values so the action default applies' {
            @(
                'DEFENDER|Rule One||EmptyInterval|1'
                'DEFENDER|Rule Two|banana|InvalidInterval|2'
                'DEFENDER|Rule Three|999999999999999999999|HugeInterval'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = @(Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share')

            $result.Count | Should -Be 3
            @($result | Where-Object { $null -ne $_.IntervalHours }).Count | Should -Be 0
            ($script:LogBuffer.Message -join ' ') | Should -Match 'IntervalHours'
        }

        It 'skips missing required fields and labels with invalid characters' {
            @(
                'DEFENDER|OnlyThree|6'
                'DEFENDER||6|EmptyRule'
                'DEFENDER|Some Rule|6|'
                'DEFENDER|Some Rule|6|Bad Label'
                'DEFENDER|Some Rule|6|Bad/Label'
            ) | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

            $result = @(Read-NeedleFile -Path $script:LocalNeedlesFile -SourceTag 'share')

            $result.Count | Should -Be 0
            ($script:LogBuffer.Message -join ' ') | Should -Match 'DEFENDER'
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

Describe 'Build-HeartbeatTriggerXml' {
    It 'builds a TimeTrigger with the configured repetition interval' {
        $start = Get-Date '2026-01-01T08:00:00'
        $xml = Build-HeartbeatTriggerXml -StartBoundary $start -IntervalMinutes 30
        $xml | Should -Match '<TimeTrigger id="HayStack_Heartbeat">'
        $xml | Should -Match '<StartBoundary>2026-01-01T08:00:00</StartBoundary>'
        $xml | Should -Match '<Interval>PT30M</Interval>'
        $xml | Should -Match '<StopAtDurationEnd>false</StopAtDurationEnd>'
    }

    It 'reflects a different configured interval' {
        $start = Get-Date '2026-01-01T08:00:00'
        $xml = Build-HeartbeatTriggerXml -StartBoundary $start -IntervalMinutes 15
        $xml | Should -Match '<Interval>PT15M</Interval>'
    }

    It 'emits RandomDelay when a jitter window is configured' {
        $start = Get-Date '2026-01-01T08:00:00'
        $xml = Build-HeartbeatTriggerXml -StartBoundary $start -IntervalMinutes 30 -RandomDelayMinutes 10
        $xml | Should -Match '<RandomDelay>PT10M</RandomDelay>'
    }

    It 'places RandomDelay as a direct child of TimeTrigger, not inside Repetition' {
        $start = Get-Date '2026-01-01T08:00:00'
        $xml = Build-HeartbeatTriggerXml -StartBoundary $start -IntervalMinutes 30 -RandomDelayMinutes 5
        $xml | Should -Match '(?s)</Repetition>\s*<RandomDelay>PT5M</RandomDelay>\s*</TimeTrigger>'
        [xml]$doc = $xml
        $doc.TimeTrigger.RandomDelay | Should -Be 'PT5M'
        $doc.TimeTrigger.Repetition.RandomDelay | Should -BeNullOrEmpty
    }

    It 'omits RandomDelay entirely when the jitter window is 0' {
        $start = Get-Date '2026-01-01T08:00:00'
        $xml = Build-HeartbeatTriggerXml -StartBoundary $start -IntervalMinutes 30 -RandomDelayMinutes 0
        $xml | Should -Not -Match 'RandomDelay'
    }

    It 'omits RandomDelay when the parameter is not supplied (backward compatible)' {
        $start = Get-Date '2026-01-01T08:00:00'
        $xml = Build-HeartbeatTriggerXml -StartBoundary $start -IntervalMinutes 30
        $xml | Should -Not -Match 'RandomDelay'
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
        $xml | Should -Match '<TimeTrigger id="HayStack_Heartbeat">'
        $xml | Should -Match '<Interval>PT30M</Interval>'
        $xml | Should -Match '<RandomDelay>PT10M</RandomDelay>'
        $xml | Should -Match '<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
        $xml | Should -Match '<ExecutionTimeLimit>PT2M</ExecutionTimeLimit>'
        $xml | Should -Match '<UserId>S-1-5-18</UserId>'
        $xml | Should -Match '<Hidden>true</Hidden>'
        $xml | Should -Match '<Description>HayStack Event Monitor - CPR subsystem v1\.0\.0\. 2 trigger\(s\), 0 Defender check\(s\) active\.'
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

    It 'excludes DEFENDER directives from trigger XML while retaining the heartbeat' {
        $needles = @(
            [pscustomobject]@{ Type='NEEDLE'; LogName='System'; EventID='6005'; XPathFilter=''; Label='BootNeedle'; Source='share' },
            [pscustomobject]@{ Type='DEFENDER'; RuleNameMatch='WebView2'; IntervalHours=6; Label='WebView2_FW_Allow'; Source='local' }
        )

        $xml = Build-HaystackTaskXml -Needles $needles

        $xml | Should -Match '<EventTrigger id="HayStack_BootNeedle">'
        $xml | Should -Match '<TimeTrigger id="HayStack_Heartbeat">'
        $xml | Should -Not -Match 'HayStack_WebView2_FW_Allow'
        $xml | Should -Match '1 trigger\(s\), 1 Defender check\(s\) active'
    }

    It 'supports DEFENDER-only lists with only the heartbeat trigger' {
        $needle = [pscustomobject]@{ Type='DEFENDER'; RuleNameMatch='WebView2'; IntervalHours=$null; Label='WebView2_FW_Allow'; Source='local' }

        $xml = Build-HaystackTaskXml -Needles @($needle)

        $xml | Should -Match '<TimeTrigger id="HayStack_Heartbeat">'
        $xml | Should -Not -Match '<EventTrigger'
        $xml | Should -Not -Match '<SessionStateChangeTrigger'
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
        Mock Write-TeeLog { }

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

        It 'emits skipped telemetry when reroll is not needed' {
            Mock Test-RerollNeeded { $false }

            Invoke-HaystackReroll

            Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
                $Tag -eq 'haystack_reroll_result' -and
                $Data.result -eq 'skipped' -and
                $Data.reason -eq 'no_reroll_needed'
            }
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

        It 'emits success telemetry with needle count on force reroll success' {
            Invoke-HaystackReroll -Force

            Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
                $Tag -eq 'haystack_reroll_result' -and
                $Data.result -eq 'success' -and
                $Data.needle_count -eq 1 -and
                $Data.reason -eq 'task_registered'
            }
        }
    }
}
