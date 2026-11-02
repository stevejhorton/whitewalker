# WW_cap_portal_runner_base.Tests.ps1

Describe "WW_cap_portal_runner_base.ps1 - HayStack Queue Payload" {
    It "Should include network_state_change and captive_portal_detected fields" {
        $payload = 'action="network_state_change" machine="TESTPC" ts="2026-01-01T00:00:00.0000000Z" reason="captive_portal_detected" ip="10.1.2.3" fqdn="portal.example.com" protocol="https" port="443"'

        $payload | Should -Match 'action="network_state_change"'
        $payload | Should -Match 'reason="captive_portal_detected"'
        $payload | Should -Match 'ip="10\.1\.2\.3"'
        $payload | Should -Match 'fqdn="portal\.example\.com"'
        $payload | Should -Match 'protocol="https"'
        $payload | Should -Match 'port="443"'
    }

    It "Should queue JSONL entries with ts/payload/extraInfo" {
        $entry = @{
            ts = (Get-Date).ToString('o')
            payload = 'action="network_state_change" machine="TESTPC" ts="2026-01-01T00:00:00.0000000Z" reason="captive_portal_detected" ip="10.1.2.3" fqdn="portal.example.com" protocol="https" port="443"'
            extraInfo = ''
        }

        $entry.Keys | Should -Contain 'ts'
        $entry.Keys | Should -Contain 'payload'
        $entry.Keys | Should -Contain 'extraInfo'
    }

    It "Should handle missing portal context with unknown defaults" {
        $payload = 'action="network_state_change" machine="TESTPC" ts="2026-01-01T00:00:00.0000000Z" reason="captive_portal_detected" ip="unknown" fqdn="unknown" protocol="unknown" port="0"'

        $payload | Should -Match 'ip="unknown"'
        $payload | Should -Match 'fqdn="unknown"'
        $payload | Should -Match 'protocol="unknown"'
        $payload | Should -Match 'port="0"'
    }
}

# =============================================================================
# Write-BaseCapOutcomeTelemetry - cap_portal_remediation_passed/failed via Write-TeeLog
# =============================================================================
Describe "WW_cap_portal_runner_base.ps1 - Write-TeeLog outcome telemetry" {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot 'WW_cap_portal_runner_base.ps1'
        $errors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Failed to parse WW_cap_portal_runner_base.ps1" }

        $wanted = @('Write-BaseCapLog', 'Write-BaseCapTee', 'Write-BaseCapOutcomeTelemetry')
        $functionAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $wanted -contains $node.Name
        }, $true)

        $functionSource = ($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n"
        Invoke-Expression $functionSource

        # Dot-sourcing WW_tee.ps1 is done at the top of the real script (hardcoded
        # C:\ProgramData\WhiteWalker path, same pattern as WW_main.ps1) - stub it
        # here so these are pure unit tests of the wiring, not an integration test
        # of the real tee engine.
        function Write-TeeLog { param([string]$Tag, [hashtable]$Data, [switch]$PassThru) }

        # Confirm the script still contains both the dot-source line and the
        # hardcoded Haystack/Tee globals required for Write-TeeLog to fire when
        # this script runs standalone in USER context.
        $script:rawSource = Get-Content -Path $scriptPath -Raw
    }

    BeforeEach {
        Mock Write-TeeLog {}
    }

    It "declares the WW_tee.ps1 dot-source and hardcoded Haystack/Tee globals" {
        $script:rawSource | Should -Match '\$global:HaystackEnabled\s*=\s*\$true'
        $script:rawSource | Should -Match '\$global:TeeEnabled\s*=\s*\$true'
        $script:rawSource | Should -Match '\$global:TeeEventsFile\s*='
        $script:rawSource | Should -Match '\.\s*"C:\\ProgramData\\WhiteWalker\\WW_tee\.ps1"'
    }

    It "still contains Write-CaptivePortalEventToHayStack and Write-CompletionFlag calls in SUCCESS_NATIVE branch" {
        $script:rawSource | Should -Match 'Write-CaptivePortalEventToHayStack -IP \$portalIP'
        $script:rawSource | Should -Match 'Write-CompletionFlag -Status "SUCCESS_NATIVE"'
    }

    It "still contains Write-CompletionFlag call in TIMEOUT_NATIVE branch" {
        # The status is chosen into $timeoutStatus (TIMEOUT_NATIVE when full escalation is allowed).
        $script:rawSource | Should -Match "'TIMEOUT_NATIVE'"
        $script:rawSource | Should -Match 'Write-CompletionFlag -Status \$timeoutStatus'
    }

    It "calls Write-TeeLog 'cap_portal_remediation_passed' with expected field shape on SUCCESS_NATIVE" {
        Write-BaseCapOutcomeTelemetry -Action 'cap_portal_remediation_passed' `
            -Url 'http://portal.example.com' -Port '80' -PortalType 'walled_garden' `
            -Status 'verified' -Reason 'native_resolution' -Ssid 'TestSSID' -VpnState 'Disconnected'

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            $Tag -eq 'cap_portal_remediation_passed' -and
            $Data.url -eq 'http://portal.example.com' -and
            $Data.port -eq '80' -and
            $Data.portal_type -eq 'walled_garden' -and
            $Data.status -eq 'verified' -and
            $Data.reason -eq 'native_resolution' -and
            $Data.ssid -eq 'TestSSID' -and
            $Data.vpn_state -eq 'Disconnected'
        }
    }

    It "calls Write-TeeLog 'cap_portal_remediation_failed' with expected field shape on TIMEOUT_NATIVE" {
        Write-BaseCapOutcomeTelemetry -Action 'cap_portal_remediation_failed' `
            -Url 'http://portal.example.com' -Port '80' -PortalType 'walled_garden' `
            -Status 'timeout' -Reason 'native_timeout_escalated' -Ssid 'TestSSID' -VpnState 'Connected'

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            $Tag -eq 'cap_portal_remediation_failed' -and
            $Data.status -eq 'timeout' -and
            $Data.reason -eq 'native_timeout_escalated'
        }
    }

    It "never throws when Write-TeeLog fails (fails safe, same try/catch style as rest of file)" {
        Mock Write-TeeLog { throw "simulated tee failure" }
        Mock Write-BaseCapLog {}

        { Write-BaseCapOutcomeTelemetry -Action 'cap_portal_remediation_failed' -Status 'timeout' -Reason 'native_timeout_escalated' } | Should -Not -Throw

        Should -Invoke Write-BaseCapLog -ParameterFilter { $Level -eq 'WARN' }
    }
}

# =============================================================================
# RC1.25 - self-gathered context, local EvtTime, legacy/normalized separation
# =============================================================================
Describe "WW_cap_portal_runner_base.ps1 RC1.25 - normalized telemetry context" {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot 'WW_cap_portal_runner_base.ps1'
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
        if ($errors) { throw "Failed to parse WW_cap_portal_runner_base.ps1" }

        $wanted = @('Write-BaseCapLog', 'Write-BaseCapTee', 'Write-BaseCapOutcomeTelemetry', 'Get-BaseCapTelemetryUrl')
        $functionAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $wanted -contains $node.Name
        }, $true)

        Invoke-Expression (($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n")

        function Write-TeeLog { param([string]$Tag, [hashtable]$Data, [switch]$PassThru) }

        $script:rawSource = Get-Content -Path $scriptPath -Raw
    }

    Describe "WW_cap_portal_runner_base.ps1 - Cisco WebHelper Event 301" {
        BeforeAll {
            $scriptPath = Join-Path $PSScriptRoot 'WW_cap_portal_runner_base.ps1'
            $errors = $null
            $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
            if ($errors) { throw "Failed to parse WW_cap_portal_runner_base.ps1" }
            $wanted = @('Write-BaseCapLog', 'Get-CiscoWebHelperQueryParameter',
                'Get-CiscoWebHelperFinalUrlPort', 'ConvertFrom-CiscoWebHelperNavigationBody',
                'Get-CiscoWebHelperNavigationEvent', 'Get-CiscoWebHelperQueryParameterAny',
                'ConvertFrom-CiscoWebHelperEventText', 'Get-CiscoWebHelperUrlFromText', 'Get-CiscoWebHelperDedupeKey')
            $functionAsts = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $wanted -contains $node.Name
            }, $true)
            Invoke-Expression (($functionAsts | ForEach-Object { $_.Extent.Text }) -join "`n`n")
            $script:CiscoWebHelperLogName = 'Cisco Secure Client'
            $script:CiscoWebHelperEventId = 301
            $global:CiscoWebHelperLogName = 'Cisco Secure Client'
            $global:CiscoWebHelperEventId = 301
            function Write-BaseCapLog { param([string]$Message, [string]$Level = "INFO") }
            function Get-WinEvent { param($FilterHashtable, $MaxEvents) }
            $script:rawSource = Get-Content -Path $scriptPath -Raw
            $script:fixture = @"
    [TID=18860 PID=176] | Function: CWebView2BrowserControl::navigationEndingHandler::<lambda_9e8a94e4c11feb3120a49d8561205e0b>::operator () | File: E:\dev\workspace\cure-client-windows_Raccoon_MR17\vpn\WebHelper\Windows\WebView2BrowserControl.cpp | Line: 1019 | primary control navigated successfully to URL 'https://secure.guestinternet.com/portal-system/portal/?api_domain=https%3a%2f%2fsecure.11os.com&ap_name=HLT-CHSSU-76-PATIO-AP001&ap_tags=11os%3asite%3aHF-789-57+HiltonHonors&UI=KH-850-48&MA=f4%3aaa4%3a75%3aaa8%3a95%3a2b&login_url=https%3a%2f%2fna.network-auth.com%2fsplash%2fgxIt2cNf.0.359%2flogin%3fcontinue_url%3dhttp%25253A%25252F%25252Fwww.msftconnecttest.com%25252Fconnecttest.txt%26mauth%3dqkVFcQKJ6rmNn3Gz&ap_mac=e4%3a55%3aa8%3a2a%3a8f%3a92&ORG=KH-850-48&SIP=10.234.35.31&PSID=34c3839a-b709-4cd0-8cbd-868c66157637&OS=http%3a%2f%2fwww.msftconnecttest.com%2fconnecttest.txt'. Final URL 'http://www.msftconnecttest.com:80/connecttest.txt'.
"@
        }

        It "decodes the complete real navigation fixture" {
            $result = ConvertFrom-CiscoWebHelperNavigationBody $script:fixture
            $result.Parsed | Should -BeTrue
            $result.ProcessId | Should -Be '176'; $result.ThreadId | Should -Be '18860'
            $result.FinalUrl | Should -Be 'http://www.msftconnecttest.com:80/connecttest.txt'
            $result.FinalUrlPort | Should -Be 80
            $result.ApName | Should -Be 'HLT-CHSSU-76-PATIO-AP001'
            $result.ApTags | Should -Be '11os:site:HF-789-57+HiltonHonors'
            $result.ApMac | Should -Be 'e4:55:a8:2a:8f:92'; $result.Ma | Should -Be 'f4:aa4:75:aa8:95:2b'
            $result.Sip | Should -Be '10.234.35.31'; $result.Org | Should -Be 'KH-850-48'
            $result.Ui | Should -Be 'KH-850-48'; $result.Psid | Should -Be '34c3839a-b709-4cd0-8cbd-868c66157637'
            $result.LoginUrl | Should -Be 'https://na.network-auth.com/splash/gxIt2cNf.0.359/login?continue_url=http%253A%252F%252Fwww.msftconnecttest.com%252Fconnecttest.txt&mauth=qkVFcQKJ6rmNn3Gz'
            $result.Os | Should -Be 'http://www.msftconnecttest.com/connecttest.txt'
            $result.ApiDomain | Should -Be 'https://secure.11os.com'
        }

        It "fails soft and keeps URL parsing independent of PID/TID" {
            { ConvertFrom-CiscoWebHelperNavigationBody "navigated successfully to URL 'https://example.test/?x=1'. Final URL 'https://example.test/'" } | Should -Not -Throw
            $result = ConvertFrom-CiscoWebHelperNavigationBody "navigated successfully to URL 'https://example.test/?x=1'. Final URL 'https://example.test/'"
            $result.Parsed | Should -BeTrue; $result.ProcessId | Should -Be ''; $result.ThreadId | Should -Be ''
            $empty = ConvertFrom-CiscoWebHelperNavigationBody ''
            $empty.Parsed | Should -BeFalse; $empty.NavigatedUrl | Should -Be ''; $empty.FinalUrlPort | Should -Be 0
        }

        It "decodes query values without converting plus to space" {
            Get-CiscoWebHelperQueryParameter 'https://x.test/?ap_tags=a%3ab+c' 'ap_tags' | Should -Be 'a:b+c'
            Get-CiscoWebHelperQueryParameter '' 'x' | Should -Be ''
            Get-CiscoWebHelperQueryParameter 'https://x.test/?x=1' 'missing' | Should -Be ''
        }

        It "extracts explicit ports including scheme defaults" {
            Get-CiscoWebHelperFinalUrlPort 'http://example.test:8080/' | Should -Be 8080
            Get-CiscoWebHelperFinalUrlPort 'http://example.test:80/' | Should -Be 80
            Get-CiscoWebHelperFinalUrlPort 'http://example.test/' | Should -Be 0
            { Get-CiscoWebHelperFinalUrlPort 'not a URL' } | Should -Not -Throw
        }

        It "reads events from the supplied start time and de-duplicates by event record" {
            $since = [datetime]'2026-10-14T00:00:00Z'
            $event = [pscustomobject]@{ Message = $script:fixture; TimeCreated = $since.AddSeconds(1); RecordId = 101 }
            $global:mockEvents = @($event, $event, [pscustomobject]@{
                Message = $script:fixture -replace 'PID=176', 'PID=177'
                TimeCreated = $since.AddSeconds(2)
                RecordId = 102
            })
            Mock Get-WinEvent { $global:mockEvents }
            $seen = @{}
            $first = Get-CiscoWebHelperNavigationEvent -Since $since -SeenProcessIds $seen
            $first.Found | Should -BeTrue; $first.DedupeKey | Should -Be 'record:102'   # newest record first
            $seen[$first.DedupeKey] = $true
            $second = Get-CiscoWebHelperNavigationEvent -Since $since -SeenProcessIds $seen
            $second.Found | Should -BeTrue; $second.DedupeKey | Should -Be 'record:101'
            Should -Invoke Get-WinEvent -ParameterFilter { $FilterHashtable.StartTime -eq $since }
        }

        It "fails soft when the event log is unavailable or has no matching events" {
            Mock Get-WinEvent { throw 'event log unavailable' }
            $failed = Get-CiscoWebHelperNavigationEvent -Since (Get-Date)
            $failed.Found | Should -BeFalse; $failed.Error | Should -Not -Be ''
            Mock Get-WinEvent { @() }
            $empty = Get-CiscoWebHelperNavigationEvent -Since (Get-Date)
            $empty.Found | Should -BeFalse; $empty.Error | Should -Not -Be ''
        }

        It "has the required top-level scope and log-only wiring" {
            $script:rawSource | Should -Match '(?m)^function Test-BaseCapPreflight'
            $script:rawSource | Should -Match '(?m)^function Test-VPNBlockingNetwork'
            $script:rawSource | Should -Match '(?m)^function Invoke-BaseCapVpnDisconnect'
            $script:rawSource | Should -Match '(?m)^function Get-BaseNativePortalProcesses'
            $script:rawSource | Should -Match '\$seenWebHelperPids\s*=\s*@\{\}'
            $script:rawSource | Should -Match 'Get-CiscoWebHelperNavigationEvent\s+-Since \$webHelperSince[\s`]+-MaxEvents \$BaseWebHelper301MaxRecords\s+-SeenProcessIds \$seenWebHelperPids[\s`]+-SeenRecordIds \$seenWebHelperRecordIds'
            $script:rawSource | Should -Match 'Write-BaseCapWebHelperTelemetry'
        }

        Describe 'WW_cap_portal_runner_base.ps1 Base evidence observations' {
            BeforeAll {
                $scriptPath = Join-Path $PSScriptRoot 'WW_cap_portal_runner_base.ps1'
                $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
                if ($errors) { throw "Failed to parse WW_cap_portal_runner_base.ps1" }
                $wanted = @('Get-BaseCapUrlDetails','Test-BaseCapPreflight','Write-BaseCapPreflightTelemetry','Write-BaseCapWebHelperTelemetry','Get-BaseCapTelemetryUrl','Write-CompletionFlag')
                Invoke-Expression (($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $wanted -contains $node.Name }, $true) | ForEach-Object { $_.Extent.Text }) -join "`n`n")
                function Write-BaseCapLog { param($Message, $Level = 'INFO') }
                function Write-TeeLog { param($Tag, $Data) }
                $script:rawSource = Get-Content $scriptPath -Raw
            }

            BeforeEach { Mock Write-TeeLog {}; Mock Write-BaseCapLog {} }

            It 'observes redirects without auto-following them or taking remediation actions' {
                $script:rawSource | Should -Match 'AllowAutoRedirect\s*=\s*\$false'
                $script:rawSource | Should -Not -Match 'Test-BaseCapPreflight[\s\S]{0,1800}(Start-Process|Stop-Process|disconnect|Start-Job)'
            }

            It 'emits separate structured preflight and WebHelper tags with flat xfinity fields' {
                # Base ships through Write-BaseCapTee (truthful, fail-soft wrapper around Write-TeeLog -PassThru).
                $script:rawSource | Should -Match "Write-BaseCapTee -Tag 'cap_portal_preflight_observation'"
                $script:rawSource | Should -Match "Write-BaseCapTee -Tag 'cap_portal_webhelper_navigation'"
                foreach ($field in @('navigated_url','final_url','ap_name','ap_mac','api_domain','event_time')) {
                    $script:rawSource | Should -Match $field
                }
            }

            It 'selects the telemetry URL in the documented precedence: preflight redirect, Main handoff, WebHelper navigated URL (corroborating only), remediation state URL' {
                $wh = 'https://cp-webapp.wifi.connected.xfinity.com/welcome'
                Get-BaseCapTelemetryUrl -WebHelperNavigatedUrl $wh -PreflightRedirectUrl 'https://preflight.portal/' -MainHandoffRedirectUrl 'https://handoff.portal/' -Url 'http://state.portal/' |
                    Should -Be 'https://preflight.portal/'
                Get-BaseCapTelemetryUrl -WebHelperNavigatedUrl $wh -MainHandoffRedirectUrl 'https://handoff.portal/' -Url 'http://state.portal/' |
                    Should -Be 'https://handoff.portal/'
                Get-BaseCapTelemetryUrl -WebHelperNavigatedUrl $wh -Url 'http://state.portal/' | Should -Be $wh
                Get-BaseCapTelemetryUrl -Url 'http://state.portal/' | Should -Be 'http://state.portal/'
            }

            It 'writes both evidence blocks into the completion artifact' {
                $script:rawSource | Should -Match 'base_preflight_observation'
                $script:rawSource | Should -Match 'base_webhelper_navigation'
                $script:rawSource | Should -Match 'Move-Item -Path \$tempFlag -Destination \$FlagFile'
            }

            It 'emits one final no-observation outcome outside the polling loop' {
                $timeoutIndex = $script:rawSource.IndexOf('if (-not $observed)')
                $timeoutIndex | Should -BeGreaterThan 0
                $missingIndex = $script:rawSource.IndexOf('Get-BaseCapMissingNavigationOutcome', $timeoutIndex)
                $missingIndex | Should -BeGreaterThan $timeoutIndex
                # The outcome token itself comes from the classifier, not a literal in the loop.
                $script:rawSource | Should -Match "Outcome = 'not_observed'"
                $script:rawSource | Should -Match "Outcome = 'not_applicable'"
            }

            It 'registers the observation tags with their exact flat fields in the level 5 profile' {
                . (Join-Path $PSScriptRoot 'WW_set_tee_level.ps1')
                $profile = Get-CprTeeLevelProfile -Level 5 -MasterPath (Join-Path $PSScriptRoot 'WW_tee_master.psd1')
                $profile.Events.cap_portal_preflight_observation.fields | Should -Be @('probe_url','status','http_status','redirect_url','redirect_type','classification','protocol','fqdn','port','duration_ms','attempt','reason','ssid','ip','gw','dns','vpn_state')
                $profile.Events.cap_portal_webhelper_navigation.fields | Should -Contain 'navigated_url'
                $profile.Events.cap_portal_webhelper_navigation.fields | Should -Contain 'api_domain'
                $profile.Events.cap_portal_webhelper_navigation.fields | Should -Contain 'event_time'
            }
        }
    }

    BeforeEach {
        Mock Write-TeeLog {}
        Mock Write-BaseCapLog {}
    }

    It 'stamps EvtTime locally and carries ip/gw/dns on the normalized outcome event' {
        Write-BaseCapOutcomeTelemetry -Action 'cap_portal_remediation_passed' `
            -Url 'http://portal.example.com' -Port '80' -PortalType 'walled_garden' `
            -Status 'verified' -Reason 'native_resolution' -Ssid 'TestSSID' -VpnState 'Disconnected' `
            -Ip '10.20.30.40' -Gw '10.20.30.1' -Dns '10.20.30.1,8.8.8.8'

        Should -Invoke Write-TeeLog -Times 1 -ParameterFilter {
            -not [string]::IsNullOrEmpty($Data.EvtTime) -and
            $Data.ip -eq '10.20.30.40' -and
            $Data.gw -eq '10.20.30.1' -and
            $Data.dns -eq '10.20.30.1,8.8.8.8'
        }
    }

    It 'prefers the url handed over in the remediation state file' {
        Get-BaseCapTelemetryUrl -Url 'http://portal.example.com' -Protocol 'https' -Fqdn 'other.example.com' |
            Should -Be 'http://portal.example.com'
    }

    It 'rebuilds the url from protocol + fqdn when no url was handed over' {
        Get-BaseCapTelemetryUrl -Protocol 'https' -Fqdn 'portal.example.com' |
            Should -Be 'https://portal.example.com'
    }

    It 'returns empty (never a fabricated unknown://unknown) and logs why when the portal URL is unknown' {
        Get-BaseCapTelemetryUrl -Url 'unknown' -Protocol 'unknown' -Fqdn 'unknown' | Should -Be ''
        Should -Invoke Write-BaseCapLog -ParameterFilter { $Level -eq 'WARN' }
    }

    It 'gathers its own network context instead of relying on the parent WW_main.ps1 process' {
        $script:rawSource | Should -Match 'function Get-BaseCapNetworkContext'
        $script:rawSource | Should -Match 'Get-BaseCapNetworkContext'
    }

    It 'tags the legacy HayStack queue event so it cannot be read as a normalized event' {
        $script:rawSource | Should -Match 'event_class="legacy_haystack"'
    }

    It 'stamps the RC1.25 version' {
        $script:rawSource | Should -Match 'RC1\.25'
    }
}
