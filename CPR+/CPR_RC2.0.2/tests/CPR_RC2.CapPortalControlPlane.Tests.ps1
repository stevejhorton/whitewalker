# CPR_RC2.CapPortalControlPlane.Tests.ps1
#
# Regression tests for the captive-portal CONTROL PLANE contract:
#
#   * gateway.optum.com remains authoritative outside the credible active-
#     WebHelper branch (200/404-no-Location = ONLINE, any 2xx/3xx WITH Location
#     = REDIRECT, timeout/DNS/transport = INCONCLUSIVE);
#   * a fresh direct EventID 301 navigated_url may precede/suppress the blocked
#     probe, but never gates the ISE posture rescan;
#   * Main persists the authoritative dispatch context before Event 777/778;
#   * EventID 301 parsing survives real Xfinity messages and escaped variants,
#     keeps multiple navigation stages per PID and de-dupes repeated reads;
#   * canonical URL precedence never substitutes the WebHelper final URL;
#   * telemetry reports queued / tag_not_in_profile / access_denied / error
#     truthfully and stays fail-soft;
#   * XmlVault ignores captive-portal FlareGun events 777/778.
#
# AST-extraction style, per repository convention.

function global:Get-CprFunctionSource {
    param([string]$Path, [string[]]$Names)

    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Failed to parse $Path" }

    $found = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Names -contains $node.Name
    }, $true)

    return (($found | ForEach-Object { $_.Extent.Text }) -join "`n`n")
}

Describe 'Authoritative preflight classification - Main and Base parity' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:root = $root

        function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') }
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') }

        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'main/Main.Network.ps1') `
            -Names @('Get-CapPreflightUrlDetails', 'Resolve-CapPreflightClassification', 'Get-RedirectType'))
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'WW_cap_portal_runner_base.ps1') `
            -Names @('Set-BaseCapPreflightStatus', 'Get-BaseCapUrlDetails', 'Get-BaseCapRedirectType', 'Write-BaseCapPreflightFinding'))

        $script:newResult = {
            param([string]$HttpStatus, [string]$Location)
            [ordered]@{
                observation_time = (Get-Date).ToString('o'); probe_url = 'https://gateway.optum.com'
                status = 'unreachable'; classification = 'INCONCLUSIVE'
                http_status = $HttpStatus; redirect_url = $Location; redirect_type = ''
                protocol = ''; fqdn = ''; port = ''; duration_ms = 0; attempt = 1
                reason = ''; error_message = ''
            }
        }
    }

    It 'treats HTTP 200 with no Location as ONLINE' {
        $main = Resolve-CapPreflightClassification -Result (& $script:newResult '200' '')
        $base = Set-BaseCapPreflightStatus        -Result (& $script:newResult '200' '')

        $main.status | Should -Be 'online'
        $main.classification | Should -Be 'ONLINE'
        $main.reason | Should -Be 'no_redirect'
        $base.status | Should -Be $main.status
        $base.classification | Should -Be $main.classification
    }

    It 'treats HTTP 404 with no Location as ONLINE' {
        $main = Resolve-CapPreflightClassification -Result (& $script:newResult '404' '')
        $base = Set-BaseCapPreflightStatus        -Result (& $script:newResult '404' '')

        $main.classification | Should -Be 'ONLINE'
        $base.classification | Should -Be 'ONLINE'
    }

    It 'treats a 302 with Location as REDIRECT and parses protocol, FQDN and port' {
        $url = 'https://cp-webapp.wifi.connected.xfinity.com:8443/en/welcome_st22/index.html?x=1'
        $main = Resolve-CapPreflightClassification -Result (& $script:newResult '302' $url)

        $main.status | Should -Be 'redirect'
        $main.classification | Should -Be 'REDIRECT'
        $main.reason | Should -Be 'http_3xx_location'
        $main.redirect_url | Should -Be $url
        $main.protocol | Should -Be 'https'
        $main.fqdn | Should -Be 'cp-webapp.wifi.connected.xfinity.com'
        [string]$main.port | Should -Be '8443'
    }

    It "treats ISE's non-standard HTTP 200 WITH Location as REDIRECT in both Main and Base" {
        $url = 'https://isepsn01.uhc.com:8443/portal/gateway?sessionId=abc&portal=employee'
        $main = Resolve-CapPreflightClassification -Result (& $script:newResult '200' $url)
        $base = Set-BaseCapPreflightStatus        -Result (& $script:newResult '200' $url)

        $main.status | Should -Be 'redirect'
        $main.reason | Should -Be 'http_2xx_with_location'
        $base.status | Should -Be 'redirect'
        $base.reason | Should -Be 'http_2xx_with_location'
    }

    It 'classifies an isepsn redirect as ISE_EMPLOYEE with no EventID 301 involved' {
        $url = 'https://isepsn01.uhc.com:8443/portal/gateway?sessionId=abc'
        $result = Resolve-CapPreflightClassification -Result (& $script:newResult '200' $url)

        $result.redirect_type | Should -Be 'ISE_EMPLOYEE'
    }

    It 'classifies an isegst redirect as ISE_GUEST and anything else as NON_ISE' {
        $guest = Resolve-CapPreflightClassification -Result (& $script:newResult '302' 'https://isegst01.uhc.com:8443/portal/guest')
        $other = Resolve-CapPreflightClassification -Result (& $script:newResult '302' 'http://xwifipass.xfinity.com/static/connect?a=1')

        $guest.redirect_type | Should -Be 'ISE_GUEST'
        $other.redirect_type | Should -Be 'NON_ISE'
    }

    It 'treats an unexpected status with no Location as INCONCLUSIVE, never ONLINE' {
        $result = Resolve-CapPreflightClassification -Result (& $script:newResult '503' '')

        $result.status | Should -Be 'unreachable'
        $result.classification | Should -Be 'INCONCLUSIVE'
        $result.status | Should -Not -Be 'online'
    }

    It 'records a timeout/DNS/transport failure as INCONCLUSIVE with the transport_failure reason in both Main and Base' {
        $mainSrc = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.Network.ps1') -Names @('Get-NwCheckResult')
        $baseSrc = Get-CprFunctionSource -Path (Join-Path $script:root 'WW_cap_portal_runner_base.ps1') -Names @('Test-BaseCapPreflight')

        $mainSrc | Should -Match "reason\s*=\s*'transport_failure'"
        $mainSrc | Should -Match "classification\s*=\s*'INCONCLUSIVE'"
        $baseSrc | Should -Match "reason\s*=\s*'transport_failure'"
        $baseSrc | Should -Match "classification\s*=\s*'INCONCLUSIVE'"
    }

    It 'reads the real status and Location out of a WebException response in both Main and Base' {
        $mainSrc = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.Network.ps1') -Names @('Get-NwCheckResult')
        $baseSrc = Get-CprFunctionSource -Path (Join-Path $script:root 'WW_cap_portal_runner_base.ps1') -Names @('Test-BaseCapPreflight')

        foreach ($src in @($mainSrc, $baseSrc)) {
            $src | Should -Match 'catch \[System\.Net\.WebException\]'
            $src | Should -Match "Headers\['Location'\]"
        }
    }

    It 'renders a Base redirect in Main style with classification, protocol, FQDN and port' {
        $script:renderLogs = @()
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') $script:renderLogs += $Message }

        Write-BaseCapPreflightFinding -Observation ([PSCustomObject]@{
            status = 'redirect'; classification = 'REDIRECT'
            redirect_url = 'https://xwifipass.xfinity.com/static/connect?a=1'
            redirect_type = 'NON_ISE'; protocol = 'https'; fqdn = 'xwifipass.xfinity.com'
            port = '443'; http_status = '302'; reason = 'http_3xx_location'; error_message = ''
        })

        ($script:renderLogs -join "`n") | Should -Match 'nwcheck: REDIRECT to https://xwifipass\.xfinity\.com/static/connect'
        ($script:renderLogs -join "`n") | Should -Match 'Redirect classification: NON_ISE'
        ($script:renderLogs -join "`n") | Should -Match 'protocol=https fqdn=xwifipass\.xfinity\.com port=443'
    }

    It 'renders an inconclusive Base preflight as not proof of a clean network' {
        $script:renderLogs = @()
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') $script:renderLogs += $Message }

        Write-BaseCapPreflightFinding -Observation ([PSCustomObject]@{
            status = 'unreachable'; classification = 'INCONCLUSIVE'; redirect_url = ''
            redirect_type = ''; protocol = ''; fqdn = ''; port = ''; http_status = ''
            reason = 'transport_failure'; error_message = 'The operation has timed out'
        })

        ($script:renderLogs -join "`n") | Should -Match 'inconclusive, not proof of a clean network'
        ($script:renderLogs -join "`n") | Should -Match 'The operation has timed out'
    }
}

Describe 'ISE_EMPLOYEE posture rescan does not depend on EventID 301' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:entrySource = Get-Content (Join-Path $root 'main/Main.Entry.ps1') -Raw
        $script:capSource = Get-Content (Join-Path $root 'main/Main.CaptivePortal.ps1') -Raw
    }

    It 'routes an ISE_EMPLOYEE preflight redirect straight into the posture rescan workflow' {
        $script:entrySource | Should -Match "ISE_EMPLOYEE"
        $script:entrySource | Should -Match 'Invoke-PostureRescan'
    }

    It 'never references EventID 301 / WebView2 on the rescan decision path' {
        $iseBlockMatch = [regex]::Match(
            $script:entrySource,
            '"ISE_EMPLOYEE"[\s\S]{0,4000}?Invoke-PostureRescan')
        $iseBlockMatch.Success | Should -BeTrue -Because 'the ISE_EMPLOYEE branch must reach the rescan workflow'
        $iseBlockMatch.Value | Should -Not -Match '301'
        $iseBlockMatch.Value | Should -Not -Match 'WebView'
        $iseBlockMatch.Value | Should -Not -Match 'WebHelper'
    }

    It 'records a missing EventID 301 as not_applicable rather than a failure' {
        $script:capSource | Should -Match 'not_applicable_ise_employee_no_event_301'
        $script:capSource | Should -Match 'optional corroboration only'
    }
}

Describe 'Main dispatch context precedes Event 777/778' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:root = $root
        $script:entrySource = Get-Content (Join-Path $root 'main/Main.Entry.ps1') -Raw
        $script:capSource = Get-Content (Join-Path $root 'main/Main.CaptivePortal.ps1') -Raw
    }

    It 'builds the dispatch context from the authoritative preflight, not from EventID 301' {
        $src = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.CaptivePortal.ps1') -Names @('Get-CapPortalDispatchContext')

        $src | Should -Match '\$global:LastCapPreflightResult'
        foreach ($field in @('run_id', 'correlation_id', 'flare_tag', 'event_id', 'runner_mode', 'probe_url',
                             'redirect_url', 'redirect_type', 'protocol', 'fqdn', 'port',
                             'ssid', 'ip', 'gw', 'dns', 'vpn_state', 'status', 'reason')) {
            $src | Should -Match "(?m)^\s*$field\s+=" -Because "dispatch context must carry $field"
        }
    }

    It 'persists dispatch_context into every state artifact that precedes a 777/778 flare' {
        ([regex]::Matches($script:entrySource, 'dispatch_context')).Count | Should -BeGreaterOrEqual 2
        $script:capSource | Should -Match 'dispatch_context\s*=\s*Get-CapPortalDispatchContext'
    }

    It 'keeps the Windows event message text stable and does not stuff URLs into it' {
        $flareSource = Get-Content (Join-Path $script:root 'main/Main.FlareGun.ps1') -Raw
        $flareSource | Should -Match 'FLARE:'
        $flareSource | Should -Not -Match '/d\s+"FLARE:[^"]*http'
    }
}

Describe 'Walled-garden fallback is supporting evidence only' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:entrySource = Get-Content (Join-Path $root 'main/Main.Entry.ps1') -Raw
    }

    It 'only runs the walled-garden probe after an inconclusive preflight' {
        $wgIndex = $script:entrySource.IndexOf('Test-WalledGarden')
        $wgIndex | Should -BeGreaterThan 0

        $before = $script:entrySource.Substring(0, $wgIndex)
        $before | Should -Match '"redirect"'
        $before | Should -Match 'Invoke-PostureRescan'
    }

    It 'still hands off to Base when the gateway does not answer ICMP' {
        $script:entrySource | Should -Match 'preflight_inconclusive'
        $script:entrySource | Should -Match 'captive_portal_browser_base'
    }
}

Describe 'Robust Cisco WebHelper EventID 301 parsing' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') }
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'WW_cap_portal_runner_base.ps1') `
            -Names @('ConvertFrom-CiscoWebHelperEventText', 'Get-CiscoWebHelperUrlFromText',
                     'Get-CiscoWebHelperQueryParameter', 'Get-CiscoWebHelperQueryParameterAny',
                     'ConvertFrom-CiscoWebHelperNavigationBody', 'Get-CiscoWebHelperDedupeKey',
                     'Get-CiscoWebHelperFinalUrlPort',
                     'Get-BaseCapMissingNavigationOutcome'))

        $script:navUrl = 'https://cp-webapp.wifi.connected.xfinity.com/en/welcome_st22/index.html?cm=AA:BB:CC:DD:EE:FF&cp_da_osname=Windows&cp_da_osversion=11&cp_da_browsername=Edge&cp_da_browserversion=141.0&cp_da_type=desktop&traceId=abc-123'
        $script:realBody = @"
Function: CWebHelperApp::OnNavigationCompleted
File: .\WebHelperApp.cpp
Line: 812
Invoked Function: Navigation
Return Code: 0 (0x00000000)
Description: Captive portal detection: navigated successfully to URL '$($script:navUrl)'
Final URL: 'http://www.msftconnecttest.com:80/connecttest.txt'
PID = 24680 TID = 13579
"@
    }

    It 'parses the real navigated URL and never confuses it with the final URL' {
        $parsed = ConvertFrom-CiscoWebHelperNavigationBody -Body $script:realBody

        $parsed.Parsed | Should -BeTrue
        $parsed.NavigatedUrl | Should -Be $script:navUrl
        $parsed.FinalUrl | Should -Be 'http://www.msftconnecttest.com:80/connecttest.txt'
        $parsed.NavigatedUrl | Should -Not -Match 'msftconnecttest'
        $parsed.FinalUrlPort | Should -Be 80
        $parsed.ProcessId | Should -Be '24680'
        $parsed.ThreadId | Should -Be '13579'
    }

    It 'maps the Xfinity cm parameter onto ap_mac and reads the cp_da_* client context' {
        $parsed = ConvertFrom-CiscoWebHelperNavigationBody -Body $script:realBody

        $parsed.ApMac | Should -Be 'AA:BB:CC:DD:EE:FF'
        $parsed.OsName | Should -Be 'Windows'
        $parsed.OsVersion | Should -Be '11'
        $parsed.BrowserName | Should -Be 'Edge'
        $parsed.BrowserVersion | Should -Be '141.0'
        $parsed.DeviceType | Should -Be 'desktop'
        $parsed.TraceId | Should -Be 'abc-123'
    }

    It 'parses the JSON/Unicode escaped representation of the same message' {
        $escaped = $script:realBody.Replace("'", '\u0027').Replace('\.', '\\.')
        $parsed = ConvertFrom-CiscoWebHelperNavigationBody -Body $escaped

        $parsed.Parsed | Should -BeTrue
        $parsed.NavigatedUrl | Should -Be $script:navUrl
        $parsed.FinalUrl | Should -Be 'http://www.msftconnecttest.com:80/connecttest.txt'
    }

    It 'parses double-quoted URLs and tolerates wording/whitespace differences' {
        $variant = @"
Description: navigated   successfully  to   URL   "$($script:navUrl)"
Final  URL : "http://www.msftconnecttest.com:80/connecttest.txt"
PID = 24680 TID = 13579
"@
        $parsed = ConvertFrom-CiscoWebHelperNavigationBody -Body $variant

        $parsed.Parsed | Should -BeTrue
        $parsed.NavigatedUrl | Should -Be $script:navUrl
        $parsed.FinalUrl | Should -Be 'http://www.msftconnecttest.com:80/connecttest.txt'
    }

    It 'returns an unparsed result without throwing when there is no navigation URL' {
        $parsed = ConvertFrom-CiscoWebHelperNavigationBody -Body 'Function: CWebHelperApp::Something else entirely'

        $parsed.Parsed | Should -BeFalse
        $parsed.NavigatedUrl | Should -Be ''
    }

    It 'keeps multiple navigation stages that share one PID but de-dupes repeated reads of one record' {
        $stageOne = Get-CiscoWebHelperDedupeKey -RecordId '101' -EventTime ([datetime]'2026-10-15T15:36:00') -ProcessId '24680' `
            -NavigatedUrl 'https://xwifipass.xfinity.com/static/connect?a=1' -FinalUrl ''
        $stageTwo = Get-CiscoWebHelperDedupeKey -RecordId '102' -EventTime ([datetime]'2026-10-15T15:36:05') -ProcessId '24680' `
            -NavigatedUrl $script:navUrl -FinalUrl 'http://www.msftconnecttest.com:80/connecttest.txt'
        $stageTwoAgain = Get-CiscoWebHelperDedupeKey -RecordId '102' -EventTime ([datetime]'2026-10-15T15:36:05') -ProcessId '24680' `
            -NavigatedUrl $script:navUrl -FinalUrl 'http://www.msftconnecttest.com:80/connecttest.txt'

        $stageOne | Should -Not -Be $stageTwo
        $stageTwoAgain | Should -Be $stageTwo
        $stageTwo | Should -Be 'record:102'
    }

    It 'marks a missing EventID 301 as not_applicable for ISE_EMPLOYEE and not_observed otherwise' {
        $ise = Get-BaseCapMissingNavigationOutcome -RedirectType 'ISE_EMPLOYEE'
        $other = Get-BaseCapMissingNavigationOutcome -RedirectType 'NON_ISE' -DefaultReason 'no_event_301'

        $ise.Outcome | Should -Be 'not_applicable'
        $ise.Reason | Should -Be 'not_applicable_ise_employee_no_event_301'
        $ise.Level | Should -Be 'INFO'
        $other.Outcome | Should -Be 'not_observed'
        $other.Reason | Should -Be 'no_event_301'
    }
}

Describe 'Canonical captive-portal URL precedence' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:root = $root
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') $script:urlLogs += $Message }
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'WW_cap_portal_runner_base.ps1') -Names @('Get-BaseCapTelemetryUrl'))
    }

    BeforeEach { $script:urlLogs = @() }

    It 'prefers the authoritative preflight redirect over every other source' {
        $url = Get-BaseCapTelemetryUrl -Url 'http://172.20.20.1' -Protocol 'http' -Fqdn '172.20.20.1' `
            -WebHelperNavigatedUrl 'https://cp-webapp.wifi.connected.xfinity.com/en/welcome_st22/index.html' `
            -PreflightRedirectUrl 'https://xwifipass.xfinity.com/static/connect?a=1' `
            -MainHandoffRedirectUrl 'https://handoff.example.com/portal'

        $url | Should -Be 'https://xwifipass.xfinity.com/static/connect?a=1'
        ($script:urlLogs -join "`n") | Should -Match 'source=authoritative_preflight_redirect'
    }

    It 'falls back to the Main handoff context when Base has no usable preflight redirect' {
        $url = Get-BaseCapTelemetryUrl -Url 'http://172.20.20.1' -WebHelperNavigatedUrl 'https://cp-webapp.wifi.connected.xfinity.com/en/welcome_st22/index.html' `
            -MainHandoffRedirectUrl 'https://handoff.example.com/portal'

        $url | Should -Be 'https://handoff.example.com/portal'
        ($script:urlLogs -join "`n") | Should -Match 'source=main_handoff_context'
    }

    It 'uses the WebHelper navigated URL only as corroborating evidence' {
        $url = Get-BaseCapTelemetryUrl -Url 'http://172.20.20.1' `
            -WebHelperNavigatedUrl 'https://cp-webapp.wifi.connected.xfinity.com/en/welcome_st22/index.html'

        $url | Should -Be 'https://cp-webapp.wifi.connected.xfinity.com/en/welcome_st22/index.html'
        ($script:urlLogs -join "`n") | Should -Match 'source=webhelper_navigated_url'
    }

    It 'never substitutes the WebHelper final URL for the captive portal URL' {
        $baseSource = Get-Content (Join-Path $script:root 'WW_cap_portal_runner_base.ps1') -Raw

        $baseSource | Should -Not -Match 'Get-BaseCapTelemetryUrl[^\r\n]*FinalUrl'
        $baseSource | Should -Not -Match '-WebHelperNavigatedUrl \$webHelperFinalUrl'
        (Get-CprFunctionSource -Path (Join-Path $script:root 'WW_cap_portal_runner_base.ps1') -Names @('Get-BaseCapTelemetryUrl')) |
            Should -Not -Match 'FinalUrl'
    }

    It 'hands the authoritative preflight context back into the artifact before escalating to Event 777' {
        $baseSource = Get-Content (Join-Path $script:root 'WW_cap_portal_runner_base.ps1') -Raw
        $handbackIndex = $baseSource.IndexOf('Write-BaseCapPreflightHandback')
        $escalateIndex = $baseSource.LastIndexOf('Send-EscalationFlare')

        $handbackIndex | Should -BeGreaterThan 0
        $escalateIndex | Should -BeGreaterThan $handbackIndex
    }
}

Describe 'Truthful, fail-soft telemetry' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:root = $root
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') $script:teeLogs += $Message }
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'WW_cap_portal_runner_base.ps1') -Names @('Write-BaseCapTee'))
        Invoke-Expression (Get-CprFunctionSource -Path (Join-Path $root 'WW_tee.ps1') -Names @('Add-TeeQueueEntry', 'Repair-TeeQueueAccess'))
    }

    BeforeEach { $script:teeLogs = @() }

    It 'logs the exact reason token when a tag is not in the active sticky profile' {
        function global:Write-TeeLog {
            param([string]$Tag, [hashtable]$Data, [switch]$PassThru)
            [PSCustomObject]@{ Tag = $Tag; Queued = $false; Reason = 'tag_not_in_profile'; Error = $null }
        }

        $result = Write-BaseCapTee -Tag 'cap_portal_preflight_observation' -Data @{ status = 'redirect' }

        $result.Reason | Should -Be 'tag_not_in_profile'
        ($script:teeLogs -join "`n") | Should -Match "queued=False reason=tag_not_in_profile"
    }

    It 'reports access_denied truthfully instead of letting the event disappear' {
        function global:Write-TeeLog {
            param([string]$Tag, [hashtable]$Data, [switch]$PassThru)
            [PSCustomObject]@{ Tag = $Tag; Queued = $false; Reason = 'access_denied'; Error = 'Access to the path is denied.' }
        }

        $result = Write-BaseCapTee -Tag 'cap_portal_webhelper_navigation' -Data @{ status = 'observed' }

        $result.Reason | Should -Be 'access_denied'
        ($script:teeLogs -join "`n") | Should -Match 'reason=access_denied'
    }

    It 'never throws when telemetry itself fails' {
        function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data, [switch]$PassThru) throw 'boom' }

        { Write-BaseCapTee -Tag 'cap_portal_preflight_observation' -Data @{ } } | Should -Not -Throw
        ($script:teeLogs -join "`n") | Should -Match 'reason=error'
    }

    It 'creates the queue file when missing and reports queued' {
        $queue = Join-Path ([System.IO.Path]::GetTempPath()) ("cpr_queue_{0}/haystack_syslog_queue.jsonl" -f ([guid]::NewGuid()))
        try {
            $result = Add-TeeQueueEntry -Path $queue -Entry '{"action":"test"}'

            $result.Queued | Should -BeTrue
            $result.Reason | Should -Be 'queued'
            (Get-Content -Path $queue -Raw) | Should -Match '"action":"test"'
        } finally {
            Remove-Item -Path (Split-Path $queue -Parent) -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'preserves the existing JSON-lines queue format (one event per line, appended)' {
        $queue = Join-Path ([System.IO.Path]::GetTempPath()) ("cpr_queue_{0}/haystack_syslog_queue.jsonl" -f ([guid]::NewGuid()))
        try {
            $null = Add-TeeQueueEntry -Path $queue -Entry '{"action":"one"}'
            $null = Add-TeeQueueEntry -Path $queue -Entry '{"action":"two"}'

            $lines = @(Get-Content -Path $queue)
            $lines.Count | Should -Be 2
            $lines[0] | Should -Be '{"action":"one"}'
            $lines[1] | Should -Be '{"action":"two"}'
        } finally {
            Remove-Item -Path (Split-Path $queue -Parent) -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports access_denied rather than throwing when the queue cannot be written' {
        $result = Add-TeeQueueEntry -Path '/proc/cpr_not_writable/haystack_syslog_queue.jsonl' -Entry '{"action":"test"}'

        $result.Queued | Should -BeFalse
        $result.Reason | Should -BeIn @('access_denied', 'error')
        $result.Error | Should -Not -BeNullOrEmpty
    }

    It 'routes Write-TeeLog queue writes through the truthful queue writer' {
        $src = Get-CprFunctionSource -Path (Join-Path $script:root 'WW_tee.ps1') -Names @('Write-TeeLog')

        $src | Should -Match 'Add-TeeQueueEntry -Path \$script:TeeQueueFile'
        $src | Should -Match "Reason\s*=\s*'access_denied'|\`$queueWrite\.Reason"
    }

    It 'makes FlareGun dispatch telemetry truthful without touching dispatch mechanics' {
        $src = Get-CprFunctionSource -Path (Join-Path $script:root 'main/Main.FlareGun.ps1') -Names @('Write-FlareTelemetry')

        $src | Should -Match '-PassThru'
        $src | Should -Match 'reason=\$\(\$teeResult\.Reason\)'
    }

    It 'reports the full runner queue result truthfully' {
        $runnerSource = Get-Content (Join-Path $script:root 'WW_cap_portal_runner.ps1') -Raw

        $runnerSource | Should -Match 'access_denied'
        $runnerSource | Should -Match 'reason=queued'
    }

    It 'registers the new corroboration fields in the HayStack schema' {
        $schema = Import-PowerShellDataFile (Join-Path $script:root 'support_files/haystack_msg_schema.psd1')

        foreach ($field in @('os_name', 'os_version', 'browser_name', 'browser_version', 'device_type', 'trace_id', 'event_record_id', 'classification')) {
            $schema.Optional.ContainsKey($field) | Should -BeTrue -Because "schema must document $field"
            $schema.CanonicalCasing | Should -Contain $field
        }
    }

    It 'registers the new fields on every tee level (cap portal detail is core since the single-master change)' {
        . (Join-Path $script:root 'WW_set_tee_level.ps1')
        foreach ($level in 1..5) {
            $profile = Get-CprTeeLevelProfile -Level $level -MasterPath (Join-Path $script:root 'WW_tee_master.psd1')
            $profile.Events['cap_portal_preflight_observation'].fields | Should -Contain 'classification'
            $profile.Events['cap_portal_webhelper_navigation'].fields | Should -Contain 'trace_id'
            $profile.Events['cap_portal_webhelper_navigation'].fields | Should -Contain 'event_record_id'
        }
    }

    It 'documents that the active profile is generated from WW_tee_master.psd1' {
        $readme = Get-Content (Join-Path $script:root 'README.txt') -Raw

        $readme | Should -Match 'WW_tee_master\.psd1'
        $readme | Should -Match 'tag_not_in_profile'
    }
}

Describe 'XmlVault trigger hygiene' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:vaultSource = Get-Content (Join-Path $root 'WW_xml_vault.ps1') -Raw
    }

    It 'only accepts its own 801/802 trigger event IDs' {
        $script:vaultSource | Should -Match '\$XmlVaultTriggerEventIds\s*=\s*@\(\$XmlVaultSyncEventId,\s*\$XmlVaultRestoreEventId\)'
        $script:vaultSource | Should -Match 'Id\s*=\s*\$XmlVaultTriggerEventIds'
    }

    It 'never treats captive-portal FlareGun events 777/778 as a sync or restore cause' {
        $script:vaultSource | Should -Not -Match "Id\s*=\s*@\([^)]*777"
        $script:vaultSource | Should -Not -Match "Id\s*=\s*@\([^)]*778"
        $filterMatch = [regex]::Match($script:vaultSource, "FilterHashtable @\{[\s\S]{0,400}?ProviderName = 'WhiteWalkerFlareGun'[\s\S]{0,200}?\}")
        $filterMatch.Success | Should -BeTrue
        $filterMatch.Value | Should -Match 'Id\s*='
    }
}
