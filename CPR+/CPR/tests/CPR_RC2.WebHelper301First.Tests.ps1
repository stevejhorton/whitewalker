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

BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    $script:configPath = Join-Path $script:root 'main/Main.Configuration.ps1'
    $script:entryPath = Join-Path $script:root 'main/Main.Entry.ps1'
    $script:capPath = Join-Path $script:root 'main/Main.CaptivePortal.ps1'
    $script:basePath = Join-Path $script:root 'WW_cap_portal_runner_base.ps1'
    $script:configSource = Get-Content $script:configPath -Raw
    $script:entrySource = Get-Content $script:entryPath -Raw
    $script:capSource = Get-Content $script:capPath -Raw
    $script:baseSource = Get-Content $script:basePath -Raw
    $script:fullSource = Get-Content (Join-Path $script:root 'WW_cap_portal_runner.ps1') -Raw

    function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') }
    function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data) }
    function global:Get-WinEvent { param($FilterHashtable, $MaxEvents, $ErrorAction) }

    Invoke-Expression (Get-CprFunctionSource -Path $script:capPath -Names @(
        'Get-CprCiscoWebHelperQueryParameter', 'Get-CprCiscoWebHelperQueryParameterAny',
        'ConvertFrom-CprCiscoWebHelperEventText', 'Get-CprCiscoWebHelperUrlFromText',
        'Get-CprCiscoWebHelperUrlDetails', 'ConvertFrom-CprCiscoWebHelperNavigationBody',
        'Get-CprCiscoWebHelperDedupeKey', 'New-CprCiscoWebHelperEvidenceResult',
        'Find-CprCiscoWebHelper301Evidence', 'Wait-CprCiscoWebHelper301Evidence',
        'Test-CprWebHelperCanSuppressPreflight', 'Write-CprCiscoWebHelper301Evidence',
        'New-CprWebHelperPreflightResult'
    ))

    $script:navUrl = 'https://cp-app.wifi.connected.xfinity.com/welcome?cm=AA:BB:CC:DD:EE:FF&cp_da_osname=Windows&cp_da_osversion=11&cp_da_browsername=Edge&cp_da_browserversion=141.0&cp_da_type=desktop&traceId=trace-301'
    $script:navigationBody = "[TID=88 PID=77] primary control navigated successfully to URL '$($script:navUrl)'. Final URL 'http://www.msftconnecttest.com:80/connecttest.txt'."
}

Describe 'Cisco Secure Client EventID 301-first direct evidence' {
    BeforeEach {
        $script:logs = @()
        $script:tee = @()
        function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') $script:logs += "$Level $Message" }
        function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data) $script:tee += [pscustomobject]@{ Tag = $Tag; Data = $Data } }
    }

    It 'selects a fresh correlated Xfinity navigation and preserves parsed metadata' {
        $transition = Get-Date
        Mock Get-WinEvent {
            @([pscustomobject]@{
                ProviderName = 'Cisco Secure Client'; Id = 301; RecordId = 9001
                TimeCreated = $transition.AddSeconds(2); Message = $script:navigationBody
            })
        }

        $result = Find-CprCiscoWebHelper301Evidence -Since $transition -Now $transition.AddSeconds(5) `
            -LogName 'Cisco Secure Client' -ProviderName 'Cisco Secure Client' -EventId 301 `
            -MaximumAgeSeconds 30 -SeenIdentities @{}

        $result.Found | Should -BeTrue
        $result.UsableNavigation | Should -BeTrue
        $result.Source | Should -Be 'cisco_webhelper_301'
        $result.NavigatedUrl | Should -Be $script:navUrl
        $result.FinalUrl | Should -Match 'msftconnecttest'
        $result.ApMac | Should -Be 'AA:BB:CC:DD:EE:FF'
        $result.TraceId | Should -Be 'trace-301'
        $result.Fqdn | Should -Be 'cp-app.wifi.connected.xfinity.com'
        $result.Protocol | Should -Be 'https'
        $result.Port | Should -Be '443'
        $result.EventRecordId | Should -Be '9001'
    }

    It 'keeps Main and standalone Base parser semantics identical for the Xfinity fixture' {
        function global:Write-BaseCapLog { param([string]$Message, [string]$Level = 'INFO') }
        Invoke-Expression (Get-CprFunctionSource -Path $script:basePath -Names @(
            'Get-CiscoWebHelperQueryParameter', 'Get-CiscoWebHelperQueryParameterAny',
            'ConvertFrom-CiscoWebHelperEventText', 'Get-CiscoWebHelperUrlFromText',
            'Get-CiscoWebHelperFinalUrlPort', 'ConvertFrom-CiscoWebHelperNavigationBody'
        ))
        $main = ConvertFrom-CprCiscoWebHelperNavigationBody $script:navigationBody
        $base = ConvertFrom-CiscoWebHelperNavigationBody $script:navigationBody
        foreach ($property in @(
            'NavigatedUrl','FinalUrl','ProcessId','ThreadId','ApMac','OsName',
            'OsVersion','BrowserName','BrowserVersion','DeviceType','TraceId')) {
            $main.$property | Should -Be $base.$property -Because "$property parser semantics must not drift"
        }
    }

    It 'retains multiple stages sharing one PID and dedupes the identical record identity' {
        $now = [datetime]'2026-10-16T11:40:10Z'
        $events = @(
            [pscustomobject]@{ ProviderName='Cisco Secure Client'; Id=301; RecordId=11; TimeCreated=$now.AddSeconds(-2); Message=$script:navigationBody },
            [pscustomobject]@{ ProviderName='Cisco Secure Client'; Id=301; RecordId=12; TimeCreated=$now.AddSeconds(-1); Message=($script:navigationBody -replace '/welcome\?', '/stage2?') }
        )
        Mock Get-WinEvent { $events }
        $seen = @{}

        $first = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now -MaximumAgeSeconds 30 -SeenIdentities $seen
        $second = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now -MaximumAgeSeconds 30 -SeenIdentities $seen

        $first.ProcessId | Should -Be '77'
        $first.NavigationStages.Count | Should -Be 2
        @($first.NavigationStages.EventRecordId) | Should -Contain '11'
        @($first.NavigationStages.EventRecordId) | Should -Contain '12'
        $second.UsableNavigation | Should -BeFalse
        $second.SkippedSeenCount | Should -Be 2
    }

    It 'treats final_url-only evidence as navigation_unavailable and never promotes final_url' {
        $now = Get-Date
        Mock Get-WinEvent {
            @([pscustomobject]@{
                ProviderName='Cisco Secure Client'; Id=301; RecordId=20; TimeCreated=$now
                Message="PID=77 Final URL 'http://www.msftconnecttest.com/connecttest.txt'."
            })
        }

        $result = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now -MaximumAgeSeconds 30 -SeenIdentities @{}
        $result.Found | Should -BeTrue
        $result.UsableNavigation | Should -BeFalse
        $result.Status | Should -Be 'navigation_unavailable'
        $result.Reason | Should -Be 'no_navigation_url'
        (New-CprWebHelperPreflightResult -Evidence $result) | Should -BeNullOrEmpty
    }

    It 'fails soft on direct Event Log read failure without requiring HayStack' {
        Mock Get-WinEvent { throw 'event log unavailable' }
        $now = Get-Date
        $result = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now -SeenIdentities @{}

        $result.UsableNavigation | Should -BeFalse
        $result.ReadFailed | Should -BeTrue
        $result.Reason | Should -Be 'read_error'
        $result.TerminalReason | Should -Be 'read_error'
        $script:capSource | Should -Not -Match 'haystack_syslog_queue\.jsonl'
    }

    It 'returns no observation when no direct EventID 301 exists' {
        Mock Get-WinEvent { @() }
        $now = Get-Date
        $result = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now -SeenIdentities @{}
        $result.Found | Should -BeFalse
        $result.UsableNavigation | Should -BeFalse
        $result.Reason | Should -Be 'no_events'
        $result.TerminalReason | Should -Be 'no_events'
    }

    It 'rejects stale evidence outside the current network transition freshness boundary' {
        $transition = Get-Date
        Mock Get-WinEvent {
            @([pscustomobject]@{
                ProviderName='Cisco Secure Client'; Id=301; RecordId=30
                TimeCreated=$transition.AddSeconds(-40); Message=$script:navigationBody
            })
        }

        $result = Find-CprCiscoWebHelper301Evidence -Since $transition.AddSeconds(-60) -Now $transition `
            -CorrelationStart $transition.AddSeconds(-10) -MaximumAgeSeconds 30 -SeenIdentities @{}
        $result.UsableNavigation | Should -BeFalse
        $result.RejectedStaleCount | Should -Be 1
    }

    It 'accepts a provider-valid navigation from the full bounded pre-transition lookback' {
        $transition = Get-Date
        Mock Get-WinEvent {
            @([pscustomobject]@{
                ProviderName='Cisco Secure Client'; Id=301; RecordId=31
                TimeCreated=$transition.AddSeconds(-20); Message=$script:navigationBody
            })
        }
        $result = Wait-CprCiscoWebHelper301Evidence -CorrelationStart $transition `
            -LookbackSeconds 120 -WaitSeconds 0 -MaximumAgeSeconds 120
        $result.UsableNavigation | Should -BeTrue
        $result.EventRecordId | Should -Be '31'
    }

    It 'finds a valid Xfinity navigation buried among more than ten same-time no-URL records' {
        $now = [datetime]'2026-10-16T08:36:56Z'
        $events = [System.Collections.Generic.List[object]]::new()
        1..12 | ForEach-Object {
            $events.Add([pscustomobject]@{
                ProviderName='csc_webhelper'; Id=301; RecordId=(1000 + $_)
                TimeCreated=$now.AddSeconds(-67); Message="[TID=$_ PID=57732] popup search completed without navigation"
            })
        }
        $events.Add([pscustomobject]@{
            ProviderName='csc_webhelper'; Id=301; RecordId=9001; TimeCreated=$now.AddSeconds(-67)
            Message="primary control navigated successfully to URL 'https://cp-webapp.wifi.connected.xfinity.com/en/welcome_st22/index.html?traceId=live&cm=f4:a4:75:a8:95:2b'; Final URL: 'http://www.msftconnecttest.com:80/connecttest.txt'"
        })
        13..24 | ForEach-Object {
            $events.Add([pscustomobject]@{
                ProviderName='csc_webhelper'; Id=301; RecordId=(1000 + $_)
                TimeCreated=$now.AddSeconds(-67); Message="[TID=$_ PID=57732] no navigated URL"
            })
        }
        Mock Get-WinEvent { $events }

        $result = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-180) -Now $now `
            -CorrelationStart $now.AddSeconds(-180) -ProviderName 'csc_webhelper' `
            -MaximumAgeSeconds 180 -MaxEvents 256 -SeenIdentities @{}

        $result.UsableNavigation | Should -BeTrue
        $result.EventRecordId | Should -Be '9001'
        $result.NavigatedUrl | Should -Match '^https://cp-webapp\.wifi\.connected\.xfinity\.com/'
        $result.FinalUrl | Should -Match 'msftconnecttest'
        $result.NonNavigationCount | Should -Be 24
        $result.QueriedCount | Should -Be 25
        $result.TerminalReason | Should -Be 'accepted'
    }

    It 'uses provider freshness when the event carries no network identity but rejects an explicit SSID mismatch' {
        $now = Get-Date
        Mock Get-WinEvent {
            @([pscustomobject]@{
                ProviderName='csc_webhelper'; Id=301; RecordId=41; TimeCreated=$now
                Message=($script:navigationBody -replace 'trace-301', 'trace-301&ssid=other-network')
            })
        }
        $mismatch = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now `
            -CurrentSsid 'xfinitywifi' -SeenIdentities @{}
        $mismatch.UsableNavigation | Should -BeFalse
        $mismatch.TerminalReason | Should -Be 'context_mismatch'

        Mock Get-WinEvent {
            @([pscustomobject]@{
                ProviderName='csc_webhelper'; Id=301; RecordId=42; TimeCreated=$now
                Message=$script:navigationBody
            })
        }
        (Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now `
            -CurrentSsid 'xfinitywifi' -SeenIdentities @{}).UsableNavigation | Should -BeTrue
    }

    It 'reports a bounded record-limit terminal reason instead of claiming no events' {
        $now = Get-Date
        Mock Get-WinEvent {
            1..3 | ForEach-Object {
                [pscustomobject]@{ ProviderName='csc_webhelper'; Id=301; RecordId=$_; TimeCreated=$now; Message='no URL' }
            }
        }
        $result = Find-CprCiscoWebHelper301Evidence -Since $now.AddSeconds(-5) -Now $now `
            -MaxEvents 3 -SeenIdentities @{}
        $result.RecordLimitReached | Should -BeTrue
        $result.TerminalReason | Should -Be 'record_limit_reached'
    }

    It 'continues the bounded poll after noise and accepts a navigation that appears next' {
        $now = Get-Date
        $script:lookupCall = 0
        Mock Get-WinEvent {
            $script:lookupCall++
            $noise = [pscustomobject]@{
                ProviderName='csc_webhelper'; Id=301; RecordId=71
                TimeCreated=$now; Message='popup record without navigation'
            }
            if ($script:lookupCall -eq 1) { return @($noise) }
            return @($noise, [pscustomobject]@{
                ProviderName='csc_webhelper'; Id=301; RecordId=72
                TimeCreated=$now.AddMilliseconds(50); Message=$script:navigationBody
            })
        }

        $result = Wait-CprCiscoWebHelper301Evidence -CorrelationStart $now.AddSeconds(-1) `
            -LookbackSeconds 180 -WaitSeconds 1 -PollIntervalMs 50 -MaximumAgeSeconds 180

        $result.UsableNavigation | Should -BeTrue
        $result.EventRecordId | Should -Be '72'
        $result.NonNavigationCount | Should -Be 1
        $result.ExaminedCount | Should -Be 2
        $script:lookupCall | Should -Be 2
    }

    It 'emits structured navigation evidence with canonical source and navigated URL' {
        $evidence = [pscustomobject]@{
            EventTime=Get-Date; EventRecordId='55'; ProcessId='77'; ThreadId='88'
            NavigatedUrl=$script:navUrl; FinalUrl='http://www.msftconnecttest.com/connecttest.txt'
            ApName=''; ApTags=''; ApMac='AA'; Sip=''; Org=''; Ui=''; Psid=''; LoginUrl=''
            Ma=''; Os=''; ApiDomain=''; OsName='Windows'; OsVersion='11'; BrowserName='Edge'
            BrowserVersion='141'; DeviceType='desktop'; TraceId='trace-301'; Protocol='https'
            Fqdn='cp-app.wifi.connected.xfinity.com'; Port='443'; Classification='NON_ISE'
            Source='cisco_webhelper_301'; Status='observed'; Reason='fresh_correlated_navigation'
        }
        Write-CprCiscoWebHelper301Evidence -Evidence $evidence -NetworkContext @{ssid='xfinitywifi';ip='172.20.20.20';gw='172.20.20.1';dns='1.1.1.1'} -VpnState 'Disconnected'

        $script:tee.Count | Should -Be 1
        $script:tee[0].Tag | Should -Be 'cap_portal_webhelper_navigation'
        $script:tee[0].Data.detection_source | Should -Be 'cisco_webhelper_301'
        $script:tee[0].Data.navigated_url | Should -Be $script:navUrl
        $script:tee[0].Data.final_url | Should -Match 'msftconnecttest'
        $script:tee[0].Data.classification | Should -Be 'NON_ISE'
    }
}

Describe '301-first control-plane ordering and configuration' {
    It 'checks direct 301 only in a credible active WebView2 branch before gateway preflight' {
        $active = $script:entrySource.IndexOf('Test-CprCiscoWebHelperActive')
        $lookup = $script:entrySource.IndexOf('Wait-CprCiscoWebHelper301Evidence')
        $preflight = $script:entrySource.IndexOf('$nwCheck = Invoke-GatedNwCheck')
        $active | Should -BeGreaterThan 0
        $lookup | Should -BeGreaterThan $active
        $preflight | Should -BeGreaterThan $lookup
    }

    It 'uses usable 301 as redirect evidence and otherwise falls back to gateway preflight' {
        $script:entrySource | Should -Match "detection_source=cisco_webhelper_301"
        $script:entrySource | Should -Match "detection_source=gateway_preflight"
        $script:entrySource | Should -Match '\$nwCheck = Invoke-GatedNwCheck'
        $script:entrySource | Should -Match 'UsableNavigation'
    }

    It 'keeps ISE_EMPLOYEE posture rescan independent of EventID 301' {
        $iseBlock = [regex]::Match($script:entrySource, '"ISE_EMPLOYEE"[\s\S]{0,4000}?Invoke-PostureRescan')
        $iseBlock.Success | Should -BeTrue
        $iseBlock.Value | Should -Not -Match 'Wait-CprCiscoWebHelper301Evidence'
        Test-CprWebHelperCanSuppressPreflight -Evidence ([pscustomobject]@{
            UsableNavigation=$true; Source='cisco_webhelper_301'; Classification='ISE_EMPLOYEE'
        }) | Should -BeFalse
    }

    It 'declares and carries every new behavior/timing value in Main.Configuration' {
        foreach ($name in @(
            'CapPortalWebHelper301FirstEnabled', 'CapPortalWebHelper301LogName',
            'CapPortalWebHelper301ProviderName', 'CapPortalWebHelper301EventId',
            'CapPortalWebHelper301LookbackSec', 'CapPortalWebHelper301MaxRecords', 'CapPortalWebHelper301WaitSec',
            'CapPortalWebHelper301PollIntervalMs', 'CapPortalWebHelper301MaxAgeSec',
            'CapPortalWebHelper301NoUrlImmediatePreflight', 'CapPortalWebHelper301SuppressPreflight',
            'CapPortalWebHelper301HaystackFallbackEnabled', 'CapPortalWebHelper301HaystackLookbackSec')) {
            $script:configSource | Should -Match ('\$' + $name + '\s*=')
        }
        foreach ($key in @(
            'webhelper_301_first_enabled', 'webhelper_301_log_name', 'webhelper_301_provider_name',
            'webhelper_301_event_id', 'webhelper_301_lookback_sec', 'webhelper_301_wait_sec',
            'webhelper_301_max_records',
            'webhelper_301_poll_interval_ms', 'webhelper_301_max_age_sec',
            'webhelper_301_no_url_immediate_preflight', 'webhelper_301_suppress_preflight',
            'webhelper_301_haystack_fallback_enabled', 'webhelper_301_haystack_lookback_sec')) {
            $script:configSource | Should -Match $key
        }
    }

    It 'configures the real provider, larger bounded lookback, and sufficiently high record cap' {
            $script:configSource | Should -Match "\`$CapPortalWebHelper301ProviderName\s*=\s*'csc_webhelper'"
            $script:configSource | Should -Match '\$CapPortalWebHelper301LookbackSec\s*=\s*180'
            $script:configSource | Should -Match '\$CapPortalWebHelper301MaxRecords\s*=\s*256'
            $script:configSource | Should -Match 'webhelper_301_max_records\s*=\s*\$CapPortalWebHelper301MaxRecords'
            $script:capSource | Should -Match '\[int\]\$MaxEvents\s*=\s*256'
            $script:baseSource | Should -Match '\[int\]\$MaxEvents\s*=\s*256'
            $script:baseSource | Should -Match "ProviderName\s*=\s*\`$CiscoWebHelperProviderName"
    }

    It 'logs truthful decision counts and selected identity for every lookup' {
            $script:capSource | Should -Match 'webhelper_301_lookup source=event_log'
            foreach ($field in @('lookback_sec','max_records','queried','examined','no_navigation_url',
                'rejected_stale','rejected_context','accepted','selected_record_id','selected_event_time','terminal_reason')) {
                $script:capSource | Should -Match $field
            }
            foreach ($reason in @('no_events','no_navigation_url','all_stale','context_mismatch','read_error','record_limit_reached')) {
                $script:capSource | Should -Match "'$reason'"
            }
    }

    It 'separates readiness-to-preflight from startup-to-preflight timing and schedules Base by remaining interval' {
            $script:entrySource | Should -Match 'startup_to_preflight_ms'
            $script:entrySource | Should -Match '\$preflightStartedAt\s*-\s*\$networkReadyAt'
            $script:baseSource | Should -Match '\$basePreflightStartedAt\s*-\s*\$baseNetworkReadyAt'
            $script:baseSource | Should -Match 'base_observe_cycle cycle=\{0\} work_ms=\{1\} sleep_ms=\{2\} remaining_ms=\{3\}'
            $script:baseSource | Should -Match '\(\$CheckIntervalSec \* 1000\) - \$cycleWorkMs'
            $script:baseSource | Should -Match 'Start-Sleep -Milliseconds \$sleepMs'
            $script:baseSource | Should -Not -Match 'Start-Sleep -Seconds \$sleepSeconds'
    }

    It 'reuses the Main and Base network snapshots without re-enumerating them in consumers' {
            $contextFunction = [regex]::Match($script:capSource, 'function Get-CaptivePortalNetworkContext \{[\s\S]*?\n\}').Value
            $contextFunction | Should -Match 'networkInfo snapshot'
            $contextFunction | Should -Not -Match 'Get-NetAdapter|Get-NetIPConfiguration|netsh'
            ([regex]::Matches($script:baseSource, '\$netCtx = Get-BaseCapNetworkContext')).Count | Should -Be 1
    }

    It 'does not add Zscaler-specific runtime coupling' {
            ($script:entrySource + $script:capSource + $script:baseSource) | Should -Not -Match '(?i)zscaler'
    }

    It 'makes Base suppress its immediate probe only for accepted active 301 evidence' {
        $script:baseSource | Should -Match 'cisco_webhelper_301'
        $script:baseSource | Should -Match 'SuppressPreflight'
        $script:baseSource | Should -Match 'gateway_preflight'
        $script:baseSource | Should -Match 'Test-BaseHandoffArtifact'
        $script:baseSource | Should -Match 'WebHelper301MaxAgeSec'
        $script:baseSource | Should -Match "candidate\.Classification -ne 'ISE_EMPLOYEE'"
    }

    It 'keeps haystack_log_fallback diagnostic-only and never uses it for the control decision' {
        $script:capSource | Should -Match "Source -eq 'cisco_webhelper_301'"
        $script:entrySource | Should -Match 'Test-CprWebHelperCanSuppressPreflight'
        $script:entrySource | Should -Match 'haystack_log_fallback is supporting diagnostic only'
        $script:entrySource | Should -Not -Match 'haystack_syslog_queue\.jsonl'
    }

    It 'makes Full consume navigated_url and never final_url as its portal URL' {
        $script:fullSource | Should -Match '\$CaptivePortalURL\s*=\s*\[string\]\$stateData\.webhelper_navigation\.NavigatedUrl'
        $script:fullSource | Should -Not -Match '\$CaptivePortalURL\s*=\s*\[string\]\$stateData\.webhelper_navigation\.FinalUrl'
    }

    It 'does not equate navigation with remediation success' {
        $script:capSource | Should -Match 'Test-CaptivePortalCleared'
        $script:capSource | Should -Match 'cap_portal_remediation_passed'
        $script:capSource | Should -Not -Match "NavigatedUrl[\s\S]{0,300}cap_portal_remediation_passed"
    }
}
