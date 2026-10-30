# CPR RC2 captive-portal detection, telemetry, remediation, and alerting.
# Depends on: Main.Network.ps1, Main.FlareGun.ps1, Main.Logging.ps1, and WW captive-portal helpers.

# ------------------------ Captive Portal Integration -------------------------
function Get-CprCiscoWebHelperQueryParameter {
    param([string]$Url = '', [string]$ParameterName = '')
    if ([string]::IsNullOrEmpty($Url) -or [string]::IsNullOrEmpty($ParameterName)) { return '' }
    try {
        $match = [regex]::Match($Url, "(?i)(?:[?&])$([regex]::Escape($ParameterName))=([^&#]*)")
        if ($match.Success) { return [Uri]::UnescapeDataString($match.Groups[1].Value) }
    } catch { }
    return ''
}

function Get-CprCiscoWebHelperQueryParameterAny {
    param([string]$Url = '', [string[]]$ParameterNames = @())
    foreach ($name in $ParameterNames) {
        $value = Get-CprCiscoWebHelperQueryParameter -Url $Url -ParameterName $name
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }
    return ''
}

function ConvertFrom-CprCiscoWebHelperEventText {
    param([string]$Body = '')
    if ([string]::IsNullOrEmpty($Body)) { return '' }
    try {
        $text = [regex]::Replace($Body, '(?i)\\u0027', "'")
        $text = [regex]::Replace($text, '(?i)\\u0022', '"')
        $text = $text -replace '\\"', '"' -replace "\\'", "'" -replace '\\\\', '\'
        return ($text -replace [char]0x2018, "'" -replace [char]0x2019, "'" `
            -replace [char]0x201C, '"' -replace [char]0x201D, '"')
    } catch { return $Body }
}

function Get-CprCiscoWebHelperUrlFromText {
    param([string]$Text = '', [Parameter(Mandatory)][string]$LabelPattern)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    try {
        $quoted = [regex]::Match($Text, "(?is)$LabelPattern\s*:?\s*(['""])(?<url>.+?)\1")
        if ($quoted.Success) { return $quoted.Groups['url'].Value.Trim() }
        $bare = [regex]::Match($Text, "(?is)$LabelPattern\s*:?\s*(?<url>[a-z][a-z0-9+.-]*://[^\s'""]+)")
        if ($bare.Success) { return $bare.Groups['url'].Value.TrimEnd('.', ',', ';') }
    } catch { }
    return ''
}

function Get-CprCiscoWebHelperUrlDetails {
    param([string]$Url = '')
    $details = @{ Protocol = ''; Fqdn = ''; Port = '' }
    if ([string]::IsNullOrWhiteSpace($Url)) { return $details }
    try {
        $uri = [Uri]$Url
        if (-not $uri.IsAbsoluteUri -or [string]::IsNullOrWhiteSpace($uri.Host)) { return $details }
        $details.Protocol = $uri.Scheme
        $details.Fqdn = $uri.Host
        $details.Port = if ($uri.IsDefaultPort) {
            if ($uri.Scheme -eq 'http') { '80' } elseif ($uri.Scheme -eq 'https') { '443' } else { '' }
        } else { [string]$uri.Port }
    } catch { }
    return $details
}

function Get-CprPortalUrlFields {
    <#
    .SYNOPSIS
    Portal-descriptor fields (ap_name, ap_mac, sip, psid, login_url, ...) read
    from the query string of a captive portal URL. Same parameter names and
    aliases as the Cisco WebHelper EventID 301 parser, so a redirect seen
    natively (preflight / enroll.cisco.com) is described in Splunk with the
    same fields as one seen via 301. Fail-soft: a parameter the URL does not
    carry stays '' (never fabricated). The cp_da_* client fields are added by
    Secure Client itself, so they are normally empty on a native redirect.
    #>
    param([string]$Url = '')
    $f = @{
        ap_name=''; ap_tags=''; ap_mac=''; sip=''; org=''; ui=''; psid=''
        login_url=''; ma=''; os=''; api_domain=''; os_name=''; os_version=''
        browser_name=''; browser_version=''; device_type=''; trace_id=''
    }
    if ([string]::IsNullOrWhiteSpace($Url)) { return $f }
    try {
        $map = @{ ap_name='ap_name'; ap_tags='ap_tags'; sip='SIP'; org='ORG'; ui='UI'
                  psid='PSID'; login_url='login_url'; ma='MA'; os='OS'; api_domain='api_domain' }
        foreach ($k in @($map.Keys)) { $f[$k] = Get-CprCiscoWebHelperQueryParameter -Url $Url -ParameterName $map[$k] }
        $f.ap_mac          = Get-CprCiscoWebHelperQueryParameterAny $Url @('ap_mac','cm')
        $f.os_name         = Get-CprCiscoWebHelperQueryParameterAny $Url @('cp_da_osname')
        $f.os_version      = Get-CprCiscoWebHelperQueryParameterAny $Url @('cp_da_osversion')
        $f.browser_name    = Get-CprCiscoWebHelperQueryParameterAny $Url @('cp_da_browsername')
        $f.browser_version = Get-CprCiscoWebHelperQueryParameterAny $Url @('cp_da_browserversion')
        $f.device_type     = Get-CprCiscoWebHelperQueryParameterAny $Url @('cp_da_type')
        $f.trace_id        = Get-CprCiscoWebHelperQueryParameterAny $Url @('traceId','trace_id','traceid')
    } catch { }
    return $f
}

function ConvertFrom-CprCiscoWebHelperNavigationBody {
    <#
    Main-side copy of Base's EventID 301 parser. Base is a standalone process,
    so sharing PowerShell scope is impossible; parity tests protect the same
    quote normalization, Xfinity aliases, and navigated/final URL separation.
    #>
    param([string]$Body = '')

    $result = [PSCustomObject]@{
        Parsed=$false; NavigatedUrl=''; FinalUrl=''; ProcessId=''; ThreadId=''
        ApName=''; ApTags=''; ApMac=''; Sip=''; Org=''; Ui=''; Psid=''
        LoginUrl=''; Ma=''; Os=''; ApiDomain=''; OsName=''; OsVersion=''
        BrowserName=''; BrowserVersion=''; DeviceType=''; TraceId=''
    }
    if ([string]::IsNullOrEmpty($Body)) { return $result }
    try {
        $text = ConvertFrom-CprCiscoWebHelperEventText -Body $Body
        $result.NavigatedUrl = Get-CprCiscoWebHelperUrlFromText -Text $text -LabelPattern 'navigated\s+successfully\s+to\s+URL'
        $result.FinalUrl = Get-CprCiscoWebHelperUrlFromText -Text $text -LabelPattern 'Final\s+URL'
        $pidMatch = [regex]::Match($text, 'PID\s*=\s*(\d+)')
        $tidMatch = [regex]::Match($text, 'TID\s*=\s*(\d+)')
        if ($pidMatch.Success) { $result.ProcessId = $pidMatch.Groups[1].Value }
        if ($tidMatch.Success) { $result.ThreadId = $tidMatch.Groups[1].Value }
        if ($result.NavigatedUrl) {
            $fields = @{
                ApName='ap_name'; ApTags='ap_tags'; Sip='SIP'; Org='ORG'; Ui='UI'
                Psid='PSID'; LoginUrl='login_url'; Ma='MA'; Os='OS'; ApiDomain='api_domain'
            }
            foreach ($field in $fields.GetEnumerator()) {
                $result.($field.Key) = Get-CprCiscoWebHelperQueryParameter -Url $result.NavigatedUrl -ParameterName $field.Value
            }
            $result.ApMac = Get-CprCiscoWebHelperQueryParameterAny $result.NavigatedUrl @('ap_mac','cm')
            $result.OsName = Get-CprCiscoWebHelperQueryParameterAny $result.NavigatedUrl @('cp_da_osname')
            $result.OsVersion = Get-CprCiscoWebHelperQueryParameterAny $result.NavigatedUrl @('cp_da_osversion')
            $result.BrowserName = Get-CprCiscoWebHelperQueryParameterAny $result.NavigatedUrl @('cp_da_browsername')
            $result.BrowserVersion = Get-CprCiscoWebHelperQueryParameterAny $result.NavigatedUrl @('cp_da_browserversion')
            $result.DeviceType = Get-CprCiscoWebHelperQueryParameterAny $result.NavigatedUrl @('cp_da_type')
            $result.TraceId = Get-CprCiscoWebHelperQueryParameterAny $result.NavigatedUrl @('traceId','trace_id','traceid')
        }
        $result.Parsed = [bool]($result.NavigatedUrl -or $result.FinalUrl)
    } catch {
        Write-Log "Cisco WebHelper EventID 301 body parse failed: $_" "DEBUG"
    }
    return $result
}

function Get-CprCiscoWebHelperDedupeKey {
    param([string]$RecordId='', $EventTime=$null, [string]$ProcessId='', [string]$NavigatedUrl='', [string]$FinalUrl='')
    if ($RecordId) { return "record:$RecordId" }
    $timeToken = if ($EventTime) { ([datetime]$EventTime).ToString('o') } else { '' }
    return "fallback:t:$timeToken|pid:$ProcessId|nav:$NavigatedUrl|fin:$FinalUrl"
}

function New-CprCiscoWebHelperEvidenceResult {
    return [PSCustomObject]@{
        Found=$false; UsableNavigation=$false; ReadFailed=$false
        Source='cisco_webhelper_301'; Status='not_observed'; Reason='no_event_301'
        NavigatedUrl=''; FinalUrl=''; ProcessId=''; ThreadId=''; ApName=''; ApTags=''
        ApMac=''; Sip=''; Org=''; Ui=''; Psid=''; LoginUrl=''; Ma=''; Os=''
        ApiDomain=''; OsName=''; OsVersion=''; BrowserName=''; BrowserVersion=''
        DeviceType=''; TraceId=''; Protocol=''; Fqdn=''; Port=''; Classification=''
        EventRecordId=''; EventTime=$null; DedupeKey=''; QueriedCount=0; ExaminedCount=0
        SkippedSeenCount=0; RejectedStaleCount=0; RejectedContextCount=0
        NonNavigationCount=0; AcceptedCount=0; RecordLimitReached=$false
        NavigationStages=@(); TerminalReason='no_events'; Error=''
    }
}

function Find-CprCiscoWebHelper301Evidence {
    <#
    One bounded-query cycle against the actual Windows Event Log. RecordId is
    marked seen before the next poll so records are never repeatedly parsed.
    #>
    param(
        [Parameter(Mandatory)][datetime]$Since,
        [datetime]$Now = (Get-Date),
        [datetime]$CorrelationStart = [datetime]::MinValue,
        [string]$LogName = 'Cisco Secure Client',
        [string]$ProviderName = 'csc_webhelper',
        [int]$EventId = 301,
        [int]$MaximumAgeSeconds = 180,
        [int]$MaxEvents = 256,
        [string]$CurrentSsid = '',
        [hashtable]$SeenIdentities = @{}
    )
    $result = New-CprCiscoWebHelperEvidenceResult
    try {
        $filter = @{ LogName=$LogName; Id=$EventId; StartTime=$Since }
        if (-not [string]::IsNullOrWhiteSpace($ProviderName)) { $filter.ProviderName = $ProviderName }
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop |
            Sort-Object @{Expression='TimeCreated';Descending=$true}, @{Expression='RecordId';Descending=$true})
        $result.QueriedCount = $events.Count
        $result.RecordLimitReached = ($events.Count -ge $MaxEvents)
        $selected = $null
        $navigationStages = [System.Collections.Generic.List[object]]::new()
        foreach ($event in $events) {
            $recordId = if ($null -ne $event.RecordId) { [string]$event.RecordId } else { '' }
            $preKey = if ($recordId) {
                "record:$recordId"
            } else {
                "fallback:$($event.TimeCreated.ToString('o'))|$($event.ProviderName)|$($event.Id)|$([string]$event.Message)"
            }
            if ($SeenIdentities.ContainsKey($preKey)) { $result.SkippedSeenCount++; continue }
            $SeenIdentities[$preKey] = $true

            $eventTime = [datetime]$event.TimeCreated
            $ageSeconds = ($Now - $eventTime).TotalSeconds
            if (($CorrelationStart -ne [datetime]::MinValue -and $eventTime -lt $CorrelationStart) -or
                $ageSeconds -lt -5 -or $ageSeconds -gt $MaximumAgeSeconds) {
                $result.RejectedStaleCount++
                continue
            }

            $parsed = ConvertFrom-CprCiscoWebHelperNavigationBody -Body ([string]$event.Message)
            $result.ExaminedCount++
            if (-not $parsed.Parsed -or [string]::IsNullOrWhiteSpace($parsed.NavigatedUrl)) {
                $result.NonNavigationCount++
                if ($parsed.Parsed) { $result.Found = $true }
                continue
            }
            $details = Get-CprCiscoWebHelperUrlDetails -Url $parsed.NavigatedUrl
            if (-not $details.Fqdn -or $details.Protocol -notin @('http','https')) {
                $result.NonNavigationCount++
                $result.Found = $true
                continue
            }
            $eventSsid = Get-CprCiscoWebHelperQueryParameterAny $parsed.NavigatedUrl @('ssid','wlan')
            if ($eventSsid -and $CurrentSsid -and $CurrentSsid -ne 'N/A' -and
                -not $eventSsid.Equals($CurrentSsid, [System.StringComparison]::OrdinalIgnoreCase)) {
                $result.RejectedContextCount++
                continue
            }
            if ($null -eq $selected) {
                $selected = [PSCustomObject]@{
                    Parsed=$parsed; Event=$event; RecordId=$recordId; EventTime=$eventTime; Details=$details
                }
            }
            $navigationStages.Add([PSCustomObject]@{
                EventRecordId=$recordId; EventTime=$eventTime
                NavigatedUrl=$parsed.NavigatedUrl; FinalUrl=$parsed.FinalUrl
                ProcessId=$parsed.ProcessId; ThreadId=$parsed.ThreadId
            })
            $result.AcceptedCount++
        }
        $result.NavigationStages = @($navigationStages)
        if ($selected) {
            foreach ($property in $selected.Parsed.PSObject.Properties) {
                if ($property.Name -ne 'Parsed') { $result.($property.Name) = $property.Value }
            }
            $result.Found = $true; $result.UsableNavigation = $true
            $result.Status = 'observed'; $result.Reason = 'fresh_correlated_navigation'
            $result.TerminalReason = 'accepted'
            $result.EventRecordId = $selected.RecordId; $result.EventTime = $selected.EventTime
            $result.DedupeKey = Get-CprCiscoWebHelperDedupeKey $selected.RecordId $selected.EventTime `
                $selected.Parsed.ProcessId $selected.Parsed.NavigatedUrl $selected.Parsed.FinalUrl
            $result.Protocol = $selected.Details.Protocol; $result.Fqdn = $selected.Details.Fqdn
            $result.Port = $selected.Details.Port
            $result.Classification = if (Get-Command Get-RedirectType -ErrorAction SilentlyContinue) {
                Get-RedirectType -RedirectUrl $selected.Parsed.NavigatedUrl
            } else { 'NON_ISE' }
        } elseif ($result.RecordLimitReached) {
            $result.Reason = 'record_limit_reached'; $result.TerminalReason = 'record_limit_reached'
        } elseif ($result.RejectedContextCount -gt 0) {
            $result.Reason = 'context_mismatch'; $result.TerminalReason = 'context_mismatch'
        } elseif ($result.RejectedStaleCount -gt 0 -and $result.ExaminedCount -eq 0) {
            $result.Reason = 'all_stale'; $result.TerminalReason = 'all_stale'
        } elseif ($result.NonNavigationCount -gt 0) {
            $result.Status = 'navigation_unavailable'
            $result.Reason = 'no_navigation_url'; $result.TerminalReason = 'no_navigation_url'
        } else {
            $result.Reason = 'no_events'; $result.TerminalReason = 'no_events'
        }
    } catch {
        $result.ReadFailed = $true
        $result.Status = 'navigation_unavailable'
        $result.Reason = 'read_error'
        $result.TerminalReason = 'read_error'
        $result.Error = [string]$_.Exception.Message
    }
    return $result
}

function Get-CprHaystack301FallbackEvidence {
    param([string]$Path, [int]$LookbackSeconds = 120)
    $result = New-CprCiscoWebHelperEvidenceResult
    $result.Source = 'haystack_log_fallback'
    try {
        if (-not (Test-Path $Path)) { $result.Reason = 'haystack_log_unavailable'; return $result }
        if (((Get-Date) - (Get-Item $Path).LastWriteTime).TotalSeconds -gt $LookbackSeconds) {
            $result.Reason = 'haystack_log_stale'; return $result
        }
        foreach ($line in @(Get-Content -Path $Path -Tail 500 -ErrorAction Stop | Select-Object -Last 500)) {
            if ($line -notmatch '(?i)(Event(?:ID)?\s*=?\s*301|CaptivePotal_Action)') { continue }
            $parsed = ConvertFrom-CprCiscoWebHelperNavigationBody -Body ([string]$line)
            if (-not $parsed.NavigatedUrl) { continue }
            $details = Get-CprCiscoWebHelperUrlDetails $parsed.NavigatedUrl
            if (-not $details.Fqdn) { continue }
            foreach ($property in $parsed.PSObject.Properties) {
                if ($property.Name -ne 'Parsed') { $result.($property.Name) = $property.Value }
            }
            $result.Found=$true; $result.UsableNavigation=$true; $result.Status='observed'
            $result.Reason='diagnostic_log_navigation'; $result.Protocol=$details.Protocol
            $result.Fqdn=$details.Fqdn; $result.Port=$details.Port; $result.EventTime=(Get-Item $Path).LastWriteTime
            $result.Classification = if (Get-Command Get-RedirectType -ErrorAction SilentlyContinue) {
                Get-RedirectType $parsed.NavigatedUrl
            } else { 'NON_ISE' }
            return $result
        }
        $result.Reason = 'no_haystack_navigation'
    } catch {
        $result.Reason = 'haystack_log_read_failed'; $result.Error = [string]$_.Exception.Message
    }
    return $result
}

function Wait-CprCiscoWebHelper301Evidence {
    param(
        [datetime]$CorrelationStart = (Get-Date),
        [int]$LookbackSeconds = 180, [int]$MaxRecords = 256,
        [int]$WaitSeconds = 3, [int]$PollIntervalMs = 250,
        [int]$MaximumAgeSeconds = 180, [string]$LogName = 'Cisco Secure Client',
        [string]$ProviderName = 'csc_webhelper', [int]$EventId = 301,
        [string]$CurrentSsid = '',
        [bool]$NoUrlImmediatePreflight = $true, [bool]$HaystackFallbackEnabled = $false,
        [string]$HaystackLogPath = 'C:\ProgramData\WhiteWalker\logs\haystack.log',
        [int]$HaystackLookbackSeconds = 120
    )
    $started = Get-Date
    $since = $CorrelationStart.AddSeconds(-[math]::Max(0, $LookbackSeconds))
    # Cisco can emit the usable navigation before Main reaches its network-ready
    # landmark. Keep the full bounded lookback eligible; provider/channel, event
    # age and RecordId freshness are sufficient when the event has no network
    # identity fields to correlate.
    $correlationFloor = $since
    $seen = @{}
    $last = New-CprCiscoWebHelperEvidenceResult
    $aggregate = @{
        QueriedCount=0; ExaminedCount=0; SkippedSeenCount=0; RejectedStaleCount=0
        RejectedContextCount=0; NonNavigationCount=0; AcceptedCount=0
        RecordLimitReached=$false
    }
    do {
        $last = Find-CprCiscoWebHelper301Evidence -Since $since -Now (Get-Date) `
            -CorrelationStart $correlationFloor -LogName $LogName -ProviderName $ProviderName `
            -EventId $EventId -MaximumAgeSeconds $MaximumAgeSeconds -MaxEvents $MaxRecords `
            -CurrentSsid $CurrentSsid -SeenIdentities $seen
        $aggregate.QueriedCount = [math]::Max($aggregate.QueriedCount, $last.QueriedCount)
        foreach ($countName in @('ExaminedCount','SkippedSeenCount','RejectedStaleCount',
            'RejectedContextCount','NonNavigationCount','AcceptedCount')) {
            $aggregate[$countName] += [int]$last.$countName
        }
        $aggregate.RecordLimitReached = ($aggregate.RecordLimitReached -or $last.RecordLimitReached)
        if ($last.UsableNavigation -or
            ($last.Found -and $NoUrlImmediatePreflight) -or
            $last.ReadFailed) { break }
        if (((Get-Date) - $started).TotalSeconds -ge $WaitSeconds) { break }
        Start-Sleep -Milliseconds ([math]::Max(50, $PollIntervalMs))
    } while (((Get-Date) - $started).TotalSeconds -lt $WaitSeconds)

    foreach ($countName in @('QueriedCount','ExaminedCount','SkippedSeenCount','RejectedStaleCount',
        'RejectedContextCount','NonNavigationCount','AcceptedCount')) {
        $last.$countName = $aggregate[$countName]
    }
    $last.RecordLimitReached = $aggregate.RecordLimitReached
    if (-not $last.UsableNavigation -and -not $last.ReadFailed) {
        if ($last.RecordLimitReached) {
            $last.Reason = 'record_limit_reached'; $last.TerminalReason = 'record_limit_reached'
        } elseif ($last.RejectedContextCount -gt 0) {
            $last.Reason = 'context_mismatch'; $last.TerminalReason = 'context_mismatch'
        } elseif ($last.RejectedStaleCount -gt 0 -and $last.ExaminedCount -eq 0) {
            $last.Reason = 'all_stale'; $last.TerminalReason = 'all_stale'
        } elseif ($last.NonNavigationCount -gt 0) {
            $last.Reason = 'no_navigation_url'; $last.TerminalReason = 'no_navigation_url'
        } else {
            $last.Reason = 'no_events'; $last.TerminalReason = 'no_events'
        }
    }
    Write-Log ("webhelper_301_lookup source=event_log lookback_sec={0} max_records={1} queried={2} examined={3} no_navigation_url={4} rejected_stale={5} rejected_context={6} accepted={7} selected_record_id='{8}' selected_event_time='{9}' terminal_reason='{10}'" -f `
        $LookbackSeconds, $MaxRecords, $last.QueriedCount, $last.ExaminedCount, `
        $last.NonNavigationCount, $last.RejectedStaleCount, $last.RejectedContextCount, `
        $last.AcceptedCount, $last.EventRecordId, $last.EventTime, $last.TerminalReason) `
        $(if ($last.UsableNavigation) { 'INFO' } elseif ($last.ReadFailed) { 'WARN' } else { 'DEBUG' })
    if ($last.ReadFailed -and $HaystackFallbackEnabled) {
        $fallback = Get-CprHaystack301FallbackEvidence -Path $HaystackLogPath -LookbackSeconds $HaystackLookbackSeconds
        if ($fallback.UsableNavigation) { return $fallback }
    }
    return $last
}

function Test-CprCiscoWebHelperActive {
    try {
        return [bool](Get-Process -Name @('csc_webhelper','acwebhelper','CiscoWebHelper','CiscoAnyConnectWebView') -ErrorAction SilentlyContinue | Select-Object -First 1)
    } catch { return $false }
}

function Test-CprWebHelperCanSuppressPreflight {
    param($Evidence, [bool]$SuppressEnabled = $true)
    return [bool]($SuppressEnabled -and $Evidence -and $Evidence.UsableNavigation -and
        $Evidence.Source -eq 'cisco_webhelper_301' -and
        $Evidence.Classification -ne 'ISE_EMPLOYEE')
}

function Write-CprCiscoWebHelper301Evidence {
    param([Parameter(Mandatory)]$Evidence, [hashtable]$NetworkContext=@{}, [string]$VpnState='')
    try {
        Write-Log ("cap_portal_webhelper_navigation detection_source={0} status={1} reason={2} event_time='{3}' record_id='{4}' pid='{5}' navigated_url='{6}' final_url='{7}' classification='{8}' protocol='{9}' fqdn='{10}' port='{11}' ssid='{12}' ip='{13}' gw='{14}'" -f `
            $Evidence.Source, $Evidence.Status, $Evidence.Reason, $Evidence.EventTime, $Evidence.EventRecordId, `
            $Evidence.ProcessId, $Evidence.NavigatedUrl, $Evidence.FinalUrl, $Evidence.Classification, `
            $Evidence.Protocol, $Evidence.Fqdn, $Evidence.Port, $NetworkContext.ssid, $NetworkContext.ip, $NetworkContext.gw) `
            $(if ($Evidence.UsableNavigation) { 'WARN' } elseif ($Evidence.Found) { 'INFO' } else { 'DEBUG' })
        Write-TeeLog 'cap_portal_webhelper_navigation' @{
            EvtTime=$(if ($Evidence.EventTime) { ([datetime]$Evidence.EventTime).ToString('o') } else { (Get-Date -Format 'o') })
            detection_source=[string]$Evidence.Source; navigated_url=[string]$Evidence.NavigatedUrl
            final_url=[string]$Evidence.FinalUrl; process_id=[string]$Evidence.ProcessId
            thread_id=[string]$Evidence.ThreadId; ap_name=[string]$Evidence.ApName
            ap_tags=[string]$Evidence.ApTags; ap_mac=[string]$Evidence.ApMac; sip=[string]$Evidence.Sip
            org=[string]$Evidence.Org; ui=[string]$Evidence.Ui; psid=[string]$Evidence.Psid
            login_url=[string]$Evidence.LoginUrl; ma=[string]$Evidence.Ma; os=[string]$Evidence.Os
            api_domain=[string]$Evidence.ApiDomain; os_name=[string]$Evidence.OsName
            os_version=[string]$Evidence.OsVersion; browser_name=[string]$Evidence.BrowserName
            browser_version=[string]$Evidence.BrowserVersion; device_type=[string]$Evidence.DeviceType
            trace_id=[string]$Evidence.TraceId; event_record_id=[string]$Evidence.EventRecordId
            event_source='Cisco Secure Client EventID 301'; event_time=$(if ($Evidence.EventTime) { ([datetime]$Evidence.EventTime).ToString('o') } else { '' })
            status=[string]$Evidence.Status; reason=[string]$Evidence.Reason
            classification=[string]$Evidence.Classification; protocol=[string]$Evidence.Protocol
            fqdn=[string]$Evidence.Fqdn; port=[string]$Evidence.Port
            ssid=[string]$NetworkContext.ssid; ip=[string]$NetworkContext.ip
            gw=[string]$NetworkContext.gw; dns=[string]$NetworkContext.dns; vpn_state=$VpnState
        }
    } catch { Write-Log "Failed to log/tee Cisco WebHelper EventID 301 evidence: $_" "WARN" }
}

function New-CprWebHelperPreflightResult {
    param($Evidence)
    if ($null -eq $Evidence -or -not $Evidence.UsableNavigation -or -not $Evidence.NavigatedUrl) { return $null }
    return [PSCustomObject]@{
        Status='redirect'; Classification='REDIRECT'; RedirectUrl=$Evidence.NavigatedUrl
        RedirectType=$Evidence.Classification; Protocol=$Evidence.Protocol; Fqdn=$Evidence.Fqdn
        Port=$Evidence.Port; HttpStatus=''; ProbeUrl=''
        Reason='cisco_webhelper_301_navigation'; DetectionSource=$Evidence.Source
        ObservationTime=$(if ($Evidence.EventTime) { ([datetime]$Evidence.EventTime).ToString('o') } else { (Get-Date -Format 'o') })
    }
}

function Clear-CaptivePortalFlag {
    if (Test-Path $FlagFile) {
        try {
            Remove-Item -Path $FlagFile -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared captive portal flag file" "DEBUG"
        } catch {
            Write-Log "Failed to clear captive portal flag file: $_" "WARN"
        }
    }
}

function Get-CaptiveEventCount {
    try {
        if (-not $global:_state.captiveEvents) {
            $global:_state | Add-Member -NotePropertyName captiveEvents -NotePropertyValue @() -Force
        }
        
        $now = Get-Date
        $recentEvents = @()
        
        foreach ($eventTime in $global:_state.captiveEvents) {
            try {
                $when = [datetime]::Parse($eventTime)
                if (($now - $when).TotalMinutes -lt $CaptiveEventCooldown) {
                    $recentEvents += $eventTime
                }
            } catch { }
        }
        
        $global:_state.captiveEvents = $recentEvents
        Save-State $global:_state
        
        return $recentEvents.Count
    } catch {
        Write-Log "Error checking captive event count: $_" "DEBUG"
        return 0
    }
}

function Add-CaptiveEvent {
    try {
        if (-not $global:_state.captiveEvents) {
            $global:_state | Add-Member -NotePropertyName captiveEvents -NotePropertyValue @() -Force
        }
        
        $global:_state.captiveEvents += (Get-Date).ToString('o')
        Save-State $global:_state
    } catch {
        Write-Log "Error recording captive event: $_" "DEBUG"
    }
}

function Clear-CaptiveEventHistory {
    param([string]$Reason = "successful connection")
    try {
        if ($global:_state.captiveEvents -and $global:_state.captiveEvents.Count -gt 0) {
            Write-Log "Clearing captive event history due to: $Reason (was: $($global:_state.captiveEvents.Count) events)" "DEBUG"
            $global:_state.captiveEvents = @()
            Save-State $global:_state
            
            try {
                $eventArgs = @("/T", "INFORMATION", "/ID", "0", "/L", "APPLICATION", "/SO", "WhiteWalker", "/D", "Network Connection Established")
                Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Network connection success event logged (ID 0)" "DEBUG"
            } catch {
                Write-Log "Failed to log success event: $_" "DEBUG"
            }
        }
        
        if (Test-Path $CaptiveFailureFlag) {
            Remove-Item $CaptiveFailureFlag -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared captive portal failure flag due to: $Reason" "DEBUG"
        }
    } catch {
        Write-Log "Error clearing captive event history: $_" "DEBUG"
    }
}

function Show-CaptivePortalAlert {
    param([int]$EventCount)
    
    Write-Log "Showing BLOCKING user alert for repeated captive portal failures (count: $EventCount)" "WARN"
    
    $currentSSID = $null
    $isWiFiConnected = $false
    
    try {
        $wifiAdapter = Get-NetAdapter | Where-Object { 
            $_.Status -eq 'Up' -and 
            $_.Name -match "Wi-Fi|Wireless|802\.11" 
        } | Select-Object -First 1
        
        if ($wifiAdapter) {
            $netshOutput = netsh wlan show interfaces 2>$null
            if ($netshOutput -and ($netshOutput -match 'State\s+:\s+connected')) {
                $isWiFiConnected = $true
                if ($netshOutput -match 'SSID\s+:\s+(.+)') {
                    $currentSSID = $matches[1].Trim()
                    Write-Log "WiFi connected to SSID: $currentSSID" "INFO"
                }
            } else {
                Write-Log "WiFi adapter exists but not connected to any network" "WARN"
            }
        } else {
            Write-Log "No active WiFi adapter found - may be on Ethernet" "INFO"
        }
    } catch {
        Write-Log "Could not detect WiFi status: $_" "DEBUG"
    }
    
    try {
        $eventArgs = @("/T", "WARNING", "/ID", "1", "/L", "APPLICATION", "/SO", "WhiteWalker", "/D", "Maximum ($EventCount) Connection Attempts Reached. Prompted user to exit browsers and disconnect/reconnect to the network, to reattempt")
        Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Captive portal failure event logged (ID 1) with count: $EventCount" "INFO"
    } catch {
        Write-Log "Failed to log failure event: $_" "WARN"
    }
    
    try {
        $promptContent = @{
            timestamp = (Get-Date).ToString('o')
            event_count = $EventCount
            message = "User prompted for captive portal connection failure"
        } | ConvertTo-Json -Compress
        
        Set-Content -Path $UserPromptedFlag -Value $promptContent -Encoding UTF8
        Write-Log "User prompted flag created - all future script executions will be blocked" "INFO"
    } catch {
        Write-Log "Failed to create user prompted flag: $_" "WARN"
    }
}

function Show-CaptivePortalAlert {
    param([int]$EventCount)
    
    Write-Log "Showing BLOCKING user alert for repeated captive portal failures (count: $EventCount)" "WARN"
    
    $currentSSID = $null
    $isWiFiConnected = $false
    
    try {
        $wifiAdapter = Get-NetAdapter | Where-Object { 
            $_.Status -eq 'Up' -and 
            $_.Name -match "Wi-Fi|Wireless|802\.11" 
        } | Select-Object -First 1
        
        if ($wifiAdapter) {
            $netshOutput = netsh wlan show interfaces 2>$null
            if ($netshOutput -and ($netshOutput -match 'State\s+:\s+connected')) {
                $isWiFiConnected = $true
                if ($netshOutput -match 'SSID\s+:\s+(.+)') {
                    $currentSSID = $matches[1].Trim()
                    Write-Log "WiFi connected to SSID: $currentSSID" "INFO"
                }
            } else {
                Write-Log "WiFi adapter exists but not connected to any network" "WARN"
            }
        } else {
            Write-Log "No active WiFi adapter found - may be on Ethernet" "INFO"
        }
    } catch {
        Write-Log "Could not detect WiFi status: $_" "DEBUG"
    }
    
    try {
        $eventArgs = @("/T", "WARNING", "/ID", "1", "/L", "APPLICATION", "/SO", "WhiteWalker", "/D", "Maximum ($EventCount) Connection Attempts Reached. Prompted user to exit browsers and disconnect/reconnect to the network, to reattempt")
        Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Captive portal failure event logged (ID 1) with count: $EventCount" "INFO"
    } catch {
        Write-Log "Failed to log failure event: $_" "WARN"
    }
    
    try {
        $promptContent = @{
            timestamp = (Get-Date).ToString('o')
            event_count = $EventCount
            message = "User prompted for captive portal connection failure"
        } | ConvertTo-Json -Compress
        
        Set-Content -Path $UserPromptedFlag -Value $promptContent -Encoding UTF8
        Write-Log "User prompted flag created - all future script executions will be blocked" "INFO"
    } catch {
        Write-Log "Failed to create user prompted flag: $_" "WARN"
    }
    
    $alertTitle = "Optum Employee Connectivity"
    $alertMessage = ""
    
    if ($isWiFiConnected -and $currentSSID) {
        $alertMessage = @"
There seems to be an issue connecting to this Captive Portal Network.

Network: $currentSSID

WhiteWalker will now disconnect and reconnect you to the network automatically.

Please wait while we attempt to reconnect...

- Optum Employee Connectivity
"@
    } elseif ($isWiFiConnected) {
        $alertMessage = @"
There seems to be an issue connecting to this Captive Portal Network.

Network: Unknown WiFi Network

WhiteWalker will now disconnect and reconnect you to the network automatically.

Please wait while we attempt to reconnect...

- Optum Employee Connectivity
"@
    } else {
        $alertMessage = @"
There seems to be an issue connecting to this Captive Portal Network.

Connection Type: Wired/Ethernet or WiFi Disconnected

Please disconnect from the network and reconnect manually to try again.

- Optum Employee Connectivity
"@
    }

    $userClickedOK = $false
    try {
        if (-not $WhatIf) {
            Add-Type -AssemblyName System.Windows.Forms
            
            $form = New-Object System.Windows.Forms.Form
            $form.Text = $alertTitle
            $form.Size = New-Object System.Drawing.Size(450,280)
            $form.StartPosition = "CenterScreen"
            $form.TopMost = $true
            
            $label = New-Object System.Windows.Forms.Label
            $label.Location = New-Object System.Drawing.Point(10,20)
            $label.Size = New-Object System.Drawing.Size(420,140)
            $label.Text = $alertMessage
            $form.Controls.Add($label)
            
            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Location = New-Object System.Drawing.Point(175,190)
            $okButton.Size = New-Object System.Drawing.Size(100,30)
            $okButton.Text = "OK"
            $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Controls.Add($okButton)
            $form.AcceptButton = $okButton
            
            $timer = New-Object System.Windows.Forms.Timer
            $timer.Interval = 5000
            $timer.Add_Tick({
                $form.Close()
            })
            $timer.Start()
            
            $result = $form.ShowDialog()
            $timer.Stop()
            
            Write-Log "User alert shown (WiFi: $isWiFiConnected, SSID: $currentSSID) - auto-proceeds after 5s or user clicks OK" "INFO"
            $userClickedOK = $true
            
        } else {
            Write-Log "WHATIF: Would show user alert with auto-reconnect for WiFi: $isWiFiConnected, SSID: $currentSSID" "INFO"
            $userClickedOK = $true
        }
    } catch {
        Write-Log "Failed to show user alert: $_" "ERROR"
        $userClickedOK = $true
    }
    
    if ($userClickedOK -and $isWiFiConnected) {
        try {
            Write-Log "Attempting automatic WiFi reconnection..." "INFO"
            
            if ($currentSSID) {
                Write-Log "Disconnecting from WiFi..." "INFO"
                & netsh wlan disconnect | Out-Null
                Start-Sleep -Seconds 3
                
                Write-Log "Reconnecting to SSID: $currentSSID" "INFO"
                & netsh wlan connect name="$currentSSID" | Out-Null
                Start-Sleep -Seconds 5
                
                Write-Log "WiFi reconnection completed" "INFO"
            } else {
                Write-Log "WiFi connected but SSID unknown - attempting disconnect/reconnect anyway" "WARN"
                & netsh wlan disconnect | Out-Null
                Start-Sleep -Seconds 3
                Write-Log "Waiting for Windows to auto-reconnect to preferred network..." "INFO"
                Start-Sleep -Seconds 3
            }
            
        } catch {
            Write-Log "Error during WiFi reconnection: $_" "ERROR"
            Write-Log "User will need to manually reconnect" "WARN"
        }
    } elseif ($userClickedOK -and -not $isWiFiConnected) {
        Write-Log "Not on WiFi - skipping auto-reconnect, user must reconnect manually" "INFO"
    }
    
    try {
        Remove-Item $UserPromptedFlag -Force -ErrorAction SilentlyContinue
        Write-Log "User prompted flag cleared - script executions can resume" "INFO"
        
        Clear-CaptiveEventHistory "user alert acknowledged"
        
    } catch {
        Write-Log "Error clearing flags: $_" "WARN"
    }
}

function Test-UserPromptedFlag {
    if (Test-Path $UserPromptedFlag) {
        try {
            $promptContent = Get-Content $UserPromptedFlag -Raw | ConvertFrom-Json
            $promptTime = [datetime]::Parse($promptContent.timestamp)
            $promptAge = (Get-Date) - $promptTime
            
            Write-Log "User prompted flag exists - script execution blocked (age: $([math]::Round($promptAge.TotalMinutes, 1)) minutes)" "INFO"
            Write-Log "Exited. Waiting on user response" "INFO"
            
            return $true
        } catch {
            Write-Log "Error reading user prompted flag, removing: $_" "WARN"
            Remove-Item $UserPromptedFlag -Force -ErrorAction SilentlyContinue
            return $false
        }
    }
    return $false
}

function Get-CaptivePortalResult {
    param([int]$TimeoutSeconds = $CaptivePortalTimeout)
    
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($TimeoutSeconds)
    
    $initialSnapshot = $null
    if (Test-Path variable:networkInfo) {
        $initialSnapshot = Get-Variable -Name networkInfo -ValueOnly -ErrorAction SilentlyContinue
    }
    $initialNetworkInfo = Get-CprCurrentNetworkSnapshot -Snapshot $initialSnapshot
    $initialFingerprint = $initialNetworkInfo.Fingerprint
    Write-Log "Initial network fingerprint: $initialFingerprint" "DEBUG"
    
    Write-Log "Waiting for captive portal remediation - Start: $($startTime.ToString('HH:mm:ss'))" "INFO"
    Write-Log "Will wait until: $($endTime.ToString('HH:mm:ss')) (up to $TimeoutSeconds seconds)" "INFO"
    
    $lastLogTime = $startTime
    $lastNetworkCheckTime = $startTime
    $lastPortalCheckTime = $startTime
    $lastInterruptCheckTime = $startTime
    $logInterval = 10
    $networkCheckInterval = 5
    $portalCheckInterval = 15
    $interruptCheckInterval = 2
    
    while ((Get-Date) -lt $endTime) {
        $now = Get-Date
        
        if (($now - $lastInterruptCheckTime).TotalSeconds -ge $interruptCheckInterval) {
            if (Test-Path $InterruptFile) {
                Write-Log "Network interrupt detected - aborting captive portal wait" "WARN"
                try {
                    Remove-Item $InterruptFile -Force -ErrorAction SilentlyContinue
                } catch { }
                return @{
                    status = "INTERRUPTED"
                    details = "Network change detected during wait"
                    user = "SYSTEM"
                    captive_browser_pid = 0
                }
            }
            $lastInterruptCheckTime = $now
        }
        
        if (($now - $lastPortalCheckTime).TotalSeconds -ge $portalCheckInterval) {
            if (Test-CaptivePortalCleared) {
                $elapsed = ($now - $startTime).TotalSeconds
                Write-Log "Portal cleared during wait after $([math]::Round($elapsed))s - exiting early!" "INFO"
                return @{
                    status = "SUCCESS"
                    details = "Portal cleared early during wait (detected at ${elapsed}s)"
                    user = "SYSTEM"
                    captive_browser_pid = 0
                }
            }
            $lastPortalCheckTime = $now
        }
        
        if (($now - $lastNetworkCheckTime).TotalSeconds -ge $networkCheckInterval) {
            $freshness = Test-CprNetworkSnapshotFresh -Snapshot $initialNetworkInfo
            if ($freshness.Fresh) {
                $currentNetworkInfo = $initialNetworkInfo
                $currentFingerprint = $freshness.Fingerprint
                Write-Log "network_snapshot_freshness fresh=true reason='fingerprint_match' use='captive_wait'" "DEBUG"
            } else {
                Write-Log "network_snapshot_freshness fresh=false reason='$($freshness.Reason)' use='captive_wait' - rebuilding" "INFO"
                $currentNetworkInfo = Get-NetworkInfo
                $currentFingerprint = $currentNetworkInfo.Fingerprint
                $initialNetworkInfo = $currentNetworkInfo
            }
            
            if ($currentFingerprint -ne $initialFingerprint) {
                Write-Log "Network change detected during wait!" "WARN"
                Write-Log "  Initial: $initialFingerprint" "WARN"
                Write-Log "  Current: $currentFingerprint" "WARN"
                return @{
                    status = "NETWORK_CHANGED"
                    details = "Network switched during captive portal authentication"
                    user = "SYSTEM"
                    captive_browser_pid = 0
                }
            }
            $lastNetworkCheckTime = $now
        }
        
        if (Test-Path $FlagFile) {
            try {
                $flagContent = Get-Content -Path $FlagFile -Raw -ErrorAction Stop
                $result = $flagContent | ConvertFrom-Json -ErrorAction Stop
                
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                Write-Log "Captive portal flag found after $([math]::Round($elapsed))s: Status=$($result.status), User=$($result.user)" "INFO"
                if ($result.details) {
                    Write-Log "Details: $($result.details)" "DEBUG"
                }
                # Base runs in a separate USER-context process.  Render its two
                # independent observations here when the completion artifact arrives;
                # older runners do not have these properties and remain compatible.
                if ($null -ne $result.base_preflight_observation) {
                    $preflight = $result.base_preflight_observation
                    Write-Log "Base passive preflight: status='$($preflight.status)' probe_url='$($preflight.probe_url)' http_status='$($preflight.http_status)' redirect_url='$($preflight.redirect_url)' reason='$($preflight.reason)'" "INFO"
                    if ($preflight.status -eq 'redirect') {
                        Write-Log "Base nwcheck: REDIRECT to $($preflight.redirect_url)" "INFO"
                        Write-Log "Base redirect classification: $($preflight.redirect_type)" "INFO"
                        Write-Log "Base observed this redirect without acting on it - follow-up routing (e.g. ISE_EMPLOYEE posture rescan) is Main's responsibility" "INFO"
                    } else {
                        # An inconclusive Base probe is NOT proof that no portal
                        # exists - say so explicitly rather than leaving a blank.
                        $preflightReason = if ($preflight.reason) { $preflight.reason } else { 'no_reason_reported' }
                        Write-Log "Base nwcheck: $(([string]$preflight.status).ToUpper()) - no usable redirect (classification='$($preflight.classification)' reason='$preflightReason') - inconclusive, not proof of a clean network" "WARN"
                    }
                } else {
                    Write-Log "Base passive preflight: unavailable (completion artifact from older runner or no observation) - reason='no_base_preflight_result'" "WARN"
                }
                if ($null -ne $result.base_webhelper_navigation) {
                    $navigation = $result.base_webhelper_navigation
                    Write-Log "Cisco WebHelper navigation: navigated_url='$($navigation.navigated_url)' final_url='$($navigation.final_url)' final_url_port='$($navigation.final_url_port)' ap_name='$($navigation.ap_name)' ap_mac='$($navigation.ap_mac)' os='$($navigation.os)' source='Cisco Secure Client EventID 301' event_time='$($navigation.event_time)' reason='$($navigation.reason)'" $(if ($navigation.observed) { 'INFO' } else { 'WARN' })
                } else {
                    # EventID 301/WebView2 is OPTIONAL corroboration. Its absence
                    # is normal for on-prem ISE and never changes classification.
                    $navReason = if ($null -ne $result.base_preflight_observation -and
                                     $result.base_preflight_observation.redirect_type -eq 'ISE_EMPLOYEE') {
                        'not_applicable_ise_employee_no_event_301'
                    } else {
                        'no_event_301'
                    }
                    Write-Log "Cisco WebHelper navigation: not_applicable (optional corroboration only) reason='$navReason'" "INFO"
                }
                
                return $result
                
            } catch {
                Write-Log "Error reading captive portal flag file: $_" "WARN"
                Start-Sleep -Seconds $MainPortalFlagPollIntervalSec
                continue
            }
        }
        
        if (($now - $lastLogTime).TotalSeconds -ge $logInterval) {
            $elapsed = ($now - $startTime).TotalSeconds
            $remaining = ($endTime - $now).TotalSeconds
            Write-Log "Still waiting for remediation... Elapsed: $([math]::Round($elapsed))s, Remaining: $([math]::Round($remaining))s" "DEBUG"
            $lastLogTime = $now
        }
        
        Start-Sleep -Seconds $MainPortalFlagPollIntervalSec
    }
    
    $totalElapsed = ((Get-Date) - $startTime).TotalSeconds
    Write-Log "Captive portal polling timeout reached after $([math]::Round($totalElapsed))s" "WARN"
    return $null
}

function Test-CaptivePortalCompatibility {
    <#
    .SYNOPSIS
    Analyze captive portal redirect URL for known compatibility issues
    
    .DESCRIPTION
    Checks redirect URL for patterns known to cause issues with corporate security policies:
    - Non-HTTPS (blocked by browser policy)
    - Non-standard ports (blocked by Defender firewall)
    - IP-based redirects (may not work)
    - Certificate issues (name mismatch, expired, self-signed)
    
    Only runs AFTER captive portal is detected, doesn't impact normal workflow.
    #>
    param([string]$RedirectUrl)
    
    $issues = @{
        HasIssues = $false
        IssueType = "NONE"
        Description = ""
        UserMessage = ""
        AllowRetry = $true
    }
    
    if ([string]::IsNullOrEmpty($RedirectUrl)) {
        return $issues
    }
    
    try {
        $uri = [System.Uri]$RedirectUrl
        
        # Check 1: Non-HTTPS redirect (blocked by browser security policy)
        if ($uri.Scheme -eq "http") {
            $issues.HasIssues = $true
            $issues.IssueType = "NON_HTTPS"
            $issues.Description = "Captive portal uses insecure HTTP (blocked by browser policy)"
            $issues.UserMessage = "This network uses an insecure captive portal that is blocked by corporate security policy. Connection may not be possible."
            $issues.AllowRetry = $false  # Retrying won't help
            Write-Log "CAPTIVE PORTAL ISSUE: Non-HTTPS redirect detected: $RedirectUrl" "WARN"
            return $issues
        }
        
        # Check 2: Non-standard port (may be blocked by Defender)
        if ($uri.Port -ne 80 -and $uri.Port -ne 443 -and $uri.Port -ne -1) {
            $issues.HasIssues = $true
            $issues.IssueType = "NON_STANDARD_PORT"
            $issues.Description = "Captive portal uses non-standard port $($uri.Port) (may be blocked by firewall)"
            $issues.UserMessage = "This network uses port $($uri.Port) which MAY be blocked by corporate firewall. Connection MAY fail."
            $issues.AllowRetry = $true  # Might work, let user try
            Write-Log "CAPTIVE PORTAL ISSUE: Non-standard port detected: $($uri.Port) in $RedirectUrl" "WARN"
            return $issues
        }
        
        # Check 3: IP-based redirect (no FQDN)
        $ipPattern = '^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if ($RedirectUrl -match $ipPattern) {
            $issues.HasIssues = $true
            $issues.IssueType = "IP_BASED_REDIRECT"
            $issues.Description = "Captive portal redirects to IP address instead of FQDN"
            $issues.UserMessage = "This network redirects to an IP address which MAY cause certificate errors. Connection may work but could be unreliable."
            $issues.AllowRetry = $true
            Write-Log "CAPTIVE PORTAL ISSUE: IP-based redirect detected: $RedirectUrl" "INFO"
            return $issues
        }
        
        # Check 4: Test if DNS resolution works for the redirect URL
        # This is the chicken/egg problem: DNS blocked until captive portal accepted,
        # but can't accept terms without DNS to reach the portal
        if ($uri.Scheme -eq "https" -or $uri.Scheme -eq "http") {
            try {
                $dnsTest = [System.Net.Dns]::GetHostEntry($uri.Host)
                Write-Log "DNS resolution successful for $($uri.Host)" "DEBUG"
            } catch {
                $issues.HasIssues = $true
                $issues.IssueType = "DNS_BLOCKED"
                $issues.Description = "DNS resolution blocked until captive portal accepted (chicken/egg problem)"
                $issues.UserMessage = "This network blocks DNS resolution until you accept terms, but the captive portal URL requires DNS to load. This is a network misconfiguration - contact the network administrator."
                $issues.AllowRetry = $false  # Retrying won't fix DNS
                Write-Log "CAPTIVE PORTAL ISSUE: DNS resolution failed for $($uri.Host) - chicken/egg problem detected" "WARN"
                return $issues
            }
        }
        
        # Check 5: Certificate validation (HTTPS only)
        if ($uri.Scheme -eq "https") {
            try {
                $certCheck = [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $req = [System.Net.HttpWebRequest]::Create($RedirectUrl)
                $req.Timeout = 5000
                $req.AllowAutoRedirect = $false
                
                try {
                    $response = $req.GetResponse()
                    $response.Close()
                } catch [System.Net.WebException] {
                    $webEx = $_.Exception
                    
                    # Check for certificate errors in exception
                    if ($webEx.Message -match "certificate|SSL|TLS") {
                        $issues.HasIssues = $true
                        $issues.IssueType = "CERTIFICATE_ERROR"
                        $issues.Description = "Captive portal has certificate validation errors"
                        $issues.UserMessage = "This network has SSL certificate problems (expired, self-signed, or name mismatch). Connection MAY fail due to security policy."
                        $issues.AllowRetry = $false
                        Write-Log "CAPTIVE PORTAL ISSUE: Certificate error detected for $RedirectUrl : $($webEx.Message)" "WARN"
                        return $issues
                    }
                }
                
            } catch {
                # Don't fail the whole check if cert validation fails
                Write-Log "Could not validate certificate for $RedirectUrl : $_" "DEBUG"
            } finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }
        }
        
        # No issues detected
        Write-Log "Captive portal compatibility check passed for $RedirectUrl" "DEBUG"
        return $issues
        
    } catch {
        Write-Log "Error analyzing captive portal URL $RedirectUrl : $_" "WARN"
        return $issues  # Return no issues if we can't parse
    }
}

function Get-CaptivePortalRedirectTelemetry {
    param([string]$RedirectUrl)

    $telemetry = [ordered]@{
        url      = ""
        port     = ""
        protocol = ""
        fqdn     = ""
    }

    if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
        return $telemetry
    }

    $telemetry.url = $RedirectUrl

    try {
        $uri = $null
        if ([System.Uri]::TryCreate($RedirectUrl, [System.UriKind]::Absolute, [ref]$uri) -and $uri) {
            # RC1.25: protocol/fqdn are handed to the base runner via the
            # remediation state file so a separate-process runner can rebuild
            # the same url/port without guessing.
            $telemetry.protocol = $uri.Scheme
            $telemetry.fqdn     = $uri.Host
            if ($uri.Port -gt 0) {
                $telemetry.port = [string]$uri.Port
            } else {
                switch ($uri.Scheme.ToLowerInvariant()) {
                    "http"  { $telemetry.port = "80" }
                    "https" { $telemetry.port = "443" }
                    default { $telemetry.port = "" }
                }
            }
        } else {
            $telemetry.port = "unknown"
            Write-Log "Could not parse captive portal redirect URL '$RedirectUrl' for telemetry port extraction" "DEBUG"
        }
    } catch {
        $telemetry.port = "unknown"
        Write-Log "Failed to parse captive portal redirect URL '$RedirectUrl' for telemetry: $_" "DEBUG"
    }

    return $telemetry
}

function ConvertTo-TelemetryValue {
    <#
    .SYNOPSIS
    Normalizes a gathered value for normalized cap_portal_* telemetry.
    Placeholder values Get-NetworkInfo uses for "not determined" ("N/A",
    "Unknown", "none") become an explicit empty string so Splunk shows an
    empty field rather than a fake value. Never fabricates data.
    #>
    param($Value)

    if ($null -eq $Value) { return '' }
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }
    if (@('n/a', 'unknown', 'none', '(none)') -contains $text.ToLowerInvariant()) { return '' }
    return $text
}

function Test-CprAccepted301RemediationEvidence {
    param($Evidence = $script:LastWebHelper301Evidence)
    if ($null -eq $Evidence -or -not $Evidence.UsableNavigation -or
        $Evidence.Source -ne 'cisco_webhelper_301' -or
        [string]::IsNullOrWhiteSpace([string]$Evidence.NavigatedUrl) -or
        $Evidence.Classification -eq 'ISE_EMPLOYEE') {
        return $false
    }
    try {
        $ageSec = ((Get-Date) - [datetime]$Evidence.EventTime).TotalSeconds
        return ($ageSec -ge -5 -and $ageSec -le $CapPortalWebHelper301MaxAgeSec)
    } catch {
        return $false
    }
}

function Get-CaptivePortalNetworkContext {
    <#
    .SYNOPSIS
    Best-available ssid/ip/gw/dns for normalized cap_portal_* telemetry,
    read from the $networkInfo snapshot the current run already gathered.

    RC1.25: these four fields were never attached to cap_portal_* events, so
    every captive portal row in Splunk showed empty ip/gw/dns/ssid. A value
    that genuinely could not be determined stays empty and the reason is
    logged - it is never fabricated.
    #>
    $ctx = @{ ssid = ''; ip = ''; gw = ''; dns = '' }

    try {
        $ni = $null
        if (Test-Path variable:networkInfo) {
            $ni = Get-Variable -Name networkInfo -ValueOnly -ErrorAction SilentlyContinue
        }

        if ($null -eq $ni) {
            Write-Log "Captive portal telemetry: no networkInfo snapshot in scope - ip/gw/dns/ssid emitted empty" "DEBUG"
            return $ctx
        }

        $ctx.ssid = ConvertTo-TelemetryValue $ni.SSID
        $ctx.ip   = ConvertTo-TelemetryValue $ni.IPAddress
        $ctx.gw   = ConvertTo-TelemetryValue $ni.DefaultGateway
        if ($ni.DNSServers) {
            $ctx.dns = ConvertTo-TelemetryValue (($ni.DNSServers | Where-Object { $_ }) -join ',')
        }

        $emptyFields = @($ctx.Keys | Where-Object { [string]::IsNullOrEmpty($ctx[$_]) })
        if ($emptyFields.Count -gt 0) {
            Write-Log "Captive portal telemetry: networkInfo had no value for $($emptyFields -join ',') - emitted empty" "DEBUG"
        }
    } catch {
        Write-Log "Captive portal telemetry: failed reading network context: $_" "DEBUG"
    }

    return $ctx
}

function Get-CapPortalFlareEventId {
    <#
    Resolves the Windows Event ID FlareGun will use for a captive-portal tag,
    from the same WW_flaregun_config.json the dispatcher reads. Fail-soft:
    returns an empty string rather than guessing.
    #>
    param([string]$FlareTag = "")

    if ([string]::IsNullOrWhiteSpace($FlareTag)) { return '' }
    try {
        $config = Get-FlareConfig
        if ($config -and $config.flare_events.$FlareTag -and $config.flare_events.$FlareTag.event_id) {
            return [string]$config.flare_events.$FlareTag.event_id
        }
    } catch { }
    return ''
}

function Get-CapPortalDispatchContext {
    <#
    .SYNOPSIS
    The authoritative preflight + dispatch context persisted into the
    remediation state artifact immediately BEFORE Main fires Event 777/778.

    .DESCRIPTION
    The Windows event message text stays stable ("FLARE:<tag>") - rich payload
    belongs in the state artifact, not in the event message. Base (and Full)
    read this back so they always know which empirical gateway.optum.com result
    caused the dispatch, and can keep it separate from their own later probe
    and from optional Cisco EventID 301 corroboration.

    The evidence block comes from this run's selected source. A fresh correlated
    301 navigation can intentionally precede/suppress the blocked PowerShell
    probe; otherwise this remains the authoritative Get-NwCheckResult result.
    #>
    param(
        [string]$FlareTag = "",
        [string]$Status = "",
        [string]$Reason = "",
        [string]$VpnState = "",
        [System.Collections.IDictionary]$NetworkContext = $null,
        [string]$Ssid = ""
    )

    $netCtx = if ($NetworkContext) { $NetworkContext } else { Get-CaptivePortalNetworkContext }

    $preflight = $null
    try { $preflight = $global:LastCapPreflightResult } catch { }

    $runId = ''
    try {
        $runIdVar = Get-Variable -Name 'RunId' -ValueOnly -ErrorAction SilentlyContinue
        if ($runIdVar) { $runId = [string]$runIdVar }
    } catch { }

    $runnerMode = ''
    try {
        $modeVar = Get-Variable -Name 'CapPortalRunnerMode' -ValueOnly -ErrorAction SilentlyContinue
        if ($modeVar) { $runnerMode = [string]$modeVar }
    } catch { }

    $resolvedSsid = ConvertTo-TelemetryValue $Ssid
    if ([string]::IsNullOrEmpty($resolvedSsid)) { $resolvedSsid = [string]$netCtx.ssid }

    $context = [ordered]@{
        source           = $(if ($preflight -and $preflight.DetectionSource) { [string]$preflight.DetectionSource } else { 'gateway_preflight' })
        detection_source = $(if ($preflight -and $preflight.DetectionSource) { [string]$preflight.DetectionSource } else { 'gateway_preflight' })
        run_id           = $runId
        correlation_id   = $runId
        flare_tag        = $FlareTag
        event_id         = (Get-CapPortalFlareEventId -FlareTag $FlareTag)
        runner_mode      = $runnerMode
        dispatch_time    = (Get-Date).ToString('o')
        probe_url        = $(if ($preflight) { [string]$preflight.ProbeUrl } else { '' })
        observation_time = $(if ($preflight) { [string]$preflight.ObservationTime } else { '' })
        http_status      = $(if ($preflight) { [string]$preflight.HttpStatus } else { '' })
        redirect_url     = $(if ($preflight) { [string]$preflight.RedirectUrl } else { '' })
        redirect_type    = $(if ($preflight) { [string]$preflight.RedirectType } else { '' })
        classification   = $(if ($preflight) { [string]$preflight.Classification } else { 'INCONCLUSIVE' })
        protocol         = $(if ($preflight) { [string]$preflight.Protocol } else { '' })
        fqdn             = $(if ($preflight) { [string]$preflight.Fqdn } else { '' })
        port             = $(if ($preflight) { [string]$preflight.Port } else { '' })
        preflight_status = $(if ($preflight) { [string]$preflight.Status } else { '' })
        preflight_reason = $(if ($preflight) { [string]$preflight.Reason } else { 'no_preflight_result_in_scope' })
        ssid             = $resolvedSsid
        ip               = [string]$netCtx.ip
        gw               = [string]$netCtx.gw
        dns              = [string]$netCtx.dns
        vpn_state        = (ConvertTo-TelemetryValue $VpnState)
        status           = $Status
        reason           = $Reason
    }

    Write-Log ("cap_portal_dispatch_context run_id='{0}' flare_tag='{1}' event_id='{2}' runner_mode='{3}' probe_url='{4}' preflight_status='{5}' classification='{6}' redirect_url='{7}' redirect_type='{8}' protocol='{9}' fqdn='{10}' port='{11}' status='{12}' reason='{13}'" -f `
        $context.run_id, $context.flare_tag, $context.event_id, $context.runner_mode, $context.probe_url, `
        $context.preflight_status, $context.classification, $context.redirect_url, $context.redirect_type, `
        $context.protocol, $context.fqdn, $context.port, $context.status, $context.reason) "INFO"

    return $context
}

function Get-CapPortalBaseEscalationPolicy {
    <#
    .SYNOPSIS
    Effective Base -> Full (Event 777) escalation policy for this run.

    .DESCRIPTION
    Mirrors the Test-MainSkipCiscoBrowserKill pattern: a single resolver so the
    effective value is logged once at dispatch and carried into the artifact.
    Undefined/missing is FAIL-SAFE FALSE - Base must never escalate unless the
    operator explicitly opted in via $CapPortalBaseAllowFullEscalation = $true.
    #>
    $policy = Get-Variable -Name CapPortalBaseAllowFullEscalation -ErrorAction SilentlyContinue
    if ($null -eq $policy) { return $false }
    return [bool]$policy.Value
}

function Import-CapPortalUserHandback {
    <#
    .SYNOPSIS
    Consumes the USER-context Base handback artifact (Required G).

    .DESCRIPTION
    SYSTEM remains the owner and authoritative consumer of the control state in
    $RemediationStateFile. Rather than weakening that artifact's ACL so an
    unprivileged runner can rewrite it, Base writes its findings atomically to a
    separate user-result artifact in the narrowly scoped spool directory. Main
    reads it here, logs the evidence, and removes it so the next run never sees
    a stale handback. Strictly fail-soft and read-only with respect to control
    state - a handback is EVIDENCE, it never decides remediation success.
    #>
    param([string]$Path = "C:\ProgramData\WhiteWalker\logs\spool\cap_portal_base_handback.json")

    try {
        if (-not (Test-Path $Path)) { return $null }

        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        $handback = $raw | ConvertFrom-Json -ErrorAction Stop

        $observation = $handback.base_preflight_observation
        Write-Log "cap_portal_base_handback consumed: updated='$($handback.base_preflight_updated)' url='$($handback.url)' url_source='$($handback.url_source)' preflight_status='$($observation.status)' redirect_url='$($observation.redirect_url)' redirect_type='$($observation.redirect_type)' reason='$($observation.reason)'" "INFO"

        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        return $handback
    } catch {
        Write-Log "Could not consume Base handback artifact: $_" "DEBUG"
        return $null
    }
}

function Write-CapPortalRemediationState {
    <#
    .SYNOPSIS
    ATOMIC writer for the Main -> runner dispatch/remediation artifact.

    .DESCRIPTION
    RC2.1. Every dispatch artifact now carries the identity a runner needs to
    decide whether the handoff still describes reality:

      created_at / timestamp  - when Main wrote it
      run_id / correlation_id - Main's run correlation
      ssid / ip / gw / dns    - the network identity at dispatch time
      runner_mode             - base | full
      base_allow_full_escalation / base_observe_timeout_sec /
      base_check_interval_sec - the Base settings Base cannot inherit (it is a
                                separate standalone process)

    Written temp+move so a runner can never read a half-written artifact.
    Fail-soft: a write failure is logged and never breaks the run.
    #>
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [System.Collections.IDictionary]$NetworkContext = $null,
        [string]$Ssid = ""
    )

    try {
        $netCtx = if ($NetworkContext) { $NetworkContext } else { Get-CaptivePortalNetworkContext }

        $runId = ''
        try {
            $runIdVar = Get-Variable -Name 'RunId' -ValueOnly -ErrorAction SilentlyContinue
            if ($runIdVar) { $runId = [string]$runIdVar }
        } catch { }

        $runnerMode = ''
        try {
            $modeVar = Get-Variable -Name 'CapPortalRunnerMode' -ValueOnly -ErrorAction SilentlyContinue
            if ($modeVar) { $runnerMode = [string]$modeVar }
        } catch { }

        $resolvedSsid = ConvertTo-TelemetryValue $Ssid
        if ([string]::IsNullOrEmpty($resolvedSsid)) { $resolvedSsid = [string]$netCtx.ssid }

        $allowEscalation = Get-CapPortalBaseEscalationPolicy

        $State['created_at']     = (Get-Date).ToString('o')
        if (-not (Test-CprMapKey -Map $State -Key 'timestamp')) { $State['timestamp'] = $State['created_at'] }
        $State['run_id']         = $runId
        $State['correlation_id'] = $runId
        $State['runner_mode']    = $runnerMode
        $State['ssid']           = $resolvedSsid
        if ([string]::IsNullOrEmpty([string]$State['ip']))  { $State['ip']  = [string]$netCtx.ip }
        if ([string]::IsNullOrEmpty([string]$State['gw']))  { $State['gw']  = [string]$netCtx.gw }
        if ([string]::IsNullOrEmpty([string]$State['dns'])) { $State['dns'] = [string]$netCtx.dns }
        $State['base_allow_full_escalation'] = $allowEscalation
        $State['base_observe_timeout_sec']   = $CapPortalBaseTimeoutSeconds
        $State['base_check_interval_sec']    = $CapPortalBaseCheckIntervalSec

        # RC2.2 (Required E): the EFFECTIVE timing/behavior contract from
        # Main.Configuration.ps1 rides in the artifact so BASE and FULL - both
        # standalone processes - consume Main's values instead of their own
        # fail-safe literals. base_allow_full_escalation is resolved separately
        # above and is the authoritative escalation value.
        $timingContractStartedAt = Get-Date
        $timingContract = $null
        if (Get-Command Get-CprCapPortalTimingContract -ErrorAction SilentlyContinue) {
            $timingContract = Get-CprCapPortalTimingContract
            $timingContract['base_allow_full_escalation'] = $allowEscalation
            $State['timing_contract'] = $timingContract
        }

        Write-Log ("cap_portal_dispatch_settings runner_mode='{0}' base_allow_full_escalation={1} base_observe_timeout_sec={2} base_check_interval_sec={3} ssid='{4}' ip='{5}' gw='{6}'" -f `
            $runnerMode, $allowEscalation, $CapPortalBaseTimeoutSeconds, $CapPortalBaseCheckIntervalSec, `
            $State['ssid'], $State['ip'], $State['gw']) "INFO"

        if ($timingContract) {
            $contractPairs = @()
            foreach ($key in $timingContract.Keys) { $contractPairs += ("{0}={1}" -f $key, $timingContract[$key]) }
            Write-Log ("cap_portal_timing_contract source='main_configuration' {0}" -f ($contractPairs -join ' ')) "INFO"
        } else {
            Write-Log "cap_portal_timing_contract source='unavailable' - runners will use their fail-safe defaults" "WARN"
        }

        $json = $State | ConvertTo-Json -Compress -Depth 6
        $temp = "$RemediationStateFile.$PID.tmp"
        Set-Content -Path $temp -Value $json -Encoding UTF8 -Force -ErrorAction Stop
        Move-Item -Path $temp -Destination $RemediationStateFile -Force -ErrorAction Stop
        Write-Log ("phase_timing phase='timing_contract_artifact_write' elapsed_ms={0}" -f `
            [math]::Round(((Get-Date) - $timingContractStartedAt).TotalMilliseconds)) "INFO"
        return $true
    } catch {
        Write-Log "Could not write remediation state file atomically: $_" "WARN"
        return $false
    }
}

function Clear-CapPortalRemediationState {
    <#
    Lifecycle boundary cleanup. Removes a remediation/dispatch artifact that
    belongs to a PREVIOUS run so a new run never inherits the prior SSID. An
    artifact written by THIS run (same run_id) is never deleted.
    #>
    param([string]$Reason = "new_run")

    try {
        if (-not (Test-Path $RemediationStateFile)) { return $false }

        $runId = ''
        try {
            $runIdVar = Get-Variable -Name 'RunId' -ValueOnly -ErrorAction SilentlyContinue
            if ($runIdVar) { $runId = [string]$runIdVar }
        } catch { }

        $existingRunId = ''
        try {
            $existing = Get-Content -Path $RemediationStateFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($existing -and $existing.run_id) { $existingRunId = [string]$existing.run_id }
        } catch { }

        if ($runId -and $existingRunId -and $runId -eq $existingRunId) {
            Write-Log "Remediation state belongs to this active run ($runId) - not clearing" "DEBUG"
            return $false
        }

        Remove-Item -Path $RemediationStateFile -Force -ErrorAction SilentlyContinue
        Write-Log "Cleared stale remediation state artifact (run_id='$existingRunId' reason=$Reason)" "INFO"
        return $true
    } catch {
        Write-Log "Could not clear stale remediation state artifact: $_" "DEBUG"
        return $false
    }
}

function Test-MainSkipCiscoBrowserKill {
    <#
    .SYNOPSIS
    Single resolver for the Main-owned Cisco browser-kill policy.

    .DESCRIPTION
    RC2.2 (Required A). This function used to be defined INSIDE
    Write-CaptivePortalOutcomeTelemetry, so it only ever existed in that
    function's local scope and was never resolvable at either call site. The
    captive portal remediation path died with:

      [ERROR] Failed to trigger captive portal event: The term
      'Test-MainSkipCiscoBrowserKill' is not recognized ...

    It now lives at file scope in Main.CaptivePortal.ps1, which WW_main.ps1
    dot-sources BEFORE Main.Entry.ps1, so BOTH the walled-garden branch
    (Main.Entry.ps1) and the remediation branch (below) resolve the same single
    definition. Semantics are unchanged: Base mode always preserves the Cisco
    native browser/WebHelper evidence, and in Full mode only an explicit
    $CapPortalSkipBrowserKill = $false restores the legacy kill-then-Edge
    behavior (true/undefined = skip the kill).
    #>
    if ($CapPortalRunnerMode -eq 'base') { return $true }
    $policy = Get-Variable -Name CapPortalSkipBrowserKill -ErrorAction SilentlyContinue
    return -not ($null -ne $policy -and $policy.Value -eq $false)
}

function Write-CaptivePortalOutcomeTelemetry {
    param(
        [Parameter(Mandatory)][string]$Action,
        [System.Collections.IDictionary]$RedirectTelemetry = @{},
        [string]$PortalType = "",
        [string]$Status = "",
        [string]$Reason = "",
        [string]$Ssid = "",
        [string]$VpnState = ""
    )

    # RC2.2 (Required B): $RedirectTelemetry comes from
    # Get-CaptivePortalRedirectTelemetry, which builds an [ordered]@{} -
    # an OrderedDictionary has Contains(), NOT ContainsKey(). Probing it with
    # .ContainsKey() is what aborted the live run. Test-CprMapKey /
    # Get-CprMapValue (main/Main.Common.ps1) handle hashtable, ordered
    # dictionary and PSCustomObject shapes identically.
    $url  = [string](Get-CprMapValue -Map $RedirectTelemetry -Key 'url'  -Default '')
    $port = [string](Get-CprMapValue -Map $RedirectTelemetry -Key 'port' -Default '')

    $netCtx = Get-CaptivePortalNetworkContext
    $resolvedSsid = ConvertTo-TelemetryValue $Ssid
    if ([string]::IsNullOrEmpty($resolvedSsid)) { $resolvedSsid = $netCtx.ssid }

    # EvtTime is stamped here, when the outcome actually happened, and carried
    # through the queue unchanged (Write-TeeLog honors a caller-supplied value).
    Write-TeeLog $Action @{
        EvtTime     = (Get-Date -Format 'o')
        url         = ConvertTo-TelemetryValue $url
        port        = ConvertTo-TelemetryValue $port
        portal_type = ConvertTo-TelemetryValue $PortalType
        status      = ConvertTo-TelemetryValue $Status
        reason      = ConvertTo-TelemetryValue $Reason
        ssid        = $resolvedSsid
        vpn_state   = ConvertTo-TelemetryValue $VpnState
        ip          = $netCtx.ip
        gw          = $netCtx.gw
        dns         = $netCtx.dns
    }
}

function Invoke-CaptivePortalRemediation {
    param(
        [string]$PortalType,
        [string]$RedirectUrl = ""
    )
    
    Write-Log "Starting captive portal remediation for $PortalType" "INFO"

    $currentSsid = $null
    if ((Test-Path variable:networkInfo) -and ($null -ne $networkInfo)) {
        $currentSsid = $networkInfo.SSID
    }
    $accepted301Carried = Test-CprAccepted301RemediationEvidence
    $accepted301RecordId = if ($accepted301Carried) { $script:LastWebHelper301Evidence.EventRecordId } else { '' }
    $accepted301Url = if ($accepted301Carried) { [string]$script:LastWebHelper301Evidence.NavigatedUrl } else { '' }

    $redirectTelemetry = Get-CaptivePortalRedirectTelemetry -RedirectUrl $RedirectUrl
    $vpnState = $null
    try {
        $vpnState = Get-VpnState
    } catch {
        Write-Log "Error getting VPN state for captive portal telemetry: $_" "DEBUG"
    }
    
    if ($accepted301Carried) {
        Write-Log ("detection_source=cisco_webhelper_301 remediation_precheck_suppressed=true selected_record_id='{0}' navigated_url='{1}' - post-auth connectivity validation remains required" -f `
            $accepted301RecordId, $accepted301Url) "INFO"
    } elseif (Test-CaptivePortalCleared) {
        Write-Log "Captive portal already cleared - no remediation needed" "INFO"
        Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_passed' `
            -RedirectTelemetry $redirectTelemetry `
            -PortalType $PortalType `
            -Status 'already_clear' `
            -Reason 'pre_check_passed' `
            -Ssid $currentSsid `
            -VpnState $vpnState
        Clear-CaptiveEventHistory "captive portal pre-check passed"
        return $true
    }
    Write-Log "Captive portal still active - proceeding with remediation" "DEBUG"
    
    # ER5: Check for known captive portal compatibility issues
    $portalIssues = $null
    if (-not [string]::IsNullOrEmpty($RedirectUrl)) {
        Write-Log "Analyzing captive portal compatibility for: $RedirectUrl" "DEBUG"
        $portalIssues = Test-CaptivePortalCompatibility -RedirectUrl $RedirectUrl
        
        if ($portalIssues.HasIssues) {
            Write-Log "NON-STANDARD CAPTIVE PORTAL CONFIG DETECTED: $($portalIssues.IssueType)" "WARN"
            Write-Log "  Issue: $($portalIssues.Description)" "WARN"
            Write-Log "  User Impact: $($portalIssues.UserMessage)" "WARN"
            Write-Log "  Retry Recommended: $($portalIssues.AllowRetry)" "INFO"
        }
    }
    
    # NEW: Force disconnect VPN if blocking traffic
    try {
        if (Test-VPNBlockingNetwork -VPNState $vpnState -RedirectDetected $true) {
            Write-Log "VPN in blocking state ($vpnState) - forcing disconnect to allow captive portal/ISE traffic" "WARN"
            Invoke-VpnCliBounded -Arguments 'disconnect' | Out-Null
            Start-Sleep -Seconds 2
            try {
                $vpnState = Get-VpnState
            } catch {
                Write-Log "Error refreshing VPN state after disconnect: $_" "DEBUG"
            }
            Write-Log "VPN disconnected to allow network authentication" "INFO"
        }
    } catch {
        Write-Log "Error checking/disconnecting VPN: $_" "DEBUG"
    }
    $redirectNetCtx = Get-CaptivePortalNetworkContext
    $redirectSsid = ConvertTo-TelemetryValue $currentSsid
    if ([string]::IsNullOrEmpty($redirectSsid)) { $redirectSsid = $redirectNetCtx.ssid }
    $redirectTee = @{
        EvtTime     = (Get-Date -Format 'o')
        url         = ConvertTo-TelemetryValue $redirectTelemetry.url
        port        = ConvertTo-TelemetryValue $redirectTelemetry.port
        ssid        = $redirectSsid
        vpn_state   = ConvertTo-TelemetryValue $vpnState
        ip          = $redirectNetCtx.ip
        gw          = $redirectNetCtx.gw
        dns         = $redirectNetCtx.dns
        portal_type = ConvertTo-TelemetryValue $PortalType
        status      = 'detected'
        reason      = 'redirect_detected'
        detection_source = $(if ($accepted301Carried) { 'cisco_webhelper_301' } else { 'native_redirect' })
        protocol    = ConvertTo-TelemetryValue $redirectTelemetry.protocol
        fqdn        = ConvertTo-TelemetryValue $redirectTelemetry.fqdn
    }
    # Same portal-descriptor fields the 301 row carries, read from the redirect URL.
    try {
        $portalFields = Get-CprPortalUrlFields -Url ([string]$RedirectUrl)
        foreach ($k in $portalFields.Keys) { $redirectTee[$k] = [string]$portalFields[$k] }
    } catch { Write-Log "cap_portal_redirect: portal field extraction failed: $_" "DEBUG" }
    Write-TeeLog 'cap_portal_redirect' $redirectTee
    
    $eventCount = Get-CaptiveEventCount
    Write-Log "Recent captive portal events in last $CaptiveEventCooldown minutes: $eventCount" "DEBUG"
    
    if ($eventCount -ge $CaptiveEventLimit) {
        Write-Log "Captive portal event limit reached ($eventCount >= $CaptiveEventLimit) - showing BLOCKING user alert" "WARN"
        Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_failed' `
            -RedirectTelemetry $redirectTelemetry `
            -PortalType $PortalType `
            -Status 'event_limit_reached' `
            -Reason "event_limit_$eventCount" `
            -Ssid $currentSsid `
            -VpnState $vpnState
        Show-CaptivePortalAlert -EventCount $eventCount
        return $false
    }
    
    # FLARE EVENT: captive_portal_ise_employee / captive_portal_ise_guest / captive_portal_non_ise
    # Context: SYSTEM | Reason: Captive portal detected, browser remediation initiated
    # Expected Flow: WW_main (SYSTEM) ???EUR ?EUR(TM) Direct flare to Ivanti EM
    # Ivanti Use: Monitoring/telemetry for captive portal encounters across fleet
    Send-FlareEvent "captive_portal_$($PortalType.ToLower())"
    
    Clear-CaptivePortalFlag
    
    try {
        if (Test-Path $InterruptFile) {
            Remove-Item $InterruptFile -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared stale interrupt flag before starting wait" "DEBUG"
        }
    } catch { }
    
    Add-CaptiveEvent
    
    # NEW ER2: Create remediation state file to track VPN stabilization need
    try {
        # RC1.25: the state file is the ONLY context channel to the base runner,
        # which is a separate process launched by Task Scheduler and therefore
        # cannot see any variable in this process. Everything the base runner
        # needs for normalized telemetry (network context + portal URL parts)
        # is written here; values that could not be determined are written as
        # empty strings rather than invented.
        $stateNetCtx = Get-CaptivePortalNetworkContext
        $remediationState = @{
            timestamp = (Get-Date).ToString('o')
            portal_type = $PortalType
            attempt_count = ($eventCount + 1)
            ssid      = $(if ([string]::IsNullOrEmpty((ConvertTo-TelemetryValue $currentSsid))) { $stateNetCtx.ssid } else { (ConvertTo-TelemetryValue $currentSsid) })
            ip        = $stateNetCtx.ip
            gw        = $stateNetCtx.gw
            dns       = $stateNetCtx.dns
            vpn_state = (ConvertTo-TelemetryValue $vpnState)
            url       = (ConvertTo-TelemetryValue $redirectTelemetry.url)
            port      = (ConvertTo-TelemetryValue $redirectTelemetry.port)
            protocol  = (ConvertTo-TelemetryValue $redirectTelemetry.protocol)
            fqdn      = (ConvertTo-TelemetryValue $redirectTelemetry.fqdn)
        }
        if ($script:LastWebHelper301Evidence -and $script:LastWebHelper301Evidence.UsableNavigation) {
            $remediationState.webhelper_navigation = $script:LastWebHelper301Evidence
            $remediationState.webhelper_301_suppress_preflight = [bool]$CapPortalWebHelper301SuppressPreflight
        }

        # B: persist the selected evidence/dispatch context BEFORE the
        # 777/778 flare so the runner never has to guess which empirical
        # gateway.optum.com result caused its launch.
        $remediationState.dispatch_context = Get-CapPortalDispatchContext `
            -FlareTag $(if ($CapPortalRunnerMode -eq 'base') { 'captive_portal_browser_base' } else { 'captive_portal_browser' }) `
            -Status 'detected' `
            -Reason 'redirect_detected' `
            -VpnState $vpnState `
            -NetworkContext $stateNetCtx `
            -Ssid $currentSsid
        
        # ER5: Add portal compatibility issues if detected
        if ($portalIssues -and $portalIssues.HasIssues) {
            $remediationState.portal_issues = @{
                issue_type = $portalIssues.IssueType
                description = $portalIssues.Description
                user_message = $portalIssues.UserMessage
                allow_retry = $portalIssues.AllowRetry
            }
        }
        
        if (Write-CapPortalRemediationState -State $remediationState -NetworkContext $stateNetCtx -Ssid $currentSsid) {
            Write-Log "Created remediation state file for VPN stabilization tracking" "DEBUG"
        }
    } catch {
        Write-Log "Failed to create remediation state file: $_" "WARN"
    }
    
    try {
        Write-Log "Triggering captive portal browser (attempt $($eventCount + 1)/$CaptiveEventLimit)" "INFO"
        
        if (-not $WhatIf) {
            # ER5: Dump flare history for debugging
            Write-Log "=== Flare History Debug Dump ===" "DEBUG"
            if ($global:flareHistory -and $global:flareHistory.Count -gt 0) {
                foreach ($key in $global:flareHistory.Keys) {
                    Write-Log "  FlareHistory[$key] = $($global:flareHistory[$key])" "DEBUG"
                }
            } else {
                Write-Log "  FlareHistory is empty (good - no de-dupe issues)" "DEBUG"
            }
            Write-Log "===========================" "DEBUG"
            
            # ER5: Check cooldown status before sending
            $inCooldown = In-Cooldown "captive_portal_browser" $FlareCooldownMinutes
            Write-Log "Cooldown check for captive_portal_browser: $inCooldown (will be bypassed anyway)" "DEBUG"
            
            Write-Log "Calling Send-FlareEvent for captive_portal_browser..." "DEBUG"
            if (Test-MainSkipCiscoBrowserKill) {
                if ($CapPortalRunnerMode -eq 'base') {
                    Write-Log "Cisco browser killing skipped: Base observer mode preserves Cisco native browser/WebHelper evidence" "INFO"
                } else {
                    Write-Log "Cisco browser killing skipped: CapPortalSkipBrowserKill is true or undefined" "INFO"
                }
                $script:ciscoBrowserKillerJob = $null
            } else {
                $script:ciscoBrowserKillerJob = Start-CiscoBrowserKiller
            }
            # FLARE EVENT: captive_portal_browser
            # Context: USER | Reason: Launch browser for captive portal authentication
            # Expected Flow: WW_main (SYSTEM) ?+' Event 777 ?+' FlareGun ?+' USER context browser launch
            # FlareGun routes this to WW_flaregun_user.ps1 ?+' WW_cap_portal_runner.ps1
            # Cap portal runner pivot - route to base observer or full runner based on $CapPortalRunnerMode
            if ($CapPortalRunnerMode -eq "base") {
                Write-Log "CapPortalRunner: mode=base - firing captive_portal_browser_base (Event 778)" "INFO"
                Send-FlareEvent 'captive_portal_browser_base'
            } else {
                Write-Log "CapPortalRunner: mode=full - firing captive_portal_browser (Event 777)" "INFO"
                Send-FlareEvent 'captive_portal_browser'
            }
            Write-Log "Send-FlareEvent completed for captive_portal_browser" "DEBUG"

            # ER5: Give event log a moment to propagate
            Start-Sleep -Milliseconds 500
            Write-Log "Event log propagation wait complete" "DEBUG"

            Write-Log "Captive portal browser launch triggered via FlareGun" "INFO"
        } else {
            Write-Log "WHATIF: Would trigger captive portal browser via FlareGun" "INFO"
            return $true
        }
        
        $result = Get-CaptivePortalResult -TimeoutSeconds $CaptivePortalTimeout
        
        if ($result) {
            if ($result.status -eq "INTERRUPTED" -or $result.status -eq "NETWORK_CHANGED") {
                Write-Log "Captive portal wait was interrupted: $($result.status) - $($result.details)" "WARN"
                Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_failed' `
                    -RedirectTelemetry $redirectTelemetry `
                    -PortalType $PortalType `
                    -Status $result.status `
                    -Reason $result.details `
                    -Ssid $currentSsid `
                    -VpnState $vpnState
                Clear-CaptivePortalFlag
                
                # Clean up remediation state file on interrupt
                if (Test-Path $RemediationStateFile) {
                    Remove-Item $RemediationStateFile -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleaned up remediation state file (interrupted)" "DEBUG"
                }
                return $false
            }
            
            # Cap portal runner handles VPN stabilization and validation browser
            # We just clean up the captive browser here
            if ($result.captive_browser_pid -and $result.captive_browser_pid -gt 0) {
                try {
                    $captivePID = $result.captive_browser_pid
                    Write-Log "Attempting to clean up captive portal browser (PID: $captivePID)" "DEBUG"
                    
                    $captiveProcess = Get-Process -Id $captivePID -ErrorAction SilentlyContinue
                    if ($captiveProcess) {
                        Write-Log "Terminating captive portal browser process: $($captiveProcess.Name) (PID: $captivePID)" "INFO"
                        $captiveProcess.Kill()
                        $captiveProcess.WaitForExit(3000) | Out-Null
                        Write-Log "Captive portal browser terminated successfully" "INFO"
                    } else {
                        Write-Log "Captive portal browser process (PID: $captivePID) no longer running" "DEBUG"
                    }
                } catch {
                    Write-Log "Error cleaning up captive portal browser (PID: $captivePID): $_" "WARN"
                }
            }
            
            Clear-CaptivePortalFlag
            
            if ($result.status -eq "SUCCESS" -or $result.status -eq "PARTIAL") {
                Write-Log "Runner reported: $($result.status) - verifying portal clearance..." "INFO"
                
                Start-Sleep -Seconds 2
                
                if (Test-CaptivePortalCleared) {
                    Write-Log "Captive portal authentication VERIFIED - portal cleared" "INFO"
                    Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_passed' `
                        -RedirectTelemetry $redirectTelemetry `
                        -PortalType $PortalType `
                        -Status 'verified' `
                        -Reason 'network_check_passed' `
                        -Ssid $currentSsid `
                        -VpnState $vpnState
                    Clear-CaptiveEventHistory "captive portal verified cleared"
                    return $true
                } else {
                    Write-Log "Runner reported success but portal still present - user may not have completed auth" "WARN"
                    Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_failed' `
                        -RedirectTelemetry $redirectTelemetry `
                        -PortalType $PortalType `
                        -Status 'verification_failed' `
                        -Reason 'network_check_still_blocked' `
                        -Ssid $currentSsid `
                        -VpnState $vpnState
                    return $false
                }
            } else {
                Write-Log "Captive portal authentication failed: $($result.details)" "WARN"
                Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_failed' `
                    -RedirectTelemetry $redirectTelemetry `
                    -PortalType $PortalType `
                    -Status $result.status `
                    -Reason $result.details `
                    -Ssid $currentSsid `
                    -VpnState $vpnState
                return $false
            }
        } else {
            Write-Log "Captive portal authentication timed out or no response" "WARN"
            Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_failed' `
                -RedirectTelemetry $redirectTelemetry `
                -PortalType $PortalType `
                -Status 'timeout' `
                -Reason 'runner_timeout_or_no_response' `
                -Ssid $currentSsid `
                -VpnState $vpnState
            Clear-CaptivePortalFlag
            return $false
        }
        
    } catch {
        Write-Log "Failed to trigger captive portal event: $_" "ERROR"
        Write-CaptivePortalOutcomeTelemetry -Action 'cap_portal_remediation_failed' `
            -RedirectTelemetry $redirectTelemetry `
            -PortalType $PortalType `
            -Status 'exception' `
            -Reason $_ `
            -Ssid $currentSsid `
            -VpnState $vpnState
        Clear-CaptivePortalFlag
        return $false
    }
}
