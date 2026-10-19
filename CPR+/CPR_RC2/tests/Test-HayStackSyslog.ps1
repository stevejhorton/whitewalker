<#
.SYNOPSIS
    Proof-of-concept syslog sender for Haystack hit validation.

.DESCRIPTION
    Simulates syslog messages that Haystack/WW tee telemetry emits, including
    connectivity pings, generic hit payloads, and captive portal lifecycle
    telemetry events.

    Delivery modes:
      - direct : sends UDP syslog immediately (bypasses Haystack network-state gating)
      - queue  : writes JSONL entries to the Haystack queue file for later drain

    Use this tool to validate that:
      1. Messages arrive at the syslog collector (cpr-syslog.uhc.com:514)
      2. Splunk indexes them correctly
      3. Field extractions / sourcetype parse as expected
      4. Captive portal telemetry flows correctly through queue and drain paths

.PARAMETER SimulateHit
    Send simulated generic HIT payloads (Haystack needle hits).

.PARAMETER SimulateCaptivePortal
    Send synthetic captive portal redirect + remediation passed/failed payloads.
    This is the primary test mode for CPR+ captive portal telemetry validation.
    Emits three events per URL: redirect detection, remediation success, remediation failure.

.PARAMETER DeliveryMode
    'direct'  = immediate UDP send to syslog server (bypasses network-state gating).
               Use this when you're on-prem or connected, want instant Splunk visibility.
    'queue'   = write entries to haystack_syslog_queue.jsonl for later drain.
               Use this to validate queue entry format and queue/drain lifecycle.

.PARAMETER SyslogServer
    IP or FQDN of syslog collector. Default: cpr-syslog.uhc.com

.PARAMETER Port
    UDP port. Default: 514

.PARAMETER Facility
    RFC 3164 facility code (0-23). Default: 16 = local0

.PARAMETER Severity
    RFC 3164 severity code (0-7). Default: 5 = Notice

.PARAMETER Count
    Number of ping/hit messages to send (ignored if -SimulateCaptivePortal).
    Default: 3

.PARAMETER IntervalSeconds
    Seconds between messages. Default: 2

.PARAMETER QueueFile
    Path to Haystack queue file (used with DeliveryMode='queue').
    Default: C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl

.PARAMETER PortalType
    Type of captive portal: 'ISE_EMPLOYEE', 'ISE_GUEST', 'NON_ISE'.
    Default: NON_ISE

.PARAMETER PortalSsid
    SSID name to include in synthetic portal events.
    Default: CPR-SYNTHETIC-PORTAL

.PARAMETER PortalVpnState
    VPN state to include in synthetic portal events.
    Default: Disconnected

.PARAMETER PortalUrls
    Array of redirect URLs to simulate. Each URL generates three events
    (redirect, pass, fail). URLs may specify explicit ports (e.g. :8443).
    Default: @('https://portal.example.test:8443/login?from=cpr_test',
                'http://portal.example.test:8080/auth?from=cpr_test')

.PARAMETER TestMarker
    Value for test= field in all events. Use to filter synthetic events in Splunk.
    Default: '1'

.EXAMPLE
    # Quick test: send default captive portal telemetry directly to syslog
    .\Test-HayStackSyslog.ps1 -SimulateCaptivePortal -DeliveryMode direct

    Sends 6 events (3 per URL) to cpr-syslog.uhc.com:514 immediately.
    Events include machine, user (from Win32_ComputerSystem), url, port, etc.
    Events are tagged with test="1" for easy Splunk filtering.

.EXAMPLE
    # Custom portal URL with specific VPN state
    .\Test-HayStackSyslog.ps1 `
      -SimulateCaptivePortal `
      -PortalUrls 'https://hotel.wifi.com:9443/auth' `
      -PortalSsid 'Marriott-WiFi' `
      -PortalVpnState 'Disconnected' `
      -PortalType 'NON_ISE' `
      -DeliveryMode direct `
      -IntervalSeconds 1

.EXAMPLE
    # Test standard HTTPS without explicit port (should infer port 443)
    .\Test-HayStackSyslog.ps1 `
      -SimulateCaptivePortal `
      -PortalUrls 'https://portal.internal.com/login' `
      -DeliveryMode direct

.EXAMPLE
    # Queue path testing: enqueue for later drain (validates queue format)
    .\Test-HayStackSyslog.ps1 `
      -SimulateCaptivePortal `
      -DeliveryMode queue `
      -QueueFile 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl'

    Then trigger drain manually:
      powershell.exe -ExecutionPolicy Bypass `
        -File C:\ProgramData\WhiteWalker\haystack_action.ps1

    Or wait for natural Haystack action (HayStack_Monitor task fires on network events).
    Queue will only drain if current state is on_prem, user_tun, or mgmt_tun.

.EXAMPLE
    # Connectivity ping test (basic syslog validation)
    .\Test-HayStackSyslog.ps1 -Count 5 -IntervalSeconds 2

    Sends 5 PING payloads at 2-second intervals. No portal data.

.EXAMPLE
    # Simulate generic Haystack hit (brute-force alert)
    .\Test-HayStackSyslog.ps1 -SimulateHit -Count 1

    Sends a single synthetic event log needle hit (event 4625, bruteforce).

.NOTES
    Author  : shorto39_uhg
    Service : OptumUHG Global Remote Access / CPR+ / Haystack
    Version : 1.0.0

    Key behaviors:
      - machine= is always resolved from Win32_ComputerSystem or environment
      - user= is always resolved from Win32_ComputerSystem.UserName (works in SYSTEM context)
      - port= is calculated from URI: explicit port if present, else 80/443 for http/https
      - EvtTime is RFC 3339 ISO format (ISO 8601 zulu time)
      - test="1" allows filtering synthetic events in Splunk
      - direct mode sends UDP immediately; queue mode writes JSONL for Haystack drain
      - Network state gating (on_prem/user_tun/mgmt_tun) only applies to queue drain, not direct send

    For direct send failures:
      - Check syslog server is reachable: Test-NetConnection cpr-syslog.uhc.com -Port 514
      - Verify firewall allows UDP 514 outbound
      - Check syslog server logs for receipt

    For queue mode:
      - Check queue file path exists or will be created
      - Verify haystack_action.ps1 is deployed and scheduled
      - Monitor state.json currentState for network state transitions that trigger drain
      - Queue file remains until successfully drained (survives restarts)

    Splunk validation after -SimulateCaptivePortal:
      index=cba_cpr_logging test="1" action="cap_portal_redirect"
      | table EvtTime,action,machine,user,url,port,ssid,vpn_state

    Port statistics (to identify common captive portal port ranges):
      index=cba_cpr_logging test="1" action="cap_portal_redirect"
      | stats count dc(machine) as endpoints by port
      | sort - count

    Full lifecycle per URL:
      index=cba_cpr_logging test="1"
      | search action IN (cap_portal_redirect, cap_portal_remediation_passed, cap_portal_remediation_failed)
      | stats values(url) as urls, values(port) as ports, values(action) as actions by machine
#>

[CmdletBinding()]
param(
    [string]  $SyslogServer      = 'cpr-syslog.uhc.com',
    [int]     $Port              = 514,
    [int]     $Facility          = 16,
    [int]     $Severity          = 5,
    [int]     $Count             = 3,
    [int]     $IntervalSeconds   = 2,
    [switch]  $SimulateHit,
    [switch]  $SimulateCaptivePortal,
    [ValidateSet('direct','queue')]
    [string]  $DeliveryMode      = 'direct',
    [string]  $QueueFile         = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl',
    [string]  $PortalType        = 'NON_ISE',
    [string]  $PortalSsid        = 'CPR-SYNTHETIC-PORTAL',
    [string]  $PortalVpnState    = 'Disconnected',
    [string[]]$PortalUrls        = @(
        'https://portal.example.test:8443/login?from=cpr_test',
        'http://portal.example.test:8080/auth?from=cpr_test'
    ),
    [string]  $TestMarker        = '1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SyslogPriority {
    param([int]$Facility, [int]$Severity)
    return ($Facility * 8) + $Severity
}

function Get-Rfc3164Timestamp {
    $now = Get-Date
    return '{0} {1,2} {2}' -f $now.ToString('MMM'), $now.Day, $now.ToString('HH:mm:ss')
}

function Get-LoggedOnUser {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($cs.UserName)) { return $cs.UserName }
        return 'NO_INTERACTIVE_USER'
    } catch {
        return 'USER_UNKNOWN'
    }
}

function Get-MachineName {
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        return $env:COMPUTERNAME
    }
    if (-not [string]::IsNullOrWhiteSpace($env:HOSTNAME)) {
        return $env:HOSTNAME
    }
    try {
        return [System.Net.Dns]::GetHostName()
    } catch {
        return 'UNKNOWN_MACHINE'
    }
}

function Get-EffectiveUriPort {
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return ''
    }

    try {
        $uri = $null
        if ([System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri) -and $uri) {
            if ($uri.Port -gt 0) {
                return [string]$uri.Port
            }
            switch ($uri.Scheme.ToLowerInvariant()) {
                'http'  { return '80' }
                'https' { return '443' }
                default { return '' }
            }
        }
    } catch { }

    return 'unknown'
}

function Format-Fields {
    param([System.Collections.IDictionary]$Fields)
    return ($Fields.GetEnumerator() | Sort-Object Name | ForEach-Object {
        '{0}="{1}"' -f $_.Key, $_.Value
    }) -join ' '
}

function Send-SyslogMessage {
    param(
        [string] $Server,
        [int]    $Port,
        [int]    $Priority,
        [string] $Message
    )

    $timestamp = Get-Rfc3164Timestamp
    $hostname  = $env:COMPUTERNAME
    $tag       = 'Haystack'

    $raw = '<{0}>{1} {2} {3}: {4}' -f $Priority, $timestamp, $hostname, $tag, $Message

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($raw)
    $udp   = [System.Net.Sockets.UdpClient]::new()

    try {
        $udp.Send($bytes, $bytes.Length, $Server, $Port) | Out-Null
        return $raw
    } finally {
        $udp.Close()
    }
}

function Write-QueueEntry {
    param(
        [string]$Path,
        [string]$Payload
    )

    $entry = @{
        ts        = (Get-Date).ToString('o')
        payload   = $Payload
        extraInfo = ''
    } | ConvertTo-Json -Compress

    Add-Content -Path $Path -Value $entry -Encoding UTF8
    return "QUEUED -> $Path | $Payload"
}

function Build-HitPayload {
    param(
        [string]$Machine,
        [string]$User,
        [string]$EvtTime,
        [string]$Marker
    )

    $params = @{
        action     = 'alert'
        EventID    = '4625'
        EvtTime    = $EvtTime
        HitCount   = (Get-Random -Minimum 3 -Maximum 20)
        Label      = 'BruteForce_Local_Logon'
        LogonType  = '2'
        machine    = $Machine
        NeedleID   = 'NEEDLE_BRUTE_LOCAL_LOGON'
        PID        = $PID
        RunID      = [guid]::NewGuid().ToString('N').Substring(0,8).ToUpper()
        seq        = 'n/a'
        TargetUser = 'testuser_haystack_poc'
        user       = $User
        WindowSec  = '300'
    }
    if (-not [string]::IsNullOrWhiteSpace($Marker)) {
        $params.test = $Marker
    }

    return 'HIT {0}' -f (Format-Fields -Fields $params)
}

function Build-CaptivePortalPayloads {
    param(
        [string[]]$Urls,
        [string]$Machine,
        [string]$User,
        [string]$Ssid,
        [string]$VpnState,
        [string]$PortalType,
        [string]$Marker
    )

    $payloads = New-Object System.Collections.Generic.List[string]

    foreach ($url in $Urls) {
        $evtTime = (Get-Date).ToString('o')
        $port = Get-EffectiveUriPort -Url $url

        $redirectFields = [ordered]@{
            action    = 'cap_portal_redirect'
            EvtTime   = $evtTime
            machine   = $Machine
            user      = $User
            url       = $url
            port      = $port
            ssid      = $Ssid
            vpn_state = $VpnState
        }
        if (-not [string]::IsNullOrWhiteSpace($Marker)) {
            $redirectFields.test = $Marker
        }
        $payloads.Add((Format-Fields -Fields $redirectFields))

        $passFields = [ordered]@{
            action      = 'cap_portal_remediation_passed'
            EvtTime     = (Get-Date).ToString('o')
            machine     = $Machine
            user        = $User
            url         = $url
            port        = $port
            portal_type = $PortalType
            status      = 'verified'
            reason      = 'network_check_passed'
            ssid        = $Ssid
            vpn_state   = $VpnState
        }
        if (-not [string]::IsNullOrWhiteSpace($Marker)) {
            $passFields.test = $Marker
        }
        $payloads.Add((Format-Fields -Fields $passFields))

        $failFields = [ordered]@{
            action      = 'cap_portal_remediation_failed'
            EvtTime     = (Get-Date).ToString('o')
            machine     = $Machine
            user        = $User
            url         = $url
            port        = $port
            portal_type = $PortalType
            status      = 'timeout'
            reason      = 'runner_timeout_or_no_response'
            ssid        = $Ssid
            vpn_state   = $VpnState
        }
        if (-not [string]::IsNullOrWhiteSpace($Marker)) {
            $failFields.test = $Marker
        }
        $payloads.Add((Format-Fields -Fields $failFields))
    }

    return $payloads
}

$priority = Get-SyslogPriority -Facility $Facility -Severity $Severity
$machine = Get-MachineName
$user = Get-LoggedOnUser

Write-Host ''
Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '  Haystack Syslog Simulator' -ForegroundColor Cyan
Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host "  Target       : $SyslogServer : $Port / UDP"
Write-Host "  Priority     : <$priority>"
Write-Host "  DeliveryMode : $DeliveryMode"
if ($DeliveryMode -eq 'direct') {
    Write-Host '  Note         : direct mode bypasses Haystack network-state gating' -ForegroundColor Yellow
} else {
    Write-Host "  QueueFile     : $QueueFile"
    Write-Host '  Note         : queue mode writes queue entries for Haystack queue/drain path' -ForegroundColor Yellow
}
Write-Host "  Test marker  : $(if ([string]::IsNullOrWhiteSpace($TestMarker)) { '<none>' } else { $TestMarker })"
Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''

$payloads = New-Object System.Collections.Generic.List[string]

if ($SimulateCaptivePortal) {
    foreach ($cpPayload in (Build-CaptivePortalPayloads -Urls $PortalUrls -Machine $machine -User $user -Ssid $PortalSsid -VpnState $PortalVpnState -PortalType $PortalType -Marker $TestMarker)) {
        $payloads.Add([string]$cpPayload)
    }
} else {
    for ($i = 1; $i -le $Count; $i++) {
        $evtTimeIso = (Get-Date).ToString('o')
        if ($SimulateHit) {
            $payloads.Add((Build-HitPayload -Machine $machine -User $user -EvtTime $evtTimeIso -Marker $TestMarker).Replace('seq="n/a"', ('seq="{0}/{1}"' -f $i, $Count)))
        } else {
            $pingFields = [ordered]@{
                action  = 'connectivity_test'
                EvtTime = $evtTimeIso
                machine = $machine
                user    = $user
                pid     = $PID
                seq     = ('{0}/{1}' -f $i, $Count)
            }
            if (-not [string]::IsNullOrWhiteSpace($TestMarker)) {
                $pingFields.test = $TestMarker
            }
            $payloads.Add('PING {0}' -f (Format-Fields -Fields $pingFields))
        }
    }
}

$sent = 0
$failed = 0
$total = $payloads.Count

for ($idx = 0; $idx -lt $payloads.Count; $idx++) {
    $payload = $payloads[$idx]
    $n = $idx + 1

    try {
        if ($DeliveryMode -eq 'queue') {
            $out = Write-QueueEntry -Path $QueueFile -Payload $payload
            Write-Host "[$(Get-Date -f 'HH:mm:ss')] QUEUED ($n/$total)" -ForegroundColor Green
            Write-Host "  $out" -ForegroundColor DarkGray
        } else {
            $raw = Send-SyslogMessage -Server $SyslogServer -Port $Port -Priority $priority -Message $payload
            Write-Host "[$(Get-Date -f 'HH:mm:ss')] SENT ($n/$total)" -ForegroundColor Green
            Write-Host "  $raw" -ForegroundColor DarkGray
        }
        $sent++
    } catch {
        $failed++
        Write-Host "[$(Get-Date -f 'HH:mm:ss')] FAILED ($n/$total) : $_" -ForegroundColor Red
    }

    if ($idx -lt ($payloads.Count - 1)) {
        Start-Sleep -Seconds $IntervalSeconds
    }
}

Write-Host ''
Write-Host '── Results ───────────────────────────────────────' -ForegroundColor Cyan
Write-Host "  Sent/Queued OK : $sent"
Write-Host "  Failed         : $failed"
Write-Host ''

if ($failed -eq 0) {
    Write-Host '  Suggested Splunk query:' -ForegroundColor Yellow
    Write-Host '  index=cba_cpr_logging test="1" | table EvtTime,action,machine,user,url,port,portal_type,status,reason,ssid,vpn_state' -ForegroundColor White
}

Write-Host ''
