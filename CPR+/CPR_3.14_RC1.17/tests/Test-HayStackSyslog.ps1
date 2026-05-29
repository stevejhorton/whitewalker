<#
.SYNOPSIS
    Proof-of-concept syslog sender for Haystack hit validation.
    Sends RFC 3164 formatted UDP syslog messages to the enterprise
    collector so Splunk ingestion and dashboarding can be validated.

.DESCRIPTION
    Simulates the syslog messages that Haystack will emit on a hit event.
    Run this manually to confirm:
      1. Messages arrive at the syslog collector (10.176.183.3:514)
      2. Splunk indexes them correctly
      3. Field extractions / sourcetype parse as expected

.PARAMETER SyslogServer
    IP or FQDN of the syslog collector. Defaults to enterprise collector.

.PARAMETER Port
    UDP port. Default 514.

.PARAMETER Facility
    Syslog facility code (0-23). Default 16 = local0 (good for security tools).

.PARAMETER Severity
    Syslog severity code (0-7). Default 5 = Notice.

.PARAMETER Count
    Number of test messages to send. Default 3.

.PARAMETER IntervalSeconds
    Seconds between messages. Default 2.

.PARAMETER SimulateHit
    If set, sends a payload that mimics a real Haystack hit event.
    Otherwise sends a simple connectivity ping message.

.EXAMPLE
    .\Test-HaystackSyslog.ps1
    Sends 3 basic connectivity test messages.

.EXAMPLE
    .\Test-HaystackSyslog.ps1 -SimulateHit -Count 1
    Sends a single simulated Haystack hit payload.

.NOTES
    Author  : shorto39_uhg
    Service : OptumUHG Global Remote Access / Haystack
    Version : 0.1.0 (PoC)
#>

[CmdletBinding()]
param(
    [string]  $SyslogServer     = 'phi-dmz-udp-syslog.optum.com',
    [int]     $Port             = 514,
    [int]     $Facility         = 16,          # local0
    [int]     $Severity         = 5,           # Notice
    [int]     $Count            = 3,
    [int]     $IntervalSeconds  = 2,
    [switch]  $SimulateHit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ────────────────────────────────────────────────────────────

function Get-SyslogPriority {
    param([int]$Facility, [int]$Severity)
    return ($Facility * 8) + $Severity
}

function Get-Rfc3164Timestamp {
    # MMM DD HH:MM:SS  (single-digit day is space-padded, not zero-padded)
    $now = Get-Date
    return '{0} {1,2} {2}' -f `
        $now.ToString('MMM'),
        $now.Day,
        $now.ToString('HH:mm:ss')
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

    # RFC 3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MSG
    $raw = '<{0}>{1} {2} {3}: {4}' -f $Priority, $timestamp, $hostname, $tag, $Message

    $bytes  = [System.Text.Encoding]::ASCII.GetBytes($raw)
    $udp    = [System.Net.Sockets.UdpClient]::new()

    try {
        $udp.Send($bytes, $bytes.Length, $Server, $Port) | Out-Null
        return $raw
    }
    finally {
        $udp.Close()
    }
}

function Build-HitPayload {
    # Mimics what Haystack will emit on a real event hit
    # Key=Value pairs keep Splunk field extraction simple
    $params = @{
        EventID    = '4625'
        NeedleID   = 'NEEDLE_BRUTE_LOCAL_LOGON'
        Label      = 'BruteForce_Local_Logon'
        HitCount   = (Get-Random -Minimum 3 -Maximum 20)
        WindowSec  = '300'
        TargetUser = 'testuser_haystack_poc'
        LogonType  = '2'
        Host       = $env:COMPUTERNAME
        User       = $env:USERNAME
        PID        = $PID
        RunID      = [guid]::NewGuid().ToString('N').Substring(0,8).ToUpper()
    }

    # Build flat key=value string
    return ($params.GetEnumerator() | Sort-Object Name |
        ForEach-Object { '{0}="{1}"' -f $_.Key, $_.Value }) -join ' '
}

#endregion ── Helpers ─────────────────────────────────────────────────────────

#region ── Main ───────────────────────────────────────────────────────────────

$priority = Get-SyslogPriority -Facility $Facility -Severity $Severity

Write-Host ''
Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '  Haystack Syslog PoC Sender' -ForegroundColor Cyan
Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host "  Target   : $SyslogServer : $Port / UDP"
Write-Host "  Facility : $Facility (local0)   Severity: $Severity (Notice)"
Write-Host "  Priority : <$priority>"
Write-Host "  Mode     : $(if ($SimulateHit) { 'Simulated HIT payload' } else { 'Connectivity ping' })"
Write-Host "  Messages : $Count   Interval: ${IntervalSeconds}s"
Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''

$sent    = 0
$failed  = 0

for ($i = 1; $i -le $Count; $i++) {

    $msg = if ($SimulateHit) {
        'HIT action=alert seq={0}/{1} {2}' -f $i, $Count, (Build-HitPayload)
    } else {
        'PING action=connectivity_test seq={0}/{1} host="{2}" user="{3}" pid="{4}"' -f `
            $i, $Count, $env:COMPUTERNAME, $env:USERNAME, $PID
    }

    try {
        $raw = Send-SyslogMessage -Server $SyslogServer -Port $Port -Priority $priority -Message $msg
        $sent++
        Write-Host "[$(Get-Date -f 'HH:mm:ss')] SENT ($i/$Count)" -ForegroundColor Green
        Write-Host "  $raw" -ForegroundColor DarkGray
    }
    catch {
        $failed++
        Write-Host "[$(Get-Date -f 'HH:mm:ss')] FAILED ($i/$Count) : $_" -ForegroundColor Red
    }

    if ($i -lt $Count) { Start-Sleep -Seconds $IntervalSeconds }
}

Write-Host ''
Write-Host '── Results ───────────────────────────────────────' -ForegroundColor Cyan
Write-Host "  Sent OK : $sent"
Write-Host "  Failed  : $failed"
Write-Host ''

if ($failed -eq 0) {
    Write-Host '  Now verify in Splunk:' -ForegroundColor Yellow
    Write-Host "  index=* sourcetype=syslog host=$($env:COMPUTERNAME) Haystack" -ForegroundColor White
    Write-Host ''
    Write-Host '  Or if they''ve set a dedicated sourcetype/index:' -ForegroundColor Yellow
    Write-Host '  index=endpoint sourcetype=haystack_hit' -ForegroundColor White
}

Write-Host ''

#endregion ── Main ────────────────────────────────────────────────────────────
