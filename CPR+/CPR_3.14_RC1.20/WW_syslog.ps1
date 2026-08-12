<#
.SYNOPSIS
  WW Syslog Sender
  Version: 1.0.0
  Author: steve.horton@optum.com
  Date: 30-May-2026

.DESCRIPTION
  Standalone RFC 3164 syslog sender for the WhiteWalker / CPR+ framework.
  Called by haystack_action.ps1 on NEEDLE_HIT events, or any other WW
  script that needs to ship a message to the enterprise syslog collector.

  Automatically enriches every message with:
    machine  - $env:COMPUTERNAME
    user     - logged-on user (Win32_ComputerSystem.UserName - works from SYSTEM context)

  Message body should be key=value pairs for clean Splunk field extraction.
  An optional freeform ExtraInfo field is appended at the end if provided.

  RFC 3164 format:  <PRI>TIMESTAMP HOSTNAME TAG: MSG
  TAG is always 'Haystack' for consistent Splunk sourcetype routing.

  Never throws - all errors are written to stderr and the script exits 1.
  Callers should treat failure as non-fatal (local log is the source of truth).

.PARAMETER Message
  Pre-built key=value payload string. Caller builds this.
  e.g. 'action=needle_hit Label="Network_Connected" EventID="10000"'

.PARAMETER ExtraInfo
  Optional freeform quoted field appended to the message.
  Use for anything not covered by the standard fields.

.PARAMETER SyslogServer
  Syslog collector FQDN or IP. Default: cpr-syslog.uhc.com

.PARAMETER Port
  UDP port. Default: 514

.PARAMETER Facility
  RFC 3164 facility code (0-23). Default: 16 (local0)

.PARAMETER Severity
  RFC 3164 severity code (0-7). Default: 5 (Notice)

.EXAMPLE
  .\WW_syslog.ps1 -Message 'action=needle_hit Label="Network_Connected" EventID="10000"'

.EXAMPLE
  .\WW_syslog.ps1 -Message 'action=needle_hit Label="App_Crash_Any"' -ExtraInfo "chrome.exe crashed at 10:32"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Message,
    [string]$ExtraInfo    = '',
    [string]$SyslogServer = 'cpr-syslog.uhc.com',
    [int]   $Port         = 514,
    [int]   $Facility     = 16,   # local0
    [int]   $Severity     = 5,    # Notice
    [string]$Tag          = 'Haystack'
)

# =============================================================================
# Helpers
# =============================================================================
function Get-Rfc3164Timestamp {
    $now = Get-Date
    return '{0} {1,2} {2}' -f $now.ToString('MMM'), $now.Day, $now.ToString('HH:mm:ss')
}

function Get-LoggedOnUser {
    # $env:USERNAME returns SYSTEM when running as SYSTEM context.
    # Win32_ComputerSystem.UserName returns the actual interactive user.
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($cs.UserName)) { return $cs.UserName }
        return 'NO_INTERACTIVE_USER'
    } catch {
        return 'USER_UNKNOWN'
    }
}

# =============================================================================
# Main
# =============================================================================
try {
    $priority  = ($Facility * 8) + $Severity
    $timestamp = Get-Rfc3164Timestamp
    $machine   = $env:COMPUTERNAME
    $user      = Get-LoggedOnUser

    # Build enriched payload
    # machine and user prepended so they show up as early fields in Splunk
    $enriched  = 'machine="{0}" user="{1}" {2}' -f $machine, $user, $Message
    if (-not [string]::IsNullOrWhiteSpace($ExtraInfo)) {
        $enriched += ' ExtraInfo="{0}"' -f $ExtraInfo
    }

    # RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
    $raw   = '<{0}>{1} {2} {3}: {4}' -f $priority, $timestamp, $machine, $Tag, $enriched
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($raw)

    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        $udp.Send($bytes, $bytes.Length, $SyslogServer, $Port) | Out-Null
    } finally {
        $udp.Close()
    }

    Write-Verbose "Syslog sent ($($bytes.Length)b) -> ${SyslogServer}:${Port} | $raw"
    exit 0

} catch {
    Write-Error "WW_syslog: send failed: $_"
    exit 1
}
