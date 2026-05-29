<#
.SYNOPSIS
  WhiteWalker User Notification Handler
  Version: 1.0.0
  Author: steve.horton@optum.com
  Date: 09-Apr-2026

.DESCRIPTION
  Runs in USER context via Task Scheduler triggered by Event ID 800.
  Reads NOTIFY payload from the event log message and displays a
  Windows toast notification to the logged-on user.

  Payload format (pipe-delimited):
    NOTIFY:toast|title=Your Title|body=Your message here.|duration=10

  Supported types:
    toast  - Windows 11 toast notification (primary)

  Called by any script in the WW framework that writes Event ID 800
  with a NOTIFY: prefixed message to the WhiteWalkerFlareGun source.

  Task Scheduler trigger: Application log, Source=WhiteWalkerFlareGun, EventID=800
#>

# =============================================================================
# Configuration - tune notification behavior up top
# =============================================================================

# Default auto-dismiss durations (seconds) per notification type
# Override per-call by including duration=N in the payload
$ToastDurationSec       = 10    # default toast display time

# App ID used for toast notifications - shows in action center
#$ToastAppId             = "WhiteWalker.CPR"
$ToastAppId		= "Microsoft.Windows.Shell.RunDialog"
# Log file
$LogFile                = "C:\ProgramData\WhiteWalker\WW_notify.log"

# Event log source to read payload from
$EventSource            = "WhiteWalkerFlareGun"
$EventId                = 800

# =============================================================================
# Logging
# =============================================================================
function Write-NLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts [$Level] [WW_notify] $Message"
    Write-Host $line
    try {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

# =============================================================================
# Payload Parser
# =============================================================================
function Parse-NotifyPayload {
    param([string]$Raw)
    # Expected: NOTIFY:toast|title=...|body=...|duration=N
    $result = @{
        Type     = "toast"
        Title    = "WhiteWalker"
        Body     = ""
        Duration = $ToastDurationSec
    }

    if (-not $Raw -or -not $Raw.StartsWith("NOTIFY:")) {
        Write-NLog "Invalid payload (missing NOTIFY: prefix): $Raw" "WARN"
        return $null
    }

    $raw = $Raw.Substring(7)  # strip "NOTIFY:"
    $parts = $raw -split '\|'

    if ($parts.Count -gt 0) { $result.Type = $parts[0].Trim().ToLower() }

    foreach ($part in $parts[1..($parts.Count-1)]) {
        if ($part -match '^title=(.+)$')    { $result.Title    = $matches[1].Trim() }
        if ($part -match '^body=(.+)$')     { $result.Body     = $matches[1].Trim() }
        if ($part -match '^duration=(\d+)$'){ $result.Duration = [int]$matches[1] }
    }

    return $result
}

# =============================================================================
# Toast Notification
# =============================================================================
function Show-ToastNotification {
    param(
        [string]$Title,
        [string]$Body,
        [int]$DurationSec = $ToastDurationSec
    )

    try {
        # Load Windows Runtime toast assemblies
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null

        # Build toast XML - short duration for quick notices, long for important ones
        $xmlDuration = if ($DurationSec -le 7) { "short" } else { "long" }

        $toastXml = @"
<toast duration="$xmlDuration">
  <visual>
    <binding template="ToastGeneric">
      <text>$([System.Security.SecurityElement]::Escape($Title))</text>
      <text>$([System.Security.SecurityElement]::Escape($Body))</text>
    </binding>
  </visual>
</toast>
"@
        $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xmlDoc.LoadXml($toastXml)

        $toast   = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)

        # Set expiration so it clears from action center after DurationSec
        $toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds($DurationSec)

        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($ToastAppId)
        $notifier.Show($toast)

        Write-NLog "Toast shown: title='$Title' body='$Body' duration=${DurationSec}s" "INFO"

    } catch {
        Write-NLog "Toast notification failed: $_ - falling back to msgbox" "WARN"
        # Silent fallback - don't pop a blocking msgbox on 500k endpoints
        # Just log it and move on
    }
}

# =============================================================================
# Main
# =============================================================================
Write-NLog "WW_notify v1.0.0 starting"

# Read the most recent Event ID 800 from the Application log
try {
    $event = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = $EventSource
        Id           = $EventId
    } -MaxEvents 1 -ErrorAction Stop

    $rawMessage = $event.Message
    Write-NLog "Event payload received: $rawMessage" "DEBUG"

} catch {
    Write-NLog "Could not read Event ID $EventId from $EventSource : $_" "WARN"
    exit 1
}

# Parse the payload
$payload = Parse-NotifyPayload -Raw $rawMessage

if (-not $payload) {
    Write-NLog "Could not parse notification payload - exiting" "WARN"
    exit 1
}

Write-NLog "Parsed: type=$($payload.Type) title='$($payload.Title)' duration=$($payload.Duration)s" "INFO"

# Dispatch to correct notification type
switch ($payload.Type) {
    "toast" {
        Show-ToastNotification -Title $payload.Title -Body $payload.Body -DurationSec $payload.Duration
    }
    default {
        Write-NLog "Unknown notification type '$($payload.Type)' - defaulting to toast" "WARN"
        Show-ToastNotification -Title $payload.Title -Body $payload.Body -DurationSec $payload.Duration
    }
}

Write-NLog "WW_notify complete"
exit 0
