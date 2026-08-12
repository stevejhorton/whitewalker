<#
.SYNOPSIS
  WhiteWalker User Notification Handler
  Version: 1.1.0
  Author: steve.horton@optum.com
  Date: 29-May-2026

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

  v1.1.0 changes:
    - Replaced Microsoft.Windows.Shell.RunDialog AUMID hack with registered
      WhiteWalker.CPR AUMID (HKCU - no admin required, USER context)
    - Added CPR+ logo (appLogoOverride) to toast
    - Added User Guide and VPN Info action buttons to toast
#>

# =============================================================================
# Configuration
# =============================================================================
$ToastDurationSec  = 10
$ToastAppId        = "WhiteWalker.CPR"
$LogFile           = "C:\ProgramData\WhiteWalker\WW_notify.log"
$EventSource       = "WhiteWalkerFlareGun"
$EventId           = 800
$DocsLocalPath     = "C:\ProgramData\WhiteWalker\docs"

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
# AUMID Registration
# Register WhiteWalker.CPR in HKCU so Windows shows "CPR+ Network Assistant"
# as the app name instead of "Run". HKCU requires no admin rights - safe in
# USER context. Runs fast (just a reg check) on every invocation.
# =============================================================================
function Register-CprAumid {
    $aumidPath = "HKCU:\SOFTWARE\Classes\AppUserModelId\$ToastAppId"
    try {
        if (-not (Test-Path $aumidPath)) {
            New-Item -Path $aumidPath -Force -ErrorAction Stop | Out-Null
            Write-NLog "AUMID registered: $ToastAppId" "DEBUG"
        }
        Set-ItemProperty -Path $aumidPath -Name "DisplayName" -Value "CPR+ Network Assistant" -ErrorAction SilentlyContinue
        $logoPath = Join-Path $DocsLocalPath "CPR_Logo.jpeg"
        if (Test-Path $logoPath) {
            Set-ItemProperty -Path $aumidPath -Name "IconUri" -Value $logoPath -ErrorAction SilentlyContinue
        }
    } catch {
        Write-NLog "AUMID registration failed (non-fatal): $_" "DEBUG"
    }
}

# =============================================================================
# Payload Parser
# =============================================================================
function Parse-NotifyPayload {
    param([string]$Raw)
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

    $raw   = $Raw.Substring(7)
    $parts = $raw -split '\|'

    if ($parts.Count -gt 0) { $result.Type = $parts[0].Trim().ToLower() }

    foreach ($part in $parts[1..($parts.Count-1)]) {
        if ($part -match '^title=(.+)$')     { $result.Title    = $matches[1].Trim() }
        if ($part -match '^body=(.+)$')      { $result.Body     = $matches[1].Trim() }
        if ($part -match '^duration=(\d+)$') { $result.Duration = [int]$matches[1] }
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
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null

        $xmlDuration = if ($DurationSec -le 7) { "short" } else { "long" }

        # Logo - graceful fallback to no image if docs not yet deployed
        $logoPath    = Join-Path $DocsLocalPath "CPR_Logo.jpeg"
        $logoXml     = ""
        if (Test-Path $logoPath) {
            $logoUri = "file:///" + ($logoPath -replace '\\','/')
            $logoXml = "<image placement=`"appLogoOverride`" src=`"$logoUri`"/>"
        }

        # Help file action buttons - only include if files exist locally
        $actionsXml  = ""
        $guidePath   = Join-Path $DocsLocalPath "cpr_user_guide.html"
        $blackholePath = Join-Path $DocsLocalPath "vpn_blackhole_info.html"
        $actionItems = ""
        if (Test-Path $guidePath) {
            $guideUri    = "file:///" + ($guidePath -replace '\\','/')
            $actionItems += "`n    <action content=`"User Guide`" arguments=`"$guideUri`" activationType=`"protocol`"/>"
        }
        if (Test-Path $blackholePath) {
            $bhUri       = "file:///" + ($blackholePath -replace '\\','/')
            $actionItems += "`n    <action content=`"VPN Info`" arguments=`"$bhUri`" activationType=`"protocol`"/>"
        }
        if ($actionItems) {
            $actionsXml  = "<actions>$actionItems`n  </actions>"
        }

        $toastXml = @"
<toast duration="$xmlDuration">
  <visual>
    <binding template="ToastGeneric">
      $logoXml
      <text>$([System.Security.SecurityElement]::Escape($Title))</text>
      <text>$([System.Security.SecurityElement]::Escape($Body))</text>
    </binding>
  </visual>
  $actionsXml
</toast>
"@
        $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xmlDoc.LoadXml($toastXml)

        $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
        $toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds($DurationSec)

        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($ToastAppId)
        $notifier.Show($toast)

        Write-NLog "Toast shown: title='$Title' body='$Body' duration=${DurationSec}s" "INFO"

    } catch {
        Write-NLog "Toast notification failed: $_ - falling back silently" "WARN"
    }
}

# =============================================================================
# Main
# =============================================================================
Write-NLog "WW_notify v1.1.0 starting"

# Register AUMID first - fixes "Run" app name, sets logo for action center
Register-CprAumid

# Read most recent Event ID 800
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

$payload = Parse-NotifyPayload -Raw $rawMessage

if (-not $payload) {
    Write-NLog "Could not parse notification payload - exiting" "WARN"
    exit 1
}

Write-NLog "Parsed: type=$($payload.Type) title='$($payload.Title)' duration=$($payload.Duration)s" "INFO"

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
