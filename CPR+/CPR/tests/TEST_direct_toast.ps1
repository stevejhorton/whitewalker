param(
  [string]$Title  = "WhiteWalker Toast Test",
  [string]$Body   = "If you see this bubble, toast rendering works in this session.",
  [int]$DurationSec = 10,
  [string]$AppId  = "WhiteWalker.CPR"
)

try {
  # Load WinRT toast assemblies
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
  [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null

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

  $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
  $toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds($DurationSec)

  $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId)
  $notifier.Show($toast)

  "Toast API call completed. If no bubble appeared, check Focus Assist / Notifications settings / AppId registration."
}
catch {
  "Toast failed: $($_.Exception.Message)"
  $_ | Format-List * -Force
}
