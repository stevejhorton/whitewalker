#Requires -RunAsAdministrator
<#
  Triggers WW_notify.ps1 by writing the expected Event ID 800 payload.
  Task Scheduler should be configured for:
    Log: Application
    Source: WhiteWalkerFlareGun
    Event ID: 800
#>

param(
  [string]$Title    = "WW Test Notification",
  [string]$Body     = "Triggering Event ID 800 to validate WW_notify.ps1 is firing.",
  [int]   $Duration = 10,
  [ValidateSet("toast")]
  [string]$Type     = "toast"
)

$payload = "NOTIFY:$Type|title=$Title|body=$Body|duration=$Duration"

$eventArgs = @(
  "/T", "INFORMATION",
  "/ID", "800",
  "/L", "APPLICATION",
  "/SO", "WhiteWalkerFlareGun",
  "/D", $payload
)

Write-Host "Writing event 800 with payload:"
Write-Host $payload

Start-Process -FilePath "eventcreate.exe" -ArgumentList $eventArgs -WindowStyle Hidden -Wait

Write-Host "Done. Check Application log for Source='WhiteWalkerFlareGun' EventID=800."
