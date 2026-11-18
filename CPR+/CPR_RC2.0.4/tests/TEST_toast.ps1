eventcreate /T INFORMATION /ID 800 /L APPLICATION /SO "WhiteWalkerFlareGun" /D "NOTIFY:toast|title=WW Test|body=If you see this, toast is working.|duration=10"

Get-WinEvent -FilterHashtable @{
  LogName      = 'Application'
  ProviderName = 'WhiteWalkerFlareGun'
  Id           = 800
} -MaxEvents 1 | Select-Object TimeCreated, Id, ProviderName, Message | Format-List
