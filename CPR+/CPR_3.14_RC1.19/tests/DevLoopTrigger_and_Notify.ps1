eventcreate /T INFORMATION /ID 800 /L APPLICATION /SO "WhiteWalkerFlareGun" /D "NOTIFY:toast|title=CPR+|body=Test message $(Get-Date)|duration=10"
powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_notify.ps1"
