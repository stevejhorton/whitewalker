Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=(Get-Date).AddMinutes(-3)} -EA SilentlyContinue |
  Where-Object Message -match 'WW_main' | Select TimeCreated,Id,Message | Format-List
