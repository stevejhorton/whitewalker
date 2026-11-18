Get-ScheduledTask -TaskName 'WW_main' | Select TaskPath,State,@{n='Trig';e={$_.Triggers.Count}} | Format-Table
Get-ScheduledTask -TaskName 'WW_main' | Get-ScheduledTaskInfo | Select LastRunTime,LastTaskResult
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=(Get-Date).AddHours(-5)} -EA SilentlyContinue |
  Where-Object Message -match 'WW_main' | Select TimeCreated,Id,Message | Format-List | Out-String -Width 160
   
