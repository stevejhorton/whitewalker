<#
One-shot diagnostic for "unlock did not fire WW_main". Run elevated AFTER one lock+unlock.
Removes the ZZ_unlock_probe test task, then writes everything useful to ONE text file
next to this script and prints its path. Read-only except removing the probe task.
#>
$ErrorActionPreference = 'SilentlyContinue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out   = Join-Path $PSScriptRoot ("unlock_diag_{0}_{1}.txt" -f $env:COMPUTERNAME, $stamp)
$sb    = New-Object System.Text.StringBuilder
function Add-Sec([string]$Title, $Body) {
    [void]$sb.AppendLine(""); [void]$sb.AppendLine("=== $Title ===")
    [void]$sb.AppendLine((($Body | Out-String -Width 200).TrimEnd()))
}

Add-Sec 'when' ("now={0} host={1} user={2}" -f (Get-Date -Format o), $env:COMPUTERNAME, $env:USERNAME)

# Probe result first, then remove the probe so it cannot muddy later runs.
$probeFile = 'C:\Windows\Temp\unlock_probe.txt'
Add-Sec 'unlock_probe.txt (one line per unlock the probe saw)' $(if (Test-Path $probeFile) { Get-Content $probeFile } else { '(no file)' })
if (Get-ScheduledTask -TaskName 'ZZ_unlock_probe' -TaskPath '\CPR\') {
    Unregister-ScheduledTask -TaskName 'ZZ_unlock_probe' -TaskPath '\CPR\' -Confirm:$false
    Add-Sec 'probe cleanup' 'ZZ_unlock_probe removed'
}
Remove-Item $probeFile -Force

# Where do the tasks live and what do the triggers look like as registered
$tasks = @(Get-ScheduledTask -TaskName 'WW_*','HayStack_Monitor')
Add-Sec 'CPR tasks' ($tasks | Select-Object TaskPath, TaskName, State | Sort-Object TaskPath, TaskName | Format-Table -AutoSize)
$wm = $tasks | Where-Object { $_.TaskName -eq 'WW_main' }
foreach ($t in $wm) {
    Add-Sec ("WW_main triggers at {0}" -f $t.TaskPath) ($t.Triggers | ForEach-Object {
        '{0} enabled={1} state_change={2} user={3}' -f $_.CimClass.CimClassName, $_.Enabled, $_.StateChange, $_.UserId })
    Add-Sec ("WW_main task info at {0}" -f $t.TaskPath) ($t | Get-ScheduledTaskInfo | Select-Object LastRunTime, LastTaskResult, NextRunTime)
}

# Task Scheduler history for the last 45 minutes (launches, drops, registrations)
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = (Get-Date).AddMinutes(-45) } |
      Where-Object { $_.Message -match 'WW_main|ZZ_unlock_probe' } | Sort-Object TimeCreated
Add-Sec 'TaskScheduler events (WW_main / probe), last 45 min' ($ev | ForEach-Object {
    $m = ($_.Message -replace '\s+', ' ' -replace '\{[0-9a-f-]+\}', '{I}')
    '{0} id={1} {2}' -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id, $m.Substring(0, [Math]::Min(120, $m.Length)) })

# What CPR itself logged
$log = 'C:\ProgramData\WhiteWalker\logs\white_walker.main.log'
if (Test-Path $log) {
    Add-Sec 'main log: recent run boundaries' (Select-String -Path $log -Pattern 'RUN START|RUN END|White Walker v|maintenance_stage|early_vpn_gate' | Select-Object -Last 24 | ForEach-Object { $_.Line })
    Add-Sec 'main log tail (60 lines)' (Get-Content $log -Tail 60)
} else { Add-Sec 'main log' "(not found: $log)" }

$sb.ToString() | Out-File -FilePath $out -Encoding ASCII
Write-Host "Wrote: $out"
