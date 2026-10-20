<#
.SYNOPSIS
TEMPORARY one-shot migration: removes CPR scheduled tasks from their LEGACY
Task Scheduler locations so they exist only under the \CPR\ folder.

.DESCRIPTION
*** TEMPORARY - REMOVE ONCE NO ENDPOINT RUNS A PRE-RC2.1 BUILD ***
How to retire it (all four, nothing else references it):
  1. Delete this file.
  2. Delete its two blocks in install.ps1 (search: LEGACY-TASK-MIGRATION).
  3. Delete $LegacyTaskMigrationEnabled from main\Main.Configuration.ps1.
  4. Delete tests\CPR_RC2.LegacyTaskMigration.Tests.ps1.
Short of retiring it, set $LegacyTaskMigrationEnabled = $false in
main\Main.Configuration.ps1 to turn it off (the installer reads that pivot).

Legacy locations handled:
  \WW_main, \WW_cap_portal_runner, \WW_cap_portal_runner_base, \WW_flaregun_user,
  \WW_flaregun_system, \WW_notify, \WW_blackhole_shutdown, \WW_xml_vault
  \HayStack\HayStack_Monitor      (empty \HayStack\ folder removed, best effort)

Done-flag: C:\ProgramData\WhiteWalker\legacy_task_migration.done
  Present => skipped, UNLESS legacy task files have reappeared (e.g. an older
  build was reinstalled), in which case it runs again. Presence is checked on the
  Task Scheduler file store, not CIM, so the check costs milliseconds.
Log: C:\ProgramData\WhiteWalker\logs\legacy_task_migration.log (written whenever it
actually runs). Emits one result object; the installer logs a summary line.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',      # Main.Configuration.ps1 holding the pivot
    [switch]$Force                 # ignore the done-flag (not the pivot)
)

$script:MigLogPath  = 'C:\ProgramData\WhiteWalker\logs\legacy_task_migration.log'
$script:MigFlagPath = 'C:\ProgramData\WhiteWalker\legacy_task_migration.done'

function Write-MigLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] legacy_task_migration {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    try {
        $dir = Split-Path -Parent $script:MigLogPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -LiteralPath $script:MigLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch { }
}

function Get-LegacyTaskList {
    $root = @('WW_main', 'WW_cap_portal_runner', 'WW_cap_portal_runner_base', 'WW_flaregun_user',
              'WW_flaregun_system', 'WW_notify', 'WW_blackhole_shutdown', 'WW_xml_vault')
    $list = foreach ($n in $root) { [pscustomobject]@{ Name = $n; TaskPath = '\' } }
    $list += [pscustomobject]@{ Name = 'HayStack_Monitor'; TaskPath = '\HayStack\' }
    return @($list)
}

function Get-MigrationPivot {
    # Reads $LegacyTaskMigrationEnabled from the config text. Unreadable or absent
    # => $true (the migration is idempotent, so running is the safe default).
    param([string]$ConfigPath)
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -or -not (Test-Path -LiteralPath $ConfigPath)) { return $true }
    try {
        $m = Select-String -LiteralPath $ConfigPath -Pattern '^\s*\$LegacyTaskMigrationEnabled\s*=\s*\$(true|false)' |
             Select-Object -First 1
        if ($m) { return ($m.Matches[0].Groups[1].Value -eq 'true') }
    } catch { }
    return $true
}

function Get-TaskStoreFile {
    param([string]$TasksRoot, $Task)
    $rel = (($Task.TaskPath.Trim('\')), $Task.Name | Where-Object { $_ }) -join '\'
    return (Join-Path $TasksRoot $rel)
}

function Remove-EmptyTaskFolder {
    # Best effort: drop an empty legacy folder (e.g. \HayStack\) via the scheduler COM API.
    param([string]$TasksRoot, [string]$FolderName)
    $dir = Join-Path $TasksRoot $FolderName
    if (-not (Test-Path -LiteralPath $dir)) { return }
    if (@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue).Count -gt 0) { return }
    try {
        $svc = New-Object -ComObject 'Schedule.Service'
        $svc.Connect()
        $svc.GetFolder('\').DeleteFolder($FolderName, 0)
        Write-MigLog "removed empty legacy folder \$FolderName\"
    } catch {
        Write-MigLog "could not remove empty folder \$FolderName\ (harmless): $_" 'WARN'
    }
}

function Invoke-LegacyTaskMigration {
    param(
        [string]$TasksRoot = (Join-Path $env:windir 'System32\Tasks'),
        [bool]$Enabled = $true,
        [switch]$Force
    )
    $res = [pscustomobject]@{ Ran = $false; Skipped = $true; Reason = ''; Removed = @(); Failed = @() }

    if (-not $Enabled) { $res.Reason = 'pivot_off'; return $res }

    $present = @(Get-LegacyTaskList | Where-Object { Test-Path -LiteralPath (Get-TaskStoreFile $TasksRoot $_) })
    $flagged = Test-Path -LiteralPath $script:MigFlagPath

    if ($flagged -and -not $Force -and $present.Count -eq 0) { $res.Reason = 'flag_present'; return $res }

    $res.Ran = $true; $res.Skipped = $false
    Write-MigLog ("start flagged={0} force={1} legacy_found={2}" -f $flagged, [bool]$Force, $present.Count)
    if ($flagged -and $present.Count -gt 0) {
        Write-MigLog 'done-flag present but legacy tasks have reappeared (older build reinstalled?) - running again' 'WARN'
    }

    foreach ($t in $present) {
        $label = '{0}{1}' -f $t.TaskPath, $t.Name
        try {
            Unregister-ScheduledTask -TaskName $t.Name -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
            if (Test-Path -LiteralPath (Get-TaskStoreFile $TasksRoot $t)) { throw 'task file still present after unregister' }
            Write-MigLog "removed legacy task $label"
            $res.Removed += $label
        } catch {
            Write-MigLog "FAILED to remove legacy task ${label}: $_" 'ERROR'
            $res.Failed += $label
        }
    }

    Remove-EmptyTaskFolder -TasksRoot $TasksRoot -FolderName 'HayStack'

    if ($res.Failed.Count -eq 0) {
        try {
            @{ completed = (Get-Date).ToString('o'); removed = $res.Removed } | ConvertTo-Json |
                Set-Content -LiteralPath $script:MigFlagPath -Encoding UTF8 -ErrorAction Stop
            Write-MigLog ("done removed={0} - flag written" -f $res.Removed.Count)
        } catch { Write-MigLog "could not write done-flag: $_" 'WARN' }
        $res.Reason = 'completed'
    } else {
        Write-MigLog ("incomplete failed={0} - flag NOT written, will retry next install" -f $res.Failed.Count) 'ERROR'
        $res.Reason = 'incomplete'
    }
    return $res
}

# ---- entry (skipped when dot-sourced by tests: they call the functions directly) ----
if ($MyInvocation.InvocationName -ne '.') {
    $enabled = Get-MigrationPivot -ConfigPath $ConfigPath
    Invoke-LegacyTaskMigration -Enabled $enabled -Force:$Force
}
