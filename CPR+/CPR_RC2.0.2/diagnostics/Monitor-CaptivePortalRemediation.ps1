#requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitors Cisco Secure Client captive-portal remediation behavior (WebView2 launch,
    parent process, network activity, and firewall blocks) WITHOUT depending on the
    NT Kernel Logger / ETW kernel session.

.NOTES
    Author  : Clyde (for Steve Horton)
    Purpose : Diagnose intermittent Cisco Browser (msedgewebview2) failure to launch
              under AlwaysOn + Captive Portal Remediation.

.USAGE
    1. Run this script elevated BEFORE reconnecting to the test network.
    2. Reproduce the captive portal scenario (connect to guest/hotel Wi-Fi).
    3. Press "Q" then Enter when done to stop and generate the summary.
    4. Review the CSV/log files in the output folder.
#>

# ------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir    = "C:\Temp\CPR_Capture_$TimeStamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$ProcessLog   = Join-Path $OutDir "ProcessEvents.csv"
$NetLog       = Join-Path $OutDir "NetworkConnections.csv"
$FirewallLog  = Join-Path $OutDir "FirewallBlocks.csv"
$SummaryLog   = Join-Path $OutDir "Summary.txt"

# Processes we care about - Cisco Secure Client stack + WebView2 + default browsers
$WatchList = @(
    "msedgewebview2",
    "vpnui",
    "vpnagent",
    "acwebhelper",
    "acumbrella",
    "msedge",
    "chrome"
)

Write-Host "==================================================================="
Write-Host " Capture folder: $OutDir"
Write-Host " Watching for   : $($WatchList -join ', ')"
Write-Host " This uses WMI process trace events, NOT ETW / NT Kernel Logger."
Write-Host " Reproduce the captive portal issue now."
Write-Host " Type Q and press Enter when you're done to stop and summarize."
Write-Host "==================================================================="

# ------------------------------------------------------------------
# Track PIDs we discover so we can correlate network + firewall activity
# NOTE: Register-WmiEvent -Action scriptblocks do NOT support $using:.
# That scope modifier only works with Invoke-Command remoting / foreach -parallel.
# WMI/Object event subscribers must get their data via -MessageData, accessed
# inside the action as $Event.MessageData. We also keep a $global: hashtable
# for cross-event PID tracking since each action invocation is a fresh call.
# ------------------------------------------------------------------
$global:CPR_TrackedPids = @{}   # pid -> processName

# ------------------------------------------------------------------
# WMI process start/stop watchers (no kernel ETW session required)
# ------------------------------------------------------------------
$startQuery = "SELECT * FROM Win32_ProcessStartTrace"
$stopQuery  = "SELECT * FROM Win32_ProcessStopTrace"

$msgData = [PSCustomObject]@{
    WatchList  = $WatchList
    ProcessLog = $ProcessLog
}

$onStart = Register-WmiEvent -Query $startQuery -SourceIdentifier "CPR_ProcStart" -MessageData $msgData -Action {
    $data = $Event.MessageData
    $proc = $Event.SourceEventArgs.NewEvent
    $name = [System.IO.Path]::GetFileNameWithoutExtension($proc.ProcessName)

    if ($data.WatchList -contains $name) {
        $parentName = (Get-Process -Id $proc.ParentProcessID -ErrorAction SilentlyContinue).Name
        $row = [PSCustomObject]@{
            Timestamp     = Get-Date
            Event         = "Start"
            ProcessName   = $proc.ProcessName
            ProcessId     = $proc.ProcessID
            ParentProcess = $parentName
            ParentPid     = $proc.ParentProcessID
        }
        $row | Export-Csv -Path $data.ProcessLog -Append -NoTypeInformation
        $global:CPR_TrackedPids[[int]$proc.ProcessID] = $name
        Write-Host "[$($row.Timestamp)] START  $($proc.ProcessName) (PID $($proc.ProcessID))  Parent: $parentName (PID $($proc.ParentProcessID))" -ForegroundColor Green
    }
}

$onStop = Register-WmiEvent -Query $stopQuery -SourceIdentifier "CPR_ProcStop" -MessageData $msgData -Action {
    $data = $Event.MessageData
    $proc = $Event.SourceEventArgs.NewEvent
    $name = [System.IO.Path]::GetFileNameWithoutExtension($proc.ProcessName)

    if ($data.WatchList -contains $name) {
        $row = [PSCustomObject]@{
            Timestamp     = Get-Date
            Event         = "Stop"
            ProcessName   = $proc.ProcessName
            ProcessId     = $proc.ProcessID
            ParentProcess = ""
            ParentPid    = ""
        }
        $row | Export-Csv -Path $data.ProcessLog -Append -NoTypeInformation
        $global:CPR_TrackedPids.Remove([int]$proc.ProcessID)
        Write-Host "[$($row.Timestamp)] STOP   $($proc.ProcessName) (PID $($proc.ProcessID))" -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------
# Background network sampler - correlates TCP connections to tracked PIDs
# ------------------------------------------------------------------
$netJob = Start-Job -ScriptBlock {
    param($WatchList, $NetLog)

    while ($true) {
        $procs = Get-Process | Where-Object { $WatchList -contains $_.ProcessName }
        foreach ($p in $procs) {
            $conns = Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue
            foreach ($c in $conns) {
                [PSCustomObject]@{
                    Timestamp      = Get-Date
                    ProcessName    = $p.ProcessName
                    ProcessId      = $p.Id
                    LocalAddress   = $c.LocalAddress
                    LocalPort      = $c.LocalPort
                    RemoteAddress  = $c.RemoteAddress
                    RemotePort     = $c.RemotePort
                    State          = $c.State
                } | Export-Csv -Path $NetLog -Append -NoTypeInformation
            }
        }
        Start-Sleep -Seconds 1
    }
} -ArgumentList $WatchList, $NetLog

# ------------------------------------------------------------------
# Firewall/WFP block events (Event ID 5157 = WFP blocked a connection)
# Requires: auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
# ------------------------------------------------------------------
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable | Out-Null
auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable | Out-Null

$fwJob = Start-Job -ScriptBlock {
    param($WatchList, $FirewallLog)

    $lastCheck = Get-Date
    while ($true) {
        Start-Sleep -Seconds 2
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 5157
            StartTime = $lastCheck
        } -ErrorAction SilentlyContinue

        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $appName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Application' }).'#text'
            $destAddr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestAddress' }).'#text'
            $destPort = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestPort' }).'#text'

            if ($WatchList | Where-Object { $appName -like "*$_*" }) {
                [PSCustomObject]@{
                    Timestamp   = $e.TimeCreated
                    Application = $appName
                    DestAddress = $destAddr
                    DestPort    = $destPort
                } | Export-Csv -Path $FirewallLog -Append -NoTypeInformation
            }
        }
        $lastCheck = Get-Date
    }
} -ArgumentList $WatchList, $FirewallLog

Write-Host ""
Write-Host "Monitoring started. Background jobs running for network + firewall correlation." -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------
# Wait for user to stop
# ------------------------------------------------------------------
do {
    $input = Read-Host "Type Q and press Enter to stop monitoring"
} while ($input -ne "Q" -and $input -ne "q")

# ------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------
Unregister-Event -SourceIdentifier "CPR_ProcStart" -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier "CPR_ProcStop" -ErrorAction SilentlyContinue
Stop-Job $netJob, $fwJob -ErrorAction SilentlyContinue
Remove-Job $netJob, $fwJob -ErrorAction SilentlyContinue

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
$summary = @()
$summary += "Capture folder: $OutDir"
$summary += ""

if (Test-Path $ProcessLog) {
    $procEvents = Import-Csv $ProcessLog
    $webviewStarts = $procEvents | Where-Object { $_.ProcessName -match "msedgewebview2" -and $_.Event -eq "Start" }
    $summary += "WebView2 start events captured: $($webviewStarts.Count)"
    if ($webviewStarts.Count -eq 0) {
        $summary += "  --> msedgewebview2 NEVER launched during this capture window."
        $summary += "      This points to Cisco Secure Client itself not attempting to open"
        $summary += "      the captive portal browser (client-side / detection issue),"
        $summary += "      rather than a firewall/Defender block."
    } else {
        foreach ($w in $webviewStarts) {
            $summary += "  --> $($w.Timestamp): PID $($w.ProcessId), Parent: $($w.ParentProcess) (PID $($w.ParentPid))"
        }
    }
} else {
    $summary += "No process events captured (ProcessEvents.csv not created)."
}

$summary += ""

if (Test-Path $NetLog) {
    $netRows = Import-Csv $NetLog
    $summary += "Network connections captured: $($netRows.Count)"
} else {
    $summary += "No network connections captured for watched processes."
}

$summary += ""

if (Test-Path $FirewallLog) {
    $fwRows = Import-Csv $FirewallLog
    $summary += "Firewall/WFP blocks captured: $($fwRows.Count)"
    if ($fwRows.Count -gt 0) {
        $summary += "  --> Blocks were logged against watched processes. This supports"
        $summary += "      a Defender/WFP policy blocking angle rather than a Cisco"
        $summary += "      detection issue."
    }
} else {
    $summary += "No firewall blocks captured for watched processes."
}

$summary | Tee-Object -FilePath $SummaryLog

Write-Host ""
Write-Host "Capture complete. Files saved to:" -ForegroundColor Cyan
Write-Host $OutDir
Write-Host "  - ProcessEvents.csv   (start/stop + parent process correlation)"
Write-Host "  - NetworkConnections.csv (TCP state per watched process)"
Write-Host "  - FirewallBlocks.csv  (WFP/Defender blocks tied to watched processes)"
Write-Host "  - Summary.txt         (quick-read verdict)"
