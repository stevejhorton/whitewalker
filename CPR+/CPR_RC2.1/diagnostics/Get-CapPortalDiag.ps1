#Requires -RunAsAdministrator
<#
.SYNOPSIS
  CPR+ Captive Portal Telemetry Diagnostic
  Version: 1.1.0
  Author: shorto39_uhg

.DESCRIPTION
  Consolidates the diagnostic checks used to troubleshoot missing
  cap_portal_redirect (and related) telemetry in Splunk, into a single
  script with a single consolidated output file.

  Covers the full path:
    WW_main.ps1 config (Haystack/Tee enabled, version)
      -> Write-TeeLog (WW_tee.ps1 + active WW_tee_events.psd1 profile)
      -> haystack_syslog_queue.jsonl (the queue itself)
      -> state.json currentState (drain gate)
      -> haystack.log (drain results)
      -> HayStack_Monitor scheduled task (the thing that actually fires
         haystack_action.ps1 - queried via schtasks.exe, NOT
         Get-ScheduledTask, which can silently return nothing when run
         from a non-elevated or otherwise constrained session)

  Optionally fires a live synthetic captive portal event via
  tests/Test-HayStackSyslog.ps1 -SimulateCaptivePortal so you can watch
  the whole pipeline react in near-real-time (see -RunSimulation).

  Changes in 1.1.0:
    - FIX: Simulation invocation (section 9) now captures *>&1 (all
      streams - Success/Error/Warning/Verbose/Debug/Information) instead
      of just 2>&1 (Error only). Test-HayStackSyslog.ps1 reports status
      primarily via Write-Host, which writes to the host/Information
      stream - 2>&1 alone silently dropped all of it, making section 9
      appear to run with zero output even on a fully successful send.
      Confirmed via Splunk: events WERE delivered in the 1.0.0 test run
      that showed blank simulation output.
    - NEW: Falls back to Start-Transcript around the simulation call if
      stream capture still comes back empty, so there's always SOME
      evidence of what happened even if a future script version changes
      its output behavior again.

.PARAMETER RunSimulation
  If set, also invokes tests/Test-HayStackSyslog.ps1 -SimulateCaptivePortal
  -DeliveryMode direct to generate synthetic cap_portal_redirect /
  cap_portal_remediation_passed / cap_portal_remediation_failed events.
  Looks for the test script alongside the deployed CPR files first, then
  falls back to the local diagnostics directory.

.PARAMETER OutputDir
  Directory to drop the consolidated report in. Default: C:\temp

.EXAMPLE
  .\Get-CapPortalDiag.ps1

.EXAMPLE
  .\Get-CapPortalDiag.ps1 -RunSimulation
#>

[CmdletBinding()]
param(
    [switch]$RunSimulation,
    [string]$OutputDir = "C:\temp"
)

$ErrorActionPreference = 'SilentlyContinue'

$InstallDir   = "C:\ProgramData\WhiteWalker"
$LogDir       = Join-Path $InstallDir "logs"
$StateFile    = "C:\Windows\UHGLogs\state.json"
$QueueFile    = Join-Path $LogDir "haystack_syslog_queue.jsonl"
$MainLog      = Join-Path $LogDir "white_walker.main.log"
$HaystackLog  = Join-Path $LogDir "haystack.log"
$TeeEventsCfg = Join-Path $InstallDir "WW_tee_events.psd1"
$WWMain       = Join-Path $InstallDir "WW_main.ps1"
$WWTee        = Join-Path $InstallDir "WW_tee.ps1"

if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}
$stamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$OutFile   = Join-Path $OutputDir "CPR_CapPortal_Diag_$stamp.txt"

function Write-Section {
    param([string]$Title)
    $bar = ("=" * 80)
    "`n$bar" | Out-File -FilePath $OutFile -Append -Encoding UTF8
    "== $Title" | Out-File -FilePath $OutFile -Append -Encoding UTF8
    "$bar" | Out-File -FilePath $OutFile -Append -Encoding UTF8
}

function Write-Line {
    param([string]$Text)
    $Text | Out-File -FilePath $OutFile -Append -Encoding UTF8
}

# =============================================================================
# Header (overwrite/create the file)
# =============================================================================
"CPR+ Captive Portal Telemetry Diagnostic" | Out-File -FilePath $OutFile -Encoding UTF8
"Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" | Out-File -FilePath $OutFile -Append -Encoding UTF8
"Machine:   $env:COMPUTERNAME" | Out-File -FilePath $OutFile -Append -Encoding UTF8
"User:      $env:USERNAME" | Out-File -FilePath $OutFile -Append -Encoding UTF8
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"Elevated:  $isAdmin" | Out-File -FilePath $OutFile -Append -Encoding UTF8
if (-not $isAdmin) {
    "WARNING: Not running elevated. Some checks (scheduled task status) may report incomplete/incorrect results. Re-run from an elevated PowerShell for a fully trustworthy report." | Out-File -FilePath $OutFile -Append -Encoding UTF8
}

# =============================================================================
# 1. Deployed config - version, HaystackEnabled, TeeEnabled
# =============================================================================
Write-Section "1. WW_main.ps1 config (version / HaystackEnabled / TeeEnabled)"
if (Test-Path $WWMain) {
    Select-String -Path $WWMain -Pattern '\$ver\s*=|\$HaystackEnabled\s*=|\$TeeEnabled\s*=' |
        ForEach-Object { Write-Line $_.Line.Trim() }
} else {
    Write-Line "WW_main.ps1 not found at $WWMain"
}

# =============================================================================
# 2. WW_tee.ps1 deployment
# =============================================================================
Write-Section "2. WW_tee.ps1 deployment"
if (Test-Path $WWTee) {
    $item = Get-Item $WWTee
    Write-Line "Path: $($item.FullName)"
    Write-Line "LastWriteTime: $($item.LastWriteTime)"
    Write-Line "Length: $($item.Length)"
} else {
    Write-Line "WW_tee.ps1 NOT FOUND at $WWTee - Write-TeeLog calls will silently no-op (function undefined)."
}

# =============================================================================
# 3. Active tee profile (the volume knob)
# =============================================================================
Write-Section "3. Active WW_tee_events.psd1 profile contents"
if (Test-Path $TeeEventsCfg) {
    Get-Content $TeeEventsCfg | ForEach-Object { Write-Line $_ }
} else {
    Write-Line "WW_tee_events.psd1 NOT FOUND at $TeeEventsCfg - Write-TeeLog will fire nothing (safe-empty fallback)."
}

# =============================================================================
# 4. state.json - currentState (drain gate)
# =============================================================================
Write-Section "4. state.json (currentState / currentStateTime / lastFlare)"
if (Test-Path $StateFile) {
    Get-Content $StateFile | ForEach-Object { Write-Line $_ }
} else {
    Write-Line "state.json NOT FOUND at $StateFile"
}

# =============================================================================
# 5. haystack_syslog_queue.jsonl - pending/stuck entries
# =============================================================================
Write-Section "5. haystack_syslog_queue.jsonl (tail 30, if present)"
if (Test-Path $QueueFile) {
    Get-Content $QueueFile -Tail 30 | ForEach-Object { Write-Line $_ }
} else {
    Write-Line "Queue file not present at $QueueFile (either never populated, or fully drained)."
}

# =============================================================================
# 6. main.log - cap portal + tee activity
# =============================================================================
Write-Section "6. white_walker.main.log - cap_portal_redirect / remediation / tee queue activity (last 40)"
if (Test-Path $MainLog) {
    Select-String -Path $MainLog -Pattern "cap_portal_redirect|Starting captive portal remediation|WW_tee: queued|WW_tee:.*failed|tee_enabled=" |
        Select-Object -Last 40 | ForEach-Object { Write-Line $_.Line.Trim() }
} else {
    Write-Line "main.log not found at $MainLog"
}

# =============================================================================
# 7. haystack.log - reroll + drain results
# =============================================================================
Write-Section "7. haystack.log - reroll / SyslogQueue drain results (last 20)"
if (Test-Path $HaystackLog) {
    Select-String -Path $HaystackLog -Pattern "reroll|SyslogQueue|drained" |
        Select-Object -Last 20 | ForEach-Object { Write-Line $_.Line.Trim() }
} else {
    Write-Line "haystack.log not found at $HaystackLog"
}

# =============================================================================
# 8. HayStack_Monitor scheduled task status
#    NOTE: uses schtasks.exe, NOT Get-ScheduledTask - the cmdlet has been
#    observed to silently return nothing under some session contexts even
#    when the task is present, enabled, and firing normally.
# =============================================================================
Write-Section "8. HayStack_Monitor scheduled task (via schtasks.exe)"
$schtasksOut = schtasks /query /tn "\HayStack\HayStack_Monitor" /v /fo list 2>&1
if ($LASTEXITCODE -eq 0) {
    ($schtasksOut | Select-String "TaskName|Status|Last Run Time|Last Result|Next Run Time|Scheduled Task State|Schedule Type") |
        ForEach-Object { Write-Line $_.Line }
} else {
    Write-Line "schtasks query failed or task not found:"
    $schtasksOut | ForEach-Object { Write-Line $_ }
}

# =============================================================================
# 9. Optional: live captive portal simulation
# =============================================================================
if ($RunSimulation) {
    Write-Section "9. Live captive portal simulation (Test-HayStackSyslog.ps1 -SimulateCaptivePortal)"

    $simCandidates = @(
        (Join-Path $PSScriptRoot "..\tests\Test-HayStackSyslog.ps1"),
        (Join-Path $InstallDir "tests\Test-HayStackSyslog.ps1"),
        (Join-Path $PSScriptRoot "Test-HayStackSyslog.ps1")
    )
    $simScript = $simCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($simScript) {
        Write-Line "Using simulation script: $simScript"
        Write-Line "Command: $simScript -SimulateCaptivePortal -DeliveryMode direct -IntervalSeconds 1"

        # NOTE: Test-HayStackSyslog.ps1 reports status primarily via
        # Write-Host, which writes to the host/Information stream, NOT
        # the success or error streams. `2>&1` alone only merges the
        # error stream and will silently drop all Write-Host output,
        # making this section look empty even on a fully successful run
        # (confirmed via direct Splunk validation of a "blank output" run).
        # `*>&1` merges ALL streams (Success/Error/Warning/Verbose/Debug/
        # Information) into the success stream so nothing is lost.
        $simCaptured = $false
        try {
            $simOutput = & $simScript -SimulateCaptivePortal -DeliveryMode direct -IntervalSeconds 1 *>&1
            if ($simOutput) {
                $simOutput | ForEach-Object { Write-Line ($_ | Out-String).TrimEnd() }
                $simCaptured = $true
            }
        } catch {
            Write-Line "Simulation invocation failed: $_"
        }

        # Belt-and-suspenders: if stream capture still came back empty
        # (e.g. a future script version writes to the console host handle
        # directly instead of any PowerShell stream), fall back to a
        # transcript so there's always SOME evidence of what happened.
        if (-not $simCaptured) {
            Write-Line "(No output captured via stream redirection - falling back to Start-Transcript)"
            $transcriptPath = Join-Path $OutputDir "cap_portal_sim_transcript_$stamp.txt"
            try {
                Start-Transcript -Path $transcriptPath -Force | Out-Null
                & $simScript -SimulateCaptivePortal -DeliveryMode direct -IntervalSeconds 1
                Stop-Transcript | Out-Null
                if (Test-Path $transcriptPath) {
                    Write-Line "Transcript captured to: $transcriptPath"
                    Get-Content $transcriptPath | ForEach-Object { Write-Line $_ }
                }
            } catch {
                try { Stop-Transcript | Out-Null } catch { }
                Write-Line "Transcript fallback also failed: $_"
            }
        }

        Start-Sleep -Seconds 2

        Write-Line "`n--- Post-simulation: queue file state ---"
        if (Test-Path $QueueFile) {
            Get-Content $QueueFile -Tail 15 | ForEach-Object { Write-Line $_ }
        } else {
            Write-Line "Queue file not present after simulation (already drained, or direct delivery bypassed the queue entirely - this is expected/normal for -DeliveryMode direct)."
        }

        Write-Line "`n--- Verify delivery in Splunk ---"
        Write-Line "Direct delivery bypasses the local queue entirely, so an empty/missing queue file above is NOT evidence of failure."
        Write-Line "The only authoritative confirmation is Splunk. Run this query:"
        Write-Line '  index=cba_cpr_logging test="1" action="cap_portal_redirect" | table EvtTime,action,machine,user,url,port,ssid,vpn_state'
        Write-Line "Expect 2 rows (one per default PortalUrls entry) with machine=$env:COMPUTERNAME and a recent EvtTime."
    } else {
        Write-Line "Test-HayStackSyslog.ps1 not found in any expected location - skipping simulation."
        Write-Line "Expected one of:"
        $simCandidates | ForEach-Object { Write-Line "  $_" }
    }
} else {
    Write-Section "9. Live captive portal simulation"
    Write-Line "Skipped (run with -RunSimulation to fire a synthetic cap_portal_redirect event end-to-end)."
}

Write-Section "Done"
Write-Line "Report written to: $OutFile"

Write-Host "`nDone. Report written to $OutFile" -ForegroundColor Green
