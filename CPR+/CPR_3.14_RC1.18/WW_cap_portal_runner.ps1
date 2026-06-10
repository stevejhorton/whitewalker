param(
    [switch]$Debug
)

<#
.SYNOPSIS
CPR+ (Captive Portal Remediation Tool)

.DESCRIPTION
Version: 1.10.0_RC1.17

Version 1.10.0_RC1.17 changes:
  - NEW: Walled-garden portal support - reads portal_type from remediation state file at init
  - If portal_type=walled_garden: opens http://<gateway_ip> instead of enroll.cisco.com
  - Fallback: also opens http://1.1.1.1 if gateway browser gets no connectivity after 10s
  - ALWAYS shows toast notification with gateway IP text so user can navigate manually
    if corporate Edge policy blocks HTTP-to-IP navigation (NavigateToIPAddress GPO)
  - State file now carries: portal_type, gateway_ip, ssid, reason fields
  - State file cleared on runner exit (existing behavior - unchanged)
  - All walled-garden remediation logic lives here - WW_main only detects and hands off

Version 1.9.0_RC1.10 changes:
  - FIX: Browser now opens maximized and forced to foreground reliably
  - NEW: Invoke-BringToForeground polls for window handle (up to 3s in 250ms steps)
  - NEW: Edge launched with --new-window --start-maximized flags
  - Win32 SW_RESTORE + SW_MAXIMIZE + SetForegroundWindow triple ensures visibility
  - Polling replaces fixed sleep - fast machines don't wait unnecessarily
Author: steve.horton@optum.com
Date: 09-Jan-2026

Purpose: Handle captive portal browser authentication in USER context
Triggered by: Task Scheduler on FlareGun Event 777

This script:
1. Kills interfering Cisco browsers (background job, 20 seconds)
2. Opens Edge browser to captive portal URL (tracks PID properly)  
3. Waits up to 150 seconds for user authentication (checks every 5s, exits early if successful)
4. Checks for remediation state file to determine if VPN stabilization needed
5. If state file exists: Waits for VPN to reach stable state (Connected/Disconnected, up to 60s)
6. Launches full-screen validation browser to optum.com (after VPN stable)
7. Reports completion status and PID to WW_main via flag file
8. Shows user notification if authentication times out

Version 1.7.0_ER5 changes:
- BRANDING: Updated to CPR+ (Captive Portal Remediation Tool)
- NEW: DNS chicken/egg problem detection (DNS blocked until portal accepted, but portal needs DNS)
- NEW: Tracks DNS resolution failures and identifies misconfigured networks
- ENHANCED: Dynamic popup messages based on portal compatibility issues from WW_main
- ENHANCED: RETRY button conditionally hidden for unfixable issues (DNS blocked, non-HTTPS, etc.)

Version 1.7.0_ER3 changes:
- CRITICAL FIX: Reduced Test-SiteReachability timeout from 8s to 3s (prevents hang in 5s polling loop)
- FIX: Edge ArgumentList now uses proper array syntax @("--start-maximized", $URL)
- NEW: Show-TimeoutNotification function displays user-facing popup on auth timeout
- NEW: Notification auto-closes after 15 seconds, appears for FAILED/PARTIAL status with no auth
- ENHANCED: Comprehensive unit tests for all timeout/hang scenarios

Version 1.6.0 changes (ER2):
- NEW: VPN stabilization check using remediation state file
- NEW: Polls VPN state every 5s for up to 60s if in intermediate state
- NEW: Validation browser launches AFTER VPN stable (fixes AlwaysOn timing)
- ENHANCED: Cisco browser killer runs 20 seconds (was 10s) for thorough cleanup
- ENHANCED: More Cisco processes in kill list (WebLaunchHelper, WebHelper, etc.)
- All in USER context for proper browser focus and network access

Version 1.5.0 changes:
- SMART WAIT: Checks connectivity every 5 seconds during wait
- Exits immediately when authentication completes (no more 150s fixed wait!)
- Dramatically improves user experience (typical wait now 10-30s instead of 150s)

Version 1.4.0 changes:
- Fixed browser PID tracking (removed broken hidden PowerShell wrapper)
- Browser launches directly with proper PID capture
- PowerShell console hidden via Task Scheduler -WindowStyle Hidden flag

Task Scheduler Configuration:
  Program: powershell.exe
  Arguments: -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_cap_portal_runner.ps1"
#>

# Configuration
$LogPath = "C:\ProgramData\WhiteWalker\white_walker.cap_portal.log"
$FlagFile = "C:\ProgramData\WhiteWalker\portal_complete.flag"
$CaptivePortalURL = "http://enroll.cisco.com"
$InitialWaitSeconds = 150  # Wait before launching validation browser (2.5 minutes)
$FinalWaitSeconds = 30     # Additional wait after launching validation browser (30 seconds)
$ValidationSite = "https://www.optum.com"
$StateDir = "C:\ProgramData\WhiteWalker"

# Cisco browser process names to terminate (prevent interference)
$CiscoBrowserProcesses = @(
    "acwebhelper",
    "CiscoCollabHost", 
    "CiscoAnyConnectWebView",
    "CiscoWebLaunchHelper",  # NEW ER2
    "CiscoWebHelper"          # NEW ER2
)

function Initialize-CaptivePortalLogger {
    if (-not (Test-Path $StateDir)) {
        try {
            New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
        } catch {
            Write-Host "ERROR: Cannot create state directory $StateDir - $_"
            exit 1
        }
    }
    
    if (-not (Test-Path $LogPath)) {
        try {
            New-Item -Path $LogPath -ItemType File -Force | Out-Null
        } catch {
            Write-Host "WARNING: Cannot create log file $LogPath - $_"
        }
    }
}

function Write-CapLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
    $logLine = "$ts [CAP] [$Level] $Message"
    
    try {
        Add-Content -Path $LogPath -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if can't write to log
    }
    
    if ($Debug) {
        Write-Host $logLine
    }
}

function Write-CompletionFlag {
    param([string]$Status, [string]$Details = "", [int]$CaptiveBrowserPID = 0)
    
    $flagContent = @{
        timestamp = (Get-Date).ToString('o')
        status = $Status
        details = $Details
        user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        captive_browser_pid = $CaptiveBrowserPID
    } | ConvertTo-Json -Compress
    
    try {
        Set-Content -Path $FlagFile -Value $flagContent -Encoding UTF8
        Write-CapLog "Completion flag written: $Status (PID: $CaptiveBrowserPID)" "INFO"
    } catch {
        Write-CapLog "Failed to write completion flag: $_" "ERROR"
    }
}

function Start-CiscoBrowserKiller {
    try {
        Write-CapLog "Starting Cisco browser killer background job..." "DEBUG"
        
        $killerJob = Start-Job -ScriptBlock {
            param($ProcessNames)
            
            $endTime = (Get-Date).AddSeconds(20)  # ER2: Increased to 20 seconds for thorough cleanup
            $killCount = 0
            
            while ((Get-Date) -lt $endTime) {
                foreach ($processName in $ProcessNames) {
                    try {
                        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
                        if ($processes) {
                            foreach ($proc in $processes) {
                                try {
                                    $proc.Kill()
                                    $killCount++
                                    Start-Sleep -Milliseconds 100
                                } catch { }
                            }
                        }
                    } catch { }
                }
                Start-Sleep -Milliseconds 500
            }
            
            return $killCount
        } -ArgumentList (,[string[]]$CiscoBrowserProcesses)
        
        Write-CapLog "Cisco browser killer job started (JobId: $($killerJob.Id))" "DEBUG"
        return $killerJob
        
    } catch {
        Write-CapLog "Failed to start browser killer: $_" "WARN"
        return $null
    }
}

function Stop-CiscoBrowserKiller {
    param($Job)
    
    if ($Job) {
        try {
            # Wait for job to complete and get results
            $jobResult = Wait-Job -Job $Job -Timeout 15 | Receive-Job
            if ($jobResult) {
                Write-CapLog "Cisco browser killer terminated $jobResult processes" "INFO"
            }
            
            Stop-Job -Job $Job -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Job $Job -ErrorAction SilentlyContinue | Out-Null
            Write-CapLog "Cisco browser killer job stopped" "DEBUG"
        } catch {
            Write-CapLog "Error stopping browser killer job: $_" "DEBUG"
        }
    }
}

function Invoke-BringToForeground {
    param([System.Diagnostics.Process]$Process, [int]$MaxWaitMs = 3000, [int]$PollMs = 250)
    # Task Scheduler spawned processes don't get OS foreground rights by default.
    # SetForegroundWindow fails silently unless the caller holds the foreground lock.
    # Fix: AttachThreadInput briefly makes us look like the foreground thread to the OS,
    # which lets SetForegroundWindow actually work.
    if (-not $Process) { return }

    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WW_Win32 {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool AllowSetForegroundWindow(int dwProcessId);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);
    [DllImport("kernel32.dll")] public static extern int GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(int idAttach, int idAttachTo, bool fAttach);
}
"@ -ErrorAction SilentlyContinue

        $elapsed = 0
        $hwnd = [IntPtr]::Zero

        # Poll until we get a window handle or timeout
        while ($elapsed -lt $MaxWaitMs) {
            Start-Sleep -Milliseconds $PollMs
            $elapsed += $PollMs
            $Process.Refresh()
            $hwnd = $Process.MainWindowHandle
            if ($hwnd -ne [IntPtr]::Zero) { break }

            # If Edge opened in existing instance, find most recent Edge window
            $edgeProc = Get-Process -Name "msedge" -ErrorAction SilentlyContinue |
                        Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero } |
                        Sort-Object StartTime -Descending |
                        Select-Object -First 1
            if ($edgeProc) { $hwnd = $edgeProc.MainWindowHandle; break }
        }

        if ($hwnd -ne [IntPtr]::Zero) {
            # AttachThreadInput trick: attach to the current foreground thread so Windows
            # grants us foreground rights, then force our window to the front.
            $fgHwnd    = [WW_Win32]::GetForegroundWindow()
            $unused    = 0
            $fgThread  = [WW_Win32]::GetWindowThreadProcessId($fgHwnd, [ref]$unused)
            $myThread  = [WW_Win32]::GetCurrentThreadId()

            if ($fgThread -ne 0 -and $fgThread -ne $myThread) {
                [WW_Win32]::AttachThreadInput($fgThread, $myThread, $true) | Out-Null
            }

            [WW_Win32]::ShowWindow($hwnd, 9)          # SW_RESTORE - unminimize
            [WW_Win32]::ShowWindow($hwnd, 3)          # SW_MAXIMIZE - maximize
            [WW_Win32]::BringWindowToTop($hwnd)       | Out-Null
            [WW_Win32]::SetForegroundWindow($hwnd)    | Out-Null

            if ($fgThread -ne 0 -and $fgThread -ne $myThread) {
                [WW_Win32]::AttachThreadInput($fgThread, $myThread, $false) | Out-Null
            }

            Write-CapLog "Browser window maximized and brought to foreground (hWnd: $hwnd, waited ${elapsed}ms)" "DEBUG"
        } else {
            Write-CapLog "Could not obtain browser window handle after ${MaxWaitMs}ms" "WARN"
        }
    } catch {
        Write-CapLog "Invoke-BringToForeground error: $_" "WARN"
    }
}

function Open-CaptivePortalBrowser {
    param([string]$URL)

    Write-CapLog "Opening captive portal browser to: $URL" "INFO"
    Write-CapLog "Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" "DEBUG"

    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
        "${env:LOCALAPPDATA}\Microsoft\Edge\Application\msedge.exe"
    )

    foreach ($edgePath in $edgePaths) {
        if (Test-Path $edgePath) {
            try {
                Write-CapLog "Launching Edge from: $edgePath" "DEBUG"
                # --new-window: own window not a tab  --start-maximized: visible up front
                $process = Start-Process -FilePath $edgePath `
                    -ArgumentList @("--new-window", "--start-maximized", "$URL") `
                    -WindowStyle Normal -PassThru -ErrorAction Stop
                Write-CapLog "Edge browser launched (PID: $($process.Id))" "INFO"
                Invoke-BringToForeground -Process $process
                return $process
            } catch {
                Write-CapLog "Edge launch failed: $($_.Exception.Message)" "WARN"
            }
        }
    }

    # Fallback to default browser
    try {
        Write-CapLog "Trying default browser..." "DEBUG"
        $process = Start-Process "$URL" -WindowStyle Maximized -PassThru -ErrorAction Stop
        Write-CapLog "Default browser launched (PID: $($process.Id))" "INFO"
        Invoke-BringToForeground -Process $process
        return $process
    } catch {
        Write-CapLog "Default browser failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Open-ValidationBrowser {
    param([string]$URL)
    
    Write-CapLog "Opening full-screen validation browser to: $URL" "INFO"
    
    # Try Edge first with maximized window
    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
        "${env:LOCALAPPDATA}\Microsoft\Edge\Application\msedge.exe"
    )
    
    foreach ($edgePath in $edgePaths) {
        if (Test-Path $edgePath) {
            try {
                Write-CapLog "Launching full-screen Edge to validation site" "DEBUG"
                # FIX: Pass arguments as array elements, not comma-separated in ArgumentList
                $process = Start-Process -FilePath $edgePath -ArgumentList @("--start-maximized", $URL) -WindowStyle Maximized -PassThru -ErrorAction Stop
                Write-CapLog "Validation browser launched successfully (PID: $($process.Id))" "INFO"
                return $process
            } catch {
                Write-CapLog "Edge validation launch failed: $($_.Exception.Message)" "WARN"
            }
        }
    }
    
    # Fallback to default browser
    try {
        Write-CapLog "Trying default browser for validation..." "DEBUG"
        $process = Start-Process "$URL" -WindowStyle Maximized -PassThru -ErrorAction Stop
        Write-CapLog "Default validation browser launched (PID: $($process.Id))" "INFO"
        return $process
    } catch {
        Write-CapLog "Default validation browser failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Wait-WithProgress {
    param([int]$TimeoutSeconds, [string]$Activity)
    
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($TimeoutSeconds)
    
    Write-CapLog "Waiting $TimeoutSeconds seconds: $Activity - Start: $($startTime.ToString('HH:mm:ss'))" "INFO"
    Write-CapLog "Will wait until: $($endTime.ToString('HH:mm:ss'))" "INFO"
    
    $lastLogTime = $startTime
    $logInterval = 10  # Log every 10 seconds
    
    while ((Get-Date) -lt $endTime) {
        Start-Sleep -Seconds 5
        
        # Log progress every 10 seconds
        $now = Get-Date
        if (($now - $lastLogTime).TotalSeconds -ge $logInterval) {
            $elapsed = ($now - $startTime).TotalSeconds
            $remaining = ($endTime - $now).TotalSeconds
            Write-CapLog "$Activity - Elapsed: $([math]::Round($elapsed))s, Remaining: $([math]::Round($remaining))s" "DEBUG"
            $lastLogTime = $now
        }
    }
    
    $totalElapsed = ((Get-Date) - $startTime).TotalSeconds
    Write-CapLog "$Activity completed after $([math]::Round($totalElapsed))s" "INFO"
}

function Show-TimeoutNotification {
    <#
    .SYNOPSIS
    Display user-facing notification when captive portal authentication times out
    
    .DESCRIPTION
    Shows a popup dialog in USER context informing the user that authentication
    was not completed in time. Provides two options:
    - RETRY: Disconnect/reconnect to current SSID (triggers DHCP and re-runs framework)
    - EXIT: Close dialog and let user handle manually
    
    ER5: If PortalIssues detected, customizes message and may hide RETRY button
    
    Returns: "RETRY" or "EXIT" based on user choice
    #>
    param(
        [Parameter(Mandatory=$false)]
        $PortalIssues = $null
    )
    
    Write-CapLog "Displaying timeout notification to user" "INFO"
    
    try {
        Add-Type -AssemblyName System.Windows.Forms
        
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "CPR+ - Network Authentication Timeout"
        $form.Size = New-Object System.Drawing.Size(500, 420)
        $form.StartPosition = "CenterScreen"
        $form.TopMost = $true
        $form.FormBorderStyle = 'FixedDialog'
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false

        # Logo (top-left, graceful fallback if docs not yet deployed)
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        $logoPath = Join-Path $DocsLocalPath "CPR_Logo.jpeg"
        if (Test-Path $logoPath) {
            try {
                $logo = New-Object System.Windows.Forms.PictureBox
                $logo.Location = New-Object System.Drawing.Point(15, 10)
                $logo.Size = New-Object System.Drawing.Size(140, 50)
                $logo.Image = [System.Drawing.Image]::FromFile($logoPath)
                $logo.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
                $form.Controls.Add($logo)
            } catch { }
        }
        
        # ER5: Customize message based on portal issues
        $messageText = ""
        $showRetryButton = $true
        
        if ($PortalIssues -and $PortalIssues.issue_type -ne "NONE") {
            # Custom message for known incompatible portal
            Write-CapLog "Customizing notification for portal issue: $($PortalIssues.issue_type)" "INFO"
            
            $messageText = @"
NON-STANDARD CAPTIVE PORTAL DETECTED

$($PortalIssues.user_message)

Issue Type: $($PortalIssues.issue_type)

This network may not be compatible with corporate security policies.
"@
            $showRetryButton = $PortalIssues.allow_retry
            
        } else {
            # Standard timeout message
            $messageText = @"
Network authentication did not complete within the expected time.

This could mean:
- Captive portal login was not finished
- Network authentication is still in progress
- VPN may need manual reconnection

Choose an option below:

RETRY: Disconnect and reconnect to your current WiFi network.
       This will trigger the authentication process again.

EXIT: Close this dialog and handle the connection manually.
"@
        }
        
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, 68)
        $label.Size = New-Object System.Drawing.Size(460, 190)
        $label.Text = $messageText
        $form.Controls.Add($label)
        
        # Help links
        $guideLink2 = New-Object System.Windows.Forms.LinkLabel
        $guideLink2.Location = New-Object System.Drawing.Point(20, 268)
        $guideLink2.Size = New-Object System.Drawing.Size(200, 18)
        $guideLink2.Text = "CPR+ User Guide"
        $guideLink2.add_LinkClicked({
            $p = Join-Path $DocsLocalPath "cpr_user_guide.html"
            if (Test-Path $p) { Start-Process $p }
        })
        $form.Controls.Add($guideLink2)

        $blackholeLink2 = New-Object System.Windows.Forms.LinkLabel
        $blackholeLink2.Location = New-Object System.Drawing.Point(255, 268)
        $blackholeLink2.Size = New-Object System.Drawing.Size(200, 18)
        $blackholeLink2.Text = "VPN Blackhole Info"
        $blackholeLink2.add_LinkClicked({
            $p = Join-Path $DocsLocalPath "vpn_blackhole_info.html"
            if (Test-Path $p) { Start-Process $p }
        })
        $form.Controls.Add($blackholeLink2)

        # RETRY button (conditionally shown)
        if ($showRetryButton) {
            $retryButton = New-Object System.Windows.Forms.Button
            $retryButton.Location = New-Object System.Drawing.Point(80, 310)
            $retryButton.Size = New-Object System.Drawing.Size(150, 40)
            $retryButton.Text = "RETRY Network"
            $retryButton.DialogResult = [System.Windows.Forms.DialogResult]::Retry
            $form.Controls.Add($retryButton)
        } else {
            Write-CapLog "RETRY button hidden due to portal incompatibility (AllowRetry=false)" "INFO"
        }
        
        # EXIT button - center if RETRY hidden
        $exitButton = New-Object System.Windows.Forms.Button
        if ($showRetryButton) {
            $exitButton.Location = New-Object System.Drawing.Point(270, 310)
        } else {
            $exitButton.Location = New-Object System.Drawing.Point(175, 310)  # Centered
        }
        $exitButton.Size = New-Object System.Drawing.Size(150, 40)
        $exitButton.Text = "EXIT"
        $exitButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Controls.Add($exitButton)
        
        if ($showRetryButton) {
            $form.AcceptButton = $retryButton
        }
        $form.CancelButton = $exitButton
        
        Write-CapLog "Showing timeout notification form (RETRY or EXIT)" "DEBUG"
        $result = $form.ShowDialog()
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Retry) {
            Write-CapLog "User selected RETRY - will disconnect/reconnect network" "INFO"
            $form.Dispose()
            return "RETRY"
        } else {
            Write-CapLog "User selected EXIT - manual handling" "INFO"
            $form.Dispose()
            return "EXIT"
        }
        
    } catch {
        Write-CapLog "Failed to show timeout notification: $_" "ERROR"
        return "EXIT"  # Safe default on error
    }
}

function Invoke-NetworkReconnect {
    <#
    .SYNOPSIS
    Disconnect and reconnect to current WiFi SSID
    
    .DESCRIPTION
    Captures current SSID, disconnects, waits briefly, then reconnects.
    This triggers DHCP renewal and should re-run WhiteWalker framework automatically.
    Kills any open browser processes that may have been spawned by the script.
    #>
    
    Write-CapLog "Starting network reconnect process" "INFO"
    
    try {
        # Kill any browsers we may have opened
        Write-CapLog "Cleaning up browser processes..." "DEBUG"
        $browserProcesses = @("msedge", "chrome", "firefox", "iexplore")
        foreach ($proc in $browserProcesses) {
            try {
                $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
                if ($processes) {
                    foreach ($p in $processes) {
                        try {
                            Write-CapLog "Terminating browser: $($p.Name) (PID: $($p.Id))" "DEBUG"
                            $p.Kill()
                        } catch {
                            Write-CapLog "Could not kill $($p.Name): $_" "DEBUG"
                        }
                    }
                }
            } catch { }
        }
        Start-Sleep -Seconds 2
        
        # Get current SSID using netsh
        Write-CapLog "Detecting current SSID..." "DEBUG"
        $netshOutput = netsh wlan show interfaces 2>$null
        $ssidLine = $netshOutput | Select-String -Pattern '^\s+SSID\s+:\s+(.+)$'
        
        if (-not $ssidLine) {
            Write-CapLog "Could not detect current SSID - aborting reconnect" "ERROR"
            return $false
        }
        
        $ssid = $ssidLine.Matches[0].Groups[1].Value.Trim()
        Write-CapLog "Current SSID: $ssid" "INFO"
        
        # Get interface name
        $interfaceLine = $netshOutput | Select-String -Pattern '^\s+Name\s+:\s+(.+)$'
        if (-not $interfaceLine) {
            Write-CapLog "Could not detect WiFi interface name" "ERROR"
            return $false
        }
        
        $interfaceName = $interfaceLine.Matches[0].Groups[1].Value.Trim()
        Write-CapLog "WiFi Interface: $interfaceName" "INFO"
        
        # Disconnect
        Write-CapLog "Disconnecting from $ssid..." "INFO"
        $disconnectResult = netsh wlan disconnect interface="$interfaceName" 2>&1
        Write-CapLog "Disconnect result: $disconnectResult" "DEBUG"
        
        # Wait for disconnect to complete
        Start-Sleep -Seconds 3
        
        # Reconnect
        Write-CapLog "Reconnecting to $ssid..." "INFO"
        $connectResult = netsh wlan connect name="$ssid" interface="$interfaceName" 2>&1
        Write-CapLog "Reconnect result: $connectResult" "DEBUG"
        
        Write-CapLog "Network reconnect triggered - DHCP renewal should trigger WhiteWalker framework" "INFO"
        return $true
        
    } catch {
        Write-CapLog "Error during network reconnect: $_" "ERROR"
        return $false
    }
}


function Test-SiteReachability {
    param([string]$Url = $ValidationSite)
    
    Write-CapLog "Testing site reachability silently: $Url" "DEBUG"
    
    try {
        # CRITICAL: 3s timeout ensures completion within 5s polling interval (prevents hang)
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-CapLog "Site validation successful: $Url (HTTP $($response.StatusCode))" "INFO"
            return $true
        } else {
            Write-CapLog "Site validation failed: $Url (HTTP $($response.StatusCode))" "WARN"
            return $false
        }
    } catch {
        Write-CapLog "Site validation failed: $Url - $($_.Exception.Message)" "DEBUG"
        
        # ER5: Track DNS resolution failures (chicken/egg problem)
        if ($_.Exception.Message -match "could not be resolved") {
            $script:dnsFailureCount++
        }
        
        return $false
    }
}

function Test-DNSChickenEggProblem {
    <#
    .SYNOPSIS
    Detect DNS chicken/egg problem in captive portal config
    
    .DESCRIPTION
    If we've seen 10+ consecutive DNS failures, this indicates DNS is blocked
    until captive portal accepted, but can't accept without DNS - misconfiguration
    #>
    param([int]$FailureThreshold = 10)
    
    if ($script:dnsFailureCount -ge $FailureThreshold) {
        Write-CapLog "DNS CHICKEN/EGG PROBLEM DETECTED: $script:dnsFailureCount consecutive DNS failures" "WARN"
        Write-CapLog "Network blocks DNS until portal accepted, but portal requires DNS to load - misconfiguration" "WARN"
        return $true
    }
    return $false
}

function Invoke-WalledGardenRemediation {
    <#
    .SYNOPSIS
    Handle walled-garden captive portal authentication.
    
    .DESCRIPTION
    Walled-garden portals (Wyndham, Marriott, etc.) block ALL DNS before authentication.
    Standard enroll.cisco.com redirect detection does not work here.
    
    Strategy:
      1. Show toast notification with gateway IP so user can navigate manually
         even if corporate Edge policy blocks HTTP-to-IP navigation
      2. Open http://<gateway_ip> in browser (primary - portal web server is at gateway)
      3. If no connectivity after 10s, also open http://1.1.1.1 (fallback - some portals
         intercept all port-80 TCP regardless of dest IP)
      4. Poll for connectivity (same smart-wait loop as redirect path)
      5. Clear state file on exit
    
    Note on corporate browser policy: Enterprise Edge GPO may have NavigateToIPAddress
    disabled, which would cause an error page when navigating to http://<ip>. The toast
    notification shown FIRST ensures the user always has the gateway IP as text so they
    can navigate manually or use a different browser if needed.
    #>
    param(
        [string]$GatewayIP,
        [string]$Ssid = "unknown"
    )

    Write-CapLog "=== Walled-Garden Remediation Starting ===" "INFO"
    Write-CapLog "Gateway IP: $GatewayIP  SSID: $Ssid" "INFO"

    $gatewayUrl  = "http://$GatewayIP"
    $fallbackUrl = "http://1.1.1.1"
    $remediationStateFile = "C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag"

    try {
        Add-Type -AssemblyName System.Windows.Forms

        $toastForm = New-Object System.Windows.Forms.Form
        $toastForm.Text = "CPR+ - Hotel WiFi Login Required"
        $toastForm.Size = New-Object System.Drawing.Size(520, 345)
        $toastForm.StartPosition = "CenterScreen"
        $toastForm.TopMost = $true
        $toastForm.FormBorderStyle = 'FixedDialog'
        $toastForm.MaximizeBox = $false
        $toastForm.MinimizeBox = $false

        # Logo (top-left, graceful fallback if docs not yet deployed)
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        $logoPath = Join-Path $DocsLocalPath "CPR_Logo.jpeg"
        if (Test-Path $logoPath) {
            try {
                $logo = New-Object System.Windows.Forms.PictureBox
                $logo.Location = New-Object System.Drawing.Point(15, 10)
                $logo.Size = New-Object System.Drawing.Size(140, 50)
                $logo.Image = [System.Drawing.Image]::FromFile($logoPath)
                $logo.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
                $toastForm.Controls.Add($logo)
            } catch { }
        }

        $msg = @"
Hotel / Venue WiFi Login Required

A walled-garden captive portal was detected on '$Ssid'.

Your browser is opening to: $gatewayUrl

If the browser shows an error, manually navigate to:
    $gatewayUrl
or try: $fallbackUrl

Complete the WiFi login in your browser, then close this dialog.
VPN will reconnect automatically once authenticated.
"@
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Location = New-Object System.Drawing.Point(20, 68)
        $lbl.Size = New-Object System.Drawing.Size(470, 170)
        $lbl.Text = $msg
        $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $toastForm.Controls.Add($lbl)

        # Help links
        $guideLink = New-Object System.Windows.Forms.LinkLabel
        $guideLink.Location = New-Object System.Drawing.Point(20, 248)
        $guideLink.Size = New-Object System.Drawing.Size(200, 18)
        $guideLink.Text = "CPR+ User Guide"
        $guideLink.add_LinkClicked({
            $p = Join-Path $DocsLocalPath "cpr_user_guide.html"
            if (Test-Path $p) { Start-Process $p }
        })
        $toastForm.Controls.Add($guideLink)

        $blackholeLink = New-Object System.Windows.Forms.LinkLabel
        $blackholeLink.Location = New-Object System.Drawing.Point(260, 248)
        $blackholeLink.Size = New-Object System.Drawing.Size(220, 18)
        $blackholeLink.Text = "VPN Blackhole Info"
        $blackholeLink.add_LinkClicked({
            $p = Join-Path $DocsLocalPath "vpn_blackhole_info.html"
            if (Test-Path $p) { Start-Process $p }
        })
        $toastForm.Controls.Add($blackholeLink)

        $okBtn = New-Object System.Windows.Forms.Button
        $okBtn.Location = New-Object System.Drawing.Point(185, 273)
        $okBtn.Size = New-Object System.Drawing.Size(150, 35)
        $okBtn.Text = "OK - I'm Done"
        $okBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $toastForm.Controls.Add($okBtn)
        $toastForm.AcceptButton = $okBtn

        Write-CapLog "Showing walled-garden notification with gateway IP: $gatewayUrl" "INFO"

        $toastForm.Show()
        $toastForm.Activate()   # force focus - Show() displays but does not activate
        [System.Windows.Forms.Application]::DoEvents()

    } catch {
        Write-CapLog "Could not show walled-garden notification form: $_" "WARN"
        $toastForm = $null
    }

    Write-CapLog "Opening browser to gateway: $gatewayUrl" "INFO"
    $captiveBrowser = Open-CaptivePortalBrowser -URL $gatewayUrl
    if ($captiveBrowser) {
        Write-CapLog "Gateway browser launched (PID: $($captiveBrowser.Id))" "INFO"
    } else {
        Write-CapLog "Gateway browser launch failed - user must navigate manually to $gatewayUrl" "WARN"
    }

    Write-CapLog "Polling for connectivity (up to $InitialWaitSeconds seconds)..." "INFO"
    $startTime      = Get-Date
    $endTime        = $startTime.AddSeconds($InitialWaitSeconds)
    $fallbackOpened = $false
    $authCompleted  = $false
    $lastCheckTime  = $startTime
    $checkInterval  = 5

    while ((Get-Date) -lt $endTime -and -not $authCompleted) {
        $now = Get-Date

        if (($now - $lastCheckTime).TotalSeconds -ge $checkInterval) {
            Write-CapLog "Checking connectivity..." "DEBUG"
            if (Test-SiteReachability -Url $ValidationSite) {
                $elapsed = ($now - $startTime).TotalSeconds
                Write-CapLog "Connectivity restored after $([math]::Round($elapsed))s - walled garden authenticated!" "INFO"
                $authCompleted = $true
                break
            }

            if (-not $fallbackOpened -and ($now - $startTime).TotalSeconds -ge 10) {
                Write-CapLog "No connectivity after 10s - opening fallback URL: $fallbackUrl" "INFO"
                Open-CaptivePortalBrowser -URL $fallbackUrl | Out-Null
                $fallbackOpened = $true
            }

            $lastCheckTime = $now
        }

        if ($toastForm -and -not $toastForm.IsDisposed) {
            [System.Windows.Forms.Application]::DoEvents()
        }

        Start-Sleep -Seconds 1
    }

    if ($toastForm -and -not $toastForm.IsDisposed) {
        try { $toastForm.Close(); $toastForm.Dispose() } catch { }
    }

    $captivePID = if ($captiveBrowser) { $captiveBrowser.Id } else { 0 }

    if ($authCompleted) {
        Write-CapLog "Walled-garden authentication successful" "INFO"
        $validationBrowser = Open-ValidationBrowser -URL $ValidationSite
        Wait-WithProgress -TimeoutSeconds $FinalWaitSeconds -Activity "Post-auth stabilization"
        Write-CompletionFlag -Status "SUCCESS" -Details "Walled-garden portal authenticated, connectivity confirmed" -CaptiveBrowserPID $captivePID
    } else {
        Write-CapLog "Walled-garden authentication timed out - user may need to complete manually" "WARN"
        Write-CompletionFlag -Status "TIMEOUT" -Details "Walled-garden portal: user did not complete authentication within timeout. Gateway: $gatewayUrl" -CaptiveBrowserPID $captivePID
    }

    try {
        Remove-Item $remediationStateFile -Force -ErrorAction SilentlyContinue
        Write-CapLog "Removed remediation state file after walled-garden remediation" "DEBUG"
    } catch {
        Write-CapLog "Failed to remove remediation state file after walled-garden remediation: $_" "DEBUG"
    }

    Write-CapLog "=== Walled-Garden Remediation Complete ===" "INFO"
}

# ================================ MAIN ======================================

try {
    Initialize-CaptivePortalLogger
    
    # ER5: Initialize DNS failure counter for chicken/egg detection
    $script:dnsFailureCount = 0

    # RC1.17: Read portal context from remediation state file written by WW_main
    # Determines whether this is a standard redirect portal or a walled-garden portal
    $portalType = "redirect"
    $walledGatewayIp = $null
    $walledGardenSsid = $null

    $remediationStateFile = "C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag"
    if (Test-Path $remediationStateFile) {
        try {
            $stateRaw = Get-Content -Path $remediationStateFile -Raw -ErrorAction Stop
            $stateData = $stateRaw | ConvertFrom-Json -ErrorAction Stop

            if ($stateData.portal_type -eq "walled_garden") {
                $portalType = "walled_garden"
                $walledGatewayIp = $stateData.gateway_ip
                $walledGardenSsid = $stateData.ssid
                Write-CapLog "Portal type: WALLED_GARDEN (gateway=$walledGatewayIp, ssid=$walledGardenSsid)" "WARN"
                Write-CapLog "DNS is blocked on this network - will navigate to gateway IP directly" "INFO"
            } else {
                Write-CapLog "Portal type: REDIRECT (standard enroll.cisco.com flow)" "INFO"
            }
        } catch {
            Write-CapLog "Could not parse remediation state file - defaulting to redirect portal flow: $_" "DEBUG"
        }
    } else {
        Write-CapLog "No remediation state file - defaulting to redirect portal flow" "DEBUG"
    }
    
    Write-CapLog "   " "START"
    Write-CapLog "   " "START"
    Write-CapLog "   " "START"
    Write-CapLog "=== CPR+ (Captive Portal Remediation) v1.10.0_RC1.17 Starting ===" "INFO"
    Write-CapLog "Captive portal URL: $CaptivePortalURL" "INFO"
    Write-CapLog "Validation site: $ValidationSite" "INFO"
    Write-CapLog "Initial wait: $InitialWaitSeconds seconds, Final wait: $FinalWaitSeconds seconds" "INFO"
    Write-CapLog "Total timeout: $($InitialWaitSeconds + $FinalWaitSeconds) seconds (3 minutes)" "INFO"
    Write-CapLog "Flag file: $FlagFile" "INFO"
    
    # ER5: Check for DNS chicken/egg issue file FIRST
    $dnsIssueFile = "C:\ProgramData\WhiteWalker\dns_chicken_egg_issue.flag"
    if (Test-Path $dnsIssueFile) {
        Write-CapLog "DNS chicken/egg issue file detected - showing error popup only" "WARN"
        
        try {
            $dnsIssueContent = Get-Content -Path $dnsIssueFile -Raw -ErrorAction Stop
            $dnsIssue = $dnsIssueContent | ConvertFrom-Json -ErrorAction Stop
            
            Write-CapLog "DNS Issue: $($dnsIssue.issue_type) - $($dnsIssue.description)" "ERROR"
            Write-CapLog "Redirect URL: $($dnsIssue.redirect_url)" "ERROR"
            
            # Delete the issue file
            Remove-Item -Path $dnsIssueFile -Force -ErrorAction SilentlyContinue
            Write-CapLog "Deleted DNS issue file" "DEBUG"
            
            # Show popup with DNS chicken/egg message (no browser launch)
            $portalIssues = @{
                issue_type = $dnsIssue.issue_type
                description = $dnsIssue.description
                user_message = $dnsIssue.user_message
                allow_retry = $false
            }
            
            $userChoice = Show-TimeoutNotification -PortalIssues $portalIssues
            Write-CapLog "User acknowledged DNS chicken/egg issue" "INFO"
            
            # Write completion flag and exit immediately (no browser, no waiting)
            Write-CompletionFlag -Status "DNS_CHICKEN_EGG" -Details "DNS chicken/egg problem - network misconfiguration prevents authentication" -CaptiveBrowserPID 0
            Write-CapLog "=== CPR+ Exiting (DNS Chicken/Egg Issue) ===" "INFO"
            
        } catch {
            Write-CapLog "Error handling DNS issue file: $_" "ERROR"
        }
        
        return
    }
    
    # RC1.17: Branch on portal type
    if ($portalType -eq "walled_garden" -and $walledGatewayIp) {
        $killerJob = Start-CiscoBrowserKiller
        Invoke-WalledGardenRemediation -GatewayIP $walledGatewayIp -Ssid $walledGardenSsid
        Stop-CiscoBrowserKiller -Job $killerJob
    } else {
        # Normal captive portal workflow (no DNS issue detected)
        # Start Cisco browser killer to prevent interference
        $killerJob = Start-CiscoBrowserKiller
        
        # Launch browser to captive portal and track PID
        $captiveBrowser = Open-CaptivePortalBrowser -URL $CaptivePortalURL
    
    if ($captiveBrowser -and $captiveBrowser.Id) {
        $captivePID = $captiveBrowser.Id
        Write-CapLog "Captive portal browser launched successfully (PID: $captivePID)" "INFO"
        
        # SMART WAIT: Poll for connectivity every 5 seconds, exit early if auth completes
        Write-CapLog "Waiting for user authentication (up to $InitialWaitSeconds seconds, will exit early if successful)..." "INFO"
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds($InitialWaitSeconds)
        $lastCheckTime = $startTime
        $checkInterval = 5  # Check connectivity every 5 seconds
        $authCompleted = $false
        
        while ((Get-Date) -lt $endTime -and -not $authCompleted) {
            $now = Get-Date
            
            # Check connectivity every 5 seconds
            if (($now - $lastCheckTime).TotalSeconds -ge $checkInterval) {
                Write-CapLog "Checking if authentication completed..." "DEBUG"
                if (Test-SiteReachability -Url $ValidationSite) {
                    $elapsed = ($now - $startTime).TotalSeconds
                    Write-CapLog "Authentication detected complete after $([math]::Round($elapsed))s - exiting wait early!" "INFO"
                    $authCompleted = $true
                    break
                }
                $lastCheckTime = $now
            }
            
            Start-Sleep -Seconds 1
        }
        
        if ($authCompleted) {
            Write-CapLog "User authenticated successfully - checking VPN stabilization before validation browser" "INFO"
        } else {
            $totalWait = ((Get-Date) - $startTime).TotalSeconds
            Write-CapLog "Wait period complete ($([math]::Round($totalWait))s) - checking VPN stabilization before validation browser" "INFO"
        }
        
        # ER2: Check for remediation state file to determine if VPN stabilization needed
        $remediationStateFile = "C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag"
        $needsVpnWait = Test-Path $remediationStateFile
        
        # ER5: Read portal compatibility issues from state file
        $portalIssues = $null
        if ($needsVpnWait) {
            try {
                $stateContent = Get-Content -Path $remediationStateFile -Raw -ErrorAction Stop
                $stateData = $stateContent | ConvertFrom-Json -ErrorAction Stop
                
                if ($stateData.portal_issues) {
                    $portalIssues = $stateData.portal_issues
                    Write-CapLog "Portal compatibility issues detected: $($portalIssues.issue_type)" "WARN"
                    Write-CapLog "  Description: $($portalIssues.description)" "WARN"
                }
            } catch {
                Write-CapLog "Could not read portal issues from state file: $_" "DEBUG"
            }
        }
        
        if ($needsVpnWait) {
            Write-CapLog "Remediation state file detected - checking VPN state for stabilization" "INFO"
            
            # Check VPN state using vpncli
            try {
                $vpncliPath = "C:\Program Files\Cisco\Cisco Secure Client\vpncli.exe"
                if (-not (Test-Path $vpncliPath)) {
                    $vpncliPath = "C:\Program Files (x86)\Cisco\Cisco Secure Client\vpncli.exe"
                }
                
                if (Test-Path $vpncliPath) {
                    $stateOutput = & $vpncliPath state 2>$null | Out-String
                    
                    # Parse VPN state (use last >> state: line)
                    $stateMatches = [regex]::Matches($stateOutput, '(?im)^\s*>>\s*state:\s*(\w+)\s*$')
                    if ($stateMatches.Count -gt 0) {
                        $vpnState = $stateMatches[$stateMatches.Count - 1].Groups[1].Value
                        Write-CapLog "Current VPN state: $vpnState" "INFO"
                        
                        $intermediateStates = @('Connecting', 'Reconnecting', 'Unknown', 'Disconnecting')
                        
                        if ($intermediateStates -contains $vpnState) {
                            Write-CapLog "VPN in intermediate state ($vpnState) - waiting for stable state before validation browser" "INFO"
                            Write-CapLog "Polling every 5s for up to 60s..." "INFO"
                            
                            $maxWaitSeconds = 60
                            $checkInterval = 5
                            $attempts = [math]::Ceiling($maxWaitSeconds / $checkInterval)
                            $startWait = Get-Date
                            $stable = $false
                            
                            for ($i = 1; $i -le $attempts; $i++) {
                                Start-Sleep -Seconds $checkInterval
                                
                                $stateOutput = & $vpncliPath state 2>$null | Out-String
                                $stateMatches = [regex]::Matches($stateOutput, '(?im)^\s*>>\s*state:\s*(\w+)\s*$')
                                if ($stateMatches.Count -gt 0) {
                                    $vpnState = $stateMatches[$stateMatches.Count - 1].Groups[1].Value
                                }
                                
                                $elapsed = ((Get-Date) - $startWait).TotalSeconds
                                Write-CapLog "VPN check $i/$attempts (${elapsed}s): $vpnState" "DEBUG"
                                
                                if ($vpnState -eq 'Connected' -or $vpnState -eq 'Disconnected') {
                                    Write-CapLog "VPN reached stable state: $vpnState (after $([math]::Round($elapsed))s)" "INFO"
                                    $stable = $true
                                    break
                                }
                            }
                            
                            if (-not $stable) {
                                $finalElapsed = ((Get-Date) - $startWait).TotalSeconds
                                Write-CapLog "VPN still intermediate after ${finalElapsed}s - proceeding anyway (best effort)" "WARN"
                            }
                        } else {
                            Write-CapLog "VPN already stable: $vpnState - proceeding to validation browser" "INFO"
                        }
                    } else {
                        Write-CapLog "Could not parse VPN state - proceeding to validation browser anyway" "DEBUG"
                    }
                } else {
                    Write-CapLog "vpncli not found - skipping VPN check, proceeding to validation browser" "DEBUG"
                }
            } catch {
                Write-CapLog "Error checking VPN state: $_ - proceeding to validation browser anyway" "WARN"
            }
            
            # Remove remediation state file now that stabilization is complete
            try {
                Remove-Item $remediationStateFile -Force -ErrorAction SilentlyContinue
                Write-CapLog "Removed remediation state file after VPN stabilization" "DEBUG"
            } catch {
                Write-CapLog "Failed to remove remediation state file: $_" "DEBUG"
            }
        } else {
            Write-CapLog "No remediation state file - skipping VPN stabilization check" "DEBUG"
        }
        
        # Launch full-screen validation browser (smooth transition)
        Write-CapLog "Launching validation browser for seamless transition..." "INFO"
        $validationBrowser = Open-ValidationBrowser -URL $ValidationSite
        
        if ($validationBrowser) {
            Write-CapLog "Validation browser launched, allowing time for network handshake..." "INFO"
            
            # Wait for final authentication and network stabilization
            Wait-WithProgress -TimeoutSeconds $FinalWaitSeconds -Activity "Network stabilization"
            
            # Stop the Cisco browser killer
            Stop-CiscoBrowserKiller -Job $killerJob
            
            # Test connectivity silently in background
            $siteReachable = Test-SiteReachability -Url $ValidationSite
            
            if ($siteReachable) {
                Write-CompletionFlag -Status "SUCCESS" -Details "Captive portal authentication completed, VPN stabilized, validation browser opened to $ValidationSite, connectivity confirmed" -CaptiveBrowserPID $captivePID
                Write-CapLog "Captive portal remediation completed successfully with full validation" "INFO"
            } else {
                # Site not reachable - check if auth actually completed
                if (-not $authCompleted) {
                    Write-CapLog "Authentication timeout - prompting user for action" "WARN"
                    
                    # ER5: Check for DNS chicken/egg problem
                    $dnsChickenEgg = Test-DNSChickenEggProblem
                    if ($dnsChickenEgg -and -not $portalIssues) {
                        # Create portal issue for DNS blocking
                        $portalIssues = @{
                            issue_type = "DNS_BLOCKED"
                            description = "DNS resolution blocked until captive portal accepted (chicken/egg misconfiguration)"
                            user_message = "This network blocks DNS resolution until you accept terms, but the captive portal URL requires DNS to load. This is a network misconfiguration - contact the network administrator."
                            allow_retry = $false
                        }
                        Write-CapLog "DNS chicken/egg problem detected - updating portal issues for user notification" "WARN"
                    }
                    
                    $userChoice = Show-TimeoutNotification -PortalIssues $portalIssues
                    
                    if ($userChoice -eq "RETRY") {
                        Write-CapLog "User chose RETRY - initiating network reconnect" "INFO"
                        $reconnectSuccess = Invoke-NetworkReconnect
                        
                        if ($reconnectSuccess) {
                            Write-CompletionFlag -Status "RETRY_REQUESTED" -Details "User requested network reconnect - DHCP renewal will trigger framework" -CaptiveBrowserPID $captivePID
                            Write-CapLog "Network reconnect completed - exiting to allow framework re-trigger" "INFO"
                        } else {
                            Write-CompletionFlag -Status "RETRY_FAILED" -Details "Network reconnect failed - user must handle manually" -CaptiveBrowserPID $captivePID
                            Write-CapLog "Network reconnect failed" "ERROR"
                        }
                    } else {
                        Write-CapLog "User chose EXIT - manual handling" "INFO"
                        Write-CompletionFlag -Status "USER_EXIT" -Details "User chose to handle authentication manually" -CaptiveBrowserPID $captivePID
                    }
                } else {
                    Write-CompletionFlag -Status "PARTIAL" -Details "Validation browser opened to $ValidationSite but HTTP validation failed - may need more time" -CaptiveBrowserPID $captivePID
                    Write-CapLog "Captive portal remediation partially successful - validation browser opened but HTTP test failed" "WARN"
                }
            }
        } else {
            # Validation browser failed, but still report the captive browser PID for cleanup
            Write-CapLog "Validation browser launch failed, falling back to connectivity test only" "WARN"
            
            Wait-WithProgress -TimeoutSeconds $FinalWaitSeconds -Activity "Final authentication wait"
            Stop-CiscoBrowserKiller -Job $killerJob
            
            $siteReachable = Test-SiteReachability -Url $ValidationSite
            
            if ($siteReachable) {
                Write-CompletionFlag -Status "SUCCESS" -Details "Authentication completed and connectivity validated, but validation browser failed to launch" -CaptiveBrowserPID $captivePID
                Write-CapLog "Captive portal remediation successful despite validation browser failure" "INFO"
            } else {
                # Site not reachable - check if auth actually completed
                if (-not $authCompleted) {
                    Write-CapLog "Authentication timeout (validation browser fallback path) - prompting user for action" "WARN"
                    
                    # ER5: Check for DNS chicken/egg problem
                    $dnsChickenEgg = Test-DNSChickenEggProblem
                    if ($dnsChickenEgg -and -not $portalIssues) {
                        # Create portal issue for DNS blocking
                        $portalIssues = @{
                            issue_type = "DNS_BLOCKED"
                            description = "DNS resolution blocked until captive portal accepted (chicken/egg misconfiguration)"
                            user_message = "This network blocks DNS resolution until you accept terms, but the captive portal URL requires DNS to load. This is a network misconfiguration - contact the network administrator."
                            allow_retry = $false
                        }
                        Write-CapLog "DNS chicken/egg problem detected - updating portal issues for user notification" "WARN"
                    }
                    
                    $userChoice = Show-TimeoutNotification -PortalIssues $portalIssues
                    
                    if ($userChoice -eq "RETRY") {
                        Write-CapLog "User chose RETRY - initiating network reconnect" "INFO"
                        $reconnectSuccess = Invoke-NetworkReconnect
                        
                        if ($reconnectSuccess) {
                            Write-CompletionFlag -Status "RETRY_REQUESTED" -Details "User requested network reconnect - DHCP renewal will trigger framework" -CaptiveBrowserPID $captivePID
                            Write-CapLog "Network reconnect completed - exiting to allow framework re-trigger" "INFO"
                        } else {
                            Write-CompletionFlag -Status "RETRY_FAILED" -Details "Network reconnect failed - user must handle manually" -CaptiveBrowserPID $captivePID
                            Write-CapLog "Network reconnect failed" "ERROR"
                        }
                    } else {
                        Write-CapLog "User chose EXIT - manual handling" "INFO"
                        Write-CompletionFlag -Status "USER_EXIT" -Details "User chose to handle authentication manually" -CaptiveBrowserPID $captivePID
                    }
                } else {
                    Write-CompletionFlag -Status "FAILED" -Details "Authentication may have completed but $ValidationSite still not reachable and validation browser failed" -CaptiveBrowserPID $captivePID
                    Write-CapLog "Captive portal remediation failed - connectivity and validation browser both failed" "ERROR"
                }
            }
        }
        
        } else {
            # Initial browser launch failed
            Stop-CiscoBrowserKiller -Job $killerJob
            
            Write-CompletionFlag -Status "FAILED" -Details "Could not launch browser to captive portal in user context" -CaptiveBrowserPID 0
            Write-CapLog "Captive portal handling failed - initial browser launch error" "ERROR"
        }
    }
    
} catch {
    Write-CapLog "Unhandled error in captive portal handler: $_" "ERROR"
    Write-CompletionFlag -Status "FAILED" -Details "Script error: $($_.Exception.Message)" -CaptiveBrowserPID 0
} finally {
    Write-CapLog "=== WhiteWalker Captive Portal Handler Exiting ===" "INFO"
}

exit 0
