#Requires -RunAsAdministrator
param(
    [string]$URL = "http://gateway.zscalertwo.net/zcc_conn_test",
    [switch]$Debug
)

<#
Simple browser launcher test script
Purpose: Figure out what method actually works to launch a browser from SYSTEM context
Usage: 
  BrowserLauncherTest.ps1
  BrowserLauncherTest.ps1 -URL "http://google.com" -Debug
#>

$LogPath = "C:\Windows\UHGLogs\white_walker.log"

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $logLine = "$ts [$Level] $Message"
    
    # Ensure log directory exists
    $dir = Split-Path -Parent $LogPath
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    
    try {
        Add-Content -Path $LogPath -Value $logLine -Encoding UTF8
    } catch {
        Write-Host "LOG FAILED: $logLine"
    }
    
    if ($Debug) { Write-Host $logLine }
}

function Test-Method {
    param([string]$MethodName, [scriptblock]$Method)
    
    Write-TestLog "=== Testing $MethodName ===" "INFO"
    try {
        $result = & $Method
        if ($result) {
            Write-TestLog "$MethodName SUCCESS" "SUCCESS"
            return $true
        } else {
            Write-TestLog "$MethodName returned false" "WARN"
            return $false
        }
    } catch {
        Write-TestLog "$MethodName FAILED: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Get current context info
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$isSystem = $currentUser -match "NT AUTHORITY\\SYSTEM"

Write-TestLog "==================== BROWSER LAUNCHER TEST ====================" "INFO"
Write-TestLog "Target URL: $URL" "INFO"
Write-TestLog "Current User: $currentUser" "INFO"
Write-TestLog "Running as SYSTEM: $isSystem" "INFO"
Write-TestLog "=================================================================" "INFO"

# Get active session info
try {
    $sessions = query session 2>$null
    Write-TestLog "Active sessions:" "INFO"
    foreach ($line in $sessions) {
        Write-TestLog "  $line" "INFO"
        if ($line -match "^\s*(\S+)\s+(\S+)?\s*(\d+)\s+Active\s+console") {
            $activeSessionId = [int]$matches[3]
            $activeUser = $matches[1]
            Write-TestLog "Found active console: User=$activeUser, SessionID=$activeSessionId" "INFO"
        }
    }
} catch {
    Write-TestLog "Failed to get session info: $_" "ERROR"
}

# Test Method 1: Simple Start-Process
$method1 = {
    $testURL = $URL + "/Method1_StartProcess"
    Start-Process $testURL -ErrorAction Stop
    return $true
}

# Test Method 2: cmd /c start
$method2 = {
    $testURL = $URL + "/Method2_CmdStart"
    Start-Process "cmd.exe" -ArgumentList "/c", "start", "Method2_CmdStart", $testURL -WindowStyle Hidden -ErrorAction Stop
    return $true
}

# Test Method 3: rundll32 url.dll
$method3 = {
    $testURL = $URL + "/Method3_rundll32url"
    Start-Process "rundll32.exe" -ArgumentList "url.dll,FileProtocolHandler", $testURL -ErrorAction Stop
    return $true
}

# Test Method 4: rundll32 shell32
$method4 = {
    $testURL = $URL + "/Method4_rundll32shell"
    Start-Process "rundll32.exe" -ArgumentList "shell32.dll,ShellExec_RunDLL", $testURL -ErrorAction Stop
    return $true
}

# Test Method 5: Scheduled Task
$method5 = {
    $testURL = $URL + "/Method5_ScheduledTask"
    $taskName = "BrowserTest_$((Get-Date).Ticks)"
    
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c start `"Method5_ScheduledTask`" `"$testURL`""
    $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    
    Start-Sleep -Seconds 3
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    
    return $true
}

# Test Method 6: WMI Process Creation
$method6 = {
    $testURL = $URL + "/Method6_WMI"
    $processStartup = ([wmiclass]"win32_ProcessStartup").CreateInstance()
    $processStartup.ShowWindow = 1
    
    $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c start `"Method6_WMI`" `"$testURL`""
    
    return ($result.ReturnValue -eq 0)
}

# Test Method 7: Direct Edge Launch
$method7 = {
    $testURL = $URL + "/Method7_DirectEdge"
    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
    )
    
    foreach ($edgePath in $edgePaths) {
        if (Test-Path $edgePath) {
            Start-Process $edgePath -ArgumentList $testURL -ErrorAction Stop
            return $true
        }
    }
    return $false
}

# Run all tests
$results = @{}
$results["Method1_StartProcess"] = Test-Method "Simple Start-Process" $method1
Start-Sleep -Seconds 2

$results["Method2_CmdStart"] = Test-Method "cmd /c start" $method2
Start-Sleep -Seconds 2

$results["Method3_rundll32_url"] = Test-Method "rundll32 url.dll" $method3
Start-Sleep -Seconds 2

$results["Method4_rundll32_shell32"] = Test-Method "rundll32 shell32" $method4
Start-Sleep -Seconds 2

$results["Method5_ScheduledTask"] = Test-Method "Scheduled Task" $method5
Start-Sleep -Seconds 2

$results["Method6_WMI"] = Test-Method "WMI Process Creation" $method6
Start-Sleep -Seconds 2

$results["Method7_DirectEdge"] = Test-Method "Direct Edge Launch" $method7

# Summary
Write-TestLog "========================= RESULTS =========================" "INFO"
foreach ($method in $results.Keys) {
    $status = if ($results[$method]) { "SUCCESS" } else { "FAILED" }
    Write-TestLog "$method : $status" "INFO"
}

$successCount = ($results.Values | Where-Object { $_ }).Count
Write-TestLog "Total successful methods: $successCount out of $($results.Count)" "INFO"
Write-TestLog "==========================================================" "INFO"

if ($successCount -eq 0) {
    Write-TestLog "ALL METHODS FAILED - Browser may not be launching in user session" "ERROR"
    Write-TestLog "Check if any browser windows opened that you can see" "ERROR"
} else {
    Write-TestLog "At least one method worked - check which browsers opened" "SUCCESS"
}

Write-Host "Test complete. Check log at: $LogPath"
Write-Host "Did any browser windows open? (Check all desktops/users)"
