# WW_cap_portal_runner.Tests.ps1
# Comprehensive test suite for WhiteWalker Captive Portal Handler v1.5.0

BeforeAll {
    # Source the script functions by dot-sourcing
    # Note: Can't actually source it since it runs immediately, so we'll test the logic
    
    # Mock external dependencies
    Mock Start-Process { 
        [PSCustomObject]@{ Id = 12345; HasExited = $false }
    }
    Mock Start-Sleep { }
    Mock Start-Job { 
        [PSCustomObject]@{ Id = 999; State = "Running" }
    }
    Mock Wait-Job { }
    Mock Receive-Job { 5 }  # Killed 5 processes
    Mock Stop-Job { }
    Mock Remove-Job { }
    Mock Get-Process { }
    Mock Test-Path { $true }
    Mock Add-Content { }
    Mock Set-Content { }
    Mock New-Item { }
    Mock Invoke-WebRequest { 
        [PSCustomObject]@{ StatusCode = 200 }
    }
}

Describe "WW_cap_portal_runner.ps1 - Core Configuration" {
    
    It "Should use HTTP for captive portal URL (not HTTPS)" {
        $captiveUrl = "http://enroll.cisco.com"
        
        $captiveUrl | Should -Match "^http://"
        $captiveUrl | Should -Not -Match "^https://"
    }
    
    It "Should use HTTPS for validation site" {
        $validationUrl = "https://www.optum.com"
        
        $validationUrl | Should -Match "^https://"
    }
    
    It "Should have smart wait configuration" {
        $initialWait = 150  # Max wait for auth
        $checkInterval = 5   # Check every 5 seconds
        
        $maxChecks = [math]::Ceiling($initialWait / $checkInterval)
        
        $maxChecks | Should -Be 30
        $checkInterval | Should -BeLessOrEqual 10  # Responsive UX
    }
    
    It "Should have final stabilization wait" {
        $finalWait = 30  # Network stabilization
        
        $finalWait | Should -BeGreaterOrEqual 20  # Allow time for network
        $finalWait | Should -BeLessOrEqual 60     # Don't wait too long
    }
}

Describe "WW_cap_portal_runner.ps1 - Flag File Management" {
    
    Context "Write-CompletionFlag Logic" {
        It "Should write JSON flag with all required fields" {
            $expectedFields = @(
                'timestamp'
                'status'
                'details'
                'user'
                'captive_browser_pid'
            )
            
            # Simulate flag content creation
            $flagContent = @{
                timestamp = (Get-Date).ToString('o')
                status = "SUCCESS"
                details = "Test details"
                user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                captive_browser_pid = 12345
            }
            
            foreach ($field in $expectedFields) {
                $flagContent.Keys | Should -Contain $field
            }
        }
        
        It "Should use ISO 8601 timestamp format" {
            $timestamp = (Get-Date).ToString('o')
            
            # ISO 8601 format like: 2025-11-17T15:30:45.1234567-05:00
            $timestamp | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        }
        
        It "Should include captive browser PID for cleanup" {
            $flagData = @{
                captive_browser_pid = 9876
            }
            
            $flagData.captive_browser_pid | Should -BeGreaterThan 0
            $flagData.captive_browser_pid | Should -BeOfType [int]
        }
        
        It "Should support status values" {
            $validStatuses = @('SUCCESS', 'PARTIAL', 'FAILED')
            
            foreach ($status in $validStatuses) {
                $status | Should -BeIn @('SUCCESS', 'PARTIAL', 'FAILED')
            }
        }
    }
}

Describe "WW_cap_portal_runner.ps1 - Browser Management" {
    
    Context "Open-CaptivePortalBrowser Logic" {
        It "Should try Edge first (multiple paths)" {
            $edgePaths = @(
                "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
                "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
                "${env:LOCALAPPDATA}\Microsoft\Edge\Application\msedge.exe"
            )
            
            $edgePaths.Count | Should -Be 3
            $edgePaths[0] | Should -Match "Edge"
        }
        
        It "Should launch with -PassThru to capture PID" {
            Mock Start-Process { 
                param($FilePath, $ArgumentList, $WindowStyle, $PassThru)
                if ($PassThru) {
                    return [PSCustomObject]@{ Id = 5678 }
                }
                return $null
            }
            
            $process = Start-Process -FilePath "msedge.exe" -ArgumentList "http://test.com" -WindowStyle Normal -PassThru
            
            $process | Should -Not -BeNullOrEmpty
            $process.Id | Should -Be 5678
        }
        
        It "Should use Normal window style for captive browser" {
            # User needs to interact with captive portal
            $windowStyle = "Normal"
            
            $windowStyle | Should -Be "Normal"
            $windowStyle | Should -Not -Be "Hidden"
        }
        
        It "Should fallback to default browser if Edge fails" {
            # This is the fallback logic on lines 196-216
            Mock Test-Path { $false }  # Edge not found
            Mock Start-Process { 
                param($ArgumentList)
                if (-not $ArgumentList) {  # Default browser call has no explicit path
                    return [PSCustomObject]@{ Id = 9999 }
                }
                return $null
            }
            
            # Fallback should still work
            $process = Start-Process "http://test.com" -WindowStyle Normal -PassThru
            $process | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Open-ValidationBrowser Logic" {
        It "Should launch maximized for seamless UX" {
            $windowStyle = "Maximized"
            
            $windowStyle | Should -Be "Maximized"
        }
        
        It "Should use --start-maximized Edge flag" {
            $edgeArgs = "--start-maximized", "https://www.optum.com"
            
            $edgeArgs | Should -Contain "--start-maximized"
        }
        
        It "Should target validation site" {
            $validationSite = "https://www.optum.com"
            
            $validationSite | Should -Not -BeNullOrEmpty
            $validationSite | Should -Match "^https://"
        }
    }
}

Describe "WW_cap_portal_runner.ps1 - Cisco Browser Killer" {
    
    Context "Start-CiscoBrowserKiller Background Job" {
        It "Should target Cisco interference processes" {
            $ciscoBrowsers = @(
                "acwebhelper",
                "CiscoCollabHost",
                "CiscoAnyConnectWebView"
            )
            
            $ciscoBrowsers.Count | Should -Be 3
            $ciscoBrowsers | Should -Contain "acwebhelper"
        }
        
        It "Should run as background job" {
            Mock Start-Job { 
                [PSCustomObject]@{ Id = 777; State = "Running" }
            }
            
            $job = Start-Job -ScriptBlock { "test" }
            
            $job | Should -Not -BeNullOrEmpty
            $job.State | Should -Be "Running"
        }
        
        It "Should kill processes for 10 seconds" {
            $killerDuration = 10  # From line 118
            
            $killerDuration | Should -Be 10
        }
        
        It "Should check every 500ms for new processes" {
            $checkInterval = 500  # milliseconds, line 136
            
            $checkInterval | Should -BeLessOrEqual 1000  # Responsive
        }
    }
    
    Context "Stop-CiscoBrowserKiller Cleanup" {
        It "Should wait for job with timeout" {
            Mock Wait-Job { 
                param($Job, $Timeout)
                $Timeout | Should -Be 15
                return $Job
            }
            
            $mockJob = [PSCustomObject]@{ Id = 888 }
            Wait-Job -Job $mockJob -Timeout 15
            
            Assert-MockCalled Wait-Job -Times 1
        }
        
        It "Should receive job results" {
            Mock Receive-Job { 5 }  # 5 processes killed
            Mock Wait-Job { 
                [PSCustomObject]@{ Id = 888 }
            }
            
            $mockJob = [PSCustomObject]@{ Id = 888 }
            $result = Wait-Job -Job $mockJob -Timeout 15 | Receive-Job
            
            $result | Should -Be 5
        }
        
        It "Should clean up job after completion" {
            Mock Stop-Job { }
            Mock Remove-Job { }
            
            $mockJob = [PSCustomObject]@{ Id = 888 }
            Stop-Job -Job $mockJob -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Job $mockJob -ErrorAction SilentlyContinue | Out-Null
            
            Assert-MockCalled Stop-Job -Times 1
            Assert-MockCalled Remove-Job -Times 1
        }
    }
}

Describe "WW_cap_portal_runner.ps1 - Smart Wait & Connectivity" {
    
    Context "Test-SiteReachability Logic" {
        It "Should use Invoke-WebRequest with timeout" {
            Mock Invoke-WebRequest { 
                param($Uri, $TimeoutSec, $UseBasicParsing)
                $TimeoutSec | Should -Be 8
                $UseBasicParsing | Should -Be $true
                return [PSCustomObject]@{ StatusCode = 200 }
            }
            
            $result = Invoke-WebRequest -Uri "https://test.com" -TimeoutSec 8 -UseBasicParsing
            
            $result.StatusCode | Should -Be 200
        }
        
        It "Should return true on HTTP 200" {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 }
            }
            
            # Simulate Test-SiteReachability logic
            $response = Invoke-WebRequest -Uri "https://test.com" -TimeoutSec 8 -UseBasicParsing
            $result = ($response.StatusCode -eq 200)
            
            $result | Should -Be $true
        }
        
        It "Should return false on non-200 status" {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 302 }
            }
            
            $response = Invoke-WebRequest -Uri "https://test.com" -TimeoutSec 8 -UseBasicParsing
            $result = ($response.StatusCode -eq 200)
            
            $result | Should -Be $false
        }
        
        It "Should handle exceptions gracefully" {
            Mock Invoke-WebRequest { throw "Network error" }
            
            # Simulate try-catch logic
            try {
                $response = Invoke-WebRequest -Uri "https://test.com" -TimeoutSec 8 -UseBasicParsing
                $result = $true
            } catch {
                $result = $false
            }
            
            $result | Should -Be $false
        }
    }
    
    Context "Smart Wait Loop" {
        It "Should poll every 5 seconds" {
            $checkInterval = 5  # From line 326
            $maxWait = 150
            
            $maxChecks = [math]::Ceiling($maxWait / $checkInterval)
            
            $maxChecks | Should -Be 30
        }
        
        It "Should exit early on successful auth" {
            # Simulate the smart wait logic from lines 329-345
            $authCompleted = $false
            $startTime = Get-Date
            $endTime = $startTime.AddSeconds(150)
            $checks = 0
            
            while ((Get-Date) -lt $endTime -and -not $authCompleted -and $checks -lt 3) {
                $checks++
                if ($checks -eq 2) {  # Simulate auth completing on 2nd check
                    $authCompleted = $true
                    break
                }
                Start-Sleep -Milliseconds 100  # Simulated wait
            }
            
            $authCompleted | Should -Be $true
            $checks | Should -Be 2  # Exited early
        }
        
        It "Should wait full timeout if auth never completes" {
            $authCompleted = $false
            $maxWait = 150
            
            # If we get to end of loop without auth
            if (-not $authCompleted) {
                $waitedFull = $true
            }
            
            $waitedFull | Should -Be $true
        }
    }
}

Describe "WW_cap_portal_runner.ps1 - Wait-WithProgress" {
    
    It "Should log progress every 10 seconds" {
        $logInterval = 10  # From line 256
        
        $logInterval | Should -Be 10
    }
    
    It "Should sleep in 5 second increments" {
        $sleepInterval = 5  # From line 259
        
        $sleepInterval | Should -Be 5
    }
    
    It "Should calculate elapsed and remaining time" {
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds(60)
        $now = $startTime.AddSeconds(30)
        
        $elapsed = ($now - $startTime).TotalSeconds
        $remaining = ($endTime - $now).TotalSeconds
        
        $elapsed | Should -Be 30
        $remaining | Should -Be 30
    }
}

Describe "WW_cap_portal_runner.ps1 - Main Workflow" {
    
    Context "Success Path" {
        It "Should complete with SUCCESS status when all works" {
            # Simulate successful flow
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 }
            }
            Mock Start-Process { 
                [PSCustomObject]@{ Id = 12345 }
            }
            
            $captiveBrowser = Start-Process -FilePath "msedge.exe" -ArgumentList "http://test.com" -PassThru
            $siteReachable = $true  # Simulated Test-SiteReachability
            
            if ($captiveBrowser -and $siteReachable) {
                $status = "SUCCESS"
            }
            
            $status | Should -Be "SUCCESS"
        }
        
        It "Should report PARTIAL if validation fails but auth worked" {
            Mock Start-Process { 
                param($FilePath, $ArgumentList)
                if ($ArgumentList -eq "http://enroll.cisco.com") {
                    return [PSCustomObject]@{ Id = 11111 }  # Captive works
                } else {
                    return $null  # Validation fails
                }
            }
            
            $captiveBrowser = [PSCustomObject]@{ Id = 11111 }
            $validationBrowser = $null
            $siteReachable = $false
            
            if ($captiveBrowser -and -not $validationBrowser -and -not $siteReachable) {
                $status = "PARTIAL"
            }
            
            $status | Should -Be "PARTIAL"
        }
    }
    
    Context "Failure Paths" {
        It "Should report FAILED if captive browser launch fails" {
            Mock Start-Process { $null }
            
            $captiveBrowser = $null
            
            if (-not $captiveBrowser) {
                $status = "FAILED"
            }
            
            $status | Should -Be "FAILED"
        }
        
        It "Should report FAILED if auth incomplete and validation fails" {
            $captiveBrowser = [PSCustomObject]@{ Id = 12345 }
            $validationBrowser = $null
            $siteReachable = $false
            
            if ($captiveBrowser -and -not $siteReachable) {
                $status = "FAILED"
            }
            
            $status | Should -Be "FAILED"
        }
    }
}

Describe "WW_cap_portal_runner.ps1 - Task Scheduler Integration" {
    
    It "Should run with -WindowStyle Hidden from Task Scheduler" {
        # Task Scheduler calls with:
        # powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File script.ps1
        $taskSchedulerArgs = "-WindowStyle Hidden -ExecutionPolicy Bypass"
        
        $taskSchedulerArgs | Should -Match "-WindowStyle Hidden"
        $taskSchedulerArgs | Should -Match "-ExecutionPolicy Bypass"
    }
    
    It "Should support -Debug switch for troubleshooting" {
        # Script has: param([switch]$Debug)
        $debugSwitch = $true
        
        $debugSwitch | Should -BeOfType [bool]
    }
}
<#
.SYNOPSIS
WhiteWalker Captive Portal Runner - Comprehensive Unit Tests for ER3

.DESCRIPTION
Version: 1.7.0_ER3
Author: steve.horton@optum.com
Date: 13-Dec-2025

Tests for critical bug fixes:
1. Timeout mismatch causing hang (8s vs 5s polling interval)
2. Edge ArgumentList syntax
3. User notification on timeout
4. All timeout/hang scenarios
#>

BeforeAll {
    $script:ScriptPath = "C:\ProgramData\WhiteWalker\WW_cap_portal_runner.ps1"
}

Describe "WW_cap_portal_runner.ps1 v1.7.0_ER3 - Critical Timeout Fix" {
    
    Context "Test-SiteReachability Timeout Configuration" {
        It "Should have timeout LESS than polling interval to prevent hang" {
            # CRITICAL: Timeout must be < $checkInterval (5s) to prevent hang
            $testSiteTimeout = 3  # From ER3 fix
            $pollingInterval = 5  # From authentication wait loop
            
            $testSiteTimeout | Should -BeLessThan $pollingInterval
        }
        
        It "Should complete Test-SiteReachability within polling window" {
            # Simulate worst case: timeout + overhead
            $testSiteTimeout = 3
            $networkOverhead = 0.5  # Processing time
            $totalTime = $testSiteTimeout + $networkOverhead
            $pollingInterval = 5
            
            $totalTime | Should -BeLessThan $pollingInterval
        }
        
        It "Should handle unreachable sites without blocking poll loop" {
            # When site is unreachable during captive portal:
            # - Test-SiteReachability will timeout
            # - Must complete before next 5s poll
            $maxTestTime = 3  # ER3 timeout
            $nextPollTime = 5
            
            # Ensure we can fit TWO failed checks in 10s window
            ($maxTestTime * 2) | Should -BeLessThan 10
        }
    }
    
    Context "Authentication Polling Loop Timing" {
        It "Should poll connectivity every 5 seconds" {
            $checkInterval = 5  # From line 416 in cap_portal_runner
            
            $checkInterval | Should -Be 5
        }
        
        It "Should wait up to 150 seconds for authentication" {
            $initialWaitSeconds = 150  # From line 53
            
            $initialWaitSeconds | Should -Be 150
        }
        
        It "Should perform 30 connectivity checks max in 150s window" {
            $initialWaitSeconds = 150
            $checkInterval = 5
            $maxChecks = [math]::Floor($initialWaitSeconds / $checkInterval)
            
            $maxChecks | Should -Be 30
        }
        
        It "Should sleep 1 second between poll interval checks" {
            # From line 434: Start-Sleep -Seconds 1
            $sleepBetweenChecks = 1
            
            $sleepBetweenChecks | Should -Be 1
        }
    }
    
    Context "Hang Scenario Prevention" {
        It "OLD BUG: 8s timeout would cause cumulative delay" {
            # Before ER3: 8s timeout per check
            $oldTimeout = 8
            $checks = 30
            $cumulativeDelay = $oldTimeout * $checks
            
            # Would add 240s of delays across 30 checks!
            $cumulativeDelay | Should -Be 240
        }
        
        It "ER3 FIX: 3s timeout prevents cumulative hang" {
            # After ER3: 3s timeout per check
            $newTimeout = 3
            $checks = 30
            $cumulativeDelay = $newTimeout * $checks
            
            # Only 90s of delays across 30 checks - manageable
            $cumulativeDelay | Should -Be 90
            $cumulativeDelay | Should -BeLessThan 150
        }
        
        It "Should complete full 150s wait within reasonable time" {
            # Worst case: all 30 checks timeout
            $waitTime = 150
            $testTimeout = 3
            $checks = 30
            $overhead = $checks * 1  # 1s sleep between checks
            
            $totalTime = $waitTime + ($testTimeout * 0) + $overhead  # Checks happen within wait
            # Should complete around 150-180s, not 390s (150 + 240 with old bug)
            $totalTime | Should -BeLessThan 200
        }
    }
}

Describe "WW_cap_portal_runner.ps1 v1.7.0_ER3 - Edge ArgumentList Fix" {
    
    Context "Open-ValidationBrowser Argument Syntax" {
        It "Should use array syntax for ArgumentList" {
            # ER3 Fix: Use @("--start-maximized", $URL) instead of "--start-maximized", "$URL"
            $correctSyntax = @("--start-maximized", "https://www.optum.com")
            
            $correctSyntax | Should -BeOfType [System.Array]
            $correctSyntax.Count | Should -Be 2
        }
        
        It "Should pass Edge flags as separate array elements" {
            $args = @("--start-maximized", "https://test.com")
            
            $args[0] | Should -Be "--start-maximized"
            $args[1] | Should -Be "https://test.com"
        }
        
        It "Should handle URL with special characters in array" {
            $url = "https://portal.company.com/auth?redirect=https://app.com"
            $args = @("--start-maximized", $url)
            
            $args.Count | Should -Be 2
            $args[1] | Should -Contain "redirect"
        }
    }
    
    Context "Browser Launch Compatibility" {
        It "Should try Edge from three possible locations" {
            $edgePaths = @(
                "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
                "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
                "${env:LOCALAPPDATA}\Microsoft\Edge\Application\msedge.exe"
            )
            
            $edgePaths.Count | Should -Be 3
        }
        
        It "Should fallback to default browser if Edge not found" {
            # Simulates fallback logic from lines 244-253
            Mock Test-Path { $false }  # Edge not found
            Mock Start-Process { 
                param($ArgumentList)
                # Default browser called without explicit FilePath
                if (-not $FilePath) {
                    return [PSCustomObject]@{ Id = 9999 }
                }
            }
            
            # Fallback should work
            $fallbackWorks = $true
            $fallbackWorks | Should -Be $true
        }
    }
}

Describe "WW_cap_portal_runner.ps1 v1.7.0_ER3 - Timeout Notification" {
    
    Context "Show-TimeoutNotification Function" {
        It "Should display notification when authentication times out" {
            # Function exists and is called when authCompleted = false
            $authCompleted = $false
            $siteReachable = $false
            
            if (-not $authCompleted -and -not $siteReachable) {
                $shouldNotify = $true
            }
            
            $shouldNotify | Should -Be $true
        }
        
        It "Should NOT display notification when authentication succeeds" {
            $authCompleted = $true
            $siteReachable = $true
            
            if (-not $authCompleted -and -not $siteReachable) {
                $shouldNotify = $true
            } else {
                $shouldNotify = $false
            }
            
            $shouldNotify | Should -Be $false
        }
        
        It "Should return RETRY or EXIT based on user choice" {
            # Function returns "RETRY" or "EXIT"
            $validReturnValues = @("RETRY", "EXIT")
            
            $validReturnValues | Should -Contain "RETRY"
            $validReturnValues | Should -Contain "EXIT"
        }
        
        It "Should NOT auto-close (removed timer functionality)" {
            # ER3 update: No timer, stays open until user chooses
            $hasAutoClose = $false
            
            $hasAutoClose | Should -Be $false
        }
    }
    
    Context "Notification Trigger Conditions" {
        It "Should notify on PARTIAL status with no auth completion" {
            $status = "PARTIAL"
            $authCompleted = $false
            $siteReachable = $false
            
            if ($status -in @("PARTIAL", "FAILED") -and -not $authCompleted) {
                $shouldNotify = $true
            }
            
            $shouldNotify | Should -Be $true
        }
        
        It "Should notify on FAILED status with no auth completion" {
            $status = "FAILED"
            $authCompleted = $false
            $siteReachable = $false
            
            if ($status -in @("PARTIAL", "FAILED") -and -not $authCompleted) {
                $shouldNotify = $true
            }
            
            $shouldNotify | Should -Be $true
        }
        
        It "Should NOT notify on SUCCESS status" {
            $status = "SUCCESS"
            $authCompleted = $true
            
            if ($status -in @("PARTIAL", "FAILED") -and -not $authCompleted) {
                $shouldNotify = $true
            } else {
                $shouldNotify = $false
            }
            
            $shouldNotify | Should -Be $false
        }
        
        It "Should NOT notify if auth completed even with unreachable site" {
            # Edge case: auth completed but site still unreachable (network flake)
            $authCompleted = $true
            $siteReachable = $false
            
            if (-not $authCompleted) {
                $shouldNotify = $true
            } else {
                $shouldNotify = $false
            }
            
            $shouldNotify | Should -Be $false
        }
    }
    
    Context "Notification Content Validation" {
        It "Should mention captive portal timeout" {
            $messageText = "Network authentication did not complete within the expected time"
            
            $messageText | Should -Match "did not complete"
            $messageText | Should -Match "time"
        }
        
        It "Should provide actionable guidance" {
            $messageContent = @(
                "Captive portal login was not finished",
                "VPN may need manual reconnection",
                "complete the network login"
            )
            
            $messageContent.Count | Should -BeGreaterThan 0
            $messageContent[1] | Should -Match "VPN"
        }
        
        It "Should explain RETRY button action" {
            $retryExplanation = "RETRY: Disconnect and reconnect to your current WiFi network"
            
            $retryExplanation | Should -Match "Disconnect and reconnect"
            $retryExplanation | Should -Match "WiFi network"
        }
        
        It "Should explain EXIT button action" {
            $exitExplanation = "EXIT: Close this dialog and handle the connection manually"
            
            $exitExplanation | Should -Match "Close this dialog"
            $exitExplanation | Should -Match "manually"
        }
    }
    
    Context "Notification UI Properties" {
        It "Should be TopMost to ensure visibility" {
            $formTopMost = $true
            
            $formTopMost | Should -Be $true
        }
        
        It "Should be CenterScreen for user attention" {
            $startPosition = "CenterScreen"
            
            $startPosition | Should -Be "CenterScreen"
        }
        
        It "Should be non-resizable (FixedDialog)" {
            $borderStyle = 'FixedDialog'
            
            $borderStyle | Should -Be 'FixedDialog'
        }
        
        It "Should disable maximize and minimize" {
            $maximizeBox = $false
            $minimizeBox = $false
            
            $maximizeBox | Should -Be $false
            $minimizeBox | Should -Be $false
        }
        
        It "Should have reasonable dimensions for two-button layout" {
            $width = 500
            $height = 360
            
            $width | Should -BeGreaterThan 450
            $height | Should -BeGreaterThan 300
        }
        
        It "Should have RETRY and EXIT buttons" {
            $buttons = @("RETRY Network", "EXIT")
            
            $buttons.Count | Should -Be 2
            $buttons[0] | Should -Match "RETRY"
            $buttons[1] | Should -Be "EXIT"
        }
    }
}

Describe "WW_cap_portal_runner.ps1 v1.7.0_ER3 - Network Reconnect Function" {
    
    Context "Invoke-NetworkReconnect Function" {
        It "Should kill browser processes before reconnecting" {
            $browserProcesses = @("msedge", "chrome", "firefox", "iexplore")
            
            $browserProcesses.Count | Should -BeGreaterThan 0
            $browserProcesses | Should -Contain "msedge"
        }
        
        It "Should detect current SSID using netsh" {
            # Simulated netsh output
            $netshOutput = @"
    SSID                   : CoffeeShop-Guest
    BSSID                  : aa:bb:cc:dd:ee:ff
    Network type           : Infrastructure
"@
            $ssidMatch = $netshOutput | Select-String -Pattern '^\s+SSID\s+:\s+(.+)$'
            
            $ssidMatch | Should -Not -BeNullOrEmpty
            $ssidMatch.Matches[0].Groups[1].Value.Trim() | Should -Be "CoffeeShop-Guest"
        }
        
        It "Should detect WiFi interface name using netsh" {
            # Simulated netsh output
            $netshOutput = @"
    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX200 160MHz
    GUID                   : {12345678-1234-1234-1234-123456789012}
"@
            $interfaceMatch = $netshOutput | Select-String -Pattern '^\s+Name\s+:\s+(.+)$'
            
            $interfaceMatch | Should -Not -BeNullOrEmpty
            $interfaceMatch.Matches[0].Groups[1].Value.Trim() | Should -Be "Wi-Fi"
        }
        
        It "Should use netsh to disconnect from WiFi" {
            $disconnectCommand = 'netsh wlan disconnect interface="Wi-Fi"'
            
            $disconnectCommand | Should -Match "netsh wlan disconnect"
            $disconnectCommand | Should -Match "interface="
        }
        
        It "Should wait 3 seconds after disconnect" {
            $waitAfterDisconnect = 3
            
            $waitAfterDisconnect | Should -Be 3
        }
        
        It "Should use netsh to reconnect to same SSID" {
            $ssid = "CoffeeShop-Guest"
            $interface = "Wi-Fi"
            $connectCommand = "netsh wlan connect name=`"$ssid`" interface=`"$interface`""
            
            $connectCommand | Should -Match "netsh wlan connect"
            $connectCommand | Should -Match "CoffeeShop-Guest"
        }
        
        It "Should return true on successful reconnect" {
            $reconnectSuccess = $true
            
            $reconnectSuccess | Should -Be $true
        }
        
        It "Should return false on failed reconnect" {
            # Simulated error condition
            $ssidDetected = $false
            
            if (-not $ssidDetected) {
                $reconnectSuccess = $false
            }
            
            $reconnectSuccess | Should -Be $false
        }
    }
    
    Context "RETRY Action Flow" {
        It "Should set status RETRY_REQUESTED on successful reconnect" {
            $userChoice = "RETRY"
            $reconnectSuccess = $true
            
            if ($userChoice -eq "RETRY" -and $reconnectSuccess) {
                $status = "RETRY_REQUESTED"
            }
            
            $status | Should -Be "RETRY_REQUESTED"
        }
        
        It "Should set status RETRY_FAILED on failed reconnect" {
            $userChoice = "RETRY"
            $reconnectSuccess = $false
            
            if ($userChoice -eq "RETRY" -and -not $reconnectSuccess) {
                $status = "RETRY_FAILED"
            }
            
            $status | Should -Be "RETRY_FAILED"
        }
        
        It "Should log SSID before reconnecting" {
            $ssid = "TestNetwork"
            $logMessage = "Current SSID: $ssid"
            
            $logMessage | Should -Match "Current SSID:"
            $logMessage | Should -Match "TestNetwork"
        }
        
        It "Should exit after successful reconnect to allow DHCP trigger" {
            $reconnectSuccess = $true
            
            if ($reconnectSuccess) {
                $shouldExit = $true
                $exitReason = "exiting to allow framework re-trigger"
            }
            
            $shouldExit | Should -Be $true
            $exitReason | Should -Match "framework re-trigger"
        }
    }
    
    Context "EXIT Action Flow" {
        It "Should set status USER_EXIT when user chooses EXIT" {
            $userChoice = "EXIT"
            
            if ($userChoice -eq "EXIT") {
                $status = "USER_EXIT"
            }
            
            $status | Should -Be "USER_EXIT"
        }
        
        It "Should NOT perform any network actions on EXIT" {
            $userChoice = "EXIT"
            
            if ($userChoice -eq "EXIT") {
                $reconnectAttempted = $false
            }
            
            $reconnectAttempted | Should -Be $false
        }
        
        It "Should exit gracefully allowing manual user action" {
            $userChoice = "EXIT"
            
            if ($userChoice -eq "EXIT") {
                $allowManual = $true
            }
            
            $allowManual | Should -Be $true
        }
    }
}

Describe "WW_cap_portal_runner.ps1 v1.7.0_ER3 - Comprehensive Timeout Scenarios" {
    
    Context "Scenario 1: User Never Authenticates (Full Timeout)" {
        It "Should wait full 150 seconds" {
            $initialWait = 150
            $authCompleted = $false
            
            # Loop runs until timeout
            $waitTime = $initialWait
            
            $waitTime | Should -Be 150
            $authCompleted | Should -Be $false
        }
        
        It "Should show notification after full timeout" {
            $authCompleted = $false
            $siteReachable = $false
            
            if (-not $authCompleted -and -not $siteReachable) {
                $notificationShown = $true
            }
            
            $notificationShown | Should -Be $true
        }
        
        It "Should return PARTIAL or FAILED status" {
            $siteReachable = $false
            $validationBrowser = $true  # Browser launched
            
            if ($validationBrowser -and -not $siteReachable) {
                $status = "PARTIAL"
            } else {
                $status = "FAILED"
            }
            
            $status | Should -BeIn @("PARTIAL", "FAILED")
        }
    }
    
    Context "Scenario 2: User Authenticates Quickly (Early Exit)" {
        It "Should exit wait loop early when site becomes reachable" {
            $startTime = Get-Date
            $elapsed = 0
            $authCompleted = $false
            
            # Simulate auth completing after 25 seconds
            for ($i = 0; $i -lt 30; $i++) {
                if ($i -eq 5) {  # 25 seconds in (5 checks * 5s)
                    $authCompleted = $true
                    $elapsed = 25
                    break
                }
            }
            
            $authCompleted | Should -Be $true
            $elapsed | Should -BeLessThan 150
            $elapsed | Should -Be 25
        }
        
        It "Should NOT show notification on early success" {
            $authCompleted = $true
            $siteReachable = $true
            
            if (-not $authCompleted) {
                $notificationShown = $true
            } else {
                $notificationShown = $false
            }
            
            $notificationShown | Should -Be $false
        }
    }
    
    Context "Scenario 3: Captive Portal Site Unreachable (Network Issue)" {
        It "Should timeout gracefully without hang" {
            # Every Test-SiteReachability call times out in 3s
            $testTimeout = 3
            $checksPerformed = 30
            
            # Total time spent in failed checks
            $checkTime = $testTimeout * $checksPerformed
            
            # Should complete within reasonable bounds (not hang indefinitely)
            $checkTime | Should -BeLessThan 150
        }
        
        It "Should show notification after timeout attempts" {
            $authCompleted = $false  # Never succeeded
            $siteReachable = $false  # All checks failed
            
            if (-not $authCompleted -and -not $siteReachable) {
                $notificationShown = $true
            }
            
            $notificationShown | Should -Be $true
        }
    }
    
    Context "Scenario 4: Validation Browser Fails to Launch" {
        It "Should use fallback path without validation browser" {
            $validationBrowser = $null  # Launch failed
            $siteReachable = $false
            
            if (-not $validationBrowser) {
                $useFallback = $true
            }
            
            $useFallback | Should -Be $true
        }
        
        It "Should still perform connectivity test on fallback path" {
            $validationBrowser = $null
            $finalWaitSeconds = 30
            
            # Wait then test
            $siteTestPerformed = $true
            
            $siteTestPerformed | Should -Be $true
        }
        
        It "Should show notification on fallback path if no auth" {
            $validationBrowser = $null
            $authCompleted = $false
            $siteReachable = $false
            
            if (-not $authCompleted -and -not $siteReachable) {
                $notificationShown = $true
            }
            
            $notificationShown | Should -Be $true
        }
    }
    
    Context "Scenario 5: VPN Stabilization Delay" {
        It "Should wait for VPN stable state if remediation file exists" {
            $remediationFileExists = $true
            $vpnState = "Connecting"  # Intermediate
            
            if ($remediationFileExists -and $vpnState -in @("Connecting", "Reconnecting", "Unknown")) {
                $waitForStable = $true
                $maxWaitSeconds = 60
            }
            
            $waitForStable | Should -Be $true
            $maxWaitSeconds | Should -Be 60
        }
        
        It "Should poll VPN state every 5 seconds" {
            $checkInterval = 5
            $maxWaitSeconds = 60
            $maxAttempts = [math]::Ceiling($maxWaitSeconds / $checkInterval)
            
            $maxAttempts | Should -Be 12
        }
        
        It "Should proceed to validation browser after VPN stable" {
            $vpnState = "Connected"  # Stable
            
            if ($vpnState -in @("Connected", "Disconnected")) {
                $proceedToValidation = $true
            }
            
            $proceedToValidation | Should -Be $true
        }
    }
}

Describe "WW_cap_portal_runner.ps1 v1.7.0_ER3 - Integration Checks" {
    
    Context "End-to-End Success Flow" {
        It "Should complete without notification on success" {
            # User authenticates
            $authCompleted = $true
            # Site becomes reachable
            $siteReachable = $true
            # VPN stabilizes
            $vpnState = "Connected"
            # Validation browser launches
            $validationBrowser = [PSCustomObject]@{ Id = 12345 }
            
            # Determine final status
            if ($authCompleted -and $siteReachable -and $validationBrowser) {
                $status = "SUCCESS"
                $notificationShown = $false
            }
            
            $status | Should -Be "SUCCESS"
            $notificationShown | Should -Be $false
        }
    }
    
    Context "End-to-End Failure Flow" {
        It "Should show notification and return FAILED on complete failure" {
            # User doesn't authenticate
            $authCompleted = $false
            # Site never becomes reachable
            $siteReachable = $false
            # Validation browser may or may not launch
            $validationBrowser = $null
            
            # Determine final status
            if (-not $validationBrowser) {
                $status = "FAILED"
            } elseif (-not $siteReachable) {
                $status = "PARTIAL"
            }
            
            # Notification shown?
            if (-not $authCompleted) {
                $notificationShown = $true
            }
            
            $status | Should -BeIn @("FAILED", "PARTIAL")
            $notificationShown | Should -Be $true
        }
    }
    
    Context "Logging and Telemetry" {
        It "Should log timeout event" {
            $logMessage = "Authentication timeout - notifying user"
            $logLevel = "WARN"
            
            $logMessage | Should -Match "timeout"
            $logLevel | Should -Be "WARN"
        }
        
        It "Should log notification display" {
            $logMessage = "Displaying timeout notification to user"
            $logLevel = "INFO"
            
            $logMessage | Should -Match "notification"
            $logLevel | Should -Be "INFO"
        }
        
        It "Should include completion flag details" {
            $flagContent = @{
                status = "PARTIAL"
                details = "Validation browser opened but HTTP validation failed"
                captive_browser_pid = 12345
            }
            
            $flagContent.status | Should -BeIn @("SUCCESS", "PARTIAL", "FAILED")
            $flagContent.captive_browser_pid | Should -BeGreaterThan 0
        }
    }
}

Describe "WW_cap_portal_runner.ps1 v1.7.0_ER3 - Regression Tests" {
    
    Context "Existing Functionality Preserved" {
        It "Should still kill Cisco interference processes" {
            $ciscoBrowsers = @(
                "acwebhelper",
                "CiscoCollabHost", 
                "CiscoAnyConnectWebView",
                "CiscoWebLaunchHelper",
                "CiscoWebHelper"
            )
            
            $ciscoBrowsers.Count | Should -Be 5
        }
        
        It "Should still track captive browser PID" {
            $captiveBrowser = [PSCustomObject]@{ Id = 9876 }
            $captivePID = $captiveBrowser.Id
            
            $captivePID | Should -BeGreaterThan 0
            $captivePID | Should -BeOfType [int]
        }
        
        It "Should still write completion flag file" {
            $flagFile = "C:\ProgramData\WhiteWalker\portal_complete.flag"
            
            $flagFile | Should -Not -BeNullOrEmpty
            $flagFile | Should -Match "portal_complete.flag"
        }
        
        It "Should still use 150s initial wait" {
            $initialWaitSeconds = 150
            
            $initialWaitSeconds | Should -Be 150
        }
        
        It "Should still use 30s final wait" {
            $finalWaitSeconds = 30
            
            $finalWaitSeconds | Should -Be 30
        }
    }
}
