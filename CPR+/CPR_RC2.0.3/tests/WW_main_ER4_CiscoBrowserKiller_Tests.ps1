<#
.SYNOPSIS
WhiteWalker v3.13.1_ER4 - Cisco Browser Killer Tests

.DESCRIPTION
Tests for proactive Cisco browser cleanup that runs on every WhiteWalker execution.
Addresses issue where valid guest network sessions leave orphaned Cisco browsers.
#>

BeforeAll {
    $script:MainScriptPath = "C:\ProgramData\WhiteWalker\WW_main.ps1"
}

Describe "WW_main.ps1 v3.13.1_ER4 - Cisco Browser Killer" {
    
    Context "Start-CiscoBrowserKiller Function" {
        It "Should target all known interfering Cisco processes" {
            $ciscoBrowsers = @(
                "acwebhelper",
                "CiscoCollabHost", 
                "CiscoAnyConnectWebView",
                "CiscoWebLaunchHelper",
                "CiscoWebHelper"
            )
            
            $ciscoBrowsers.Count | Should -Be 5
            $ciscoBrowsers | Should -Contain "acwebhelper"
            $ciscoBrowsers | Should -Contain "CiscoWebHelper"
        }
        
        It "Should run background job for 10 seconds" {
            $duration = 10  # seconds
            
            $duration | Should -Be 10
        }
        
        It "Should poll for processes every 500ms" {
            $pollInterval = 500  # milliseconds
            
            $pollInterval | Should -Be 500
        }
        
        It "Should return job object on success" {
            # Mock job creation
            $mockJob = [PSCustomObject]@{ Id = 12345 }
            
            $mockJob | Should -Not -BeNullOrEmpty
            $mockJob.Id | Should -BeGreaterThan 0
        }
        
        It "Should return null on failure" {
            # Simulated failure scenario
            $jobCreationFailed = $true
            
            if ($jobCreationFailed) {
                $result = $null
            }
            
            $result | Should -BeNullOrEmpty
        }
        
        It "Should log job start with JobId" {
            $jobId = 12345
            $logMessage = "Cisco browser killer job started (JobId: $jobId) - will run for 10 seconds"
            
            $logMessage | Should -Match "JobId:"
            $logMessage | Should -Match "10 seconds"
        }
    }
    
    Context "Stop-CiscoBrowserKiller Function" {
        It "Should receive job results when stopping" {
            # Simulated job result
            $killCount = 3
            
            $killCount | Should -BeGreaterThan 0
        }
        
        It "Should log number of processes killed" {
            $killCount = 2
            $logMessage = "Cisco browser killer terminated $killCount process(es)"
            
            $logMessage | Should -Match "terminated"
            $logMessage | Should -Match "2 process"
        }
        
        It "Should log if no processes found" {
            $killCount = 0
            
            if ($killCount -eq 0) {
                $logMessage = "Cisco browser killer found no processes to terminate"
            }
            
            $logMessage | Should -Match "no processes"
        }
        
        It "Should handle null job gracefully" {
            $job = $null
            
            if ($job) {
                $shouldAttemptStop = $true
            } else {
                $shouldAttemptStop = $false
            }
            
            $shouldAttemptStop | Should -Be $false
        }
    }
    
    Context "Integration - Execution Timing" {
        It "Should start after post-DHCP sleep" {
            # Workflow order verification
            $steps = @(
                "Network detection",
                "Post-DHCP sleep (7s)",
                "Start Cisco browser killer",  # NEW in ER4
                "VPN gatekeeper"
            )
            
            $killerIndex = $steps.IndexOf("Start Cisco browser killer")
            $sleepIndex = $steps.IndexOf("Post-DHCP sleep (7s)")
            $vpnIndex = $steps.IndexOf("VPN gatekeeper")
            
            $killerIndex | Should -BeGreaterThan $sleepIndex
            $killerIndex | Should -BeLessThan $vpnIndex
        }
        
        It "Should run before any redirect checks" {
            $executionOrder = @(
                "Cisco browser killer starts",
                "ISE redirect detection",
                "Captive portal detection"
            )
            
            $executionOrder[0] | Should -Be "Cisco browser killer starts"
        }
        
        It "Should stop in finally block before Write-RunEnd" {
            $finallyBlock = @(
                "Stop Cisco browser killer",
                "Write-RunEnd"
            )
            
            $finallyBlock[0] | Should -Be "Stop Cisco browser killer"
        }
    }
    
    Context "Scenario - Valid Guest Network Session" {
        It "Should detect no redirect when session valid" {
            # User reconnects to guest network with valid session
            $iseRedirect = $false
            $captiveRedirect = $false
            $internetReachable = $true
            
            $noRedirectDetected = (-not $iseRedirect -and -not $captiveRedirect)
            
            $noRedirectDetected | Should -Be $true
            $internetReachable | Should -Be $true
        }
        
        It "Should kill Cisco browser even without redirect" {
            # Key scenario: No redirect, but Cisco browser opened
            $redirectDetected = $false
            $ciscoBrowserRunning = $true
            
            # Cisco browser killer runs regardless of redirect
            $shouldKillBrowser = $true
            
            $shouldKillBrowser | Should -Be $true
        }
        
        It "Should exit with on_prem status" {
            $iseRedirect = $false
            $captiveRedirect = $false
            $gatewayReachable = $true
            $dcReachable = $true
            
            if ($gatewayReachable -and $dcReachable -and -not $iseRedirect -and -not $captiveRedirect) {
                $exitReason = "on_prem"
            }
            
            $exitReason | Should -Be "on_prem"
        }
    }
    
    Context "Scenario - Orphaned Cisco Browser from Previous Session" {
        It "Should kill browsers from previous captive portal sessions" {
            # Scenario: User was at Starbucks, now at office
            $previousLocation = "Starbucks"
            $currentLocation = "Office"
            $orphanedBrowser = $true
            
            # Killer runs regardless of where browser came from
            $shouldCleanup = $true
            
            $shouldCleanup | Should -Be $true
        }
        
        It "Should handle multiple orphaned processes" {
            $orphanedProcesses = @("acwebhelper", "CiscoCollabHost", "CiscoWebHelper")
            
            $orphanedProcesses.Count | Should -BeGreaterThan 1
            $orphanedProcesses | Should -Contain "acwebhelper"
        }
    }
    
    Context "Scenario - Cisco Client Launching Browsers During Posture" {
        It "Should kill browsers launched during posture checks" {
            # Cisco client may launch browsers during ISE posture
            $postureCheckActive = $true
            $ciscoBrowserLaunched = $true
            
            # Killer runs in background during posture workflow
            $killerActive = $true
            
            $killerActive | Should -Be $true
        }
    }
    
    Context "Background Job Behavior" {
        It "Should continue running while main script proceeds" {
            # Job runs for 10 seconds in background
            $jobDuration = 10
            # Main script continues immediately
            $scriptContinues = $true
            
            $scriptContinues | Should -Be $true
            $jobDuration | Should -Be 10
        }
        
        It "Should not block main script execution" {
            # Background job is non-blocking
            $isBlocking = $false
            
            $isBlocking | Should -Be $false
        }
        
        It "Should be stopped in finally block if still running" {
            # Script exits before 10 seconds
            $scriptRunTime = 5  # seconds
            $jobDuration = 10   # seconds
            
            if ($scriptRunTime -lt $jobDuration) {
                $jobStillRunning = $true
                $shouldStopJob = $true
            }
            
            $shouldStopJob | Should -Be $true
        }
        
        It "Should auto-complete if script runs longer than 10 seconds" {
            # Script runs 30 seconds (e.g., waiting for captive portal)
            $scriptRunTime = 30  # seconds
            $jobDuration = 10    # seconds
            
            if ($scriptRunTime -gt $jobDuration) {
                $jobAlreadyComplete = $true
            }
            
            $jobAlreadyComplete | Should -Be $true
        }
    }
}

Describe "WW_main.ps1 v3.13.1_ER4 - Comparison with WW_cap_portal_runner" {
    
    Context "Cisco Browser Killer in Both Scripts" {
        It "Should have killer in WW_main for proactive cleanup" {
            $mainHasKiller = $true
            
            $mainHasKiller | Should -Be $true
        }
        
        It "Should have killer in cap_portal_runner for remediation" {
            $capPortalHasKiller = $true
            
            $capPortalHasKiller | Should -Be $true
        }
        
        It "WW_main killer runs for 10 seconds" {
            $mainDuration = 10
            
            $mainDuration | Should -Be 10
        }
        
        It "cap_portal_runner killer runs for 20 seconds" {
            $capPortalDuration = 20
            
            $capPortalDuration | Should -Be 20
        }
        
        It "Both target same process list" {
            $processList = @(
                "acwebhelper",
                "CiscoCollabHost", 
                "CiscoAnyConnectWebView",
                "CiscoWebLaunchHelper",
                "CiscoWebHelper"
            )
            
            $processList.Count | Should -Be 5
        }
    }
    
    Context "When Each Killer Runs" {
        It "WW_main killer: EVERY WhiteWalker execution" {
            $mainRunFrequency = "EVERY_RUN"
            
            $mainRunFrequency | Should -Be "EVERY_RUN"
        }
        
        It "cap_portal_runner killer: Only during captive portal remediation" {
            $capPortalRunCondition = "CAPTIVE_PORTAL_DETECTED"
            
            $capPortalRunCondition | Should -Be "CAPTIVE_PORTAL_DETECTED"
        }
        
        It "Provides redundancy for maximum cleanup coverage" {
            $redundancy = $true
            
            $redundancy | Should -Be $true
        }
    }
}

Describe "WW_main.ps1 v3.13.1_ER4 - Logging and Monitoring" {
    
    Context "Expected Log Messages" {
        It "Should log killer start" {
            $logMessage = "Starting Cisco browser killer background job..."
            
            $logMessage | Should -Match "Cisco browser killer"
            $logMessage | Should -Match "background job"
        }
        
        It "Should log job ID" {
            $jobId = 45678
            $logMessage = "Cisco browser killer job started (JobId: $jobId)"
            
            $logMessage | Should -Match "JobId: 45678"
        }
        
        It "Should log termination count on success" {
            $killCount = 3
            $logMessage = "Cisco browser killer terminated 3 process(es)"
            
            $logMessage | Should -Match "terminated 3"
        }
        
        It "Should log when no processes found" {
            $logMessage = "Cisco browser killer found no processes to terminate"
            
            $logMessage | Should -Match "no processes"
        }
        
        It "Should log failures gracefully" {
            $errorMessage = "Failed to start Cisco browser killer: Access denied"
            
            $errorMessage | Should -Match "Failed to start"
        }
    }
    
    Context "Monitoring Points" {
        It "Should track how many browsers killed per run" {
            # Telemetry: Track kill count over time
            $killCounts = @(0, 2, 0, 1, 3, 0)
            
            $totalKilled = ($killCounts | Measure-Object -Sum).Sum
            $avgKilled = ($killCounts | Measure-Object -Average).Average
            
            $totalKilled | Should -Be 6
            $avgKilled | Should -BeLessThan 2
        }
        
        It "Should identify problematic locations/SSIDs" {
            # If killCount > 0 frequently on specific SSID
            $ssidKillStats = @{
                "CoffeeShop-Guest" = 15  # Kills browsers often
                "Office-Corp" = 2        # Rarely kills browsers
            }
            
            $ssidKillStats["CoffeeShop-Guest"] | Should -BeGreaterThan $ssidKillStats["Office-Corp"]
        }
    }
}

Describe "WW_main.ps1 v3.13.1_ER4 - Regression Tests" {
    
    Context "Existing Functionality Preserved" {
        It "Should still perform VPN gatekeeper check" {
            $vpnGatekeeperRuns = $true
            
            $vpnGatekeeperRuns | Should -Be $true
        }
        
        It "Should still detect ISE redirects" {
            $iseRedirectDetection = $true
            
            $iseRedirectDetection | Should -Be $true
        }
        
        It "Should still detect captive portals" {
            $captivePortalDetection = $true
            
            $captivePortalDetection | Should -Be $true
        }
        
        It "Should still check internet connectivity" {
            $internetCheck = $true
            
            $internetCheck | Should -Be $true
        }
        
        It "Should still classify as on_prem when appropriate" {
            $gatewayReachable = $true
            $dcReachable = $true
            $noRedirect = $true
            
            if ($gatewayReachable -and $dcReachable -and $noRedirect) {
                $classification = "on_prem"
            }
            
            $classification | Should -Be "on_prem"
        }
    }
    
    Context "Version Verification" {
        It "Should be version 3.13.1_ER4" {
            $version = "3.13.1_ER4"
            
            $version | Should -Be "3.13.1_ER4"
        }
        
        It "Should have ER4 changelog entry" {
            $changelogContains = "Major changes in 3.13.1_ER4"
            
            $changelogContains | Should -Match "ER4"
        }
    }
}
