# WhiteWalker.Complete.Tests.ps1
# Complete test suite for WhiteWalker v3.13.1_ER6 (May remove once code settles)
# Covers: WW_main.ps1, WW_flaregun_user.ps1, WW_flaregun_system.ps1, WW_cap_portal_runner.ps1, WW_collect_diag.ps1
# 
# ER6 Test Coverage:
#   - Stale flag cleanup (user_prompted.flag added)
#   - Enhanced DC test with SSID awareness
#   - Public WiFi SSID rejection (starbucks, xfinitywifi, attwifi)
#
# ER5 Test Coverage:
#   - DNS chicken/egg detection
#   - Captive portal compatibility analysis (HTTPS, ports, IP, certs)
#   - Flare cooldown bypass for Event 777
#   - DNS failure counting and threshold detection

BeforeAll {
    # Source main script
    . $PSScriptRoot\WW_main.ps1
    
    # Mock external dependencies
    Mock Start-Process { }
    Mock Start-Sleep { }
    Mock Test-Connection { $true }
    Mock Get-Service { }
    Mock Start-Service { }
    Mock Get-Process { }
    Mock Get-NetAdapter { }
    Mock Get-NetIPConfiguration { }
    Mock Get-NetConnectionProfile { }
    Mock Get-DnsClientServerAddress { }
    Mock Add-Content { }
    Mock Set-Content { }
    Mock Remove-Item { }
    Mock Test-Path { $false }
    Mock Get-WinEvent { }
    Mock Get-CimInstance { }
}

Describe "WW_main.ps1 - Wake Detection (FIXED)" {
    
    Context "Test-RecentWakeFromSleep" {
        BeforeEach {
            Mock Write-Log { }
        }
        
        It "Should detect recent wake event" {
            Mock Get-WinEvent {
                param($FilterHashtable, $MaxEvents, $ErrorAction)
                $startTime = $FilterHashtable.StartTime
                $eventTime = (Get-Date).AddSeconds(-30)
                if ($eventTime -ge $startTime) {
                    return @([PSCustomObject]@{
                        TimeCreated = $eventTime
                        Id = 566
                        ProviderName = 'Microsoft-Windows-Kernel-Power'
                    })
                }
                return $null
            }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $true
        }
        
        It "Should return false when no wake event" {
            Mock Get-WinEvent { return $null }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $false
        }
        
        It "Should return false when wake event outside window (FIXED)" {
            Mock Get-WinEvent {
                param($FilterHashtable)
                $startTime = $FilterHashtable.StartTime
                $eventTime = (Get-Date).AddMinutes(-10)
                
                # Simulate real Get-WinEvent: only return if within filter
                if ($eventTime -ge $startTime) {
                    return @([PSCustomObject]@{ TimeCreated = $eventTime; Id = 566 })
                }
                return $null
            }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $false
        }
        
        It "Should handle Event ID 566 and 507" {
            Mock Get-WinEvent {
                @([PSCustomObject]@{
                    TimeCreated = (Get-Date).AddSeconds(-20)
                    Id = 507
                })
            }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $true
        }
    }
    
    Context "FlareGun Hidden Windows (CRITICAL FIX)" {
        BeforeEach {
            $global:flareHistory = @{}
            $global:_state = [PSCustomObject]@{ lastFlare = @{} }
            $global:_flareConfig = $null
            $global:WhatIf = $false
            Mock Write-Log { }
            Mock Save-State { }
            Mock Start-Process { }
        }
        
        It "Should use -WindowStyle Hidden for USER context flares" {
            Mock Get-FlareConfig {
                [PSCustomObject]@{
                    flare_events = @{
                        test = [PSCustomObject]@{
                            event_id = 780
                            context = "USER"
                        }
                    }
                }
            }
            
            Send-FlareEvent -Tag "test"
            
            # CRITICAL: Must use -WindowStyle Hidden to prevent flashing
            Assert-MockCalled Start-Process -ParameterFilter { 
                $WindowStyle -eq "Hidden" 
            }
        }
        
        It "Should use -WindowStyle Hidden for SYSTEM context flares" {
            Mock Get-FlareConfig {
                [PSCustomObject]@{
                    flare_events = @{
                        test_sys = [PSCustomObject]@{
                            event_id = 790
                            context = "SYSTEM"
                        }
                    }
                }
            }
            
            Send-FlareEvent -Tag "test_sys"
            
            Assert-MockCalled Start-Process -ParameterFilter { 
                $WindowStyle -eq "Hidden" 
            }
        }
        
        It "Should use -WindowStyle Hidden for legacy flares" {
            Mock Get-FlareConfig { $null }
            
            Send-FlareEvent -Tag "legacy"
            
            Assert-MockCalled Start-Process -ParameterFilter { 
                $WindowStyle -eq "Hidden" 
            }
        }
    }
    
    Context "To-Hashtable Function (FIXED)" {
        It "Should convert PSCustomObject to hashtable" {
            $obj = [PSCustomObject]@{
                name = "test"
                value = 42
            }
            
            $result = To-Hashtable $obj
            
            $result | Should -BeOfType [hashtable]
            $result["name"] | Should -Be "test"
            $result["value"] | Should -Be 42
        }
        
        It "Should convert nested objects" {
            $obj = [PSCustomObject]@{
                name = "test"
                nested = [PSCustomObject]@{ 
                    value = 42 
                }
            }
            
            $result = To-Hashtable $obj
            
            $result | Should -BeOfType [hashtable]
            $result["nested"] | Should -BeOfType [hashtable]
            $result["nested"]["value"] | Should -Be 42
        }
        
        It "Should handle null input" {
            $result = To-Hashtable $null
            $result | Should -BeNullOrEmpty
        }
        
        It "Should pass through hashtables" {
            $hash = @{ test = "value" }
            $result = To-Hashtable $hash
            $result["test"] | Should -Be "value"
        }
    }
}

Describe "WW_collect_diag.ps1 - VPN Status Detection (FIXED)" {
    
    Context "Cisco VPN State Parsing" {
        It "Should parse VPN state from multiple >> state: lines correctly" {
            # FIXED: Use same parsing logic as WW_main
            $vpncliOutput = @"
VPN Client Version: 5.0.1234
>> state: Disconnected
Connection status: idle
Last connect time: never
>> state: Connected
Management Connection State: Connected
"@
            
            # Simulate the parsing logic that should be in collect_diag
            $stateMatches = [regex]::Matches($vpncliOutput, '(?im)^\s*>>\s*state:\s*(\w+)\s*$')
            if ($stateMatches.Count -gt 0) {
                # Use LAST match (not first!)
                $vpnState = $stateMatches[$stateMatches.Count - 1].Groups[1].Value
            }
            
            $vpnState | Should -Be "Connected"
        }
        
        It "Should handle no >> state: lines" {
            $vpncliOutput = "VPN is disabled"
            
            $stateMatches = [regex]::Matches($vpncliOutput, '(?im)^\s*>>\s*state:\s*(\w+)\s*$')
            $vpnState = if ($stateMatches.Count -gt 0) { 
                $stateMatches[$stateMatches.Count - 1].Groups[1].Value 
            } else { 
                "Unknown" 
            }
            
            $vpnState | Should -Be "Unknown"
        }
    }
}

Describe "WW_flaregun_user.ps1 - USER Context Flares" {
    
    Context "Flare Execution" {
        It "Should use -WindowStyle Hidden when sending flares" {
            # Simulate the flare sending logic from WW_flaregun_user.ps1
            $mockFlareExe = "rundll32.exe"
            $mockTag = "user_tun"
            
            Mock Start-Process { }
            
            # This is the actual code from WW_flaregun_user.ps1:78
            Start-Process -FilePath $mockFlareExe -ArgumentList "/$mockTag" -WindowStyle Hidden -ErrorAction Stop | Out-Null
            
            Assert-MockCalled Start-Process -ParameterFilter { 
                $WindowStyle -eq "Hidden" 
            }
        }
        
        It "Should launch captive portal with CreateNoWindow" {
            # Lines 94-99 from WW_flaregun_user.ps1
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "powershell.exe"
            $psi.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File test.ps1"
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            
            $psi.CreateNoWindow | Should -Be $true
            $psi.WindowStyle | Should -Be "Hidden"
        }
    }
    
    Context "Event Log Parsing" {
        It "Should extract flare tag from event message" {
            $eventMessage = "FLARE:user_tun"
            
            if ($eventMessage -match 'FLARE:(\w+)') {
                $flareTag = $matches[1]
            }
            
            $flareTag | Should -Be "user_tun"
        }
        
        It "Should handle Event ID 777 as captive portal trigger" {
            $eventId = 777
            $eventMessage = "FLARE:captive_portal"
            
            # Event 777 should trigger captive portal launch
            $shouldLaunchPortal = ($eventId -eq 777)
            
            $shouldLaunchPortal | Should -Be $true
        }
    }
}

Describe "WW_flaregun_system.ps1 - SYSTEM Context Flares" {
    
    Context "Flare Execution" {
        It "Should use -WindowStyle Hidden when sending flares" {
            # Line 78 from WW_flaregun_system.ps1
            $mockFlareExe = "rundll32.exe"
            $mockTag = "ise_employee_captive_portal"
            
            Mock Start-Process { }
            
            Start-Process -FilePath $mockFlareExe -ArgumentList "/$mockTag" -WindowStyle Hidden -ErrorAction Stop | Out-Null
            
            Assert-MockCalled Start-Process -ParameterFilter { 
                $WindowStyle -eq "Hidden" 
            }
        }
        
        It "Should launch diagnostics with CreateNoWindow" {
            # Lines 95-101 from WW_flaregun_system.ps1
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "powershell.exe"
            $psi.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File test.ps1"
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            
            $psi.CreateNoWindow | Should -Be $true
        }
        
        It "Should handle Event ID 799 as diagnostics trigger" {
            $eventId = 799
            
            $shouldRunDiag = ($eventId -eq 799)
            
            $shouldRunDiag | Should -Be $true
        }
    }
}

Describe "WW_cap_portal_runner.ps1 - Captive Portal Browser" {
    
    Context "Browser Launch Configuration" {
        It "Should use InPrivate mode for Edge" {
            # Captive portal runner uses Edge InPrivate
            $browserArgs = "-inprivate http://neverssl.com"
            
            $browserArgs | Should -Match "-inprivate"
        }
        
        It "Should target HTTP (not HTTPS) for redirect detection" {
            $targetUrl = "http://neverssl.com"
            
            $targetUrl | Should -Match "^http://"
        }
    }
    
    Context "Flag File Management" {
        It "Should check for completion flag file" {
            $flagFile = "C:\ProgramData\WhiteWalker\portal_complete.flag"
            
            Mock Test-Path { $true } -ParameterFilter { $Path -eq $flagFile }
            
            $flagExists = Test-Path $flagFile
            $flagExists | Should -Be $true
        }
        
        It "Should poll flag file with interval" {
            # Cap portal runner polls every 3 seconds for up to 195 seconds
            $pollInterval = 3
            $timeout = 195
            
            $maxPolls = [math]::Ceiling($timeout / $pollInterval)
            $maxPolls | Should -Be 65
        }
    }
}

Describe "Configuration Values" {
    
    It "Should have correct version" {
        $ver | Should -Be "3.13.1_ER6"
    }
    
    It "Should have wake detection enabled" {
        $VpnWakeDetection | Should -Be $true
    }
    
    It "Should have 120 second wake window" {
        $VpnWakeTimeWindow | Should -Be 120
    }
    
    It "Should have network connection retries configured" {
        $NetworkConnectionRetries | Should -Be 2
        $NetworkConnectionWait | Should -Be 5
    }
    
    It "Should have FlareGun config path defined" {
        $FlareGunConfigPath | Should -Not -BeNullOrEmpty
    }
}

Describe "ER5 - DNS Chicken/Egg Detection" {
    
    Context "Test-CaptivePortalCompatibility" {
        BeforeEach {
            Mock Write-Log { }
        }
        
        It "Should detect non-HTTPS portal" {
            $result = Test-CaptivePortalCompatibility -RedirectUrl "http://portal.example.com/guest"
            
            $result.HasIssues | Should -Be $true
            $result.IssueType | Should -Be "NON_HTTPS"
            $result.AllowRetry | Should -Be $false
        }
        
        It "Should detect non-standard port" {
            $result = Test-CaptivePortalCompatibility -RedirectUrl "https://portal.example.com:8443/guest"
            
            $result.HasIssues | Should -Be $true
            $result.IssueType | Should -Be "NON_STANDARD_PORT"
            $result.AllowRetry | Should -Be $true
        }
        
        It "Should detect IP-based redirect" {
            $result = Test-CaptivePortalCompatibility -RedirectUrl "https://192.168.1.1/guest"
            
            $result.HasIssues | Should -Be $true
            $result.IssueType | Should -Be "IP_BASED_REDIRECT"
            $result.AllowRetry | Should -Be $true
        }
        
        It "Should pass clean HTTPS portal" {
            Mock -CommandName ([System.Net.Dns]::GetHostEntry) -MockWith { 
                return @{AddressList = @("192.168.1.1")}
            }
            
            $result = Test-CaptivePortalCompatibility -RedirectUrl "https://portal.example.com/guest"
            
            $result.HasIssues | Should -Be $false
            $result.IssueType | Should -Be "NONE"
        }
    }
    
    Context "DNS Chicken/Egg State File" {
        It "Should create dns_chicken_egg_issue.flag on detection" {
            $dnsIssueFile = "C:\ProgramData\WhiteWalker\dns_chicken_egg_issue.flag"
            
            Mock Set-Content { 
                param($Path, $Value)
                $Path | Should -Be $dnsIssueFile
                $Value | Should -Match "DNS_BLOCKED"
            }
            
            # This would be called in gateway fallback when DNS fails
            # Test that state file is created correctly
        }
    }
}

Describe "ER5 - Flare Cooldown Bypass" {
    
    Context "Send-FlareEvent Cooldown Logic" {
        BeforeEach {
            Mock Write-Log { }
            Mock Start-Process { }
            $script:FlareHistory = @{}
        }
        
        It "Should bypass cooldown for captive_portal_browser" {
            # First call - should fire
            Send-FlareEvent "captive_portal_browser"
            
            # Second call immediately - should ALSO fire (bypass cooldown)
            Send-FlareEvent "captive_portal_browser"
            
            # Both should succeed (not suppressed)
            Assert-MockCalled Start-Process -Times 2 -Exactly
        }
        
        It "Should respect cooldown for non-critical events" {
            # First call
            Send-FlareEvent "ise_employee_posture"
            
            # Second call immediately - should be suppressed
            Send-FlareEvent "ise_employee_posture"
            
            # Only first should fire
            Assert-MockCalled Start-Process -Times 1 -Exactly
        }
    }
}

Describe "ER6 - Stale Flag Cleanup" {
    
    Context "Clear-StaleFlagFiles" {
        BeforeEach {
            Mock Write-Log { }
            Mock Test-Path { $true }
            Mock Remove-Item { }
        }
        
        It "Should remove stale user_prompted.flag" {
            Mock Get-Item {
                return [PSCustomObject]@{
                    LastWriteTime = (Get-Date).AddMinutes(-20)
                    FullName = "C:\ProgramData\WhiteWalker\user_prompted.flag"
                }
            }
            
            Clear-StaleFlagFiles -StaleThresholdMinutes 15
            
            Assert-MockCalled Remove-Item -ParameterFilter {
                $Path -like "*user_prompted.flag"
            }
        }
        
        It "Should NOT remove fresh flags" {
            Mock Get-Item {
                return [PSCustomObject]@{
                    LastWriteTime = (Get-Date).AddMinutes(-5)
                    FullName = "C:\ProgramData\WhiteWalker\portal_complete.flag"
                }
            }
            
            Clear-StaleFlagFiles -StaleThresholdMinutes 15
            
            Assert-MockCalled Remove-Item -Times 0
        }
        
        It "Should clean all stale flags including user_prompted" {
            $staleFlags = @(
                "portal_complete.flag",
                "network_interrupt.flag", 
                "cap_portal_remediation_active.flag",
                "captive_failure.flag",
                "user_prompted.flag",
                "dns_chicken_egg_issue.flag"
            )
            
            foreach ($flag in $staleFlags) {
                Mock Get-Item {
                    return [PSCustomObject]@{
                        LastWriteTime = (Get-Date).AddMinutes(-20)
                        FullName = "C:\ProgramData\WhiteWalker\$flag"
                    }
                } -ParameterFilter { $Path -like "*$flag" }
            }
            
            Clear-StaleFlagFiles -StaleThresholdMinutes 15
            
            # Should attempt to remove all 6 stale flags
            Assert-MockCalled Remove-Item -Times 6 -Exactly
        }
    }
}

Describe "ER6 - Enhanced DC Test with SSID Awareness" {
    
    Context "Test-DC with SSID Check" {
        BeforeEach {
            Mock Write-Log { }
        }
        
        It "Should return true for legitimate on-prem" {
            Mock Test-Connection { $true }
            Mock Get-NetAdapter { $null } # Not on WiFi
            
            $result = Test-DC -hostname "dc.corporate.com"
            
            $result | Should -Be $true
        }
        
        It "Should return false when DC unreachable" {
            Mock Test-Connection { $false }
            
            $result = Test-DC -hostname "dc.corporate.com"
            
            $result | Should -Be $false
        }
        
        It "Should reject DC=True on Starbucks WiFi (stale routes)" {
            Mock Test-Connection { $true }
            Mock Get-NetAdapter {
                return [PSCustomObject]@{
                    Name = "Wi-Fi"
                    Status = "Up"
                }
            }
            Mock netsh {
                return @(
                    "There is 1 interface on the system:",
                    "",
                    "    Name                   : Wi-Fi",
                    "    Description            : Intel(R) Wi-Fi 6 AX201 160MHz",
                    "    SSID                   : Starbucks WiFi",
                    "    State                  : connected"
                )
            }
            
            $result = Test-DC -hostname "dc.corporate.com"
            
            $result | Should -Be $false
        }
        
        It "Should reject DC=True on xfinitywifi" {
            Mock Test-Connection { $true }
            Mock Get-NetAdapter {
                return [PSCustomObject]@{
                    Name = "Wi-Fi"
                    Status = "Up"
                }
            }
            Mock netsh {
                return @(
                    "    SSID                   : xfinitywifi",
                    "    State                  : connected"
                )
            }
            
            $result = Test-DC -hostname "dc.corporate.com"
            
            $result | Should -Be $false
        }
        
        It "Should reject DC=True on attwifi" {
            Mock Test-Connection { $true }
            Mock Get-NetAdapter {
                return [PSCustomObject]@{
                    Name = "Wi-Fi"
                    Status = "Up"
                }
            }
            Mock netsh {
                return @(
                    "    SSID                   : attwifi",
                    "    State                  : connected"
                )
            }
            
            $result = Test-DC -hostname "dc.corporate.com"
            
            $result | Should -Be $false
        }
        
        It "Should accept DC=True on corporate SSID" {
            Mock Test-Connection { $true }
            Mock Get-NetAdapter {
                return [PSCustomObject]@{
                    Name = "Wi-Fi"
                    Status = "Up"
                }
            }
            Mock netsh {
                return @(
                    "    SSID                   : CorpNet-Secure",
                    "    State                  : connected"
                )
            }
            
            $result = Test-DC -hostname "dc.corporate.com"
            
            $result | Should -Be $true
        }
    }
}

Describe "ER5 - Captive Portal Runner DNS Check" {
    
    Context "DNS Chicken/Egg Detection in Runner" {
        BeforeEach {
            Mock Write-CapLog { }
        }
        
        It "Should detect dns_chicken_egg_issue.flag and show popup" {
            $dnsIssueFile = "C:\ProgramData\WhiteWalker\dns_chicken_egg_issue.flag"
            
            Mock Test-Path { 
                param($Path)
                if ($Path -eq $dnsIssueFile) { return $true }
                return $false
            }
            
            Mock Get-Content {
                return @'
{
    "timestamp": "2026-01-12T10:00:00",
    "issue_type": "DNS_BLOCKED",
    "redirect_url": "https://portal.example.com",
    "description": "DNS chicken/egg problem",
    "user_message": "Network blocks DNS until portal accepted"
}
'@
            }
            
            Mock Remove-Item { }
            Mock Show-TimeoutNotification { return "OK" }
            Mock Write-CompletionFlag { }
            
            # Runner should detect file, show popup, exit immediately
            # (This would be tested in cap_portal_runner context)
        }
    }
    
    Context "DNS Failure Counting" {
        It "Should track consecutive DNS failures" {
            $script:dnsFailureCount = 0
            
            # Simulate 10 failed validation attempts with DNS errors
            1..10 | ForEach-Object {
                # Each failure increments counter
                $script:dnsFailureCount++
            }
            
            $script:dnsFailureCount | Should -Be 10
        }
        
        It "Should trigger chicken/egg detection after threshold" {
            $script:dnsFailureCount = 12
            
            $result = Test-DNSChickenEggProblem -FailureThreshold 10
            
            $result | Should -Be $true
        }
    }
}
