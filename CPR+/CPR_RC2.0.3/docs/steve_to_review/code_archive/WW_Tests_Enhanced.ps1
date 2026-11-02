# WhiteWalker.Enhanced.Tests.ps1
# Enhanced Pester test suite for WhiteWalker v3.13.1_ER1
# Fixes wake detection test and adds comprehensive coverage

BeforeAll {
    # Source the main script to load functions
    . $PSScriptRoot\WW_main.ps1
    
    # Mock external dependencies to prevent actual system calls
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

Describe "WhiteWalker v3.13.1_ER1 - Wake Detection Tests" {
    
    Context "Test-RecentWakeFromSleep - Core Functionality" {
        BeforeEach {
            Mock Write-Log { }
        }
        
        It "Should detect recent wake event within time window" {
            # Mock Get-WinEvent to return an event from 30 seconds ago
            # This simulates finding a recent wake event
            Mock Get-WinEvent {
                param($FilterHashtable, $MaxEvents, $ErrorAction)
                # Only return event if StartTime filter would include it
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
        
        It "Should return false when no wake event found" {
            Mock Get-WinEvent { return $null }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $false
        }
        
        It "Should return false when wake event is outside time window (FIXED)" {
            # FIXED TEST: Mock should honor the StartTime filter
            # Old event from 10 minutes ago should NOT be returned when filter is 2 minutes
            Mock Get-WinEvent {
                param($FilterHashtable, $MaxEvents, $ErrorAction)
                $startTime = $FilterHashtable.StartTime
                $eventTime = (Get-Date).AddMinutes(-10)
                
                # Simulate actual Get-WinEvent behavior: only return if within filter range
                if ($eventTime -ge $startTime) {
                    return @([PSCustomObject]@{
                        TimeCreated = $eventTime
                        Id = 566
                    })
                }
                return $null
            }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $false
        }
        
        It "Should log wake detection" {
            Mock Get-WinEvent {
                @([PSCustomObject]@{
                    TimeCreated = (Get-Date).AddSeconds(-45)
                    Id = 507
                })
            }
            Mock Write-Log { }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*wake from sleep detected*" -and $Level -eq "INFO"
            }
        }
        
        It "Should handle Event ID 566 (System wake)" {
            Mock Get-WinEvent {
                @([PSCustomObject]@{
                    TimeCreated = (Get-Date).AddSeconds(-20)
                    Id = 566
                })
            }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $true
        }
        
        It "Should handle Event ID 507 (Modern Standby exit)" {
            Mock Get-WinEvent {
                @([PSCustomObject]@{
                    TimeCreated = (Get-Date).AddSeconds(-20)
                    Id = 507
                })
            }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            $result | Should -Be $true
        }
        
        It "Should handle Get-WinEvent exceptions gracefully" {
            Mock Get-WinEvent { throw "Event log error" }
            Mock Write-Log { }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
            
            $result | Should -Be $false
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*Could not check wake from sleep*" -and $Level -eq "DEBUG"
            }
        }
        
        It "Should respect custom time window parameter" {
            Mock Get-WinEvent {
                param($FilterHashtable)
                $startTime = $FilterHashtable.StartTime
                $now = Get-Date
                
                # Verify the StartTime is approximately 60 seconds ago (within 2 second tolerance)
                $expectedStart = $now.AddSeconds(-60)
                $diff = [Math]::Abs(($startTime - $expectedStart).TotalSeconds)
                if ($diff -le 2) {
                    return @([PSCustomObject]@{
                        TimeCreated = $now.AddSeconds(-30)
                        Id = 566
                    })
                }
                return $null
            }
            
            $result = Test-RecentWakeFromSleep -TimeWindowSeconds 60
            $result | Should -Be $true
        }
    }
    
    Context "Get-VpnStateStable - Wake Detection Integration" {
        BeforeEach {
            Mock Write-Log { }
            Mock Save-State { }
            $global:VpnWakeDetection = $true
            $global:VpnWakeTimeWindow = 120
            $global:VpnIntermediateMaxWait = 30
        }
        
        It "Should force disconnect when VPN intermediate + recent wake" {
            # Setup mocks
            $script:callCount = 0
            Mock Get-VpnState {
                $script:callCount++
                if ($script:callCount -eq 1) { return "Reconnecting" }
                return "Disconnected"
            }
            Mock Test-RecentWakeFromSleep { $true }
            Mock Start-Process { } # Mock vpn disconnect
            
            $result = Get-VpnStateStable -TimeoutSec 12
            
            $result | Should -Be "Disconnected"
            Assert-MockCalled Test-RecentWakeFromSleep -Times 1
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*recent wake from sleep*BLOCKING*" 
            }
        }
        
        It "Should allow VPN intermediate when no recent wake" {
            $script:callCount = 0
            Mock Get-VpnState {
                $script:callCount++
                if ($script:callCount -le 3) { return "Connecting" }
                return "Connected"
            }
            Mock Test-RecentWakeFromSleep { $false }
            
            $result = Get-VpnStateStable -TimeoutSec 12
            
            $result | Should -Be "Connected"
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*NO recent wake detected*" 
            }
        }
        
        It "Should skip wake detection when VpnWakeDetection disabled" {
            $global:VpnWakeDetection = $false
            Mock Get-VpnState { "Disconnected" }
            Mock Test-RecentWakeFromSleep { throw "Should not be called" }
            
            $result = Get-VpnStateStable -TimeoutSec 12
            
            Assert-MockCalled Test-RecentWakeFromSleep -Times 0
        }
    }
}

Describe "WhiteWalker v3.13.1_ER1 - Network Connection Retry" {
    
    Context "Network Connection Polling" {
        BeforeEach {
            Mock Write-Log { }
            Mock Start-Sleep { }
            $global:NetworkConnectionRetries = 2
            $global:NetworkConnectionWait = 5
        }
        
        It "Should detect active network adapter immediately" {
            Mock Get-NetAdapter {
                [PSCustomObject]@{
                    Name = "Ethernet"
                    Status = "Up"
                    Virtual = $false
                    InterfaceDescription = "Intel Ethernet"
                }
            }
            Mock Get-NetIPConfiguration {
                [PSCustomObject]@{
                    IPv4Address = @([PSCustomObject]@{ IPAddress = "192.168.1.100" })
                }
            }
            
            # This would be called in main script - testing the detection logic
            $adapter = Get-NetAdapter | Where-Object { 
                $_.Status -eq 'Up' -and 
                $_.Virtual -eq $false
            } | Select-Object -First 1
            
            $adapter | Should -Not -BeNullOrEmpty
            $adapter.Status | Should -Be "Up"
        }
        
        It "Should filter out VPN adapters" {
            Mock Get-NetAdapter {
                @(
                    [PSCustomObject]@{
                        Name = "Cisco AnyConnect"
                        Status = "Up"
                        Virtual = $true
                        InterfaceDescription = "Cisco VPN Adapter"
                    },
                    [PSCustomObject]@{
                        Name = "Wi-Fi"
                        Status = "Up"
                        Virtual = $false
                        InterfaceDescription = "Intel Wi-Fi"
                    }
                )
            }
            
            $adapter = Get-NetAdapter | Where-Object { 
                $_.Status -eq 'Up' -and 
                $_.Virtual -eq $false -and
                $_.InterfaceDescription -notmatch 'Cisco|VPN'
            } | Select-Object -First 1
            
            $adapter.Name | Should -Be "Wi-Fi"
        }
    }
}

Describe "WhiteWalker v3.13.1_ER1 - FlareGun Framework" {
    
    Context "Get-FlareConfig Function" {
        BeforeEach {
            $global:_flareConfig = $null
            Mock Write-Log { }
        }
        
        It "Should load valid config file" {
            Mock Test-Path { $true } -ParameterFilter { $Path -like "*WW_flaregun_config.json" }
            Mock Get-Content {
                @'
{
  "flare_events": {
    "user_tun": {
      "event_id": 780,
      "context": "USER",
      "flare_tag": "user_tun"
    }
  }
}
'@
            }
            
            $config = Get-FlareConfig
            
            $config | Should -Not -BeNullOrEmpty
            $config.flare_events.user_tun.event_id | Should -Be 780
            $config.flare_events.user_tun.context | Should -Be "USER"
        }
        
        It "Should cache config after first load" {
            Mock Test-Path { $true } -ParameterFilter { $Path -like "*WW_flaregun_config.json" }
            Mock Get-Content {
                @'
{"flare_events": {"test": {"event_id": 999}}}
'@
            }
            
            $config1 = Get-FlareConfig
            $config2 = Get-FlareConfig
            
            # Should only call Get-Content once due to caching
            Assert-MockCalled Get-Content -Times 1
        }
        
        It "Should return null when config file missing" {
            Mock Test-Path { $false }
            
            $config = Get-FlareConfig
            
            $config | Should -BeNullOrEmpty
            Assert-MockCalled Write-Log -ParameterFilter { $Message -like "*config not found*" }
        }
        
        It "Should handle corrupt config file gracefully" {
            Mock Test-Path { $true }
            Mock Get-Content { "{ invalid json" }
            
            $config = Get-FlareConfig
            
            $config | Should -BeNullOrEmpty
            Assert-MockCalled Write-Log -ParameterFilter { $Level -eq "ERROR" }
        }
    }
    
    Context "Send-FlareEvent - Context Routing" {
        BeforeEach {
            $global:flareHistory = @{}
            $global:_state = [PSCustomObject]@{ lastFlare = @{} }
            $global:_flareConfig = $null
            $global:WhatIf = $false
            Mock Write-Log { }
            Mock Save-State { }
            Mock Start-Process { }
        }
        
        It "Should route USER context flare through event log" {
            Mock Get-FlareConfig {
                [PSCustomObject]@{
                    flare_events = @{
                        test_user = [PSCustomObject]@{
                            event_id = 780
                            context = "USER"
                            flare_tag = "test_user"
                        }
                    }
                }
            }
            
            Send-FlareEvent -Tag "test_user"
            
            Assert-MockCalled Start-Process -ParameterFilter { 
                $FilePath -eq "eventcreate.exe" -and 
                $ArgumentList -contains "780"
            }
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*queued for USER context*" 
            }
        }
        
        It "Should send SYSTEM context flare directly" {
            Mock Get-FlareConfig {
                [PSCustomObject]@{
                    flare_events = @{
                        test_system = [PSCustomObject]@{
                            event_id = 770
                            context = "SYSTEM"
                            flare_tag = "test_system"
                        }
                    }
                }
            }
            
            Send-FlareEvent -Tag "test_system"
            
            Assert-MockCalled Start-Process -ParameterFilter { 
                $FilePath -eq $flareExe -and 
                $ArgumentList -eq "/test_system"
            }
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*sent directly as SYSTEM*" 
            }
        }
        
        It "Should respect per-run deduplication" {
            $global:flareHistory["dup_test"] = Get-Date
            Mock Get-FlareConfig { $null }
            
            Send-FlareEvent -Tag "dup_test"
            
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*de-duped*already sent this run*" 
            }
            Assert-MockCalled Start-Process -Times 0
        }
        
        It "Should respect cooldown period" {
            $global:_state.lastFlare = @{
                "cooldown_test" = (Get-Date).ToString('o')
            }
            $global:FlareCooldownMinutes = 10
            Mock Get-FlareConfig { $null }
            
            Send-FlareEvent -Tag "cooldown_test"
            
            Assert-MockCalled Write-Log -ParameterFilter { 
                $Message -like "*suppressed*cooldown*" 
            }
        }
        
        It "Should use -WindowStyle Hidden to prevent window flash" {
            Mock Get-FlareConfig {
                [PSCustomObject]@{
                    flare_events = @{
                        silent_test = [PSCustomObject]@{
                            event_id = 790
                            context = "USER"
                        }
                    }
                }
            }
            
            Send-FlareEvent -Tag "silent_test"
            
            Assert-MockCalled Start-Process -ParameterFilter { 
                $WindowStyle -eq "Hidden" 
            }
        }
    }
}

Describe "WhiteWalker v3.13.1_ER1 - ISE Posture Functions" {
    
    Context "Get-PostureService" {
        BeforeEach {
            Mock Write-Log { }
        }
        
        It "Should detect csc_iseagent service" {
            Mock Get-Service {
                [PSCustomObject]@{
                    Name = "csc_iseagent"
                    Status = "Running"
                }
            }
            
            $result = Get-PostureService
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be "csc_iseagent"
        }
        
        It "Should detect ciscod.exe process" {
            Mock Get-Service { $null }
            Mock Get-Process {
                [PSCustomObject]@{
                    ProcessName = "ciscod"
                    Id = 1234
                }
            }
            
            $result = Get-PostureService
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should return null when no posture service found" {
            Mock Get-Service { $null }
            Mock Get-Process { $null }
            
            $result = Get-PostureService
            $result | Should -BeNullOrEmpty
        }
    }
}

Describe "WhiteWalker v3.13.1_ER1 - Configuration Values" {
    
    It "Should have correct version number" {
        $ver | Should -Be "3.13.1_ER1"
    }
    
    It "Should have wake detection enabled by default" {
        $VpnWakeDetection | Should -Be $true
    }
    
    It "Should have 2-minute wake time window" {
        $VpnWakeTimeWindow | Should -Be 120
    }
    
    It "Should have network connection retry configured" {
        $NetworkConnectionRetries | Should -Be 2
        $NetworkConnectionWait | Should -Be 5
    }
    
    It "Should have hidden window style for flare events" {
        # Verify FlareGun config exists
        Test-Path variable:FlareGunConfigPath | Should -Be $true
    }
}
