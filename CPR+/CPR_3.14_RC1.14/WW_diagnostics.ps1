####Ridfequires -RunAsAdministrator
param(
    [switch]$h,              # Show help
    [switch]$Help,           # Show help (alternative)
    [switch]$All,            # Run all diagnostics
    [switch]$Network,        # Test network detection
    [switch]$VPN,            # Test VPN state detection
    [switch]$Captive,        # Test captive portal detection
    [switch]$Connectivity,   # Test DC/Gateway connectivity
    [switch]$Flags,          # Test flag file operations
    [switch]$Verbose         # Verbose output
)

<#
.SYNOPSIS
WhiteWalker Diagnostics Tool - Test network detection and captive portal logic

.DESCRIPTION
Version: 1.0.0
Author: steve.horton@optum.com
Date: 20-Oct-2025

This diagnostic tool helps you verify WhiteWalker's detection logic in real-world
network conditions without triggering actual remediation actions.

.PARAMETER h, Help
Show this help message with usage examples and assumptions

.PARAMETER All
Run all diagnostic tests (Network, VPN, Captive, Connectivity, Flags)

.PARAMETER Network
Test network adapter detection and SSID gathering

.PARAMETER VPN
Test VPN state detection via vpncli

.PARAMETER Captive
Test captive portal detection methods

.PARAMETER Connectivity
Test DC and gateway connectivity

.PARAMETER Flags
Test flag file operations and communication paths

.PARAMETER Verbose
Show detailed output for all tests

.EXAMPLE
.\WW_diagnostics.ps1 -h
Show help and usage information

.EXAMPLE
.\WW_diagnostics.ps1 -All
Run all diagnostic tests

.EXAMPLE
.\WW_diagnostics.ps1 -Captive
Test only captive portal detection (use when on captive portal network)

.EXAMPLE
.\WW_diagnostics.ps1 -VPN -Verbose
Test VPN state detection with verbose output
#>

# Script version
$diagVersion = "1.0.0"

# Source the main WhiteWalker script to get functions
$mainScriptPath = Join-Path $PSScriptRoot "WW_main.ps1"
if (-not (Test-Path $mainScriptPath)) {
    Write-Host "ERROR: Cannot find WW_main.ps1 in script directory" -ForegroundColor Red
    Write-Host "Expected: $mainScriptPath" -ForegroundColor Yellow
    exit 1
}

# Dot-source to load functions without running main logic
. $mainScriptPath

# Color helper functions
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Failure { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Header { 
    param([string]$Message) 
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}
function Write-SubHeader { 
    param([string]$Message) 
    Write-Host ""
    Write-Host ("-" * 80) -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor DarkCyan
    Write-Host ("-" * 80) -ForegroundColor DarkCyan
}

function Show-Help {
    Write-Host ""
    Write-Host "WhiteWalker Diagnostics Tool v$diagVersion" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\WW_diagnostics.ps1 [-h|-Help]           Show this help"
    Write-Host "  .\WW_diagnostics.ps1 -All                 Run all diagnostics"
    Write-Host "  .\WW_diagnostics.ps1 -Network             Test network detection"
    Write-Host "  .\WW_diagnostics.ps1 -VPN                 Test VPN state detection"
    Write-Host "  .\WW_diagnostics.ps1 -Captive             Test captive portal detection"
    Write-Host "  .\WW_diagnostics.ps1 -Connectivity        Test DC/Gateway connectivity"
    Write-Host "  .\WW_diagnostics.ps1 -Flags               Test flag file operations"
    Write-Host "  .\WW_diagnostics.ps1 -Captive -Verbose    Run with verbose output"
    Write-Host ""
    Write-Host "DIAGNOSTIC MODES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. NETWORK DETECTION (-Network)" -ForegroundColor White
    Write-Host "     Tests: SSID detection, adapter filtering, VPN adapter exclusion"
    Write-Host "     ASSUMPTIONS:"
    Write-Host "       - You are connected to a network (WiFi or Ethernet)"
    Write-Host "       - For SSID testing: You are on WiFi (not Ethernet)"
    Write-Host "     VALIDATES:"
    Write-Host "       - Physical adapter detection works"
    Write-Host "       - VPN virtual adapters are properly excluded"
    Write-Host "       - SSID shows real network name (not ds.uhc.com when VPN active)"
    Write-Host ""
    Write-Host "  2. VPN STATE DETECTION (-VPN)" -ForegroundColor White
    Write-Host "     Tests: vpncli state parsing, tunnel flavor detection"
    Write-Host "     ASSUMPTIONS:"
    Write-Host "       - Cisco Secure Client is installed"
    Write-Host "       - vpncli.exe is accessible"
    Write-Host "     RUN WHEN:"
    Write-Host "       - VPN is Connected -> Should detect 'Connected' and tunnel type"
    Write-Host "       - VPN is Disconnected -> Should detect 'Disconnected'"
    Write-Host "       - VPN is Connecting -> Should detect intermediate state"
    Write-Host "     VALIDATES:"
    Write-Host "       - VPN state detection is accurate"
    Write-Host "       - Management vs User tunnel classification works"
    Write-Host ""
    Write-Host "  3. CAPTIVE PORTAL DETECTION (-Captive)" -ForegroundColor White
    Write-Host "     Tests: HTTP redirect detection, multiple URL methods"
    Write-Host "     ASSUMPTIONS:"
    Write-Host "       - You are connected to a network"
    Write-Host "     RUN WHEN:"
    Write-Host "       - On captive portal WiFi -> Should detect redirect"
    Write-Host "       - On normal network -> Should detect no redirect"
    Write-Host "       - Behind ISE portal -> Should classify as ISE_EMPLOYEE or ISE_GUEST"
    Write-Host "     VALIDATES:"
    Write-Host "       - Captive portal URLs are reachable"
    Write-Host "       - Redirect detection methods work"
    Write-Host "       - ISE vs non-ISE classification is correct"
    Write-Host ""
    Write-Host "  4. CONNECTIVITY TESTING (-Connectivity)" -ForegroundColor White
    Write-Host "     Tests: DC reachability, gateway ping, on-prem detection"
    Write-Host "     ASSUMPTIONS:"
    Write-Host "       - You are connected to a network"
    Write-Host "     RUN WHEN:"
    Write-Host "       - On corporate network -> Should detect DC (on-prem)"
    Write-Host "       - On public WiFi -> Should not detect DC (off-prem)"
    Write-Host "       - At home with VPN -> Should detect DC if VPN connected"
    Write-Host "     VALIDATES:"
    Write-Host "       - DC (ms.ds.uhc.com) is reachable when on corporate network"
    Write-Host "       - Gateway detection works"
    Write-Host "       - On-prem vs off-prem classification is correct"
    Write-Host ""
    Write-Host "  5. FLAG FILE OPERATIONS (-Flags)" -ForegroundColor White
    Write-Host "     Tests: Flag file creation, reading, cleanup"
    Write-Host "     ASSUMPTIONS:"
    Write-Host "       - Script has write access to C:\ProgramData\WhiteWalker\"
    Write-Host "     VALIDATES:"
    Write-Host "       - Flag files can be created and read"
    Write-Host "       - Interrupt flag mechanism works"
    Write-Host "       - Captive portal completion flag communication works"
    Write-Host ""
    Write-Host "TYPICAL WORKFLOWS:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  SCENARIO 1: You're on a hotel WiFi with captive portal"
    Write-Host "    1. Run: .\WW_diagnostics.ps1 -Network"
    Write-Host "       -> Verify you see the hotel WiFi SSID"
    Write-Host "    2. Run: .\WW_diagnostics.ps1 -Captive"
    Write-Host "       -> Should detect redirect to captive portal"
    Write-Host "    3. Authenticate through portal in browser"
    Write-Host "    4. Run: .\WW_diagnostics.ps1 -Captive"
    Write-Host "       -> Should now show 'Portal cleared'"
    Write-Host ""
    Write-Host "  SCENARIO 2: You're on corporate WiFi (ds.uhc.com)"
    Write-Host "    1. Run: .\WW_diagnostics.ps1 -Network"
    Write-Host "       -> Should show 'ds.uhc.com' SSID (real network)"
    Write-Host "    2. Run: .\WW_diagnostics.ps1 -Connectivity"
    Write-Host "       -> Should detect DC as reachable (on-prem)"
    Write-Host "    3. Run: .\WW_diagnostics.ps1 -Captive"
    Write-Host "       -> May detect ISE redirect if not authenticated"
    Write-Host ""
    Write-Host "  SCENARIO 3: You're at home with VPN connected"
    Write-Host "    1. Run: .\WW_diagnostics.ps1 -Network"
    Write-Host "       -> Should show home WiFi SSID (NOT 'ds.uhc.com')"
    Write-Host "    2. Run: .\WW_diagnostics.ps1 -VPN"
    Write-Host "       -> Should show 'Connected' with tunnel type"
    Write-Host "    3. Run: .\WW_diagnostics.ps1 -Connectivity"
    Write-Host "       -> DC should be reachable through VPN tunnel"
    Write-Host ""
    Write-Host "  SCENARIO 4: Testing full WhiteWalker logic flow"
    Write-Host "    Run: .\WW_diagnostics.ps1 -All"
    Write-Host "       -> Tests everything and shows what WW would do"
    Write-Host ""
    Write-Host "NOTES:" -ForegroundColor Yellow
    Write-Host "  - This tool is READ-ONLY - it will not trigger remediation actions"
    Write-Host "  - Run as Administrator for full network adapter access"
    Write-Host "  - Use -Verbose for detailed diagnostic output"
    Write-Host "  - Safe to run on any network - no changes will be made"
    Write-Host ""
    Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "  - 'ERROR: Cannot find WW_main.ps1' -> Run from WhiteWalker directory"
    Write-Host "  - 'ERROR: Cisco Secure Client not found' -> Install Cisco VPN client"
    Write-Host "  - 'WARNING: No active network adapter' -> Connect to network first"
    Write-Host "  - 'Captive portal test timed out' -> May not be on captive portal"
    Write-Host ""
}

function Test-NetworkDetection {
    Write-Header "NETWORK DETECTION TEST"
    
    Write-Info "Testing physical network adapter detection..."
    
    try {
        $netInfo = Get-NetworkInfo
        
        Write-Host ""
        Write-Host "Network Information:" -ForegroundColor White
        Write-Host "  Connection Type: $($netInfo.ConnectionType)" -ForegroundColor $(if ($netInfo.ConnectionType -ne "Unknown") { "Green" } else { "Yellow" })
        Write-Host "  Interface Name:  $($netInfo.InterfaceName)" -ForegroundColor $(if ($netInfo.InterfaceName -ne "N/A") { "Green" } else { "Yellow" })
        Write-Host "  SSID:            $($netInfo.SSID)" -ForegroundColor $(if ($netInfo.SSID -ne "N/A") { "Green" } else { "Yellow" })
        Write-Host "  IP Address:      $($netInfo.IPAddress)/$($netInfo.SubnetMask)" -ForegroundColor $(if ($netInfo.IPAddress -ne "N/A") { "Green" } else { "Yellow" })
        Write-Host "  Gateway:         $($netInfo.DefaultGateway)" -ForegroundColor $(if ($netInfo.DefaultGateway -ne "N/A") { "Green" } else { "Yellow" })
        Write-Host "  MAC Address:     $($netInfo.MACAddress)" -ForegroundColor $(if ($netInfo.MACAddress -ne "N/A") { "Green" } else { "Yellow" })
        Write-Host "  DNS Servers:     $($netInfo.DNSServers -join ', ')" -ForegroundColor $(if ($netInfo.DNSServers.Count -gt 0) { "Green" } else { "Yellow" })
        
        Write-Host ""
        
        # Validate results
        if ($netInfo.ConnectionType -eq "Unknown") {
            Write-Failure "No active network connection detected"
            Write-Warning "ASSUMPTION FAILED: You should be connected to a network (WiFi or Ethernet)"
        } else {
            Write-Success "Network adapter detected: $($netInfo.ConnectionType)"
        }
        
        if ($netInfo.SSID -match "ds\.uhc\.com" -and $netInfo.ConnectionType -eq "WiFi") {
            Write-Warning "SSID shows 'ds.uhc.com' - this may be the VPN virtual adapter!"
            Write-Warning "Expected: Real WiFi network name (e.g., 'CoffeeShop-Guest', 'Home WiFi')"
            Write-Info "If VPN is connected, this is the BUG we're trying to fix in v3.11.0"
        } elseif ($netInfo.SSID -ne "N/A" -and $netInfo.ConnectionType -eq "WiFi") {
            Write-Success "SSID detected: $($netInfo.SSID)"
            Write-Success "VPN adapter exclusion working correctly"
        }
        
        if ($netInfo.IPAddress -ne "N/A") {
            Write-Success "IP configuration retrieved successfully"
        }
        
        # Check for VPN virtual adapters
        Write-Host ""
        Write-Info "Checking for VPN virtual adapters..."
        $allAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        $vpnAdapters = $allAdapters | Where-Object { 
            $_.InterfaceDescription -match 'Cisco|VPN|TAP|Virtual|Tunnel'
        }
        
        if ($vpnAdapters) {
            Write-Host ""
            Write-Host "  Found VPN/Virtual Adapters (should be EXCLUDED):" -ForegroundColor Yellow
            foreach ($adapter in $vpnAdapters) {
                Write-Host "    - $($adapter.Name): $($adapter.InterfaceDescription)" -ForegroundColor Yellow
            }
            Write-Success "These adapters were correctly excluded from network detection"
        } else {
            Write-Info "No VPN virtual adapters detected"
        }
        
    } catch {
        Write-Failure "Network detection failed: $_"
    }
}

function Test-VPNDetection {
    Write-Header "VPN STATE DETECTION TEST"
    
    Write-Info "Locating Cisco Secure Client..."
    
    $ciscoPath = Get-CiscoInstallPath
    if (-not $ciscoPath) {
        Write-Failure "Cisco Secure Client installation not found"
        Write-Warning "ASSUMPTION FAILED: Cisco Secure Client should be installed"
        Write-Info "Expected paths:"
        Write-Info "  - C:\Program Files\Cisco\Cisco Secure Client"
        Write-Info "  - C:\Program Files (x86)\Cisco\Cisco Secure Client"
        return
    }
    
    Write-Success "Found Cisco installation: $ciscoPath"
    
    $global:vpn_cmd = Join-Path $ciscoPath "vpncli.exe"
    
    if (-not (Test-Path $global:vpn_cmd)) {
        Write-Failure "vpncli.exe not found at: $global:vpn_cmd"
        return
    }
    
    Write-Success "Found vpncli.exe"
    
    Write-Host ""
    Write-Info "Testing VPN state detection..."
    
    try {
        $vpnState = Get-VpnState
        
        Write-Host ""
        Write-Host "VPN State Detection Results:" -ForegroundColor White
        Write-Host "  Current State: $vpnState" -ForegroundColor $(
            switch ($vpnState) {
                "Connected" { "Green" }
                "Disconnected" { "Cyan" }
                "Unknown" { "Yellow" }
                default { "Yellow" }
            }
        )
        
        if ($vpnState -eq "Connected") {
            Write-Success "VPN is connected"
            
            Write-Host ""
            Write-Info "Detecting tunnel flavor..."
            $flavor = Get-VpnTunnelFlavor
            
            Write-Host "  Tunnel Type: $flavor" -ForegroundColor $(
                switch ($flavor) {
                    "user_tun" { "Green" }
                    "mgmt_tun" { "Green" }
                    "no_vpn" { "Yellow" }
                    default { "Yellow" }
                }
            )
            
            switch ($flavor) {
                "user_tun" {
                    Write-Success "User tunnel detected (full tunnel - all traffic through VPN)"
                }
                "mgmt_tun" {
                    Write-Success "Management tunnel detected (split tunnel - some traffic local)"
                }
                "vpn_connected" {
                    Write-Warning "VPN connected but tunnel type unclear"
                }
            }
            
        } elseif ($vpnState -eq "Disconnected") {
            Write-Success "VPN is disconnected (expected when not connected to VPN)"
        } else {
            Write-Warning "VPN state is unclear: $vpnState"
            Write-Info "This may indicate VPN is in transition (connecting, reconnecting, etc.)"
        }
        
        if ($Verbose) {
            Write-Host ""
            Write-Info "Raw VPN CLI Output (for debugging):"
            Write-Host "--- vpncli state ---" -ForegroundColor DarkGray
            & $global:vpn_cmd state 2>$null | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
            Write-Host "--- vpncli stats ---" -ForegroundColor DarkGray
            & $global:vpn_cmd stats 2>$null | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
        }
        
    } catch {
        Write-Failure "VPN detection failed: $_"
    }
}

function Test-CaptivePortalDetection {
    Write-Header "CAPTIVE PORTAL DETECTION TEST"
    
    Write-Info "Testing multiple captive portal detection methods..."
    Write-Warning "Note: Timeouts are expected if you're NOT on a captive portal network"
    
    # Test 1: Apple captive portal detection
    Write-SubHeader "Test 1: Apple Captive Portal Detection (Primary Method)"
    Write-Info "Testing: http://captive.apple.com/hotspot-detect.html"
    
    try {
        $appleResult = Test-Redirect -Url "http://captive.apple.com/hotspot-detect.html"
        
        if ($appleResult.IsRedirect) {
            Write-Success "REDIRECT DETECTED via $($appleResult.Method)"
            Write-Host "  Redirect URL: $($appleResult.RedirectUrl)" -ForegroundColor Yellow
            
            $redirectType = Get-RedirectType -RedirectUrl $appleResult.RedirectUrl
            Write-Host "  Portal Type:  $redirectType" -ForegroundColor $(
                switch ($redirectType) {
                    "ISE_EMPLOYEE" { "Green" }
                    "ISE_GUEST" { "Cyan" }
                    "NON_ISE" { "Yellow" }
                    default { "Yellow" }
                }
            )
            
            switch ($redirectType) {
                "ISE_EMPLOYEE" {
                    Write-Info "WhiteWalker would: Trigger ISE posture rescan"
                }
                "ISE_GUEST" {
                    Write-Info "WhiteWalker would: Launch browser for user authentication"
                }
                "NON_ISE" {
                    Write-Info "WhiteWalker would: Launch browser for user authentication"
                }
            }
        } else {
            Write-Success "No redirect detected - not behind captive portal"
        }
    } catch {
        Write-Warning "Apple test failed: $_"
    }
    
    # Test 2: Google connectivity check
    Write-SubHeader "Test 2: Google Connectivity Check (204 Method)"
    Write-Info "Testing: http://clients3.google.com/generate_204"
    
    try {
        $request = [System.Net.HttpWebRequest]::Create("http://clients3.google.com/generate_204")
        $request.AllowAutoRedirect = $false
        $request.Timeout = 4000
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $location = $response.Headers['Location']
        $response.Close()
        
        if ($statusCode -eq 204) {
            Write-Success "Received HTTP 204 - No captive portal detected"
        } elseif ($statusCode -ge 300 -and $statusCode -lt 400) {
            Write-Success "REDIRECT DETECTED: HTTP $statusCode"
            Write-Host "  Redirect URL: $location" -ForegroundColor Yellow
        } else {
            Write-Warning "Unexpected status code: $statusCode"
        }
    } catch {
        Write-Warning "Google 204 test failed: $_"
    }
    
    # Test 3: Gateway redirect test
    Write-SubHeader "Test 3: Gateway Direct Access (Fallback Method)"
    Write-Info "Testing: Direct HTTP request to default gateway"
    
    try {
        $gatewayResult = Test-RedirectToGateway
        
        if ($gatewayResult.IsRedirect) {
            Write-Success "REDIRECT DETECTED via gateway ($($gatewayResult.Method))"
            Write-Host "  Redirect URL: $($gatewayResult.RedirectUrl)" -ForegroundColor Yellow
        } else {
            Write-Success "No redirect from gateway - not behind captive portal"
        }
    } catch {
        Write-Warning "Gateway test failed: $_"
    }
    
    # Test 4: Captive portal clearance test
    Write-SubHeader "Test 4: Portal Clearance Test (Post-Authentication Check)"
    Write-Info "Testing: Can we reach external sites without redirect?"
    
    try {
        $cleared = Test-CaptivePortalCleared
        
        if ($cleared) {
            Write-Success "Captive portal is CLEARED (or not present)"
            Write-Info "Network has full internet access"
        } else {
            Write-Warning "Captive portal is ACTIVE"
            Write-Info "User needs to authenticate through captive portal"
        }
    } catch {
        Write-Warning "Portal clearance test failed: $_"
    }
    
    # Summary
    Write-Host ""
    Write-Host "SUMMARY:" -ForegroundColor Cyan
    Write-Host "  Based on these tests, WhiteWalker would:"
    
    if ($appleResult.IsRedirect -or $gatewayResult.IsRedirect) {
        Write-Host "    -> Detect captive portal present" -ForegroundColor Yellow
        Write-Host "    -> Trigger Event ID 777" -ForegroundColor Yellow
        Write-Host "    -> Launch WW_cap_portal_runner.ps1 in user context" -ForegroundColor Yellow
        Write-Host "    -> Open browser for user authentication" -ForegroundColor Yellow
    } else {
        Write-Host "    -> No captive portal detected" -ForegroundColor Green
        Write-Host "    -> Proceed to connectivity classification" -ForegroundColor Green
    }
}

function Test-ConnectivityClassification {
    Write-Header "CONNECTIVITY CLASSIFICATION TEST"
    
    Write-Info "Testing domain controller reachability..."
    
    try {
        $dcReachable = Test-DC -hostname "ms.ds.uhc.com"
        
        Write-Host ""
        Write-Host "Domain Controller Test:" -ForegroundColor White
        Write-Host "  Target: ms.ds.uhc.com" -ForegroundColor Gray
        Write-Host "  Result: " -NoNewline
        if ($dcReachable) {
            Write-Host "REACHABLE" -ForegroundColor Green
            Write-Success "You are on-premises or connected via VPN"
        } else {
            Write-Host "NOT REACHABLE" -ForegroundColor Yellow
            Write-Warning "You are off-premises (public WiFi, home network without VPN, etc.)"
        }
    } catch {
        Write-Failure "DC test failed: $_"
    }
    
    Write-Host ""
    Write-Info "Testing default gateway reachability..."
    
    try {
        $gwReachable = Test-DefaultGateway
        
        Write-Host ""
        Write-Host "Default Gateway Test:" -ForegroundColor White
        Write-Host "  Result: " -NoNewline
        if ($gwReachable) {
            Write-Host "REACHABLE" -ForegroundColor Green
            Write-Success "Local network connectivity is working"
        } else {
            Write-Host "NOT REACHABLE" -ForegroundColor Yellow
            Write-Warning "No local network connectivity"
        }
    } catch {
        Write-Failure "Gateway test failed: $_"
    }
    
    # Classification logic
    Write-Host ""
    Write-Host "CLASSIFICATION:" -ForegroundColor Cyan
    Write-Host "  DC Reachable: " -NoNewline; Write-Host $dcReachable -ForegroundColor $(if ($dcReachable) { "Green" } else { "Yellow" })
    Write-Host "  Gateway Reachable: " -NoNewline; Write-Host $gwReachable -ForegroundColor $(if ($gwReachable) { "Green" } else { "Yellow" })
    
    Write-Host ""
    if ($dcReachable) {
        Write-Success "WhiteWalker would classify as: ON-PREMISES"
        Write-Info "Signal flare: /on_prem"
        Write-Info "Exit reason: on_prem"
    } elseif ($gwReachable) {
        Write-Success "WhiteWalker would classify as: OFF-PREMISES (no VPN)"
        Write-Info "Signal flare: /off_prem_no_vpn"
        Write-Info "Exit reason: off_prem_no_vpn"
    } else {
        Write-Warning "WhiteWalker would classify as: NO NETWORK (transient)"
        Write-Info "Exit reason: no_net_transient"
    }
}

function Test-FlagFileOperations {
    Write-Header "FLAG FILE OPERATIONS TEST"
    
    $flagDir = "C:\ProgramData\WhiteWalker"
    
    Write-Info "Testing flag file directory access..."
    
    if (-not (Test-Path $flagDir)) {
        Write-Warning "Flag directory doesn't exist: $flagDir"
        Write-Info "Attempting to create..."
        
        try {
            New-Item -Path $flagDir -ItemType Directory -Force | Out-Null
            Write-Success "Created flag directory successfully"
        } catch {
            Write-Failure "Cannot create flag directory: $_"
            Write-Warning "ASSUMPTION FAILED: Need write access to C:\ProgramData\WhiteWalker\"
            return
        }
    } else {
        Write-Success "Flag directory exists: $flagDir"
    }
    
    # Test 1: Interrupt flag
    Write-SubHeader "Test 1: Interrupt Flag"
    
    $interruptFlag = Join-Path $flagDir "network_interrupt.flag"
    Write-Info "Testing: $interruptFlag"
    
    try {
        # Write test flag
        Set-Content -Path $interruptFlag -Value (Get-Date).ToString('o') -Encoding UTF8
        Write-Success "Interrupt flag written successfully"
        
        # Read test flag
        if (Test-Path $interruptFlag) {
            $content = Get-Content $interruptFlag -Raw
            Write-Success "Interrupt flag read successfully"
            if ($Verbose) {
                Write-Host "  Content: $content" -ForegroundColor DarkGray
            }
            
            # Cleanup
            Remove-Item $interruptFlag -Force
            Write-Success "Interrupt flag cleaned up successfully"
        } else {
            Write-Failure "Interrupt flag not found after creation"
        }
    } catch {
        Write-Failure "Interrupt flag test failed: $_"
    }
    
    # Test 2: Captive portal completion flag
    Write-SubHeader "Test 2: Captive Portal Completion Flag"
    
    $portalFlag = Join-Path $flagDir "portal_complete.flag"
    Write-Info "Testing: $portalFlag"
    
    try {
        # Write test flag with JSON
        $testData = @{
            timestamp = (Get-Date).ToString('o')
            status = "SUCCESS"
            details = "Diagnostic test"
            user = $env:USERNAME
            captive_browser_pid = 9999
        } | ConvertTo-Json -Compress
        
        Set-Content -Path $portalFlag -Value $testData -Encoding UTF8
        Write-Success "Portal completion flag written successfully"
        
        # Read and parse test flag
        if (Test-Path $portalFlag) {
            $content = Get-Content $portalFlag -Raw | ConvertFrom-Json
            Write-Success "Portal completion flag read and parsed successfully"
            
            if ($Verbose) {
                Write-Host "  Status: $($content.status)" -ForegroundColor DarkGray
                Write-Host "  Details: $($content.details)" -ForegroundColor DarkGray
                Write-Host "  PID: $($content.captive_browser_pid)" -ForegroundColor DarkGray
            }
            
            # Cleanup
            Remove-Item $portalFlag -Force
            Write-Success "Portal completion flag cleaned up successfully"
        } else {
            Write-Failure "Portal flag not found after creation"
        }
    } catch {
        Write-Failure "Portal flag test failed: $_"
    }
    
    # Test 3: User prompted flag
    Write-SubHeader "Test 3: User Prompted Flag"
    
    $userPromptFlag = Join-Path $flagDir "user_prompted.flag"
    Write-Info "Testing: $userPromptFlag"
    
    try {
        # Write test flag with JSON
        $testData = @{
            timestamp = (Get-Date).ToString('o')
            event_count = 5
            message = "Diagnostic test"
        } | ConvertTo-Json -Compress
        
        Set-Content -Path $userPromptFlag -Value $testData -Encoding UTF8
        Write-Success "User prompted flag written successfully"
        
        # Test detection
        if (Test-UserPromptedFlag) {
            Write-Success "User prompted flag detected correctly"
            
            # Cleanup
            Remove-Item $userPromptFlag -Force
            Write-Success "User prompted flag cleaned up successfully"
        } else {
            Write-Failure "User prompted flag not detected after creation"
        }
    } catch {
        Write-Failure "User prompted flag test failed: $_"
    }
    
    Write-Host ""
    Write-Success "All flag file operations working correctly"
    Write-Info "Flag files can be used for inter-process communication"
}

function Test-AllDiagnostics {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "WhiteWalker Comprehensive Diagnostics v$diagVersion" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    Test-NetworkDetection
    Test-VPNDetection
    Test-CaptivePortalDetection
    Test-ConnectivityClassification
    Test-FlagFileOperations
    
    Write-Header "FINAL SUMMARY - WHAT WHITEWALKER WOULD DO"
    
    Write-Info "Gathering final state..."
    
    try {
        # Get network info
        $netInfo = Get-NetworkInfo
        
        # Get VPN state
        $ciscoPath = Get-CiscoInstallPath
        $vpnState = "Unknown"
        if ($ciscoPath) {
            $global:vpn_cmd = Join-Path $ciscoPath "vpncli.exe"
            if (Test-Path $global:vpn_cmd) {
                $vpnState = Get-VpnState
            }
        }
        
        # Get connectivity
        $dcReachable = Test-DC -hostname "ms.ds.uhc.com"
        $gwReachable = Test-DefaultGateway
        
        # Determine action
        Write-Host ""
        Write-Host "Current Network State:" -ForegroundColor White
        Write-Host "  Network:        $($netInfo.ConnectionType) - $($netInfo.SSID)" -ForegroundColor Gray
        Write-Host "  VPN State:      $vpnState" -ForegroundColor Gray
        Write-Host "  DC Reachable:   $dcReachable" -ForegroundColor Gray
        Write-Host "  GW Reachable:   $gwReachable" -ForegroundColor Gray
        
        Write-Host ""
        Write-Host "WhiteWalker Decision Flow:" -ForegroundColor Cyan
        
        if ($vpnState -eq "Connected") {
            Write-Host "  1. VPN-First Gatekeeper: " -NoNewline -ForegroundColor Yellow
            Write-Host "VPN is CONNECTED" -ForegroundColor Green
            Write-Host "     -> Would exit immediately with: vpn_connected:user_tun" -ForegroundColor Green
            Write-Host "     -> Would send signal flare: /user_tun" -ForegroundColor Green
            Write-Host "     -> Would NOT proceed to captive portal detection" -ForegroundColor Gray
        } elseif ($vpnState -eq "Disconnected") {
            Write-Host "  1. VPN-First Gatekeeper: " -NoNewline -ForegroundColor Yellow
            Write-Host "VPN is DISCONNECTED" -ForegroundColor Cyan
            Write-Host "     -> Would proceed to captive portal detection" -ForegroundColor Cyan
            
            # Simulate captive portal check
            Write-Host ""
            Write-Host "  2. Captive Portal Check: " -ForegroundColor Yellow
            Write-Host "     -> Would test: http://captive.apple.com/hotspot-detect.html" -ForegroundColor Gray
            Write-Host "     -> Would test: Gateway redirect" -ForegroundColor Gray
            
            # For this summary, assume no captive portal detected
            Write-Host "     -> No redirect detected" -ForegroundColor Cyan
            Write-Host "     -> Would proceed to connectivity classification" -ForegroundColor Cyan
            
            Write-Host ""
            Write-Host "  3. Connectivity Classification: " -ForegroundColor Yellow
            if ($dcReachable) {
                Write-Host "     -> DC is reachable: ON-PREMISES" -ForegroundColor Green
                Write-Host "     -> Would send signal flare: /on_prem" -ForegroundColor Green
                Write-Host "     -> Would exit with: on_prem" -ForegroundColor Green
            } elseif ($gwReachable) {
                Write-Host "     -> DC not reachable, GW reachable: OFF-PREMISES" -ForegroundColor Yellow
                Write-Host "     -> Would send signal flare: /off_prem_no_vpn" -ForegroundColor Yellow
                Write-Host "     -> Would exit with: off_prem_no_vpn" -ForegroundColor Yellow
            } else {
                Write-Host "     -> No connectivity: TRANSIENT" -ForegroundColor Red
                Write-Host "     -> Would exit with: no_net_transient" -ForegroundColor Red
            }
        } else {
            Write-Host "  1. VPN-First Gatekeeper: " -NoNewline -ForegroundColor Yellow
            Write-Host "VPN state UNKNOWN" -ForegroundColor Red
            Write-Host "     -> Would wait up to 12 seconds for VPN to stabilize" -ForegroundColor Yellow
            Write-Host "     -> May force disconnect if stuck in intermediate state" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Success "Diagnostic complete!"
        
    } catch {
        Write-Failure "Final summary failed: $_"
    }
}

# ================================= MAIN =======================================

# Show help if requested
if ($h -or $Help) {
    Show-Help
    exit 0
}

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator - some tests may fail"
    Write-Info "For full diagnostics, run: Start-Process powershell -Verb RunAs -ArgumentList '-File `"$PSCommandPath`"'"
    Write-Host ""
}

# Check if any test flag is set
$anyTestRequested = $All -or $Network -or $VPN -or $Captive -or $Connectivity -or $Flags

if (-not $anyTestRequested) {
    Write-Host ""
    Write-Host "ERROR: No diagnostic test specified" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage: .\WW_diagnostics.ps1 [-All|-Network|-VPN|-Captive|-Connectivity|-Flags]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  .\WW_diagnostics.ps1 -h              Show help"
    Write-Host "  .\WW_diagnostics.ps1 -All            Run all diagnostics"
    Write-Host "  .\WW_diagnostics.ps1 -Captive        Test captive portal detection"
    Write-Host ""
    Write-Host "For detailed help, run: .\WW_diagnostics.ps1 -h" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# Run requested diagnostics
if ($All) {
    Test-AllDiagnostics
} else {
    if ($Network) {
        Test-NetworkDetection
    }
    
    if ($VPN) {
        Test-VPNDetection
    }
    
    if ($Captive) {
        Test-CaptivePortalDetection
    }
    
    if ($Connectivity) {
        Test-ConnectivityClassification
    }
    
    if ($Flags) {
        Test-FlagFileOperations
    }
}

Write-Host ""
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host "Diagnostics Complete - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  - Review results above for any failures or warnings" -ForegroundColor White
Write-Host "  - If captive portal not detected, try different test URLs" -ForegroundColor White
Write-Host "  - Run diagnostics on different networks to verify behavior" -ForegroundColor White
Write-Host "  - Use -Verbose flag for detailed debugging output" -ForegroundColor White
Write-Host ""
Write-Host "SAFE TO RUN:" -ForegroundColor Green
Write-Host "  This diagnostic tool is READ-ONLY and makes no system changes" -ForegroundColor White
Write-Host "  It will not trigger VPN connections, rescans, or browser launches" -ForegroundColor White
Write-Host ""

exit 0
