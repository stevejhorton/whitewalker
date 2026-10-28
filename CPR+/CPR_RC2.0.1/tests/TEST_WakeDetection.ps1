# Test-WakeDetection.ps1
# Quick verification script for WhiteWalker v3.13.1_ER1 wake detection

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "WhiteWalker Wake Detection Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check if wake events exist
Write-Host "[Test 1] Checking for Kernel-Power wake events in last hour..." -ForegroundColor Yellow

try {
    $wakeEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-Power'
        Id = 566, 507
        StartTime = (Get-Date).AddHours(-1)
    } -ErrorAction Stop
    
    if ($wakeEvents) {
        Write-Host "[PASS] Found $($wakeEvents.Count) wake event(s)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Recent wake events:" -ForegroundColor Cyan
        $wakeEvents | Select-Object -First 5 | ForEach-Object {
            $timeSince = ((Get-Date) - $_.TimeCreated).TotalSeconds
            Write-Host "  - Event $($_.Id) at $($_.TimeCreated) ($([math]::Round($timeSince))s ago)" -ForegroundColor White
            Write-Host "    Message: $($_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)))" -ForegroundColor Gray
        }
    } else {
        Write-Host "[FAIL] No wake events found in last hour" -ForegroundColor Red
        Write-Host "  Put device to sleep and wake it, then run this test again" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Could not query wake events" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# Test 2: Show all Kernel-Power events to help debugging
Write-Host "[Test 2] All Kernel-Power events in last hour (by frequency)..." -ForegroundColor Yellow
Write-Host ""

try {
    $allEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-Power'
        StartTime = (Get-Date).AddHours(-1)
    } -ErrorAction Stop
    
    $grouped = $allEvents | Group-Object Id | Sort-Object Count -Descending
    
    Write-Host "Event ID breakdown:" -ForegroundColor Cyan
    foreach ($group in $grouped) {
        $sample = $group.Group[0]
        Write-Host "  Event $($group.Name): $($group.Count) occurrences" -ForegroundColor White
        Write-Host "    Sample: $($sample.Message.Substring(0, [Math]::Min(80, $sample.Message.Length)))" -ForegroundColor Gray
    }
    
} catch {
    Write-Host "No Kernel-Power events found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# Test 3: Simulate wake detection function
Write-Host "[Test 3] Simulating WhiteWalker wake detection logic..." -ForegroundColor Yellow
Write-Host ""

$timeWindow = 120 # 2 minutes
try {
    $wakeEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-Power'
        Id = 566, 507
        StartTime = (Get-Date).AddSeconds(-$timeWindow)
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    
    if ($wakeEvents) {
        $timeSince = ((Get-Date) - $wakeEvents[0].TimeCreated).TotalSeconds
        Write-Host "[PASS] Recent wake detected" -ForegroundColor Green
        Write-Host "  Time since wake: $([math]::Round($timeSince))s" -ForegroundColor White
        Write-Host "  Event ID: $($wakeEvents[0].Id)" -ForegroundColor White
        Write-Host "  Timestamp: $($wakeEvents[0].TimeCreated)" -ForegroundColor White
        Write-Host ""
        Write-Host "WhiteWalker would detect this as a wake event and disconnect VPN if needed" -ForegroundColor Green
    } else {
        Write-Host "[INFO] No wake event in last $timeWindow seconds" -ForegroundColor Yellow
        Write-Host "  This is NORMAL if device hasn't woken recently" -ForegroundColor Gray
        Write-Host "  To test: Put device to sleep, wake it, and run this script immediately" -ForegroundColor Gray
    }
} catch {
    Write-Host "[ERROR] Could not check for wake events" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# Test 4: Network connection status
Write-Host "[Test 4] Current network connection status..." -ForegroundColor Yellow
Write-Host ""

try {
    $adapter = Get-NetAdapter | Where-Object { 
        $_.Status -eq 'Up' -and 
        $_.Virtual -eq $false -and
        $_.InterfaceDescription -notmatch 'Cisco|VPN|TAP|Virtual'
    } | Select-Object -First 1
    
    if ($adapter) {
        Write-Host "[OK] Active adapter found: $($adapter.Name)" -ForegroundColor Green
        
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
        
        if ($ipConfig -and $ipConfig.IPv4Address) {
            $ip = $ipConfig.IPv4Address.IPAddress
            Write-Host "[OK] IP Address: $ip" -ForegroundColor Green
            Write-Host ""
            Write-Host "WhiteWalker would proceed normally (no connection retry needed)" -ForegroundColor Green
        } else {
            Write-Host "[WARN] No IP address assigned" -ForegroundColor Yellow
            Write-Host "  This would trigger connection retry logic (10s wait)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[WARN] No active physical network adapter" -ForegroundColor Yellow
        Write-Host "  This would trigger connection retry logic (10s wait)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Could not check network status" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "- Wake detection uses Event IDs 566 and 507" -ForegroundColor White
Write-Host "- Time window: 120 seconds (2 minutes)" -ForegroundColor White
Write-Host "- Connection retry: 2 attempts x 5 seconds = 10s total" -ForegroundColor White
Write-Host ""
