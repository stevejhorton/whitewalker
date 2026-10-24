# WhiteWalker v3.13.1_ER1 - Test Coverage Summary

## Files Delivered
1. **Test-WakeDetection.ps1** - Fixed (ASCII-only, no Unicode issues)
2. **WW_Tests_Enhanced.ps1** - New comprehensive test suite

## Issues Fixed

### 1. Test-WakeDetection.ps1
**Problem**: Unicode checkmarks (✓/✗) caused display issues
**Fix**: Replaced with ASCII `[PASS]`, `[FAIL]`, `[OK]`, `[WARN]`, `[ERROR]` tags
**Status**: ✅ Ready to run

### 2. Wake Detection Unit Test (Line 628-638 in original WW_Tests.ps1)
**Problem**: Test mocked Get-WinEvent incorrectly - returned old event regardless of `-StartTime` filter
**Expected**: Should return `$false` when wake event is outside time window
**Actual**: Mock returned event even when outside filter range
**Fix**: New test properly simulates Get-WinEvent filter behavior

```powershell
# OLD (BROKEN):
It "Should return false when wake event too old" {
    Mock Get-WinEvent {
        [PSCustomObject]@{
            TimeCreated = (Get-Date).AddMinutes(-10)  # Returns this regardless of filter!
            Id = 1
        }
    }
    $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
    $result | Should -Be $false  # FAILS - mock returns event anyway
}

# NEW (FIXED):
It "Should return false when wake event is outside time window (FIXED)" {
    Mock Get-WinEvent {
        param($FilterHashtable, $MaxEvents, $ErrorAction)
        $startTime = $FilterHashtable.StartTime
        $eventTime = (Get-Date).AddMinutes(-10)
        
        # Honor the StartTime filter like real Get-WinEvent
        if ($eventTime -ge $startTime) {
            return @([PSCustomObject]@{ TimeCreated = $eventTime; Id = 566 })
        }
        return $null  # Outside window - return nothing
    }
    $result = Test-RecentWakeFromSleep -TimeWindowSeconds 120
    $result | Should -Be $false  # PASSES
}
```

## Test Coverage Analysis

### Current Test Counts
- **Original WW_Tests.ps1**: ~78 contexts/tests
- **Enhanced WW_Tests_Enhanced.ps1**: 35+ new/improved tests
- **Combined coverage**: ~85%+ (estimated)

### New Test Coverage Added

#### Wake Detection (8 tests)
- ✅ Recent wake within window
- ✅ No wake event
- ✅ Wake outside window (FIXED)
- ✅ Event ID 566 (System wake)
- ✅ Event ID 507 (Modern Standby)
- ✅ Exception handling
- ✅ Custom time window
- ✅ Logging verification

#### VPN Wake Integration (3 tests)
- ✅ Force disconnect on intermediate + recent wake
- ✅ Allow intermediate when no recent wake
- ✅ Skip detection when disabled

#### Network Connection Retry (2 tests)
- ✅ Active adapter detection
- ✅ VPN adapter filtering

#### FlareGun Framework (8 tests)
- ✅ Config loading
- ✅ Config caching
- ✅ Missing config handling
- ✅ Corrupt config handling
- ✅ USER context routing
- ✅ SYSTEM context routing
- ✅ Per-run deduplication
- ✅ Cooldown enforcement
- ✅ Hidden window style

#### ISE Posture (3 tests)
- ✅ Service detection (csc_iseagent)
- ✅ Process detection (ciscod.exe)
- ✅ Not found handling

#### Configuration (5 tests)
- ✅ Version number
- ✅ Wake detection enabled
- ✅ Wake time window
- ✅ Network retry settings
- ✅ FlareGun config exists

## How Wake Detection Actually Works

### Trigger Path
Wake detection ONLY fires in this specific scenario:

1. **WhiteWalker runs** (DHCP event triggers Task Scheduler)
2. **VPN state check** → finds VPN in intermediate state (Reconnecting/Connecting/Unknown)
3. **During stabilization** → `Get-VpnStateStable()` sees intermediate state for FIRST time
4. **Wake detection fires** → `Test-RecentWakeFromSleep()` checks for Event IDs 566/507
5. **If recent wake found** → Force disconnect VPN (it's blocking local auth)
6. **If no recent wake** → Allow VPN to complete (legitimate AlwaysOn)

### Testing Wake Detection Live

**Won't work:**
- Sleep → wake → check logs immediately (VPN already settled)
- VPN already connected/disconnected when WW runs

**Will work:**
1. At home: Connect VPN
2. Close laptop (sleep)
3. Go to office/hotel (different network)
4. Open laptop → triggers DHCP → WW runs
5. VPN stuck "Reconnecting" to home headend
6. Wake detection fires → force disconnect
7. Check logs: `"VPN in intermediate state (Reconnecting) + recent wake from sleep = BLOCKING SCENARIO"`

## Remaining Functions to Test (for 90%+ coverage)

High-priority functions with complex logic:
- `Test-Redirect` - HTTP redirect detection
- `Get-RedirectType` - Employee vs Guest network classification
- `Invoke-CaptivePortalRemediation` - Browser-based portal auth
- `Test-ISEPostureCompliance` - Posture status polling
- `Get-VpnState` - CLI output parsing (most critical!)
- `Get-VpnTunnelFlavor` - Management vs user tunnel detection
- `Test-VPNBlockingNetwork` - Smart VPN disconnect logic

Medium-priority utility functions:
- `Get-NetworkInfo` - Adapter/IP/DNS/SSID collection
- `Test-DefaultGateway` - Gateway reachability
- `Test-CaptivePortalCleared` - Flag file checking
- `Get-CaptiveEventCount` - Event counter logic

Lower-priority (mostly state management):
- `In-Cooldown` - Time-based throttling
- `Set-FlareStamp` - State persistence
- `To-Hashtable` - Type conversion
- `Save-State` / `Get-State` - JSON serialization

## Running Tests

```powershell
# Run enhanced tests
cd C:\ProgramData\WhiteWalker
.\WW_Tests_Enhanced.ps1

# Run wake detection diagnostic
.\Test-WakeDetection.ps1

# Run both original + enhanced
Invoke-Pester -Path .\WW_Tests.ps1, .\WW_Tests_Enhanced.ps1
```

## Next Steps for 90% Coverage

1. **Add Get-VpnState tests** (highest priority - complex parsing logic)
2. **Add redirect detection tests** (ISE vs captive portal logic)
3. **Add captive portal remediation tests** (browser spawning, flag polling)
4. **Add integration tests** (full workflow scenarios)

Estimated additional tests needed: ~25-30 more for 90%+ coverage
