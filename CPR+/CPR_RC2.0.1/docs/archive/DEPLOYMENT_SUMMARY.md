# WhiteWalker v3.13.0 - FlareGun Integration Deployment Summary

## What Changed

### New Files (7 total)
1. **WW_flaregun_config.json** - Event ID and context routing configuration
2. **WW_flaregun_user.xml** - Task Scheduler job for USER context flares (Event IDs 780-782)
3. **WW_flaregun_system.xml** - Task Scheduler job for SYSTEM context flares (Event IDs 790-795, 799)
4. **install.ps1** - Robust installer with clean uninstall
5. **FLAREGUN_QUICK_REF.md** - Quick reference guide
6. **WW_main.ps1** - Updated with FlareGun integration
7. **WW_flaregun_user.ps1** - Updated to parse event messages
8. **WW_flaregun_system.ps1** - Updated to parse event messages

### Modified Files (4 total)
- **WW_main.ps1**:
  - Version bumped to 3.13.0
  - Added `Get-FlareConfig()` function
  - Added `Send-FlareEvent()` function (replaces Send-SignalFlare)
  - Kept `Send-SignalFlare()` as legacy wrapper
  - Added detailed comment blocks at ALL 11 flare call sites
  - All existing functionality preserved (surgical changes only)

- **WW_flaregun_user.ps1**:
  - Removed hardcoded Event ID switch logic
  - Now parses flare tag from event log message ("FLARE:tag_name")
  - Removed obsolete `Get-TriggeringEventID()` function
  - Event ID 777 still handled for captive portal (legacy path)

- **WW_flaregun_system.ps1**:
  - Removed hardcoded Event ID switch logic
  - Now parses flare tag from event log message ("FLARE:tag_name")
  - Removed obsolete `Get-TriggeringEventID()` function
  - Event ID 799 still handled for diagnostics

- **install.ps1**:
  - Complete rewrite for production robustness
  - Clean uninstall of old tasks/scripts (preserves logs/diagnostics)
  - Works from any directory (finds own location)
  - Variablized paths for future relocation
  - Comprehensive validation
  - Better error handling and logging

### Unchanged Files (Keep existing)
- WW_main.xml (existing Task Scheduler job)
- WW_cap_portal_runner.xml (existing Task Scheduler job)
- WW_cap_portal_runner.ps1 (captive portal handler)
- WW_collect_diag.ps1 (diagnostics collector)

## Installation Instructions

### Prerequisites
- Windows PowerShell 5.1 or later
- Administrator privileges
- Existing WhiteWalker deployment (or fresh install)

### Deployment Steps

1. **Stop existing WhiteWalker tasks** (optional, installer handles this):
```powershell
Get-ScheduledTask -TaskName "WW_*" | Disable-ScheduledTask
```

2. **Place all files in deployment directory**:
```
WhiteWalker/
├── WW_main.ps1
├── WW_cap_portal_runner.ps1
├── WW_flaregun_user.ps1
├── WW_flaregun_system.ps1
├── WW_collect_diag.ps1
├── WW_flaregun_config.json
├── install.ps1
└── triggers/
    ├── WW_main.xml
    ├── WW_cap_portal_runner.xml
    ├── WW_flaregun_user.xml
    └── WW_flaregun_system.xml
```

3. **Run installer as Administrator**:
```powershell
# From WhiteWalker directory
.\install.ps1
```

4. **Verify installation**:
```powershell
# Check tasks registered
Get-ScheduledTask -TaskName "WW_*" | Format-Table TaskName, State

# Check files deployed
Get-ChildItem C:\ProgramData\WhiteWalker\WW_*.ps1
Get-Item C:\ProgramData\WhiteWalker\WW_flaregun_config.json

# Tail main log
Get-Content C:\ProgramData\WhiteWalker\white_walker.main.log -Tail 20 -Wait
```

## Testing Plan

### Test 1: SYSTEM Flare (Direct)
**Scenario**: Connect to on-premises network
**Expected**:
1. WW_main detects DC reachable
2. Log shows: "FlareEvent sent directly as SYSTEM: /on_prem"
3. Ivanti receives flare as SYSTEM
4. No event log message created (direct path)

**Verify**:
```powershell
# Check main log
Select-String "FlareEvent sent directly as SYSTEM" C:\ProgramData\WhiteWalker\white_walker.main.log -Tail 10
```

### Test 2: USER Flare (Event Log Path)
**Scenario**: Connect VPN with user tunnel
**Expected**:
1. WW_main detects user_tun
2. Log shows: "FlareEvent queued for USER context: user_tun (Event ID 780)"
3. Event log shows: "FLARE:user_tun" with Event ID 780
4. Task Scheduler triggers WW_flaregun_user.ps1
5. USER handler log shows: "Sending USER context flare: /user_tun"
6. Ivanti receives flare with logged-in user identity

**Verify**:
```powershell
# Check event log
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'WhiteWalkerFlareGun'
    Id = 780
} -MaxEvents 1

# Check USER handler log
Get-Content C:\ProgramData\WhiteWalker\white_walker.flaregun_user.log -Tail 20
```

### Test 3: ISE Posture Compliance
**Scenario**: On-prem with ISE redirect
**Expected**:
1. WW_main detects ISE redirect
2. Triggers posture rescan
3. Monitors compliance
4. Sends ise_posture_compliant or ise_posture_failed
5. Ivanti receives appropriate flare

**Verify**:
```powershell
# Check for ISE-related flares
Select-String "ise_posture" C:\ProgramData\WhiteWalker\white_walker.main.log -Tail 50
```

### Test 4: Captive Portal (Legacy Path - Event ID 777)
**Scenario**: Connect to hotel WiFi
**Expected**:
1. WW_main detects captive portal
2. Creates Event ID 777
3. WW_cap_portal_runner.ps1 launches browser
4. No FlareGun involvement (legacy path preserved)

**Verify**:
```powershell
# Check captive portal log
Get-Content C:\ProgramData\WhiteWalker\white_walker.cap_portal.log -Tail 20
```

## Rollback Plan

If issues arise, rollback to previous version:

```powershell
# 1. Stop all tasks
Get-ScheduledTask -TaskName "WW_*" | Disable-ScheduledTask

# 2. Unregister FlareGun tasks
Unregister-ScheduledTask -TaskName "WW_flaregun_user" -Confirm:$false
Unregister-ScheduledTask -TaskName "WW_flaregun_system" -Confirm:$false

# 3. Restore previous WW_main.ps1
Copy-Item C:\Backup\WW_main.ps1 C:\ProgramData\WhiteWalker\WW_main.ps1 -Force

# 4. Re-enable main tasks
Get-ScheduledTask -TaskName "WW_main","WW_cap_portal_runner" | Enable-ScheduledTask
```

## Known Issues / Limitations

### Non-Issues (By Design)
1. **SYSTEM flares don't use event log** - This is intentional for performance (immediate execution)
2. **Config file not validated at runtime** - Invalid config falls back to legacy behavior
3. **Event message must be exact format** - "FLARE:tag_name" is required (case-sensitive tag)

### Potential Issues
1. **Event log lag** - USER flares may have 1-2 second delay vs SYSTEM flares (Event Log → Task Scheduler latency)
2. **User must be logged in** - USER context flares won't fire if no user session (by design for Ivanti)
3. **Event ID collisions** - Using Event IDs 780-799 for WhiteWalkerFlareGun only

### Monitoring Points
1. **Flare cooldowns** - Default 10 minutes may suppress legitimate state changes
2. **Per-run de-dupe** - Same flare won't fire twice in one WW_main execution
3. **Event log capacity** - High-frequency flares could fill Application log

## Performance Impact

### Before (v3.12.0_ER8.1)
- All flares: Direct rundll32.exe call (~50ms)
- No event log writes for flares
- No Task Scheduler overhead

### After (v3.13.0)
- SYSTEM flares: Direct call (~50ms) - NO CHANGE
- USER flares: Event log write + Task Scheduler trigger (~1-2 seconds)
- Minimal impact: Only USER flares (user_tun, mgmt_tun, off_prem_no_vpn) use slower path

### Mitigation
- Config file cached in memory after first read
- Event log writes are async (non-blocking)
- Task Scheduler MultipleInstancesPolicy=IgnoreNew prevents queue buildup

## Support Information

### Logs to Collect for Troubleshooting
```powershell
# Main script log
C:\ProgramData\WhiteWalker\white_walker.main.log

# FlareGun handler logs
C:\ProgramData\WhiteWalker\white_walker.flaregun_user.log
C:\ProgramData\WhiteWalker\white_walker.flaregun_system.log

# Installation log
C:\ProgramData\WhiteWalker\white_walker_install.log

# Event log export
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='WhiteWalkerFlareGun'} |
  Export-Csv C:\Temp\whitewalker_events.csv
```

### Common Troubleshooting Commands
```powershell
# Force re-read of config (restart WW_main)
Get-ScheduledTask WW_main | Start-ScheduledTask

# Clear flare cooldowns (delete state file)
Remove-Item C:\Windows\UHGLogs\state.json -Force

# Test flare manually
eventcreate /T INFORMATION /ID 780 /L APPLICATION /SO "WhiteWalkerFlareGun" /D "FLARE:user_tun"
```

## Contact
- Author: steve.horton@optum.com
- Version: 3.13.0
- Date: 14-Nov-2025
