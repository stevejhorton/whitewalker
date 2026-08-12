# WhiteWalker v3.13.1_ER2 - Final Workflow (Corrected)

## Architecture Decision: VPN Stabilization in USER Context

**KEY INSIGHT**: Validation browser must run as USER (not SYSTEM), so VPN stabilization must also happen in USER context (cap_portal_runner) where validation browser launches.

---

## Complete ER2 Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ WW_main.ps1 (SYSTEM Context)                                │
│ 1. Detect captive portal                                    │
│ 2. Create remediation state file                            │
│ 3. Send-FlareEvent "captive_portal_browser"                 │
│    → Creates Event 777 with WhiteWalkerFlareGun source      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Task Scheduler                                              │
│ Event 777 triggers WW_flaregun_user.ps1                     │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ WW_flaregun_user.ps1 (USER Context)                         │
│ Routes to WW_cap_portal_runner.ps1                          │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ WW_cap_portal_runner.ps1 (USER Context) - DOES EVERYTHING  │
│                                                              │
│ 1. Start Cisco browser killer (background, 20s)             │
│ 2. Launch Edge → captive portal                             │
│ 3. Smart wait (up to 150s, 5s polls, early exit)            │
│ 4. User authenticates                                        │
│                                                              │
│ 5. CHECK: Does remediation state file exist?                │
│    ├─ YES → VPN stabilization needed                        │
│    │   ├─ Get VPN state via vpncli                          │
│    │   ├─ IF intermediate (Connecting/Reconnecting):        │
│    │   │   └─ Poll every 5s for up to 60s                   │
│    │   │   └─ Wait for Connected OR Disconnected            │
│    │   └─ Delete state file                                 │
│    └─ NO → Skip VPN check                                   │
│                                                              │
│ 6. Launch Edge → https://www.optum.com (maximized)          │
│ 7. Wait 30s for network stabilization                       │
│ 8. Test connectivity                                         │
│ 9. Write completion flag (SUCCESS/PARTIAL/FAILED)           │
│ 10. Exit                                                     │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ WW_main.ps1 (SYSTEM Context)                                │
│ 1. Reads completion flag                                    │
│ 2. Cleans up captive browser PID                            │
│ 3. SUCCESS!                                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Why This Architecture?

### Problem: Validation Browser Needs USER Context
```
Edge browser → optum.com must run as USER
USER context required for:
  - Proper window focus/display
  - User cookies/session
  - Network adapter access
```

### Solution: Everything in Cap Portal Runner
```
Cap portal runner runs as USER (via Task Scheduler)
  → Can launch Edge properly
  → Has network access
  → Can call vpncli to check VPN state
  → Perfect place for VPN stabilization check
```

### What WW_main Does
```
WW_main (SYSTEM context):
  1. Detect captive portal
  2. Create state file (signals "VPN check needed")
  3. Fire Event 777 via FlareGun
  4. Wait for completion
  5. Clean up captive browser
  
WW_main does NOT:
  - Launch validation browser (can't, wrong context)
  - Check VPN state after auth (cap_portal_runner handles it)
```

---

## State File Purpose

**File**: `C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag`

**Created By**: WW_main (SYSTEM) when firing Event 777
**Checked By**: Cap portal runner (USER) before launching validation browser
**Deleted By**: Cap portal runner (USER) after VPN stabilizes

**Content**:
```json
{
  "timestamp": "2025-11-18T15:30:00.000Z",
  "portal_type": "NON_ISE",
  "attempt_count": 1
}
```

**Logic**:
```
IF state file exists:
  → WW_main thinks VPN might auto-connect (AlwaysOn)
  → Cap portal runner should check VPN state
  → Wait for stable before validation browser

IF state file does NOT exist:
  → Not expected (but handle gracefully)
  → Skip VPN check, launch validation browser immediately
```

---

## VPN Stabilization Details

**Location**: WW_cap_portal_runner.ps1 (lines ~354-450)

**Trigger**: State file exists after user authenticates

**Process**:
1. Call `vpncli.exe state` to get current state
2. Parse output (use LAST `>> state:` line)
3. IF intermediate state (Connecting/Reconnecting/Unknown/Disconnecting):
   - Loop: Check every 5 seconds
   - Max: 60 seconds (12 checks)
   - Exit when: Connected OR Disconnected
   - Log progress
4. Delete state file
5. Launch validation browser

**Example Log Output**:
```
Remediation state file detected - checking VPN state for stabilization
Current VPN state: Connecting
VPN in intermediate state (Connecting) - waiting for stable state before validation browser
Polling every 5s for up to 60s...
VPN check 1/12 (5s): Connecting
VPN check 2/12 (10s): Connecting  
VPN check 3/12 (15s): Connected
VPN reached stable state: Connected (after 15s)
Removed remediation state file after VPN stabilization
Launching validation browser for seamless transition...
```

---

## Code Changes Summary

### WW_main.ps1
**Lines Changed**:
- Header: Updated to reflect simplified role
- Line 117: Added `$RemediationStateFile` config
- Lines 1303-1316: Create state file before Event 777
- Lines 1318-1332: Replace eventcreate with `Send-FlareEvent`
- Lines 1339-1344: Clean up state file on interrupt
- Removed: All VPN stabilization logic (moved to cap_portal_runner)
- Removed: Validation browser launch (moved to cap_portal_runner)

### WW_cap_portal_runner.ps1
**Lines Changed**:
- Header: Updated to reflect new responsibilities
- Lines 50-56: Enhanced Cisco process kill list
- Line 118: Increased killer duration to 20s
- Lines 354-450: **NEW** - VPN stabilization logic with state file check
- Kept: Original validation browser logic (runs AFTER VPN stable)

### WW_flaregun_config.json
**Lines Changed**:
- Lines 71-77: Added Event 777 definition

---

## Testing Scenarios

### Scenario 1: AlwaysOn VPN at TacoBell
```
1. Connect to TacoBell WiFi
2. Captive portal detected
3. State file created
4. Event 777 fires
5. Browser opens, user authenticates
6. Internet restored → VPN auto-connects (Connecting state)
7. Cap portal runner: "State file exists, checking VPN..."
8. Cap portal runner: Polls VPN every 5s
9. After ~15s: VPN reaches "Connected"
10. Delete state file
11. Launch Edge → optum.com (works perfectly!)
12. SUCCESS
```

### Scenario 2: No AlwaysOn VPN at McDs
```
1. Connect to McDs WiFi
2. Captive portal detected
3. State file created
4. Event 777 fires
5. Browser opens, user authenticates
6. Internet restored, VPN stays "Disconnected"
7. Cap portal runner: "State file exists, checking VPN..."
8. Cap portal runner: "VPN already stable: Disconnected"
9. Delete state file immediately
10. Launch Edge → optum.com (works!)
11. SUCCESS
```

### Scenario 3: No State File (Edge Case)
```
1. State file somehow missing
2. Cap portal runner: "No state file, skipping VPN check"
3. Launch validation browser immediately
4. Best effort (usually works)
```

---

## Files Deployed

1. **WW_main.ps1** - v3.13.1_ER2
   - Creates state file
   - Fires Event 777 via FlareGun
   - Simplified: No VPN checks, no validation browser

2. **WW_cap_portal_runner.ps1** - v1.6.0
   - Checks state file
   - VPN stabilization if needed
   - Launches validation browser (USER context)

3. **WW_flaregun_config.json**
   - Event 777 definition added

4. **No changes needed**:
   - WW_flaregun_user.ps1 (already correct)
   - WW_flaregun_user.xml (already correct)

---

## Advantages of This Architecture

✅ **Validation browser runs as USER** (proper context)
✅ **VPN check happens where it's needed** (before validation browser)
✅ **Clean separation**: WW_main = detection, cap_portal_runner = remediation
✅ **State file = simple signal** (no complex IPC)
✅ **Works with/without AlwaysOn VPN** (conditional logic)
✅ **All browser launches in same script** (consistency)

---

## Deployment Quick Start

```powershell
# 1. Backup
$backup = "C:\ProgramData\WhiteWalker\backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $backup -ItemType Directory
Copy-Item C:\ProgramData\WhiteWalker\WW_*.ps1 $backup
Copy-Item C:\ProgramData\WhiteWalker\WW_flaregun_config.json $backup

# 2. Deploy ER2
Copy-Item .\WW_main.ps1 C:\ProgramData\WhiteWalker\ -Force
Copy-Item .\WW_cap_portal_runner.ps1 C:\ProgramData\WhiteWalker\ -Force
Copy-Item .\WW_flaregun_config.json C:\ProgramData\WhiteWalker\ -Force

# 3. Test at captive portal location
```

---

## Success Criteria

- [ ] Event 777 fires with WhiteWalkerFlareGun source
- [ ] State file created by WW_main
- [ ] Cap portal runner launches
- [ ] User authenticates
- [ ] State file checked by cap portal runner
- [ ] VPN stabilization waits (if intermediate)
- [ ] State file deleted
- [ ] Validation browser opens to optum.com
- [ ] optum.com loads successfully

**Expected result**: Smooth, seamless captive portal remediation with proper VPN timing! 🎯
