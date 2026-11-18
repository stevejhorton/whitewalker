# WhiteWalker v3.13.0 - Monday Deployment Checklist

## 📦 Files to Download (13 Total)

### Core Scripts (4 files)
- [ ] WW_main.ps1 (91 KB)
- [ ] WW_flaregun_user.ps1 (5.4 KB)
- [ ] WW_flaregun_system.ps1 (5.5 KB)
- [ ] install.ps1 (13 KB)

### Configuration (1 file)
- [ ] WW_flaregun_config.json (2.8 KB)

### Task Scheduler XMLs (2 files)
- [ ] WW_flaregun_user.xml (2.1 KB)
- [ ] WW_flaregun_system.xml (2.2 KB)

### Testing (3 files)
- [ ] WW_Tests.ps1 (26 KB)
- [ ] Run-WhiteWalkerTests.ps1 (3.5 KB)
- [ ] TESTING_GUIDE.md (11 KB)

### Documentation (3 files)
- [ ] DEPLOYMENT_SUMMARY.md (8.1 KB)
- [ ] FLAREGUN_QUICK_REF.md (7.7 KB)
- [ ] TEST_COVERAGE_SUMMARY.md (9.6 KB)

---

## 🧪 Pre-Deployment Testing

### Step 1: Install Pester
```powershell
Install-Module -Name Pester -Force -SkipPublisherCheck
Get-Module -Name Pester -ListAvailable  # Should be 5.x
```

### Step 2: Run Test Suite
```powershell
cd C:\Path\To\WhiteWalker
.\Run-WhiteWalkerTests.ps1
```

**Expected Output:**
```
========================================
Test Summary
========================================
Total:  45
Passed: 45
Failed: 0
Skipped: 0

ALL TESTS PASSED!
```

### Step 3: Run with Code Coverage (Optional)
```powershell
.\Run-WhiteWalkerTests.ps1 -CodeCoverage
```

**Expected:** Coverage >75%

### Step 4: Test Specific FlareGun Features
```powershell
.\Run-WhiteWalkerTests.ps1 -TestName "FlareGun" -Detailed
```

**Expected:** All 18 FlareGun tests pass

---

## 📁 Directory Structure Setup

Create this structure on deployment machine:

```
C:\WhiteWalker_Deploy\
├── WW_main.ps1
├── WW_flaregun_user.ps1
├── WW_flaregun_system.ps1
├── WW_flaregun_config.json
├── install.ps1
├── triggers\
│   ├── WW_main.xml              (existing - from your repo)
│   ├── WW_cap_portal_runner.xml (existing - from your repo)
│   ├── WW_flaregun_user.xml     (NEW)
│   └── WW_flaregun_system.xml   (NEW)
└── tests\
    ├── WW_Tests.ps1
    ├── Run-WhiteWalkerTests.ps1
    └── TESTING_GUIDE.md
```

**Important:** Also copy these EXISTING files to the deploy directory:
- WW_cap_portal_runner.ps1
- WW_collect_diag.ps1
- WW_main.xml
- WW_cap_portal_runner.xml

---

## 🚀 Deployment Steps

### 1. Backup Existing Installation
```powershell
# Backup current production scripts
Copy-Item C:\ProgramData\WhiteWalker\*.ps1 C:\Backup\WhiteWalker_$(Get-Date -Format 'yyyyMMdd') -Recurse

# Export current task scheduler jobs
Get-ScheduledTask -TaskName "WW_*" | ForEach-Object {
    Export-ScheduledTask -TaskName $_.TaskName | 
    Out-File "C:\Backup\WhiteWalker_Tasks_$(Get-Date -Format 'yyyyMMdd')\$($_.TaskName).xml"
}
```

### 2. Run Installer
```powershell
cd C:\WhiteWalker_Deploy

# Run as Administrator
.\install.ps1
```

**Expected Output:**
```
=== Removing Old Task Scheduler Jobs ===
Removed task: WW_main
Removed task: WW_cap_portal_runner
Removed 2 old task(s)

=== Removing Old Script Files ===
Removed old script: WW_main.ps1
Removed 5 old file(s)

=== Copying Script Files ===
Copied: WW_main.ps1 -> C:\ProgramData\WhiteWalker
Copied: WW_flaregun_user.ps1 -> C:\ProgramData\WhiteWalker
...

=== Registering Task Scheduler Jobs ===
Registered task: WW_main
Registered task: WW_cap_portal_runner
Registered task: WW_flaregun_user
Registered task: WW_flaregun_system

========================================
Installation completed successfully!
========================================
```

### 3. Verify Installation
```powershell
# Check tasks registered
Get-ScheduledTask -TaskName "WW_*" | Format-Table TaskName, State

# Expected output:
# TaskName                  State
# --------                  -----
# WW_main                   Ready
# WW_cap_portal_runner      Ready
# WW_flaregun_user          Ready
# WW_flaregun_system        Ready

# Check files deployed
Get-ChildItem C:\ProgramData\WhiteWalker\WW_*.ps1

# Expected output:
# WW_main.ps1
# WW_cap_portal_runner.ps1
# WW_flaregun_user.ps1
# WW_flaregun_system.ps1
# WW_collect_diag.ps1

# Check config deployed
Test-Path C:\ProgramData\WhiteWalker\WW_flaregun_config.json
# Expected: True
```

---

## ✅ Post-Deployment Validation

### Test 1: Trigger Main Script Manually
```powershell
# Force trigger WW_main
Get-ScheduledTask -TaskName "WW_main" | Start-ScheduledTask

# Wait 10 seconds
Start-Sleep 10

# Check log for successful run
Get-Content C:\ProgramData\WhiteWalker\white_walker.main.log -Tail 30
```

**Look for:**
- `RUN START  White Walker v3.13.0`
- `FlareGun config loaded:` (or fallback message if config missing)
- No errors

### Test 2: Verify Config Loading
```powershell
# Search for FlareGun config load in log
Select-String "FlareGun config" C:\ProgramData\WhiteWalker\white_walker.main.log -Context 0,2
```

**Expected:**
```
FlareGun config loaded: C:\ProgramData\WhiteWalker\WW_flaregun_config.json
```

### Test 3: Test SYSTEM Flare (Simulate On-Prem)
```powershell
# Manually trigger a SYSTEM flare for testing
# (This simulates what WW_main does)

# Create test script:
@"
`$flareExe = "`$env:SystemRoot\System32\rundll32.exe"
Start-Process -FilePath `$flareExe -ArgumentList "/test_system_flare" -WindowStyle Hidden
Write-Host "Test SYSTEM flare sent: /test_system_flare"
"@ | Out-File C:\Temp\test_system_flare.ps1

# Run it
powershell.exe -File C:\Temp\test_system_flare.ps1
```

**Verify:** Check with Ivanti team if they received `/test_system_flare`

### Test 4: Test USER Flare (Simulate VPN)
```powershell
# Manually trigger a USER flare via event log
eventcreate /T INFORMATION /ID 780 /L APPLICATION /SO "WhiteWalkerFlareGun" /D "FLARE:test_user_tun"

# Wait 5 seconds for Task Scheduler to pick up event
Start-Sleep 5

# Check USER handler log
Get-Content C:\ProgramData\WhiteWalker\white_walker.flaregun_user.log -Tail 20
```

**Expected in log:**
```
Retrieved triggering event: ID 780, Time ...
Parsed flare tag from event message: test_user_tun
Sending USER context flare: /test_user_tun
USER flare sent successfully: /test_user_tun
```

**Verify:** Check with Ivanti team if they received `/test_user_tun` with USER context

---

## 🐛 Troubleshooting

### Issue: "FlareGun config not found"
**Cause:** Config file wasn't deployed

**Fix:**
```powershell
# Verify file exists
Test-Path C:\ProgramData\WhiteWalker\WW_flaregun_config.json

# If missing, copy manually
Copy-Item C:\WhiteWalker_Deploy\WW_flaregun_config.json C:\ProgramData\WhiteWalker\
```

### Issue: "Task WW_flaregun_user not registered"
**Cause:** XML wasn't in triggers\ directory during install

**Fix:**
```powershell
# Register manually
Register-ScheduledTask -Xml (Get-Content C:\WhiteWalker_Deploy\triggers\WW_flaregun_user.xml -Raw) -TaskName "WW_flaregun_user"
```

### Issue: "USER flare not firing"
**Cause:** Event log message not in correct format

**Debug:**
```powershell
# Check recent events
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'WhiteWalkerFlareGun'
} -MaxEvents 5 | Format-Table TimeCreated, Id, Message -Wrap

# Message should be: "FLARE:tag_name"
# If not, check WW_main.ps1 Send-FlareEvent function
```

### Issue: "Tests fail with 'Cannot source WW_main.ps1'"
**Cause:** Wrong directory

**Fix:**
```powershell
cd C:\WhiteWalker_Deploy
.\Run-WhiteWalkerTests.ps1
```

---

## 📊 Monitoring After Deployment

### Day 1: Watch for Flares
```powershell
# Monitor main log
Get-Content C:\ProgramData\WhiteWalker\white_walker.main.log -Tail 50 -Wait

# Look for these patterns:
# "FlareEvent sent directly as SYSTEM: /on_prem"
# "FlareEvent queued for USER context: user_tun (Event ID 780)"
```

### Day 2-7: Verify No Regressions
- [ ] VPN detection still works (check exit_reason in logs)
- [ ] Captive portal remediation still works (Event ID 777)
- [ ] ISE rescan still works (ise_employee_compliant/failed)
- [ ] No increase in errors/exceptions

### Week 2: Performance Check
- [ ] No noticeable slowdown in script execution
- [ ] Event log not filling up with flare messages
- [ ] Task Scheduler not showing failed runs

---

## 🎯 Success Criteria

### Immediate (Day 1)
- ✅ All 4 tasks registered and Ready
- ✅ Config file deployed and loaded
- ✅ WW_main runs without errors
- ✅ Test flares sent successfully

### Short-term (Week 1)
- ✅ SYSTEM flares reach Ivanti with SYSTEM context
- ✅ USER flares reach Ivanti with logged-in user identity
- ✅ Ivanti can launch user-session automations
- ✅ No regressions in existing functionality

### Long-term (Month 1)
- ✅ All 500k+ endpoints upgraded
- ✅ Ivanti automations working as expected
- ✅ No increase in support tickets
- ✅ Flare cooldowns working (no spam)

---

## 📞 Rollback Plan

If critical issues arise:

```powershell
# 1. Stop all tasks
Get-ScheduledTask -TaskName "WW_*" | Disable-ScheduledTask

# 2. Remove FlareGun tasks
Unregister-ScheduledTask -TaskName "WW_flaregun_user" -Confirm:$false
Unregister-ScheduledTask -TaskName "WW_flaregun_system" -Confirm:$false

# 3. Restore previous version
Copy-Item C:\Backup\WhiteWalker_20251114\WW_main.ps1 C:\ProgramData\WhiteWalker\ -Force

# 4. Re-enable main tasks
Get-ScheduledTask -TaskName "WW_main","WW_cap_portal_runner" | Enable-ScheduledTask

# 5. Verify rollback
Get-Content C:\ProgramData\WhiteWalker\white_walker.main.log -Tail 10
# Should show older version number
```

---

## 📝 Notes for Production

### FlareGun Config Updates
To change Event IDs or add new flares:
1. Edit `C:\ProgramData\WhiteWalker\WW_flaregun_config.json`
2. Update Task Scheduler XMLs if Event IDs changed
3. Re-register tasks: `.\install.ps1`
4. Config changes take effect immediately (cached in memory, cleared on next run)

### Cooldown Adjustments
If flares firing too frequently:
1. Edit `$FlareCooldownMinutes` in WW_main.ps1
2. Redeploy via install.ps1
3. Or manually clear cooldowns: `Remove-Item C:\Windows\UHGLogs\state.json`

### Adding New Flares
1. Add to WW_flaregun_config.json
2. Update appropriate Task Scheduler XML (if USER context)
3. Add flare call in WW_main.ps1 with detailed comment
4. Add test to WW_Tests.ps1
5. Redeploy

---

**Ready to deploy? Let's go! 🚀**

Author: steve.horton@optum.com  
Version: 3.13.0  
Date: 14-Nov-2025
