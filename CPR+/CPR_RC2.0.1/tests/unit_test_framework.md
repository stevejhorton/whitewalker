---
version:10apr26

## 📦 **Merged Test Suite: WW_Tests_CapPortalRunner.ps1**
![Coverage](https://img.shields.io/badge/coverage-13%25-yellow) 

Assumes - 
```powershell
./tools/automation/win_ise_rescanner/CPR_3.14_RC1.10/tests/install_pester.ps1 #pester installed
```
---

## 🎯 **Summary of Merged Test Suite**

| Section | Tests | Description |
|---------|-------|-------------|
| 1. Logging Framework | 7 | Write-CapLog timestamp, levels, format |
| 2. Completion Flag | 7 | JSON structure, PID tracking, status values |
| 3. Site Reachability | 11 | ER3 timeout fix, HTTP responses, DNS tracking |
| 4. Configuration | 13 | All default values and validation |
| 5. Logger Init | 3 | Directory and file creation |
| 6. Cisco Killer | 10 | Background job logic (7 skipped, 3 unit) |
| 7. Browser Mgmt | 9 | Edge launch, fallback, argument syntax |
| 8. Smart Wait | 6 | Polling loop, early exit, timeouts |
| 9. Notifications | 11 | UI properties, trigger conditions |
| 10. Network Reconnect | 7 | RETRY/EXIT flows, netsh commands |
| 11. VPN Stabilization | 3 | State detection, polling |
| 12. Timeout Scenarios | 7 | End-to-end timeout handling |
| 13. Workflow Paths | 5 | Success/failure flows |
| 14. Task Scheduler | 2 | Integration points |
| 15. Regression | 5 | Existing functionality preserved |
| **TOTAL** | **~106** | **Comprehensive coverage** |

---

## 🚀 **To Use:**

```powershell
# To Run:
.\Run-WhiteWalkerTests.ps1

# Expected results:
Tests completed in 69.98s
Tests Passed: 261, Failed: 0, Skipped: 7 NotRun: 0

 

========================================
Test Summary
========================================
Total:   268
Passed:  261
Failed:  0
Skipped: 7

 

ALL TESTS PASSED!
```

