# CPR+ Manual Test Plan

**CPR+ Version:** v1.10.0_RC1.17  
**Test Plan Version:** 1.0  
**Script:** `WW_cap_portal_runner.ps1`  
**Author:** steve.horton@optum.com  
**Date:** 2026-05-26

---

## Version History

| CPR+ Version | Test Plan Version | Date | Changes |
|---|---|---|---|
| v1.10.0_RC1.17 | 1.0 | 2026-05-26 | Initial release covering all RC1.17 functionality |

---

## Table of Contents

1. [Test Environment Setup](#1-test-environment-setup)
2. [Automated Pester Tests](#2-automated-pester-tests)
3. [Core Infrastructure](#3-core-infrastructure)
4. [Portal Type Detection (RC1.17)](#4-portal-type-detection-rc117)
5. [Redirect Portal Flow (Standard)](#5-redirect-portal-flow-standard)
6. [Walled-Garden Portal Flow (RC1.17)](#6-walled-garden-portal-flow-rc117)
7. [VPN Stabilization (Redirect Path)](#7-vpn-stabilization-redirect-path)
8. [DNS Chicken/Egg Detection (ER5)](#8-dns-chickenegg-detection-er5)
9. [Timeout Notification UI (ER3/ER5)](#9-timeout-notification-ui-er3er5)
10. [Network Reconnect (ER3)](#10-network-reconnect-er3)
11. [Cisco Browser Killer](#11-cisco-browser-killer)
12. [Browser Foreground Management (RC1.10)](#12-browser-foreground-management-rc110)
13. [Task Scheduler Integration](#13-task-scheduler-integration)
14. [FlareGun Integration](#14-flaregun-integration)
15. [End-to-End Field Scenarios](#15-end-to-end-field-scenarios)
16. [Regression Checklist](#16-regression-checklist)
17. [Log Analysis Guide](#17-log-analysis-guide)

---

## 1. Test Environment Setup

### 1.1 Required Machines / VMs

| Role | Spec | Notes |
|---|---|---|
| Test endpoint | Windows 11 22H2+, domain-joined | Must have Ivanti agent and Cisco Secure Client 5.x installed |
| ISE policy server | Cisco ISE 3.x (lab or WLAN sandbox) | Needs employee + guest PSKs configured |
| Wireless AP | Cisco WLC or standalone AP | Used for ISE redirect and simulated walled-garden scenarios |
| Internet-connected host | Any | Used to verify `https://www.optum.com` reachability post-auth |

### 1.2 Required Network Configurations

| Config | How to Set Up |
|---|---|
| Corporate WiFi with ISE posture | Connect to WLANi03 (or lab equivalent) before posture compliant |
| Guest WiFi (ISE-managed) | Connect to guest SSID; portal should redirect to ISE guest portal |
| Non-ISE captive portal | Use a consumer AP (hotel simulator) with captive portal firmware |
| Walled-garden simulation | Block UDP 53 outbound on the AP or use the Windows Firewall rule below |
| No-network | Disable all adapters or use Airplane Mode |

**Simulating a walled-garden with Windows Firewall (no AP config needed):**

```powershell
# Block all outbound DNS so portal type detection sees DNS failure
New-NetFirewallRule -DisplayName "WG-Sim: Block DNS" `
    -Direction Outbound -Protocol UDP -RemotePort 53 `
    -Action Block -Profile Any

# Allow gateway IP on port 80 (keeps portal reachable)
New-NetFirewallRule -DisplayName "WG-Sim: Allow GW HTTP" `
    -Direction Outbound -Protocol TCP `
    -RemoteAddress 192.168.1.1 -RemotePort 80 `
    -Action Allow -Profile Any

# To remove simulation:
Remove-NetFirewallRule -DisplayName "WG-Sim: Block DNS"
Remove-NetFirewallRule -DisplayName "WG-Sim: Allow GW HTTP"
```

> **Note:** The gateway address (`192.168.1.1` above) must match the default gateway on the test adapter. Run `Get-NetRoute -DestinationPrefix 0.0.0.0/0` to find the active gateway.

### 1.3 Required Software

| Software | Version | Notes |
|---|---|---|
| Pester | 5.x | Install via `Install-Module Pester -Force -SkipPublisherCheck` |
| Cisco Secure Client | 5.x | Must include `vpncli.exe` in `C:\Program Files\Cisco\Cisco Secure Client\` |
| Microsoft Edge | Current release | Required for browser launch tests |
| PowerShell | 5.1 or 7.x | Script targets 5.1; test on both if possible |

### 1.4 How to Enable Debug Logging

Pass the `-Debug` switch when launching the runner manually:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_cap_portal_runner.ps1" -Debug
```

When triggered through Task Scheduler the `-Debug` flag is not set by default. To enable it for field testing, temporarily edit the Task Scheduler action arguments.

### 1.5 Log Location

```
C:\ProgramData\WhiteWalker\white_walker.cap_portal.log
```

Tail the log in real time:

```powershell
# From the CPR_3.14_RC1.14 folder:
.\tail_ww_cap_log.ps1
```

### 1.6 Completion Flag

```
C:\ProgramData\WhiteWalker\portal_complete.flag
```

Read and pretty-print the completion flag:

```powershell
Get-Content "C:\ProgramData\WhiteWalker\portal_complete.flag" | ConvertFrom-Json | Format-List
```

The flag is valid JSON. Expected fields: `status`, `timestamp`, `username`, `browser_pid`, `details` (and additional fields depending on portal type).

### 1.7 Remediation State File

```
C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag
```

Written by `WW_main.ps1` before firing Event 777. Read by `WW_cap_portal_runner.ps1` at init. Contains: `portal_type`, `gateway_ip`, `ssid`, `reason`, `timestamp`. Cleared by the runner on exit.

### 1.8 Simulating Each Portal Type

| Portal Type | How to Simulate |
|---|---|
| ISE redirect | Connect to WLANi03 before posture; `WW_main` will detect and write state file with `portal_type=redirect` |
| Walled garden | Use Windows Firewall DNS-block method above **or** connect to a hotel AP; `WW_main` writes `portal_type=walled_garden` |
| DNS chicken/egg | Manually drop a crafted `dns_chicken_egg_issue.flag` (see TC-DNS-001 for JSON structure) |

---

## 2. Automated Pester Tests

**How to run:**

```powershell
# From the CPR_3.14_RC1.14 folder:
Invoke-Pester -Path .\WW_Tests_CapPortalRunner.ps1 -Output Detailed
```

Or use the wrapper script:

```powershell
.\Run-WhiteWalkerTests.ps1
```

> **Note:** Integration tests that require live network, Task Scheduler, or a real browser are marked `-Skip` in the Pester file. Only unit tests (mocked external calls) run in the automated suite.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-AUTO-001 | Run full Pester suite | Pester 5.x installed; script in `C:\ProgramData\WhiteWalker\` | `Invoke-Pester -Path .\WW_Tests_CapPortalRunner.ps1` | All tests pass; 0 failures | [ ] | Run as the logged-on user, not SYSTEM |
| TC-AUTO-002 | Verify `-Output Detailed` coverage | TC-AUTO-001 passed | `Invoke-Pester -Path .\WW_Tests_CapPortalRunner.ps1 -Output Detailed` | Each section in this document has at least one corresponding Pester block in the output | [ ] | Integration-only sections (TC-TS-*, TC-FG-*, E2E) will show as Skipped, not failed |

---

## 3. Core Infrastructure

Tests for the logger, completion flag, and state directory. All of these can be verified by running the Pester suite (TC-AUTO-001) and by inspecting log output after a manual run.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-INFRA-001 | Logger creates directory if missing | `C:\ProgramData\WhiteWalker\` does not exist | Delete the directory; run the script | Directory is created; no error thrown | [ ] | Run as elevated user since `ProgramData` requires admin for mkdir |
| TC-INFRA-002 | Logger creates log file if missing | Log directory exists; `white_walker.cap_portal.log` absent | Delete the log file; run the script | Log file is created | [ ] | |
| TC-INFRA-003 | Log line format | Script running | Inspect log after any run | Each line matches `YYYY-MM-DD HH:mm:ss.fff ±HH:MM [CAP] [LEVEL] message` | [ ] | Example: `2026-05-26 14:32:11.042 -05:00 [CAP] [INFO] CPR+ starting` |
| TC-INFRA-004 | All log levels work | Script running with `-Debug` | Run script; inspect log | Lines present for `INFO`, `WARN`, `ERROR`, and `DEBUG` levels | [ ] | DEBUG lines only appear when `-Debug` switch is passed |
| TC-INFRA-005 | Completion flag written as valid JSON | Script runs to any terminal state | Open `portal_complete.flag`; run `ConvertFrom-Json` | Parses without error; contains `status`, `timestamp`, `username` fields | [ ] | |
| TC-INFRA-006 | Completion flag includes current Windows username | Any user logs on; script runs | Inspect `portal_complete.flag` → `username` field | Matches output of `whoami` (domain\user format) | [ ] | |
| TC-INFRA-007 | All status values accepted | Various terminal conditions | Trigger each condition; inspect flag `status` field | Valid values: `SUCCESS`, `FAILED`, `PARTIAL`, `TIMEOUT`, `RETRY_REQUESTED`, `RETRY_FAILED`, `USER_EXIT`, `DNS_CHICKEN_EGG` | [ ] | See each section for how to trigger each status |
| TC-INFRA-008 | Log write failure does not crash the script | Log path write-protected | `icacls C:\ProgramData\WhiteWalker\white_walker.cap_portal.log /deny Everyone:W`; run script | Script continues to completion; no unhandled exception | [ ] | Restore ACL after test: `icacls ... /remove:d Everyone` |

---

## 4. Portal Type Detection (RC1.17)

The runner reads `cap_portal_remediation_active.flag` (the remediation state file) at startup and branches on `portal_type`. Tests verify the branching logic is correct.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-PTD-001 | No state file → redirect flow | State file absent | Delete state file if present; run runner | Script proceeds with standard redirect portal flow (opens `http://enroll.cisco.com`) | [ ] | Verify via log: `[INFO] No remediation state file` or similar |
| TC-PTD-002 | State file `portal_type=redirect` → redirect flow | State file present with `portal_type=redirect` | Write state file: `{"portal_type":"redirect","gateway_ip":null,"ssid":"WLANi03","reason":"ise_redirect","timestamp":"..."}` ; run runner | Script proceeds with redirect portal flow | [ ] | |
| TC-PTD-003 | State file `portal_type=walled_garden` → walled-garden flow | State file present with `portal_type=walled_garden` | Write state file: `{"portal_type":"walled_garden","gateway_ip":"192.168.1.1","ssid":"HotelWifi","reason":"dns_blocked_gateway_reachable","timestamp":"..."}` ; run runner | Script proceeds with `Invoke-WalledGardenRemediation` path | [ ] | Verify via log: `WALLED GARDEN` |
| TC-PTD-004 | Malformed JSON state file → redirect flow | State file present but not valid JSON | Write `bad-json` to state file; run runner | Script defaults to redirect flow; logs DEBUG message about parse failure | [ ] | Should NOT crash |
| TC-PTD-005 | `gateway_ip` logged from state file | State file with `gateway_ip=172.20.0.1` | Write valid walled-garden state file; run runner | Log contains `172.20.0.1` in CAP log | [ ] | |
| TC-PTD-006 | `ssid` field logged from state file | State file with `ssid=HotelWifi` | Write valid walled-garden state file; run runner | Log contains `HotelWifi` in CAP log | [ ] | |

---

## 5. Redirect Portal Flow (Standard)

Tests for the existing ISE redirect path. The runner opens `http://enroll.cisco.com`, polls for connectivity, then opens a validation browser to `https://www.optum.com`.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-RED-001 | Cisco browser killer starts on entry | No state file or `portal_type=redirect` | Run runner; check running background jobs early in execution | Background job for Cisco process killer starts within first 5 seconds | [ ] | Use `Get-Job` in a parallel PS window |
| TC-RED-002 | Browser opens to `http://enroll.cisco.com` | Edge installed; redirect flow active | Run runner; observe browser | Edge opens to `http://enroll.cisco.com` | [ ] | |
| TC-RED-003 | Edge launched as primary browser | Edge installed | Run runner | Edge is the browser process launched (not Chrome, Firefox, or IE) | [ ] | If Edge not found, default browser is fallback — verify log |
| TC-RED-004 | Browser PID captured in completion flag | Script completes | Inspect `portal_complete.flag` → `browser_pid` field | Contains a non-zero integer matching the Edge process PID | [ ] | `Get-Process msedge` to cross-reference |
| TC-RED-005 | Smart wait polls every 5 seconds | Portal auth pending | Watch log during 150-second wait window | Log shows reachability check entries at ~5-second intervals (not fixed 150s sleep) | [ ] | |
| TC-RED-006 | Early exit on HTTP 200 from `https://www.optum.com` | Corporate WiFi with Internet access | Complete portal auth; observe script timing | Script exits the polling loop immediately when `optum.com` returns 200 — no wait for remainder of 150s | [ ] | Time from auth complete to flag write should be < 10s |
| TC-RED-007 | Full 150s wait when auth never completes | No portal auth performed | Run runner; do not interact with browser | Script waits the full 150 seconds before showing timeout notification | [ ] | |
| TC-RED-008 | Validation browser opens to `https://www.optum.com` | Auth completes | Complete portal auth; observe behavior | A second browser window opens to `https://www.optum.com` after auth | [ ] | |
| TC-RED-009 | Validation browser launched maximized | Auth completes | Complete portal auth; observe Edge window | Validation browser launches maximized (`--start-maximized` flag) | [ ] | |
| TC-RED-010 | Cisco browser killer runs for 20 seconds | Redirect flow active | Start runner; time killer job duration | Cisco browser killer job terminates at approximately 20 seconds | [ ] | Inspect log for killer stop message |

---

## 6. Walled-Garden Portal Flow (RC1.17)

Tests for `Invoke-WalledGardenRemediation`. These are the new RC1.17 behaviors.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-WG-001 | Toast notification appears before browser launch | Walled-garden state file present | Run runner in walled-garden mode; observe screen | Windows toast notification appears **before** any browser window opens | [ ] | |
| TC-WG-002 | Toast shows gateway IP as text | State file with `gateway_ip=172.20.0.1` | Observe toast content | Toast body contains `172.20.0.1` as readable text | [ ] | GPO safety net — user can copy-paste even if browser fails |
| TC-WG-003 | Toast shows SSID name | State file with `ssid=HotelWifi` | Observe toast content | Toast body contains `HotelWifi` | [ ] | |
| TC-WG-004 | Toast shows fallback URL | Any walled-garden run | Observe toast content | Toast body contains `http://1.1.1.1` | [ ] | |
| TC-WG-005 | Browser opens to `http://<gateway_ip>` (primary) | State file with `gateway_ip=192.168.1.1`; no Edge GPO blocking HTTP-to-IP | Run runner; observe browser | Edge opens to `http://192.168.1.1` | [ ] | |
| TC-WG-006 | Fallback `http://1.1.1.1` opens after 10s no connectivity | Walled garden; `http://<gateway_ip>` unreachable | Run runner; gateway IP blocked; wait 10+ seconds | A second browser tab opens to `http://1.1.1.1` approximately 10 seconds after primary browser launch | [ ] | |
| TC-WG-007 | Fallback does NOT open if connectivity restored within 10s | Walled garden; auth completed quickly | Complete portal auth within 10 seconds | Only one browser opened; no `http://1.1.1.1` tab | [ ] | |
| TC-WG-008 | Smart wait polls for connectivity | Walled-garden flow, auth pending | Watch log during wait | Log shows reachability check entries at ~5-second intervals | [ ] | Same polling mechanism as redirect path |
| TC-WG-009 | Auth success → validation browser opens → SUCCESS in flag | Walled garden; auth completed | Complete portal auth | Validation browser opens to `https://www.optum.com`; flag status is `SUCCESS` | [ ] | |
| TC-WG-010 | Timeout → TIMEOUT in flag | Walled garden; no auth | Do not interact with portal; wait 150s | Completion flag status is `TIMEOUT` (not `FAILED` or `PARTIAL`) | [ ] | |
| TC-WG-011 | Gateway IP in TIMEOUT flag details | Walled garden; timeout occurred | Inspect completion flag after timeout | `details` field contains gateway IP string | [ ] | |
| TC-WG-012 | State file cleared on completion | Walled-garden run completes (any outcome) | Inspect `cap_portal_remediation_active.flag` after run | File no longer exists | [ ] | |
| TC-WG-013 | State file cleared on both success AND timeout | Run through both paths in sequence | Complete one successful run, one timeout run | State file absent after each run | [ ] | |
| TC-WG-014 | Edge GPO blocks HTTP-to-IP → toast still visible (manual) | Corporate endpoint with `NavigateToIPAddress` GPO enforced | Run runner; observe browser and toast | Edge shows error page for `http://<gateway_ip>`; toast notification remains visible with IP text for manual navigation | [ ] | **Manual field test — cannot be automated** |
| TC-WG-015 | Cisco browser killer runs during walled-garden flow | Walled-garden state file present | Run runner; check job start/stop in log | Cisco browser killer starts at entry and stops after ~20 seconds | [ ] | |

---

## 7. VPN Stabilization (Redirect Path)

After portal auth completes on the redirect path, the runner checks for a remediation state file and optionally waits for VPN to reach a stable state before launching the validation browser.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-VPN-001 | No state file → VPN stabilization skipped | No remediation state file | Run redirect flow; observe behavior | No VPN stabilization wait; validation browser launches immediately after auth | [ ] | Log should show skip message |
| TC-VPN-002 | State file present, VPN Connected → proceeds immediately | State file present; `vpncli.exe` reports `Connected` | Run redirect flow through auth; observe timing | Validation browser launches without waiting for VPN | [ ] | |
| TC-VPN-003 | State file present, VPN Disconnected → proceeds immediately | State file present; VPN not connected | Run redirect flow; observe behavior | Validation browser launches without VPN wait | [ ] | |
| TC-VPN-004 | State file present, VPN Connecting → polls every 5s up to 60s | State file present; VPN in `Connecting` state | Run redirect flow; observe log during VPN wait window | Log shows VPN state checks at ~5-second intervals for up to 60 seconds | [ ] | |
| TC-VPN-005 | VPN reaches Connected within 60s | VPN transitions from Connecting to Connected | Run redirect flow; observe timing | Validation browser launches as soon as VPN reaches Connected | [ ] | |
| TC-VPN-006 | VPN still intermediate after 60s → proceeds with WARN | VPN stuck in Connecting for >60s | Allow 60-second timeout; observe behavior | Runner logs WARN and proceeds to launch validation browser anyway | [ ] | |
| TC-VPN-007 | `vpncli.exe` not found → skips VPN check | `vpncli.exe` renamed or absent from expected path | Run redirect flow | Runner logs DEBUG and proceeds without VPN check | [ ] | |
| TC-VPN-008 | State file removed after VPN stabilization | State file present; VPN check completes | Run redirect flow to completion | `cap_portal_remediation_active.flag` is absent after completion | [ ] | |

---

## 8. DNS Chicken/Egg Detection (ER5)

The runner checks for `dns_chicken_egg_issue.flag` at startup. If present, it skips browser launch and shows an error dialog.

**DNS issue flag file path:** `C:\ProgramData\WhiteWalker\dns_chicken_egg_issue.flag`

**Sample flag file JSON:**
```json
{
  "timestamp": "2026-05-26T14:00:00Z",
  "failure_count": 12,
  "details": "DNS resolution failed 12 consecutive times",
  "allow_retry": false
}
```

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-DNS-001 | DNS issue flag present → error popup, no browser | Drop `dns_chicken_egg_issue.flag` with valid JSON | Run runner | Error dialog appears; no browser window launched | [ ] | |
| TC-DNS-002 | DNS flag parsed correctly | Flag file with `failure_count` and `details` fields | Observe error dialog text | Dialog contains information from flag file | [ ] | |
| TC-DNS-003 | DNS flag deleted after reading | Flag file present; runner starts | Run to completion; inspect directory | `dns_chicken_egg_issue.flag` no longer exists after runner exits | [ ] | |
| TC-DNS-004 | RETRY hidden when `allow_retry=false` | Flag file with `"allow_retry": false` | Run runner; observe dialog | Dialog shows EXIT button only; RETRY button is hidden | [ ] | |
| TC-DNS-005 | Completion flag written as `DNS_CHICKEN_EGG` | DNS flag triggers popup path | Run runner to completion | `portal_complete.flag` has `status = "DNS_CHICKEN_EGG"` | [ ] | |
| TC-DNS-006 | 10+ consecutive DNS failures → `Test-DNSChickenEggProblem` returns true | Pester test environment | Run Pester suite (TC-AUTO-001) | Pester test for `Test-DNSChickenEggProblem` with ≥10 failures passes | [ ] | |
| TC-DNS-007 | Fewer than 10 DNS failures → returns false | Pester test environment | Run Pester suite (TC-AUTO-001) | Pester test for `Test-DNSChickenEggProblem` with <10 failures passes | [ ] | |

---

## 9. Timeout Notification UI (ER3/ER5)

`Show-TimeoutNotification` displays a Windows Forms dialog when authentication does not complete within the wait window.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-NOTIF-001 | Standard timeout message shown | Auth not completed within 150s | Allow 150s to elapse without auth | Timeout dialog appears with standard message | [ ] | |
| TC-NOTIF-002 | RETRY button visible in standard timeout | No `PortalIssues` provided | Observe standard timeout dialog | RETRY button is visible and clickable | [ ] | |
| TC-NOTIF-003 | EXIT button always visible | Any timeout condition | Observe any timeout dialog | EXIT button is always present | [ ] | |
| TC-NOTIF-004 | Dialog is TopMost | Timeout dialog active | Open other windows; observe dialog position | Dialog appears above all other windows | [ ] | |
| TC-NOTIF-005 | Dialog centered on screen | Timeout dialog active | Observe dialog position | Dialog appears centered on the primary display | [ ] | |
| TC-NOTIF-006 | Custom message shown when `PortalIssues` provided | DNS chicken/egg or other `PortalIssues` data | Trigger a portal issue condition; observe dialog | Dialog body shows the custom issue message rather than standard timeout text | [ ] | |
| TC-NOTIF-007 | RETRY hidden when `allow_retry=false` | `PortalIssues` data with `allow_retry=false` | Trigger DNS chicken/egg with `allow_retry=false` | Dialog shows EXIT only | [ ] | |
| TC-NOTIF-008 | Dialog title reads "CPR+ - Network Authentication Timeout" | Any timeout dialog | Observe dialog title bar | Title is exactly `CPR+ - Network Authentication Timeout` | [ ] | |
| TC-NOTIF-009 | Window is FixedDialog | Any timeout dialog | Attempt to resize dialog | Window cannot be resized; maximize and minimize buttons absent | [ ] | `FormBorderStyle = FixedDialog` |
| TC-NOTIF-010 | Returns "RETRY" on RETRY click | Dialog active | Click RETRY button | Script continues on RETRY path (network reconnect initiated) | [ ] | |
| TC-NOTIF-011 | Returns "EXIT" on EXIT click | Dialog active | Click EXIT button | Script writes `USER_EXIT` to completion flag and exits | [ ] | |

---

## 10. Network Reconnect (ER3)

When the user clicks RETRY in the timeout dialog, the runner disconnects and reconnects the current WiFi SSID before writing the completion flag.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-RECONNECT-001 | Browsers killed before reconnect | RETRY selected | Observe process list after RETRY clicked | All browser processes terminated before network commands issued | [ ] | |
| TC-RECONNECT-002 | Current SSID detected via `netsh` | Connected to any SSID | RETRY path triggered | Log shows SSID correctly read from `netsh wlan show interfaces` | [ ] | |
| TC-RECONNECT-003 | `netsh wlan disconnect` issued with correct interface | RETRY path triggered | Inspect log | Log contains `netsh wlan disconnect` with interface name | [ ] | |
| TC-RECONNECT-004 | 3 second wait between disconnect and reconnect | RETRY path triggered | Time the gap between disconnect and reconnect log entries | ~3 seconds between disconnect and reconnect commands | [ ] | |
| TC-RECONNECT-005 | `netsh wlan connect` issued with same SSID | RETRY path triggered | Inspect log | Log contains `netsh wlan connect` with original SSID name | [ ] | |
| TC-RECONNECT-006 | Successful reconnect → `RETRY_REQUESTED` in flag | Network reconnects within timeout | Inspect completion flag after RETRY | `status = "RETRY_REQUESTED"` | [ ] | |
| TC-RECONNECT-007 | Failed reconnect → `RETRY_FAILED` in flag | Disconnect but do not reconnect (disable AP) | Inspect completion flag after RETRY | `status = "RETRY_FAILED"` | [ ] | |
| TC-RECONNECT-008 | EXIT → no network actions, `USER_EXIT` in flag | Timeout dialog active | Click EXIT | No `netsh` commands in log; flag `status = "USER_EXIT"` | [ ] | |

---

## 11. Cisco Browser Killer

Background job that terminates Cisco browser-related processes for 20 seconds to prevent interference with the captive portal browser.

**Processes targeted:** `acwebhelper`, `CiscoCollabHost`, `CiscoAnyConnectWebView`, `CiscoWebLaunchHelper`, `CiscoWebHelper`

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-CBK-001 | Background job starts on entry (both paths) | Either redirect or walled-garden state | Run runner; check `Get-Job` early in execution | Cisco killer job is present and in Running state | [ ] | Check within first 5s of script start |
| TC-CBK-002 | Kills all five named processes | All five Cisco processes running | Launch all five processes; run runner | All five terminated within 20 seconds | [ ] | |
| TC-CBK-003 | Runs for 20 seconds | Runner started | Time from job start log entry to job stop log entry | Approximately 20 seconds | [ ] | |
| TC-CBK-004 | Kill count logged when processes terminated | At least one Cisco process running | Run runner with Cisco processes present | Log entry shows number of processes killed | [ ] | Example: `[INFO] Killed 2 Cisco browser processes` |
| TC-CBK-005 | Null-safe when no Cisco processes running | No Cisco processes present | Run runner without any Cisco processes | No errors; no exception; job completes normally | [ ] | |
| TC-CBK-006 | Job stopped and removed on script exit | Runner runs to any terminal state | Inspect `Get-Job` after script exits | No lingering background jobs from this script | [ ] | |

---

## 12. Browser Foreground Management (RC1.10)

`Invoke-BringToForeground` ensures the captive portal browser is visible to the user immediately after launch.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-BFGD-001 | Browser brought to foreground after launch | Any browser launch (redirect or walled-garden) | Run runner; observe browser immediately after launch | Browser window appears in front of all other windows | [ ] | |
| TC-BFGD-002 | Window handle polling up to 3000ms in 250ms steps | Browser launched | Inspect log timing around foreground call | Log shows polling attempts at 250ms intervals; total wait ≤ 3000ms | [ ] | |
| TC-BFGD-003 | SW_RESTORE + SW_MAXIMIZE + SetForegroundWindow called | Browser launched | Verify via Pester test | Pester mocks verify Win32 calls are made in correct sequence | [ ] | |
| TC-BFGD-004 | Falls back to most recent Edge window if process has no main window | Browser launched but main window handle is zero | Trigger via fast machine where handle isn't immediately available | Log shows fallback to most recent Edge window | [ ] | |
| TC-BFGD-005 | Logs WARN if no window handle after 3000ms | No window handle found within 3000ms | Block window creation (test environment) | WARN log entry; script continues without crash | [ ] | |

---

## 13. Task Scheduler Integration

Manual tests verifying the trigger chain: `WW_main` → FlareGun → Task Scheduler → CPR+.

> **Note:** These tests require a fully deployed WhiteWalker installation. They cannot be Pester-automated.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-TS-001 | FlareGun Event 777 written to APPLICATION log by WW_main | WW_main running; captive portal detected | Trigger portal detection; inspect Event Log (`eventvwr`) | Event 777 appears in APPLICATION log with source `WhiteWalkerFlareGun` | [ ] | `Get-WinEvent -LogName Application -FilterXPath "*[System[EventID=777]]" -MaxEvents 5` |
| TC-TS-002 | Task Scheduler fires on Event 777 | Task Scheduler job registered with Event 777 trigger | Observe Task Scheduler history after Event 777 fires | Task `WW_cap_portal_runner` shows Running status | [ ] | `Get-ScheduledTask -TaskName "WW_cap_portal_runner"` |
| TC-TS-003 | CPR+ runs in USER context | Task configured for user context | Check log at script start | Log entry includes `username` of the logged-on user (not SYSTEM) | [ ] | |
| TC-TS-004 | CPR+ runs with `-WindowStyle Hidden` | Task Scheduler action configured | Run via Task Scheduler; observe desktop | No PowerShell console window appears during CPR+ execution | [ ] | |
| TC-TS-005 | CPR+ reads remediation state file written by WW_main | WW_main wrote state file before firing Event 777 | Inspect log after CPR+ launches | Log shows `portal_type` value read from state file | [ ] | |
| TC-TS-006 | `captive_walled_garden` Event 797 written (SYSTEM context) | Walled-garden detected by WW_main | Inspect APPLICATION event log | Event 797 appears in APPLICATION log from SYSTEM context | [ ] | |
| TC-TS-007 | `captive_portal_browser` Event 777 written after Event 797 | Walled-garden path active | Inspect APPLICATION event log timestamps | Event 797 precedes Event 777 in the same run | [ ] | |

---

## 14. FlareGun Integration

Verifies the FlareGun configuration file (`WW_flaregun_config.json`) contains all required entries for RC1.17.

| ID | Title | Preconditions | Steps | Expected Result | Pass | Notes |
|---|---|---|---|---|---|---|
| TC-FG-001 | `captive_walled_garden` entry present with event_id 797 | `WW_flaregun_config.json` in place | `(Get-Content .\WW_flaregun_config.json \| ConvertFrom-Json).flare_events.captive_walled_garden` | Returns object with `event_id = 797` | [ ] | |
| TC-FG-002 | `captive_walled_garden` context is SYSTEM | Inspect config | Same as TC-FG-001 | `context = "SYSTEM"` | [ ] | |
| TC-FG-003 | `no_net_transient` entry present with event_id 798 | Inspect config | `(Get-Content .\WW_flaregun_config.json \| ConvertFrom-Json).flare_events.no_net_transient` | Returns object with `event_id = 798` | [ ] | |
| TC-FG-004 | `captive_portal_browser` entry present with event_id 777, context USER | Inspect config | Check `captive_portal_browser` entry | `event_id = 777`, `context = "USER"` | [ ] | |
| TC-FG-005 | All existing flare entries still present (regression) | Inspect config | Count `flare_events` keys | All pre-RC1.17 entries still present: `user_tun`, `mgmt_tun`, `off_prem_no_vpn`, `on_prem`, `ise_employee_captive_portal`, `ise_posture_compliant`, `ise_posture_failed`, `ise_guest_captive_portal`, `non_ise_captive_portal`, `captive_portal_browser`, `captive_portal_dns_misconfiguration`, `deep_diagnostics`, `notify_user` | [ ] | |

---

## 15. End-to-End Field Scenarios

Full real-world walkthrough tests. Performed manually in lab or field. Each scenario is a complete user experience from network connection to CPR+ completion.

> **Note:** Record pass/fail for each step within the scenario. A scenario only passes if every step passes.

---

### Scenario A: Corporate WiFi → ISE Posture Redirect

**Prerequisites:** Test endpoint is domain-joined; Cisco Secure Client installed; WLANi03 or lab equivalent SSID available; ISE policy server configured to require posture.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| A1 | Connect to WLANi03 (or lab ISE WiFi) before posture compliant | Network connects; no Internet access yet | [ ] |
| A2 | Observe WW_main behavior | WW_main detects ISE redirect captive portal; writes state file with `portal_type=redirect`; fires Event 777 | [ ] |
| A3 | Observe Task Scheduler | CPR+ launches in user context within a few seconds of Event 777 | [ ] |
| A4 | Observe CPR+ behavior | Toast or browser opens to `http://enroll.cisco.com`; Cisco browser killer runs | [ ] |
| A5 | Complete ISE posture in browser | AnyConnect posture scan completes; ISE redirects to success page | [ ] |
| A6 | Observe CPR+ polling | CPR+ detects `optum.com` 200 early; exits poll loop | [ ] |
| A7 | Observe validation browser | Validation browser opens to `https://www.optum.com` | [ ] |
| A8 | Inspect completion flag | `status = "SUCCESS"` | [ ] |
| A9 | Inspect log | End-to-end log shows clean redirect flow | [ ] |

---

### Scenario B: Hotel WiFi → Walled Garden (simulated)

**Prerequisites:** Walled-garden simulation active (DNS blocked, gateway reachable at `192.168.1.1`); `WW_main` deployed and running.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| B1 | Connect to hotel/simulated AP | Network connects; DNS fails; gateway pingable | [ ] |
| B2 | Observe WW_main behavior | WW_main detects walled-garden; writes state file with `portal_type=walled_garden`, `gateway_ip=192.168.1.1`; fires Event 797 then Event 777 | [ ] |
| B3 | Observe Task Scheduler | CPR+ launches in user context | [ ] |
| B4 | Toast notification appears | Toast shows gateway IP `192.168.1.1` and SSID name before browser opens | [ ] |
| B5 | Browser opens to `http://192.168.1.1` | Edge navigates to gateway IP | [ ] |
| B6 | Complete portal auth on hotel page | Auth completes; DNS unblocked | [ ] |
| B7 | Observe CPR+ polling | Connectivity detected; poll loop exits early | [ ] |
| B8 | Validation browser opens | `https://www.optum.com` opens | [ ] |
| B9 | Inspect completion flag | `status = "SUCCESS"` | [ ] |
| B10 | Inspect state file | `cap_portal_remediation_active.flag` is gone | [ ] |

---

### Scenario C: Walled Garden → Edge GPO Blocks HTTP-to-IP

**Prerequisites:** Corporate endpoint with Edge `NavigateToIPAddress` GPO enforced; walled-garden state file in place.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| C1 | Run CPR+ in walled-garden mode | Toast notification appears with gateway IP | [ ] |
| C2 | Observe browser launch | Edge opens but shows error page (GPO block) | [ ] |
| C3 | User reads toast | Gateway IP is clearly visible as text in the toast | [ ] |
| C4 | User opens alternate browser (or Edge InPrivate) and navigates manually | User can complete portal auth using info from toast | [ ] |
| C5 | Observe CPR+ polling | Connectivity detected; flag written correctly | [ ] |

---

### Scenario D: Guest WiFi (Non-ISE Redirect)

**Prerequisites:** AP with non-ISE captive portal (e.g., consumer router); WW_main configured to detect non-ISE portals.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| D1 | Connect to guest SSID | Network connects; portal redirect active | [ ] |
| D2 | WW_main detects portal; fires Event 777 | CPR+ launches | [ ] |
| D3 | Browser opens to captive portal URL | Portal page displayed | [ ] |
| D4 | User completes guest portal auth | Auth completes | [ ] |
| D5 | Validation browser opens | `https://www.optum.com` visible | [ ] |
| D6 | Inspect flag | `status = "SUCCESS"` | [ ] |

---

### Scenario E: Authentication Timeout → RETRY

**Prerequisites:** Any portal scenario active; user must not interact with portal browser.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| E1 | Run CPR+; do not interact with browser | Browser open, no auth | [ ] |
| E2 | Wait 150 seconds | Timeout notification dialog appears | [ ] |
| E3 | Click RETRY | Dialog closes; network disconnect/reconnect initiated | [ ] |
| E4 | Inspect log | `netsh wlan disconnect` and `netsh wlan connect` logged | [ ] |
| E5 | Inspect completion flag | `status = "RETRY_REQUESTED"` | [ ] |
| E6 | WW_main re-triggers CPR+ | Event 777 fires again; CPR+ relaunches | [ ] |

---

### Scenario F: Authentication Timeout → EXIT

**Prerequisites:** Any portal scenario active.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| F1 | Run CPR+; do not interact with browser | Browser open, no auth | [ ] |
| F2 | Wait 150 seconds | Timeout notification appears | [ ] |
| F3 | Click EXIT | Dialog closes immediately | [ ] |
| F4 | Inspect log | No `netsh` commands in log | [ ] |
| F5 | Inspect completion flag | `status = "USER_EXIT"` | [ ] |
| F6 | Verify no further automation | WW_main does not relaunch CPR+ after USER_EXIT | [ ] |

---

### Scenario G: DNS Chicken/Egg

**Prerequisites:** Network blocks DNS until portal accepted, but portal URL itself requires DNS resolution.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| G1 | WW_main writes `dns_chicken_egg_issue.flag` with `"allow_retry": false` | Flag file exists in `C:\ProgramData\WhiteWalker\` | [ ] |
| G2 | CPR+ launches | Runner reads and parses flag file | [ ] |
| G3 | Observe CPR+ behavior | Error dialog appears; no browser launched | [ ] |
| G4 | Inspect dialog | Shows issue details; RETRY button absent | [ ] |
| G5 | Click EXIT | Dialog closes | [ ] |
| G6 | Inspect completion flag | `status = "DNS_CHICKEN_EGG"` | [ ] |
| G7 | Inspect state file directory | `dns_chicken_egg_issue.flag` is gone | [ ] |

---

### Scenario H: Wake from Sleep with Captive Portal

**Prerequisites:** Laptop with active VPN; hotel WiFi. Laptop sleeps and wakes on hotel network.

| Step | Action | Expected Result | Pass |
|---|---|---|---|
| H1 | Let laptop sleep; move to hotel WiFi | — | [ ] |
| H2 | Wake laptop | Windows reconnects to hotel WiFi; VPN in intermediate state | [ ] |
| H3 | WW_main runs | Detects walled-garden; VPN disconnect may have been issued by WW_main | [ ] |
| H4 | State file written | `portal_type=walled_garden`; `gateway_ip` populated | [ ] |
| H5 | CPR+ launches | Toast and browser appear | [ ] |
| H6 | Complete portal auth | Connectivity restored | [ ] |
| H7 | VPN reconnects | Cisco Secure Client reconnects after portal success | [ ] |
| H8 | Inspect completion flag | `status = "SUCCESS"` | [ ] |

---

## 16. Regression Checklist

Run this checklist on every release to verify previously fixed bugs have not regressed. Each item corresponds to a historical fix.

| Bug Ref | Description | How to Verify | Pass | Notes |
|---|---|---|---|---|
| ER3 | `Test-SiteReachability` uses 3s timeout (not 8s) | Pester: mock site check with 3s timeout assertion | [ ] | Prevents hang inside 5s polling loop |
| ER3 | Edge `ArgumentList` uses array syntax | Pester: verify `Start-Process` called with `@(...)` not comma string | [ ] | |
| ER5 | Captive portal Event 777 routes through FlareGun | Inspect log for FlareGun dispatch; no direct `eventcreate` calls | [ ] | |
| ER5 | `user_prompted.flag` included in stale flag cleanup | Verify cleanup routine removes `user_prompted.flag` | [ ] | |
| RC1.3 | Redirect detected on `200+Location` response | Test with ISE that returns 200 with Location header | [ ] | Not just standard 3xx |
| RC1.8 | WLANi03 with no IP waits up to 18s before `no_net_transient` | Connect to WLANi03; block DHCP; observe WW_main wait | [ ] | |
| RC1.9 | Blackhole `-rm` fires unconditionally on non-on-prem states | Inspect WW_main log on any non-on-prem detection | [ ] | |
| RC1.10 | SSID cache written at end of every run | Inspect SSID cache file after each WW_main run | [ ] | Not just on nwcheck 200 |
| RC1.15 | Walled-garden exits as `captive_walled_garden`, not `no_net_transient` | Event log shows Event 797 (not 798) for walled-garden | [ ] | |
| RC1.17 | Walled-garden browser launch NOT done from WW_main (runner owns it) | Inspect WW_main code/log — no browser open call on walled-garden path | [ ] | Runner is sole owner of browser lifecycle |

---

## 17. Log Analysis Guide

### 17.1 Successful Redirect Flow — Log Pattern

```
2026-05-26 14:30:00.100 -05:00 [CAP] [INFO] CPR+ starting (v1.10.0_RC1.17)
2026-05-26 14:30:00.150 -05:00 [CAP] [INFO] Username: DOMAIN\jsmith
2026-05-26 14:30:00.200 -05:00 [CAP] [INFO] No remediation state file - using redirect portal flow
2026-05-26 14:30:00.250 -05:00 [CAP] [INFO] Starting Cisco browser killer job
2026-05-26 14:30:00.300 -05:00 [CAP] [INFO] Opening captive portal browser: http://enroll.cisco.com (PID: 14532)
2026-05-26 14:30:05.000 -05:00 [CAP] [INFO] Checking site reachability...
2026-05-26 14:30:10.000 -05:00 [CAP] [INFO] Checking site reachability...
2026-05-26 14:30:21.000 -05:00 [CAP] [INFO] Site reachable - authentication complete (early exit)
2026-05-26 14:30:21.050 -05:00 [CAP] [INFO] Opening validation browser: https://www.optum.com
2026-05-26 14:30:21.100 -05:00 [CAP] [INFO] Completion flag written: SUCCESS
```

### 17.2 Successful Walled-Garden Flow — Log Pattern

```
2026-05-26 14:30:00.100 -05:00 [CAP] [INFO] CPR+ starting (v1.10.0_RC1.17)
2026-05-26 14:30:00.200 -05:00 [CAP] [INFO] Remediation state file found: portal_type=walled_garden gateway_ip=192.168.1.1 ssid=HotelWifi
2026-05-26 14:30:00.250 -05:00 [CAP] [INFO] Starting Cisco browser killer job
2026-05-26 14:30:00.300 -05:00 [CAP] [INFO] [WG] Showing toast: gateway_ip=192.168.1.1 ssid=HotelWifi
2026-05-26 14:30:00.400 -05:00 [CAP] [INFO] [WG] Opening primary browser: http://192.168.1.1
2026-05-26 14:30:05.000 -05:00 [CAP] [INFO] Checking site reachability...
2026-05-26 14:30:35.000 -05:00 [CAP] [INFO] Site reachable - authentication complete (early exit)
2026-05-26 14:30:35.050 -05:00 [CAP] [INFO] Opening validation browser: https://www.optum.com
2026-05-26 14:30:35.100 -05:00 [CAP] [INFO] State file cleared
2026-05-26 14:30:35.200 -05:00 [CAP] [INFO] Completion flag written: SUCCESS
```

### 17.3 Timeout vs Genuine Network Failure

| Log Pattern | Meaning |
|---|---|
| `Completion flag written: TIMEOUT` after 150s of poll | Normal portal timeout — user didn't auth |
| `Completion flag written: FAILED` | Script hit an unexpected error path |
| `Site reachability: failed (timeout)` repeated 30 times then `TIMEOUT` | Full poll window elapsed — portal not completed |
| `DNS resolution failed` in WW_main log but `TIMEOUT` in CPR+ flag | Possible DNS chicken/egg not caught at startup |

### 17.4 Key Log Strings Reference

| Log String | Meaning |
|---|---|
| `CPR+ starting` | Script entry point |
| `No remediation state file` | Redirect flow selected |
| `portal_type=walled_garden` | Walled-garden flow selected |
| `dns_chicken_egg_issue.flag found` | DNS chicken/egg branch taken |
| `Starting Cisco browser killer job` | Background kill job started |
| `early exit` | Portal auth detected; poll loop exited before 150s |
| `Cisco browser killer stopped` | Kill job finished (≈20s after start) |
| `State file cleared` | `cap_portal_remediation_active.flag` removed |
| `Completion flag written:` | Terminal state recorded |

### 17.5 Correlating WW_main Log with CPR+ Log

Both logs use the same timestamp format. To correlate:

1. Find the Event 777 write in WW_main log: grep for `captive_portal_browser`
2. Note the timestamp (e.g., `14:30:00`)
3. Find `CPR+ starting` in `white_walker.cap_portal.log` at the same time ± a few seconds (Task Scheduler latency)

```powershell
# Tail both logs simultaneously (run in separate terminals):
.\tail_ww_log.ps1       # WW_main log
.\tail_ww_cap_log.ps1   # CPR+ log
```

### 17.6 Reading the Completion Flag

```powershell
$flag = Get-Content "C:\ProgramData\WhiteWalker\portal_complete.flag" | ConvertFrom-Json

$flag.status      # SUCCESS, FAILED, TIMEOUT, etc.
$flag.timestamp   # ISO 8601 timestamp of completion
$flag.username    # DOMAIN\user who ran CPR+
$flag.browser_pid # PID of the captive portal browser (0 if not launched)
$flag.details     # Additional context (gateway IP for walled-garden, etc.)
```

Expected fields for each status:

| Status | Required Fields | Notes |
|---|---|---|
| `SUCCESS` | `status`, `timestamp`, `username`, `browser_pid` | `details` optional |
| `TIMEOUT` | `status`, `timestamp`, `username`, `browser_pid`, `details` | `details` should include reason |
| `RETRY_REQUESTED` | `status`, `timestamp`, `username` | Network reconnect was triggered |
| `RETRY_FAILED` | `status`, `timestamp`, `username`, `details` | `details` contains netsh output or error |
| `USER_EXIT` | `status`, `timestamp`, `username` | User clicked EXIT |
| `DNS_CHICKEN_EGG` | `status`, `timestamp`, `username` | Browser was never launched |
| `FAILED` | `status`, `timestamp`, `username`, `details` | Unexpected error; check `details` for exception |

---

*This document is a living test plan. When new functionality is added to CPR+, add new test sections here and update the Version History table at the top.*
