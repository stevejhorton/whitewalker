# CPR+ (WhiteWalker) RC1.13 - Technical Overview

**Project:** CPR+ / WhiteWalker  
**Current Version:** 3.14.0_RC1.13  
**Author:** steve.horton@optum.com  
**Last Updated:** May 2026  
**Environment:** Optum/UnitedHealth Group Global VPN Infrastructure  

---

## Executive Summary

CPR+ (formerly WhiteWalker) is a PowerShell-based zero-touch automation framework that solves the critical challenge of maintaining network connectivity across heterogeneous environments. It automatically handles:

- ISE 802.1x posture remediation
- Captive portal authentication
- VPN state management
- Network classification and routing

The framework runs in SYSTEM context via Task Scheduler, triggered by DHCP lease events, system unlock, or wake-from-sleep, ensuring endpoints remain productive across corporate, guest, and public networks without user intervention.

---

## Core Architecture

### Execution Model

**Primary Triggers:**
- DHCP lease acquisition (Event ID 50058)
- System unlock (Event ID 4800/4801)
- Wake from sleep (Kernel-Power Event ID 1/107)

**Contexts:**
- **SYSTEM context** (WW_main.ps1) - Network probing, ISE rescans, infrastructure detection
- **USER context** (WW_cap_portal_runner.ps1) - Browser-based authentication, user-facing actions

**Execution Flow:**
```
Task Scheduler → WW_main.ps1 (SYSTEM)
                      ↓
               Network Classification
                      ↓
        ┌─────────────┴──────────────┐
        │                             │
   ISE Redirect                  Captive Portal
        │                             │
   Auto-rescan                  Event 777 → Task Scheduler
        │                             │
   Exit Success              WW_cap_portal_runner.ps1 (USER)
                                      │
                               Browser Auth → Validation
```

---

## Network Classification Engine

### Single Preflight Architecture (RC1 Core)

**Endpoint:** `https://gateway.optum.com`  
**Response Interpretation:**
- **HTTP 404 + known JSON** → Online (gateway routing table "no match" = proof of life)
- **HTTP 200 + Location header** → Redirect detected
- **Timeout/Connection failure** → Network unreachable

This single call determines all workflow routing - no multi-step probing required.

### VPN State Detection

**Critical Implementation Detail:**  
Standard `vpncli.exe state` returns **stale** data on first line. RC1 architecture:

1. Capture **second state line** from vpncli output
2. Parse `Management Connection State:` field for authoritative classification
3. Management tunnels show "Disconnected" on basic state but "Connected" on management state

**VPN States:**
- `user_tun` - Full user VPN tunnel active
- `mgmt_tun` - Management-only tunnel (limited access)
- `Disconnected` - No tunnel
- Intermediate states (`Connecting`, `Reconnecting`) - Connection in progress

**Intermediate State Handling:**
- Detected via wake-from-sleep event correlation (Kernel-Power ID 1/107)
- Grace window: 2 minutes post-wake
- If VPN still intermediate after wake grace → forced disconnect (prevents blocking local auth)
- If intermediate without recent wake → allow connection (legitimate AlwaysOn VPN)

### SSID Change Detection (RC1.10+)

**Problem Solved:** VPN attempts on new network block captive portal/ISE traffic

**Implementation:**
1. SSID cached in `ssid_last_known.flag` after successful nwcheck
2. On SSID change + active VPN → 15s grace window for VPN to progress
3. If VPN stuck after grace → forced disconnect + `ssid_changed.flag` set
4. Flag cleared when nwcheck confirms network accessibility
5. Cache updated ONLY after 200 response (prevents caching bad SSIDs)

**Config Variables:**
- `$SsidCacheFile` - Last known good SSID
- `$SsidChangedFlag` - SSID change detected marker
- `$VpnSsidChangeGraceSec` = 15s
- `$VpnSsidChangePollSec` = 3s

### Domain Controller Reachability

**Test:** Ping to `$DC_FQDN` with SSID awareness
**Gather DNS Suffix List:** If ANY untrusted suffixes exitst, user off prem or on VPN. (drives VPN Blackhole logic if enabled)
**SSID Exclusions:** xfinitywifi, Starbucks WiFi, attwifi, etc.  
**Purpose:** Distinguish on-premises from off-premises with stale VPN routes

Critical: DC reachability on public WiFi SSIDs while OFF VPN = false positive. SSID and SUFFIX checks prevents misclassification when stale VPN routes exist.

---

## ISE Posture Remediation

### Redirect Detection

**RC1.3 Critical Fix:** ISE PSNs return non-standard HTTP 200 + Location header (not proper 302/307)

**Detection Logic:**
```
ANY 2xx or 3xx response with Location header = redirect
```

This handles both:
- Standard HTTP redirects (302, 307)
- ISE quirks (200 + Location)

### Rescan Workflow

1. **Redirect Classification:** Parse redirect URL for ISE employee PSN pattern
2. **Service Wait:** Poll for `csc_iseagent`, `ciscod.exe`, or other posture services (default: 30s timeout)
3. **Invoke Rescan:** Execute `vpncli.exe posture reapply -session network/Corporate`
4. **Compliance Monitor:** Poll ISE status via event logs (default: 120s timeout)
5. **Post-Compliance Verification (RC1.5):** Poll gateway.optum.com for up to 30s to confirm ACL lift

**Why Post-Compliance Verification?**  
ISE agent may report "Compliant" before WLC propagates ACL change. Independent nwcheck verification ensures network access is actually restored.

**Posture Services Detected:**
- `csc_iseagent` (Cisco Secure Client ISE Agent)
- `ciscod.exe` (Cisco legacy daemon)
- `ISEPOSAgent` (ISE POS Agent)
- `ISEAgent` (generic ISE agent)

### Compliance Detection

**Event Log Monitoring:** Application log, Cisco Secure Client source  
**Success Indicators:**
- Event ID matching compliance keywords
- Message text containing "Compliant", "Compliance Checking succeeded", etc.

**Failure Scenarios:**
- Timeout (120s default)
- "Failed" / "Non-Compliant" events
- Service unavailable

---

## Captive Portal Remediation

### Detection Patterns

**HTTP Response Analysis:**
```
Status 2xx/3xx + Location header → redirect detected
```

**Redirect Classification:**
- **ISE_EMPLOYEE** - Matches employee PSN pattern → auto-rescan
- **ISE_GUEST** - ISE guest portal → browser remediation
- **NON_ISE** - Commercial captive portals (hotels, coffee shops) → browser remediation
- **UNKNOWN** - Unclassified redirect → browser remediation + alert flare

### Browser Remediation Workflow

**RC1 Architecture - Two-Stage Process:**

**Stage 1 - WW_main.ps1 (SYSTEM):**
1. Detect redirect to non-ISE employee portal
2. Create remediation state file (contains portal URL, VPN state flags)
3. Fire Event 777 (captive_portal_browser) via FlareGun
4. Exit immediately (no blocking wait)

**Stage 2 - WW_cap_portal_runner.ps1 (USER):**
1. Triggered by Task Scheduler on Event 777
2. Kill interfering Cisco browsers (background job, 20s)
3. Check remediation state file for VPN flags
4. If VPN in intermediate state → wait up to 60s for stable state (Connected/Disconnected)
5. Launch Edge browser to portal URL (maximized, track PID)
6. Poll gateway.optum.com every 5s for up to 150s (exits early on success)
7. On success → launch validation browser to optum.com (fullscreen)
8. On timeout → show retry notification popup
9. Write completion flag with PID for tracking

**DNS Chicken-Egg Problem Detection (RC1.7.0_ER5):**
Portal redirect URL requires ACTIVE DNS, but DNS is blocked until portal accepted. Runner detects this scenario and provides appropriate user messaging.

**Browser Tracking:**
- Edge browser PID captured at launch
- Stored in completion flag for later cleanup
- Prevents orphaned browser processes

### Critical Timing Details

**Initial Wait:** 150 seconds with 5-second polling  
**Early Exit:** Terminates immediately when nwcheck succeeds (typical: 10-30s)  
**VPN Stabilization:** Up to 60s for AlwaysOn VPN to reach stable state  
**Validation Site:** Opens optum.com in fullscreen after auth success

---

## FlareGun Event Framework

### Architecture

**Purpose:** Context-aware Ivanti EM telemetry and workflow triggering

**Execution Contexts:**
- **SYSTEM flares** → fire directly via `eventcreate.exe` (monitoring/logging)
- **USER flares** → route through Event Log → Task Scheduler → USER context script

**Configuration:** `WW_flaregun_config.json` (NETLOGON share + local cache)

### Event Catalog

| Event ID | Tag | Context | Purpose |
|----------|-----|---------|---------|
| 780 | user_tun | USER | User VPN tunnel active |
| 781 | mgmt_tun | USER | Management tunnel active |
| 782 | off_prem_no_vpn | USER | Off-premises without VPN - prompt user |
| 793 | on_prem | SYSTEM | On-premises detected - telemetry |
| 790 | ise_employee_captive_portal | SYSTEM | ISE redirect detected - telemetry |
| 791 | ise_posture_compliant | SYSTEM | Posture check passed - success telemetry |
| 792 | ise_posture_failed | SYSTEM | Posture check failed - alert |
| 794 | ise_guest_captive_portal | SYSTEM | ISE guest portal - telemetry |
| 795 | non_ise_captive_portal | SYSTEM | Commercial captive portal - telemetry |
| 777 | captive_portal_browser | USER | Launch browser for auth - **bypasses cooldown** |
| 796 | captive_portal_dns_misconfiguration | SYSTEM | DNS chicken-egg problem - alert |
| 799 | deep_diagnostics | SYSTEM | Trigger diagnostic collection |

### Cooldown Logic

**Default:** 1 minute per flare tag (prevents event spam)  
**Exception:** Event 777 (captive_portal_browser) **always bypasses cooldown**

**Why Bypass for 777?**  
- Time-sensitive user action required
- User waiting for authentication
- Re-trigger scenarios (rapid network changes) must work
- Other flares are telemetry/monitoring - can wait

---

## VPN Blackhole Feature (RC1.10+)

### Purpose

Prevent on-premises hairpinning - laptops on corporate network attempting VPN through internet gateway.

### Implementation

**Script:** `Set-VpnHostsEntry.ps1` v2.0.0  
**Location:** `C:\ProgramData\WhiteWalker\Set-VpnHostsEntry.ps1`

**Action:**
- **IF enabled in WW_main.ps1 ::
- **On `on_prem` flare:** Execute `-add` mode → sinkhole 38 VPN headend FQDNs to 127.0.0.1
- **On any other state:** Execute `-rm` mode **unconditionally** → remove all sinkhole entries

**Critical Safety Rule:** `-rm` fires unconditionally (not gated by flag file)  
**Reason:** Installer upgrades can delete flag while leaving hosts entries → permanent VPN breakage at scale

**AD Group Exemption:**
- Checks `WindowsPrincipal.IsInRole()` for exemption group membership
- Exempted users bypass blackhole entirely
- All logic lives inside Set-VpnHostsEntry.ps1 (not WW_main)

**Config Distribution:**
- Master files on NETLOGON share (`\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN\CPR\`)
- Local cache with 24hr refresh throttle
- Version header + SHA256 verification
- `-rm` path skips sync for speed (safety-critical operation)

**Kill Switch:** `$BlackholeEnabled = $false` in WW_main disables entire feature

**Startup Safety:** `-rm` fires at every WW_main run start (before any logic) to be sure if user happens to be off prem, they can access VPN

---

## Safety Features & Edge Cases

### WLANi03 Awareness (RC1.8)

**Problem:** ISE mid-posture, no IP assigned yet → false `no_net_transient` exit

**Solution:**
- Detect WLANi03 SSID + APIPA/no valid IP
- Wait up to 18s (6 retries × 3s) for ISE to assign IP
- Prevent premature exit during normal ISE posture flow

**Important:** WLANi03 does NOT bypass preflight - gateway.optum.com redirect is still the authoritative signal

### APIPA Early Exit

**Condition:** 169.254.x.x address + no default gateway  
**Action:** Immediate exit with `no_net_transient` flare  
**Reason:** No point hitting network endpoints - device not truly connected

### Stale Flag Cleanup

**15-minute staleness window:**
- `user_prompted.flag` - User response pending (prevents lockout)
- All other operational flags

**Unconditional cleanup (every run):**
- VPN blackhole removal (safety)
- Cisco browser processes (prevent interference)

### Log Rotation (RC1.7)

**Trigger:** 1MB log file size  
**Retention:** Last 5 logs as `.1` through `.5` (circular)  
**Function:** `Invoke-LogRotation`

**Files Managed:**
- `white_walker.log` (main)
- `white_walker.cap_portal.log` (captive portal runner)

### Cisco Browser Killer (ER4+)

**Problem:** Valid guest sessions leave orphaned Cisco browsers (acwebhelper, CiscoCollabHost, etc.)

**Solution:**
- Background job runs for 10-20 seconds on every WW execution
- Kills interfering Cisco browser processes
- Runs **after** post-DHCP sleep, **before** connectivity checks

**Processes Terminated:**
- acwebhelper
- CiscoCollabHost
- CiscoAnyConnectWebView
- CiscoWebLaunchHelper
- CiscoWebHelper

---

## Workflow Decision Tree

```
WW_main.ps1 Execution
    │
    ├─ Safety Checks
    │   ├─ Blackhole -rm (unconditional)
    │   ├─ Stale flag cleanup
    │   └─ Browser killer (background)
    │
    ├─ Network Info Gathering
    │   ├─ SSID detection (netsh wlan)
    │   ├─ IP/Gateway/DNS
    │   └─ SSID change detection
    │
    ├─ APIPA Check
    │   └─ 169.254.x.x + no gateway → EXIT (no_net_transient)
    │
    ├─ WLANi03 Special Handling
    │   └─ Wait up to 18s for valid IP if needed
    │
    ├─ VPN Intermediate State Check
    │   ├─ Recent wake? → Force disconnect
    │   └─ No wake? → Allow (AlwaysOn)
    │
    ├─ Preflight: gateway.optum.com
    │   │
    │   ├─ [ONLINE - HTTP 404]
    │   │   ├─ Update SSID cache
    │   │   ├─ Get VPN tunnel flavor (mgmt/user)
    │   │   │   ├─ VPN active → Flare + EXIT
    │   │   │   └─ No VPN
    │   │   │       ├─ DC reachable → Flare: on_prem + Blackhole -add
    │   │   │       └─ DC unreachable → Flare: off_prem_no_vpn
    │   │   └─ EXIT
    │   │
    │   ├─ [REDIRECT - HTTP 2xx/3xx + Location]
    │   │   ├─ Force VPN disconnect if blocking
    │   │   ├─ Classify redirect type
    │   │   │   │
    │   │   │   ├─ ISE_EMPLOYEE
    │   │   │   │   ├─ Wait for posture service
    │   │   │   │   ├─ Invoke rescan
    │   │   │   │   ├─ Monitor compliance
    │   │   │   │   ├─ Verify nwcheck post-compliance
    │   │   │   │   └─ Flare: ise_posture_compliant/failed + EXIT
    │   │   │   │
    │   │   │   ├─ ISE_GUEST / NON_ISE / UNKNOWN
    │   │   │   │   ├─ Create remediation state file
    │   │   │   │   ├─ Flare: Event 777 (captive_portal_browser)
    │   │   │   │   └─ EXIT
    │   │   │   │       │
    │   │   │   │       └─ [Task Scheduler triggers WW_cap_portal_runner.ps1]
    │   │   │   │           ├─ Kill Cisco browsers (20s background)
    │   │   │   │           ├─ Wait for VPN stable (if needed, up to 60s)
    │   │   │   │           ├─ Launch Edge to portal URL
    │   │   │   │           ├─ Poll nwcheck every 5s (up to 150s)
    │   │   │   │           ├─ Early exit on success
    │   │   │   │           ├─ Launch validation browser on success
    │   │   │   │           ├─ Show notification on timeout
    │   │   │   │           └─ Write completion flag
    │   │   │   │
    │   │   └─ EXIT
    │   │
    │   └─ [UNREACHABLE - Timeout/Error]
    │       ├─ Test enroll.cisco.com (re-probe)
    │       ├─ Multiple retry passes
    │       └─ Flare: no_net_transient + EXIT
    │
    └─ EXIT with reason code
```

---

## Configuration Variables

### Critical Timeouts

```powershell
$initial_sleep = 3                    # Post-DHCP wait (reduced from 5s in RC1.8)
$PostureWaitSeconds = 30              # Wait for ISE posture service availability
$PostureComplianceTimeout = 120       # ISE compliance monitoring window
$VpnWakeTimeWindow = 120              # Wake detection window (2 minutes)
$VpnSsidChangeGraceSec = 15           # SSID change grace for VPN progress
$VpnSsidChangePollSec = 3             # SSID change VPN poll interval
$FlareCooldownMinutes = 1             # Flare event cooldown (except Event 777)
```

### File Locations

```powershell
# Main script and runner
C:\ProgramData\WhiteWalker\WW_main.ps1
C:\ProgramData\WhiteWalker\WW_cap_portal_runner.ps1
C:\ProgramData\WhiteWalker\Set-VpnHostsEntry.ps1

# Configuration
C:\ProgramData\WhiteWalker\WW_flaregun_config.json

# Logs
C:\ProgramData\WhiteWalker\white_walker.log
C:\ProgramData\WhiteWalker\white_walker.cap_portal.log

# Flag files
C:\ProgramData\WhiteWalker\flags\user_prompted.flag
C:\ProgramData\WhiteWalker\flags\ssid_last_known.flag
C:\ProgramData\WhiteWalker\flags\ssid_changed.flag
C:\ProgramData\WhiteWalker\flags\vpn_blocked.flag
C:\ProgramData\WhiteWalker\portal_complete.flag

# Diagnostics
C:\ProgramData\WhiteWalker\diagnostics\
```

### Infrastructure Endpoints

```powershell
$PreflightURL = "https://gateway.optum.com"      # Primary network probe (HTTP 404 = online)
$EnrollURL = "http://enroll.cisco.com"           # ISE redirect detection
$ValidationSite = "https://www.optum.com"        # Post-auth validation browser

# AWS-hosted DR endpoints (netcheck/nwcheck)
# East: nwcheck.optum.com
# West: netcheck.optum.com
```

---

## Deployment Architecture

### Task Scheduler Jobs

**Primary Trigger - WW_main.ps1:**
```xml
Trigger 1: DHCP Lease Acquisition (Event ID 50058)
Trigger 2: System Unlock (Event ID 4800/4801)
Principal: SYSTEM
Program: powershell.exe
Arguments: -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\ProgramData\WhiteWalker\WW_main.ps1"
```

**Captive Portal Runner - WW_cap_portal_runner.ps1:**
```xml
Trigger: Event ID 777, Source "WhiteWalkerFlareGun", Application Log
Principal: Current interactive user (USER context)
Program: powershell.exe
Arguments: -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\WhiteWalker\WW_cap_portal_runner.ps1"
```

### Installation Flow via install.ps1

1. **File Deployment:**
   - Copy scripts to `C:\ProgramData\WhiteWalker\`
   - Create directory structure
   - Set proper NTFS permissions

2. **Task Scheduler Registration:**
   - Import XML task definitions
   - Verify Event Log source creation (WhiteWalkerFlareGun)
   - Test task trigger conditions

3. **Config Distribution:**
   - Push WW_flaregun_config.json to NETLOGON share
   - Endpoints cache locally on first run
   - 24hr refresh cycle

4. **Validation:**
   - Manual test: `WW_main.ps1 -WWDebug -WhatIf`
   - Check logs in `C:\ProgramData\WhiteWalker\`
   - Verify Event 777 task fires on captive portal

---

## Testing Framework

### Pester 5.x Test Suite

**Test Scripts:**
- `WW_Tests_RC1.ps1` - Core functionality tests
- `WW_cap_portal_runner_Tests.ps1` - Captive portal runner tests
- `Run-WhiteWalkerTests.ps1` - Test harness

**Coverage:**
- Network state detection
- VPN classification
- Redirect detection (standard + ISE quirks)
- SSID change handling
- Wake detection
- Captive portal workflows
- Blackhole integration
- Log rotation

**Test Execution:**
```powershell
.\Run-WhiteWalkerTests.ps1
```

### Field Testing Locations

**Real-world validation environments:**
- Hotel WiFi (Marriott, Hilton, etc.)
- Coffee shops (Starbucks, Panera)
- Fast food WiFi (McDonald's, etc.)
- Airport networks
- Corporate PSNs (on-prem ISE)
- Home networks (baseline)

**Test Scenarios:**
- Wake from sleep on guest network
- SSID changes with active VPN
- Rapid network transitions
- ISE posture non-compliance
- DNS-blocked captive portals
- VPN intermediate states
- Stale VPN routes on public WiFi

---

## Debugging & Diagnostics

### Debug Modes

**WWDebug:**
```powershell
.\WW_main.ps1 -WWDebug
```
Light debug - decision breadcrumbs only

**WWTrace:**
```powershell
.\WW_main.ps1 -WWTrace
```
Heavy debug - raw vpncli stats/status dumps

**WhatIf:**
```powershell
.\WW_main.ps1 -WhatIf
```
Show what would be done without executing

### Log Analysis

**Main Log Markers:**
```
[WW] [INFO] RC1: nwcheck preflight - single call determines all workflow routing
[WW] [INFO] nwcheck: ONLINE - classifying connection type...
[WW] [INFO] nwcheck: REDIRECT to <URL> - routing to correct workflow
[WW] [INFO] VPN tunnel flavor: mgmt_tun
[WW] [INFO] FlareEvent bypassing cooldown (critical event): captive_portal_browser
```

**Captive Portal Log Markers:**
```
[CAP] [INFO] Captive portal authentication attempt 1/30
[CAP] [INFO] NWCHECK SUCCEEDED - Network access confirmed
[CAP] [INFO] Launching validation browser to https://www.optum.com
```

### Diagnostic Collection

**Manual:**
```powershell
.\WW_collect_diag.ps1
```

**Automated (Flare Event 799):**
```powershell
Send-FlareEvent 'deep_diagnostics'
```

**Collected Data:**
- Full logs (main + cap_portal)
- Network adapter info (ipconfig /all)
- Route tables
- VPN state dumps
- Event log excerpts (DHCP, VPN, FlareGun)
- Flag file status
- Task Scheduler job status

**Output Location:** `C:\ProgramData\WhiteWalker\diagnostics\diag_<timestamp>.log`

---

## Key Learnings & Design Principles

### Always Parse vpncli's Second State Line
First line is stale. Management tunnels show "Disconnected" on basic state. Parse `Management Connection State:` field for authoritative classification.

### ISE Returns HTTP 200 + Location Header
Not proper 302/307. Detection must check Location header on ANY 2xx/3xx response.

### Captive Portal/VPN Intermediate States Block All Traffic
Redirect detection impossible during these states. Use wake-from-sleep event detection instead.

### -rm Must Be Unconditional
Flag-file-gated removal creates permanent breakage risk at scale. Blackhole `-rm` fires at every startup.

### Enroll.cisco.com Timeout (~20s) Can Mask Transient States
Re-probe before declaring failure. Multiple retry passes prevent false negatives.

### SSID Detection: Use netsh wlan, Not Get-NetConnectionProfile
Get-NetConnectionProfile contaminates with VPN virtual adapters. `netsh wlan show interfaces` is authoritative.

### Stale Flag Files Are a Recurring Production Hazard
Cleanup must be comprehensive. 15-minute staleness window + unconditional safety removals.

### Post-ISE-Compliant ACL Lift Needs Independent Verification
Don't trust agent report alone. Poll nwcheck for up to 30s to confirm WLC ACL propagation.

---

## Version History

### RC1.13 (Current)
- Latest stable release
- Improved Test-DC logic

### RC1.12
- All RC1 features stabilized
- Production-ready

### RC1.10
- SSID change detection
- Grace window for VPN progress on new networks
- Prevents VPN blocking captive portal/ISE traffic

### RC1.9
- Blackhole -rm now unconditional (safety fix)
- Removed flag file gate on removal path
- Prevents orphaned hosts entries

### RC1.8
- WLANi03 awareness (18s IP wait)
- Initial sleep reduced to 3s
- Blackhole -rm fires at every startup

### RC1.7
- Size-based log rotation (1MB / 5 files)
- VPN blackhole integration
- Blackhole toggle ($BlackholeEnabled)

### RC1.6
- Preflight URL change: nwcheck → gateway.optum.com
- HTTP 404 = online signal (not 200)

### RC1.5
- Post-compliance nwcheck verification
- Confirms ACL lifted after ISE reports compliant

### RC1.3
- Critical fix: Detect redirects on ANY 2xx/3xx with Location header
- Handles ISE 200+Location quirk

### RC1.2
- Critical race fix: Test enroll.cisco.com immediately on nwcheck failure
- Prevents DHCP lease expiration before completion

### RC1.1
- Critical fix: Test-Redirect catch block redirect detection
- AllowAutoRedirect=false exception handling

### RC1
- Single preflight architecture (nwcheck.optum.com)
- Primary gate: HTTP 200 = G2G, redirect = route to workflow

---

## Infrastructure Dependencies

### Cisco Secure Client
- vpncli.exe for VPN state queries
- ISE posture agent (csc_iseagent, ciscod.exe)
- Management vs user tunnel detection

### Cisco ISE
- Employee PSN redirects for posture
- Guest portal redirects
- 802.1x enforcement

### Cisco WLCs
- Posture redirect ACL enforcement
- ACL propagation post-compliance
- WLANi03 posture flow

### Ivanti EM (FlareGun Telemetry)
- SYSTEM flares for monitoring
- USER flares for session actions
- Event ID 777 → Task Scheduler integration

### AWS Preflight Endpoints
- gateway.optum.com (primary)
- nwcheck.optum.com / netcheck.optum.com (DR)
- East/West regional redundancy

### Active Directory
- NETLOGON share for config distribution
- Group Policy Objects for wake detection events
- Blackhole exemption group checks

---

## Production Metrics & Scale

**Deployment Scale:** ~500K-580K Windows endpoints  
**Geographic Coverage:** 32 countries  
**Average Daily Executions:** ~2-3 million (DHCP + wake + unlock triggers)  
**Success Rate:** >99% automated remediation  
**User Intervention Reduced:** ~90% vs manual processes  

**Network Types Supported:**
- Corporate on-premises (Cisco ISE)
- ISE guest networks
- Commercial captive portals (hotels, airports, coffee shops)
- Home/residential networks
- Public WiFi (xfinitywifi, attwifi, Google WiFi, etc.)

**Common Remediation Scenarios:**
- ISE posture non-compliance: ~15-45s average resolution
- Captive portal auth: ~20-60s with user interaction
- VPN hairpinning prevention: Immediate (hosts file update)
- Wake-from-sleep VPN blocking: Immediate (forced disconnect)

---

## Support & Maintenance

### Primary Contacts
**Development:** steve.horton@optum.com  
**Architecture:** VPN SLO Team  
**Deployment:** Desktop Engineering  

### Documentation Links
- Git Repository: (internal Optum repo)
- FlareGun Quick Reference: `FLAREGUN_QUICK_REF.md`
- Deployment Checklist: `DEPLOYMENT_SUMMARY.md`
- Testing Guide: `TESTING_GUIDE.md`

### Common Issues & Resolutions

**Event 777 not firing:**
- Verify Task Scheduler job registered
- Check Event Log source "WhiteWalkerFlareGun" exists
- Confirm cooldown bypass in Send-FlareEvent function

**ISE rescan failing:**
- Verify posture service running (Get-Service | Where {$_.Name -match 'ise|cisco'})
- Check Event Log for posture compliance events
- Confirm PSN redirect URL matches ISE_EMPLOYEE pattern

**Captive portal browser not opening:**
- Check WW_cap_portal_runner.ps1 execution in USER context
- Verify Edge browser executable path
- Review white_walker.cap_portal.log for errors

**VPN blackhole not removing:**
- Verify -rm fires at startup (every WW_main run)
- Check Set-VpnHostsEntry.ps1 execution logs
- Confirm hosts file permissions (SYSTEM write access)

---

## Future Roadmap

### Planned Enhancements
- Multi-DC redundancy for reachability tests
- IPv6 support (currently IPv4-only)
- Certificate-based ISE posture (machine cert validation)
- Enhanced telemetry (response times, success rates by location)
- AI-powered anomaly detection (unusual network patterns)

### Under Consideration
- Linux/macOS variants (currently Windows-only)
- Mobile device support (iOS/Android)
- Integration with ServiceNow for incident automation
- Real-time dashboard for global VPN health

---

## Conclusion

CPR+/WhiteWalker RC1.13 represents a mature, battle-tested solution for zero-touch network connectivity across heterogeneous enterprise environments. The architecture's single-preflight design, comprehensive state detection, and context-aware remediation workflows enable reliable automation at massive scale.

Key architectural strengths:
- **Single preflight call** eliminates multi-step probing complexity
- **VPN intermediate state detection** prevents blocking legitimate connections
- **SSID change awareness** handles real-world mobility scenarios
- **Unconditional safety cleanups** prevent production breakage
- **Context-aware FlareGun** enables appropriate SYSTEM vs USER actions
- **Post-compliance verification** ensures actual network access, not just agent compliance

The framework successfully handles the most challenging edge cases:
- ISE's non-standard HTTP 200+Location redirects
- Wake-from-sleep VPN blocking scenarios
- DNS chicken-egg problems on captive portals
- Stale VPN routes on public WiFi
- Management tunnel misclassification
- Rapid SSID changes with active VPN

With >99% automated remediation success, CPR+ demonstrates that surgical, principle-driven automation can solve complex real-world connectivity challenges at enterprise scale.

---

**Document Version:** 1.1  
**Last Updated:** May 2026  
**Maintained By:** steve.horton@optum.com, VPN SLO Team, Optum/UnitedHealth Group
