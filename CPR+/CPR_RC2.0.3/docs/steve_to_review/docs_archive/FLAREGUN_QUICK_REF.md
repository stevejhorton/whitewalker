# WhiteWalker FlareGun Integration - Quick Reference
Version: 3.13.0
Date: 14-Nov-2025
Author: steve.horton@optum.com

## Overview
FlareGun provides context-aware Ivanti signal flare execution:
- SYSTEM flares fire immediately (fast, for monitoring/telemetry)
- USER flares route through Event Log → Task Scheduler (for user-session automations)
- Config-driven routing eliminates hardcoding

## Architecture Flow

### SYSTEM Context Flares (Immediate)
```
WW_main.ps1 (SYSTEM)
  ↓
Send-FlareEvent "on_prem"
  ↓
Start-Process rundll32.exe /on_prem
  ↓
Ivanti EM receives flare as SYSTEM
```

### USER Context Flares (Event-driven)
```
WW_main.ps1 (SYSTEM)
  ↓
Send-FlareEvent "user_tun"
  ↓
eventcreate ... "FLARE:user_tun" (Event ID 780)
  ↓
Task Scheduler detects Event ID 780
  ↓
Launches WW_flaregun_user.ps1 as logged-in USER
  ↓
Parses "FLARE:user_tun" from event message
  ↓
Start-Process rundll32.exe /user_tun (as USER)
  ↓
Ivanti EM receives flare with user identity
```

## Files

### Configuration
- **WW_flaregun_config.json**: Event ID mappings and context routing
  - Location: C:\ProgramData\WhiteWalker\
  - Edit this to add new flares or change Event IDs

### Scripts
- **WW_main.ps1**: Main WhiteWalker script (runs as SYSTEM)
- **WW_flaregun_user.ps1**: USER context handler
- **WW_flaregun_system.ps1**: SYSTEM context handler (currently unused - direct flares)

### Task Scheduler Jobs
- **WW_main.xml**: Main trigger (DHCP/VPN/unlock events)
- **WW_cap_portal_runner.xml**: Captive portal browser (Event ID 777)
- **WW_flaregun_user.xml**: USER flare handler (Event IDs 780-782)
- **WW_flaregun_system.xml**: SYSTEM flare handler (Event IDs 790-795, 799)

## Current Flare Mappings

### USER Context (via Event Log)
| Flare Tag        | Event ID | Trigger Condition              | Ivanti Use Case                    |
|------------------|----------|--------------------------------|------------------------------------|
| user_tun         | 780      | User tunnel VPN connected      | Launch user-session tools/GUI      |
| mgmt_tun         | 781      | Mgmt tunnel VPN connected      | Launch user-session tools/GUI      |
| off_prem_no_vpn  | 782      | Off-prem without VPN           | Prompt user to connect VPN         |

### SYSTEM Context (Direct - No Event Log)
| Flare Tag                    | Used | Trigger Condition                    | Ivanti Use Case                  |
|------------------------------|------|--------------------------------------|----------------------------------|
| on_prem                      | Yes  | On-premises (DC reachable)           | Campus presence telemetry        |
| ise_employee_captive_portal  | Yes  | ISE employee network redirect        | ISE remediation monitoring       |
| ise_posture_compliant        | Yes  | ISE posture check passed             | Compliance success telemetry     |
| ise_posture_failed           | Yes  | ISE posture check failed             | Alert for manual intervention    |
| ise_posture_service_unavailable | Yes | ISE redirect but no posture service | Alert for broken Cisco client    |
| unknown_captive_portal       | Yes  | Unclassified redirect detected       | Investigation alert              |
| captive_portal_*             | Yes  | Captive portal remediation started   | Captive portal encounter tracking|

### SYSTEM Context (via Event Log - Reserved for Future)
| Flare Tag                 | Event ID | Reserved For                         |
|---------------------------|----------|--------------------------------------|
| ise_employee_captive_portal | 790    | Future: If event log routing needed |
| ise_posture_compliant     | 791      | Future: If event log routing needed  |
| ise_posture_failed        | 792      | Future: If event log routing needed  |
| on_prem                   | 793      | Future: If event log routing needed  |
| ise_guest_captive_portal  | 794      | Future: ISE guest network            |
| non_ise_captive_portal    | 795      | Future: Non-ISE captive portal       |
| deep_diagnostics          | 799      | Trigger diagnostic collection        |

## Debugging Flare Flow

### Enable Debug Mode
```powershell
# Run WW_main with debug flag
powershell.exe -File C:\ProgramData\WhiteWalker\WW_main.ps1 -WWDebug
```

### Check Logs
```powershell
# Main script log (shows Send-FlareEvent calls)
Get-Content C:\ProgramData\WhiteWalker\white_walker.main.log -Tail 50

# USER flare handler log
Get-Content C:\ProgramData\WhiteWalker\white_walker.flaregun_user.log -Tail 50

# SYSTEM flare handler log (future use)
Get-Content C:\ProgramData\WhiteWalker\white_walker.flaregun_system.log -Tail 50
```

### Verify Event Log Messages
```powershell
# Check recent WhiteWalkerFlareGun events
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'WhiteWalkerFlareGun'
} -MaxEvents 10 | Format-Table TimeCreated, Id, Message -Wrap
```

### Check Task Scheduler Status
```powershell
# Verify tasks are registered and enabled
Get-ScheduledTask -TaskName "WW_*" | Format-Table TaskName, State

# Check last run result
Get-ScheduledTask -TaskName "WW_flaregun_user" | Get-ScheduledTaskInfo
```

## Comments in WW_main.ps1

Every flare call site has a detailed comment block:
```powershell
# FLARE EVENT: user_tun
# Context: USER (Event ID 780) | Reason: User tunnel detected via vpncli
# Expected Flow: WW_main (SYSTEM) → Event Log → Task Scheduler → WW_flaregun_user.ps1 (USER) → Flare
# Ivanti Use: Trigger USER session automations (can launch GUI, user-context tools)
# Why USER context: Ivanti needs logged-in user identity for session-specific actions
Send-FlareEvent "user_tun"
```

Use these comments to:
1. Understand what triggers each flare
2. Know expected execution path
3. See Ivanti's downstream use case
4. Debug flow when flares don't fire

## Adding New Flares

1. **Edit WW_flaregun_config.json**:
```json
"new_flare_tag": {
  "event_id": 785,
  "context": "USER",
  "flare_tag": "new_flare_tag",
  "description": "Description of when this fires",
  "source": "WhiteWalkerFlareGun"
}
```

2. **Update Task Scheduler XML** (if USER context):
   - Add Event ID to `WW_flaregun_user.xml`

3. **Add flare call in WW_main.ps1**:
```powershell
# FLARE EVENT: new_flare_tag
# Context: USER (Event ID 785) | Reason: Why this fires
# Expected Flow: ...
# Ivanti Use: ...
Send-FlareEvent "new_flare_tag"
```

4. **Reinstall** via install.ps1

## Troubleshooting

### Flare not firing at all
1. Check WW_main.log for "FlareEvent" entries
2. Verify cooldown hasn't suppressed it (10 min default)
3. Check de-dupe (only fires once per script run)

### USER flare not executing (Event log shows event, but no flare)
1. Check Task Scheduler job is enabled: `Get-ScheduledTask WW_flaregun_user`
2. Verify event message format: Should be "FLARE:tag_name"
3. Check WW_flaregun_user.log for parsing errors
4. Ensure user is logged in (task only runs when user logged on)

### SYSTEM flare not visible to Ivanti
1. WW_main runs as SYSTEM - verify with: `whoami` in script
2. Check flare exe path: Should be rundll32.exe
3. Verify WhatIf mode not enabled (`-WhatIf` flag)

### Event ID conflicts
1. All WhiteWalkerFlareGun events: 780-799 (780-782 USER, 790-799 SYSTEM)
2. Event ID 777: Reserved for captive portal (legacy)
3. Don't use Event IDs outside this range

## Installation

```powershell
# Run as Administrator from WhiteWalker directory
.\install.ps1

# Installer will:
# 1. Remove old tasks and scripts
# 2. Deploy all files to C:\ProgramData\WhiteWalker\
# 3. Register Task Scheduler jobs
# 4. Validate installation
```

## Version History
- **3.13.0** (14-Nov-2025): FlareGun integration with context-aware routing
- **3.12.0_ER8.1** (06-Nov-2025): Wake-from-sleep VPN detection
- **3.12.0_ER7**: ISE compliance monitoring
