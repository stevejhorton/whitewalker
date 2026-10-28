# Exit reasons and exit flares - design (DRAFT, nothing built; Steve approved the uniform convention 2026-10-28)

Goal: fix the exit-reason vocabulary and the Ivanti-facing exit flares BEFORE the Splunk boards exist, and keep it portable so the macOS port inherits it unchanged.

## Rules
1. **Every exit is `<outcome>:<type>`. No exceptions.** Parse by splitting on the LAST colon; outcomes never contain a colon.
2. **`<type>` is the connection path the machine is on at exit, and it is the same word as the exit state flare.** One vocabulary:
   `on_prem` | `user_tun` | `mgmt_tun` | `off_prem_no_vpn` | `off_prem_untrusted_ssid` | `vpn_connecting` | `captive_portal` | `no_net_transient` | `cpr_error`
   So `ise_employee_compliant:on_prem` and `ise_employee_compliant:user_tun` (ISE over VPN, e.g. overseas Macs) are different, distinguishable facts.
3. **Every run ends with exactly one state flare for `<type>`** (Ivanti reads it; `currentState` is updated by it). Action flares (`captive_portal_browser` 777, `captive_portal_browser_base` 778, `ise_posture_*` 791/792, ...) are unchanged and still fire; the exit state flare is in addition.
4. **Outcomes are platform-neutral** (no Windows-only words), so the Mac port reuses the same strings. `<type>` describes the path, not the OS.
5. **`<type>` is derived, never read from `state.json`**: VPN Connected -> tunnel flavor; else corp-only DNS suffix (`Test-OnPremBySuffix`) -> `on_prem`; else untrusted SSID -> `off_prem_untrusted_ssid`; else `off_prem_no_vpn`. Non-connectivity exits use `no_net_transient` / `cpr_error` / `vpn_connecting` as listed.
6. **One choke point:** `Set-CprRunExit -Outcome <o> -Type <t>` sets the reason AND sends the state flare. A Pester test fails if any `$script:exitReason =` appears outside it.

## Mechanics read from the code (affect the build)
* `Send-FlareEvent`: one send per tag per run, 1-minute per-tag cooldown (`$FlareCooldownMinutes`); `Set-FlareStamp` updates `currentState` only for tags in `$script:StateFlares`.
* A tag not in `WW_flaregun_config.json` falls back to a legacy direct send with no event ID. `captive_portal` and `off_prem_untrusted_ssid` are in `$StateFlares` but have no config entry.
* Today the `off_prem_untrusted_ssid` exit sends the `off_prem_no_vpn` flare (782): reason and flare already disagree.
* **Consumer that must change:** `Invoke-MaintenanceStage` decides "offline" by exact exit-reason strings (`unknown`, `no_net_transient`, ...). It must compare the outcome part (before the last colon). `maintSkip` uses `-like 'vpn_connected:*'` and keeps working.
* Event IDs 777-802 are taken; new ones start at 803.

## State flares (target set)
| Flare | Event ID | Status |
|---|---|---|
| user_tun / mgmt_tun / off_prem_no_vpn / on_prem | 780 / 781 / 782 / 793 | exist |
| no_net_transient | 798 | exists; add to `$StateFlares` |
| off_prem_untrusted_ssid | 803 | NEW |
| vpn_connecting | 804 | NEW (HostScan scan in progress) |
| cpr_error | 805 | NEW |
| captive_portal | ? | **decision**: reuse 794/795/797 as the state, or one new ID |

## Mapping: current -> proposed `exit_reason` (state flare = the `<type>`)
| Current | Proposed |
|---|---|
| `vpn_connected:<flavor>` (4 sites) | unchanged |
| `vpn_connected_nwcheck_unreachable:<flavor>` | unchanged |
| `vpn_hostscan_posturing` | `hostscan_in_progress:vpn_connecting` |
| `on_prem` (2 sites) | `no_vpn_dc_reachable:on_prem` |
| `off_prem_no_vpn` (2 sites) | `no_vpn_dc_unreachable:off_prem_no_vpn` |
| `off_prem_untrusted_ssid` | `dc_reachable_untrusted_ssid:off_prem_untrusted_ssid` |
| `ise_employee_compliant` | `ise_employee_compliant:<type>` |
| `ise_employee_failed_<result>` | `ise_employee_failed_<result>:<type>` |
| `ise_redirect_no_posture_service` | `ise_redirect_no_posture_service:<type>` |
| `ise_guest_browser_remediated` | `ise_guest_browser_remediated:<type>` |
| `non_ise_browser_remediated`, `non_ise_browser_remediated_via_enroll` | same outcome + `:<type>` |
| `captive_portal_suspected`, `captive_walled_garden` | same outcome + `:<type>` (`captive_portal` if the decision below says so) |
| `waiting_user_response` | `waiting_user_response:<type>` (type of the current connection; no new flare needed) |
| `no_network_connection`, `network_changed_no_ip` | same outcome + `:no_net_transient` |
| `no_net_transient` (3 sites, 3 meanings) | `network_dropped:no_net_transient`, `no_network_after_portal_check:no_net_transient`, `no_network_after_base_handoff:no_net_transient` (names confirmed when each site is read) |
| `error_no_cisco`, `error_no_vpncli`, `error_no_posturecli`, `error_exception` | same outcome + `:cpr_error` |
| `unknown` | `state_unknown:cpr_error` |

## Decisions still open
1. OK to allocate 803/804/805 (Ivanti side to define triggers)? Note `off_prem_untrusted_ssid` will stop sending 782 and send 803, a behavior change Ivanti will see.
2. Captive state: reuse 794/795/797 as the state flare, or one new `captive_portal` ID?

## Build plan once approved (small, test-first)
1. `Set-CprRunExit`, `Get-CprExitType`, `$StateFlares` additions, `WW_flaregun_config.json` entries (+ tee master / schema if a tag needs it).
2. Convert the ~40 assignments; fix the `Invoke-MaintenanceStage` offline check to use the outcome part.
3. Pester: choke-point scan, mapping as a data-driven test, type derivation, outcome-part parsing, existing tests updated for the new strings.
4. Update the docs' exit-reason catalog and field catalog; the old->new table above is the hand-off for the Splunk board work.
