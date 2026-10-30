# Exit reasons and exit flares - design (BUILT 2026-10-28; Steve approved the convention)

Goal: fix the exit-reason vocabulary and the Ivanti-facing exit flares BEFORE the Splunk boards exist, and keep it portable so the macOS port inherits it unchanged.

## Rules
1. **Every exit is `<outcome>:<type>`. No exceptions.** Parse by splitting on the LAST colon; outcomes never contain a colon.
2. **`<type>` is the connection path the machine is on at exit, and it is the same word as the exit state flare.** One vocabulary:
   `on_prem` | `user_tun` | `mgmt_tun` | `off_prem_no_vpn` | `vpn_connecting` | `captive_portal` | `no_net_transient` | `cpr_error`
   So `ise_employee_compliant:on_prem` and `ise_employee_compliant:user_tun` (ISE over VPN, e.g. overseas Macs) are different, distinguishable facts.
3. **Every run ends with exactly one state flare for `<type>`** (Ivanti reads it; `currentState` is updated by it). Action flares (`captive_portal_browser` 777, `captive_portal_browser_base` 778, `ise_posture_*` 791/792, ...) are unchanged and still fire; the exit state flare is in addition.
4. **Outcomes are platform-neutral** (no Windows-only words), so the Mac port reuses the same strings. `<type>` describes the path, not the OS.
5. **`<type>` is derived, never read from `state.json`**: tunnel flavor if a tunnel is up; else DC reachable AND (wired or trusted SSID) -> `on_prem`; else `off_prem_no_vpn`. `off_prem_no_vpn` means no tunnel and not on a trusted path, whatever the reason; the outcome carries the reason. Trusted = the 3 corp suffixes (code var, reroll to change) plus the trusted-SSID list (share file + code; currently one entry). Anything else is untrusted, in line with Cisco TND.
6. **Outcomes never reuse a type word** (Pester-enforced), so the two halves never say the same thing twice. Non-connectivity exits use `no_net_transient` / `cpr_error` / `vpn_connecting` as listed.
7. **One choke point:** `Set-CprRunExit -Reason <r> [-State <s>]` is the only place `$script:exitReason` is assigned (state derived via `Get-CprExitType` when omitted, e.g. ISE exits). The state flare is sent once from the run's `finally` block by `Send-CprExitFlare`, so every exit gets exactly one. A Pester test fails if any `$script:exitReason =` appears outside it.

## Mechanics read from the code (affect the build)
* `Send-FlareEvent`: one send per tag per run, 1-minute per-tag cooldown (`$FlareCooldownMinutes`); `Set-FlareStamp` updates `currentState` only for tags in `$script:StateFlares`.
* A tag not in `WW_flaregun_config.json` falls back to a legacy direct send with no event ID. `captive_portal` and `off_prem_untrusted_ssid` (to be removed from `$StateFlares`) are in `$StateFlares` but have no config entry.
* **Consumer that must change:** `Invoke-MaintenanceStage` decides "offline" by exact exit-reason strings (`unknown`, `no_net_transient`, ...). It must compare the outcome part (before the last colon). `maintSkip` uses `-like 'vpn_connected:*'` and keeps working.
* Event IDs 777-802 are taken; new ones start at 803.

## State flares (target set)
| Flare | Event ID | Status |
|---|---|---|
| user_tun / mgmt_tun / off_prem_no_vpn / on_prem | 780 / 781 / 782 / 793 | exist |
| no_net_transient | 798 | exists; add to `$StateFlares` |
| vpn_connecting | 803 | NEW (HostScan scan in progress) |
| cpr_error | 804 | NEW |
| captive_portal | 805 | NEW state flare; action flares 777/778/794/795/797 unchanged |

## Mapping: current -> new `reason:connection_state`
Reason = what CPR concluded or did. State = where the machine sits (same word as the state flare). A reason never contains a state word (Pester-enforced). `<state>` = derived from the live path at exit.
| Current | New |
|---|---|
| `vpn_connected:<flavor>`, `vpn_connected_nwcheck_unreachable:<flavor>` | unchanged |
| `vpn_hostscan_posturing` | `hostscan_in_progress:vpn_connecting` |
| `on_prem` | `no_action_dc_reachable:on_prem` |
| `off_prem_no_vpn`, `off_prem_untrusted_ssid` | `untrusted:off_prem_no_vpn` (both; the odd untrusted-SSID-with-reachable-DC case stays visible in the WARN log) |
| `ise_employee_compliant`, `ise_employee_failed_<result>`, `ise_redirect_no_posture_service`, `ise_guest_browser_remediated` | same reason + `:<state>` |
| `non_ise_browser_remediated`, `non_ise_browser_remediated_via_enroll` | same reason + `:<state>` |
| `captive_portal_suspected` -> `portal_suspected`, `captive_walled_garden` | reason + `:captive_portal` (renamed so the reason never repeats the state word) |
| `waiting_user_response` | `waiting_user_response:captive_portal` |
| `no_network_connection`, `network_changed_no_ip` | same reason + `:no_net_transient` |
| `no_net_transient` (4 sites) | `apipa_no_gateway`, `nwcheck_unreachable_after_vpn_disconnect`, `no_plausible_local_network`, `nwcheck_unreachable_enroll_no_redirect`, each `:no_net_transient` |
| `error_no_cisco`, `error_no_vpncli`, `error_no_posturecli`, `error_exception` | same reason + `:cpr_error` |
| `unknown` | `state_unknown:cpr_error` |

## Decisions
IDs 803/804/805 and the captive state flare are set as above; Ivanti side defines triggers. None open.

## Build plan once approved (small, test-first)
1. `Set-CprRunExit`, `Get-CprExitType`, `$StateFlares` additions, `WW_flaregun_config.json` entries (+ tee master / schema if a tag needs it).
2. Convert the ~40 assignments; fix the `Invoke-MaintenanceStage` offline check to use the outcome part.
3. Pester: choke-point scan, mapping as a data-driven test, type derivation, outcome-part parsing, existing tests updated for the new strings.
4. Update the docs' exit-reason catalog and field catalog; the old->new table above is the hand-off for the Splunk board work.
