# Exit reasons and exit flares - design (DRAFT for Steve's approval, nothing built yet)

Goal: settle the exit-reason vocabulary and the Ivanti-facing exit flares BEFORE the Splunk boards are built, so neither changes later.

## Principles
1. **Every run ends with exactly one *state* flare** that says what the machine's connectivity state is. Ivanti reads that. Action flares (`captive_portal_browser` 777, `captive_portal_browser_base` 778, `ise_posture_*`, `notify_user`, ...) are unchanged and still fire as today; the exit state flare is in addition.
2. **`exit_reason` = `<outcome>:<type>`**, where `<type>` is the same word as the state flare, so there is ONE vocabulary:
   `on_prem` | `user_tun` | `mgmt_tun` | `off_prem_no_vpn` | `off_prem_untrusted_ssid` | `vpn_connecting` | `no_net_transient` | `captive_portal` | `cpr_error`
3. **No suffix when the outcome already names the state** (`on_prem`, `off_prem_no_vpn`, `vpn_hostscan_posturing`, `no_net_transient`, `error_*`). A suffix is added only when the outcome alone does not say where the machine is (ISE, remediation).
4. **How `<type>` is found** (never from stale `state.json`): VPN Connected -> the tunnel flavor (`user_tun`/`mgmt_tun`); else corp-only DNS suffix (`Test-OnPremBySuffix`) -> `on_prem`; else `off_prem_no_vpn` (or `off_prem_untrusted_ssid` when the SSID is untrusted).
5. **One choke point.** Replace the ~40 scattered `$script:exitReason = ...` with `Set-CprRunExit -Outcome <..> [-Type <..>]`, which sets the reason AND sends the state flare. A Pester test fails the build if any `$script:exitReason =` exists outside that function, so a future exit cannot forget its flare.

## Mechanics that matter (read from the code)
* `Send-FlareEvent`: one send per tag per run (per-run de-dupe), 1-minute per-tag cooldown (`$FlareCooldownMinutes`), `Set-FlareStamp` updates `currentState` only for tags in `$script:StateFlares`.
* A tag NOT in `WW_flaregun_config.json` falls back to a direct SYSTEM send with no configured event ID ("legacy"). `captive_portal` and `off_prem_untrusted_ssid` are in `$StateFlares` today but have **no config entry** -> Ivanti has no event ID for them.
* Event IDs 777-802 are taken. Proposed new IDs start at **803** (Ivanti side must define triggers for them; nothing breaks if it has not yet, but nothing acts either).

## State flares (target set)
| Flare | Event ID | Status |
|---|---|---|
| user_tun | 780 | exists |
| mgmt_tun | 781 | exists |
| off_prem_no_vpn | 782 | exists |
| on_prem | 793 | exists |
| no_net_transient | 798 | exists; add to `$StateFlares` |
| captive_portal | 795 (`non_ise_captive_portal`) or new | **decision**: reuse 795 / 794 / 797 as state, or one new `captive_portal` ID |
| off_prem_untrusted_ssid | 803 | NEW (in `$StateFlares`, no ID today) |
| vpn_connecting | 804 | NEW (HostScan posture scan / connect in progress) |
| cpr_error | 805 | NEW (Cisco/vpncli/posturecli missing, exception, unknown) |

## Exit-by-exit mapping (current -> proposed reason | exit state flare)
| Current exit_reason | Proposed exit_reason | Exit state flare |
|---|---|---|
| `vpn_connected:<flavor>` (4 sites) | unchanged | user_tun / mgmt_tun |
| `vpn_connected_nwcheck_unreachable:<flavor>` | unchanged | user_tun / mgmt_tun |
| `vpn_hostscan_posturing` | unchanged | vpn_connecting (NEW) |
| `on_prem` | unchanged | on_prem |
| `off_prem_no_vpn` | unchanged | off_prem_no_vpn |
| `off_prem_untrusted_ssid` | unchanged | off_prem_untrusted_ssid (NEW id) |
| `ise_employee_compliant` | `ise_employee_compliant:<type>` | per `<type>` |
| `ise_employee_failed_<result>` | `ise_employee_failed_<result>:<type>` | per `<type>` |
| `ise_redirect_no_posture_service` | `ise_redirect_no_posture_service:<type>` | per `<type>` |
| `ise_guest_browser_remediated` | `ise_guest_browser_remediated:<type>` | per `<type>` (normally off_prem_no_vpn) |
| `non_ise_browser_remediated` / `_via_enroll` | same `:<type>` | per `<type>` |
| `captive_portal_suspected` | `captive_portal_suspected:<type>` | captive_portal (decision) |
| `captive_walled_garden` | `captive_walled_garden:<type>` | captive_portal (decision) |
| `no_net_transient` (3 sites, 3 meanings) | split: `no_net_transient`, `no_net_after_portal_check`, `no_net_after_base_handoff` | no_net_transient |
| `no_network_connection`, `network_changed_no_ip` | unchanged | no_net_transient |
| `waiting_user_response` | unchanged | **decision** (leave state as is vs. new flare) |
| `error_no_cisco`, `error_no_vpncli`, `error_no_posturecli`, `error_exception`, `unknown` | unchanged | cpr_error (NEW) |

## Decisions needed from Steve
1. Captive states: reuse the existing action flares (794/795/797) as state flares, or add one new `captive_portal` state ID?
2. `waiting_user_response`: no state change, or its own flare?
3. OK to allocate 803/804/805 (and tell the Ivanti side)? Or give me the IDs to use.
4. `no_net_transient` split: confirm the three new names after I read each site.

## Build plan once approved (small, test-first)
1. `Set-CprRunExit` + `$StateFlares` additions + `WW_flaregun_config.json` entries (and tee-master/schema if a new tag needs it).
2. Convert the ~40 assignments; compute `<type>` in one helper (`Get-CprExitType`).
3. Pester: choke-point scan, mapping table as data-driven test, suffix/type derivation tests.
4. Update `docs/` exit-reason catalog and the field catalog; note the old->new table for the Splunk board work.
