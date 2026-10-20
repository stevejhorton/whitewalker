# CPR / WhiteWalker telemetry field catalog

**Scope:** CPR_RC2, schema version `11Oct26` in
`support_files/haystack_msg_schema.psd1`. This is a reader-friendly catalog of
the contract; the PSD1 remains authoritative.

## How to read the evidence

CPR has three different kinds of evidence. A **Flare** (Windows Event Log
777/778 and related WhiteWalkerFlareGun events) proves that dispatch or a
trigger occurred, but is not normalized telemetry. A **legacy queue event**
usually has `action="network_state_change"` and
`event_class="legacy_haystack"`; it is retained for existing consumers, but is
not a normalized captive-portal outcome. A **normalized tee event** is emitted
through `Write-TeeLog` and is the dashboard-grade row. The field lists below
describe queue/Splunk payloads, not Flares.

## Field rules

Every normalized message requires these fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `EvtTime` | Yes | ISO-8601 time when the underlying event occurred, stamped before queueing. |
| `action` | Yes | Event/action tag used to select the message family in Splunk. |
| `machine` | Yes | Originating endpoint hostname. |
| `user` | Yes | Resolved interactive user, or a documented sentinel. |

`domain\user` means the interactive user was resolved. `NO_INTERACTIVE_USER`
means the probes worked but nobody is logged on. `USER_UNKNOWN` means every
resolver probe failed and is an alertable defect. `SYSTEM` is legitimate for
some unattended SYSTEM-only operations. Truly unavailable non-user context is
an empty string; CPR does not use fabricated `N/A` or `Unknown` values.

The four fields above are shared by nearly every normalized action. The
remaining fields are action-specific and are normally optional in the schema:
an emitter may omit them when the information is not applicable. In the
tables below, **common** means `EvtTime`, `action`, `machine`, and `user`;
**optional** means optional in the contract (even when a particular emitter
usually supplies it).

## Action and tag catalog

### Captive portal outcomes

Actions: `cap_portal_redirect`, `cap_portal_remediation_passed`,
`cap_portal_remediation_failed`.

| Field | Required | Meaning |
| --- | --- | --- |
| `EvtTime`, `action`, `machine`, `user` | Yes | Common fields. |
| `ssid` | Optional | Actual wireless SSID, or `N/A` when unavailable/not applicable. |
| `connection_type` | Optional | Adapter-identity classification: `WiFi`, `Wired`, `Unknown`, or `NoNetwork`. Never inferred from blank SSID alone. |
| `url` | Optional | Captive-portal/redirect URL. |
| `port` | Optional | Relevant network port. |
| `ip` | Optional | Endpoint IP address. |
| `gw` | Optional | Default gateway. |
| `dns` | Optional | DNS server(s). |
| `vpn_state` | Optional | CPR state, such as `on_prem`, `user_tun`, `mgmt_tun`, `off_prem_no_vpn`, `captive_portal`, or `off_prem_untrusted_ssid`. |
| `portal_type` | Optional | Portal classification, such as `walled_garden` or `standard_redirect`. |
| `status` | Optional | Pass/fail/skip-style sub-event status. |
| `reason` | Optional | Human-readable or machine-readable outcome reason. |

### Captive portal legacy queue event

Action: `network_state_change`, with `event_class="legacy_haystack"`.
This is emitted by the cap-portal runners and is deliberately not the same as
the normalized `cap_portal_*` actions.

| Field | Required | Meaning |
| --- | --- | --- |
| `action`, `machine` | Yes in legacy payload | Legacy action and originating endpoint. |
| `event_class` | Yes for this legacy family | `legacy_haystack`, identifying the preserved queue format. |
| `ts` | Legacy field | Legacy event timestamp; older rows use this instead of normalized `EvtTime`. |
| `reason` | Optional | Typically `captive_portal_detected`. |
| `ip` | Optional | Endpoint IP. |
| `fqdn` | Optional | Captive-portal host parsed from the redirect URL. |
| `protocol` | Optional | URL scheme, normally `http` or `https`. |
| `port` | Optional | Redirect port. |

### Needle hits

Action: `needle_hit`.

**Windows Event Log NEEDLE variant:** common fields plus `Label`, `EventID`,
`LogName`, `Provider`, and optional `body`.

**DEFENDER variant:** common fields plus `Label`, `EventID="DEFENDER"`,
`rule_match`, `rule_state`, and optional `body`. `rule_state` is `PRESENT` or
`MISSING`; `rule_match` is the configured literal descriptive substring.

**SESSION variant:** `machine`, `Label`, `EventID="SESSION"`, `LogName`
(the session state change), and `EvtTime`. The current SESSION emitter omits
`user`; this is a known contract discrepancy.

| Field | Required | Meaning |
| --- | --- | --- |
| `Label` | Yes for needle hits | Configured needle label. |
| `EventID` | Yes for needle hits | Matched Windows Event ID, or `DEFENDER`/`SESSION`. |
| `LogName` | Optional | Windows event channel, or SESSION state-change name. |
| `Provider` | Optional | Windows event provider. |
| `body` | Optional | Extended event/rule body, subject to the needle's logging mode and truncation. |
| `rule_match` | DEFENDER only | Configured rule-name substring. |
| `rule_state` | DEFENDER only | `PRESENT` or `MISSING`. |

### Header telemetry

Action: `haystack_header_fields`, emitted by a `HEADER` needle. Common fields
plus `Label`, `header_field`, and one or more cached run-header fields:
`collected_at`, `ww_version`, `os`, `model`, `serial`, `last_boot`,
`csc_version`, `csc_source`, and `vpn_profile`. `header_field` is the
requested field name or `*` for the bundled all-fields form. `collected_at`
is the cache recomputation time. `vpn_profile` can be `NOT_SET` when absent.

### Self-update

Actions: `cpr_self_update_triggered`, `cpr_self_update_passed`,
`cpr_self_update_failed`. Common fields plus `channel` (`DEV`/`PROD`),
`status`, `network_state`, `reason`; passed/failed events also normally carry
`exit_code`.

### XmlVault

Actions: `xml_vault_triggered`, `xml_vault_passed`, `xml_vault_failed`,
`xml_vault_restore`. The first three carry common fields plus `mode`, `status`,
`source`, `reason`, `profile_name`, and `profile_count`. `xml_vault_restore`
carries common fields plus `profile_name` and `reason`. `mode` is `sync` or
`restore`; `source` identifies `netlogon` or `local_vault`.

### ISE posture

Actions: `ise_posture_redirect`, `ise_posture_compliant`,
`ise_posture_failed`. `ise_posture_redirect` carries `psn_url` and `ssid`;
`ise_posture_compliant` carries `duration_sec`; `ise_posture_failed` carries
`reason`, in each case alongside the common fields.

### VPN and network state

* `vpn_disconnect_forced`: common fields plus `reason` and `vpn_state_was`
(the previous VPN state).
* `vpn_profile_missing`: common fields; no action-specific fields.
* `network_state`: common fields plus `ip`, `gw`, `dns`, `ssid`, `connection_type`, `vpn_state`,
and `lease_sec` (DHCP lease duration in seconds).
* `vpn_blackhole_add`: common fields plus `ssid` and `dc_reachable`.
* `vpn_blackhole_remove`: common fields plus `reason`.
* `captive_walled_garden`: common fields plus `gateway_ip` and `ssid`.

### HayStack and subsystem operations

* `haystack_reroll_result`: common fields plus `result`, `needle_count`, and
`reason`.
* `subsystem_task_sync_failed`: common fields plus `subsystem`, `operation`,
and `reason`.
* `tech_checkin`: common fields plus optional free-text `note` supplied by the
admin console.

## Other schema-supported fields

These fields are registered for emitters or higher-volume profiles and may
appear on action families above: `status_code` (HTTP/protocol code),
`classification` (probe classification), `zip` (self-update package),
`success` (boolean-like operation result), `old_ssid`/`new_ssid` (SSID
transition), `vpn_forced_disconnect` (boolean-like forced-disconnect flag),
`process_name`/`pid` (process context), `operation`, `tier`, `trusted`,
`event_id`, `seconds_since_wake`, `service_found`, `wait_sec`, `tag`,
`minutes_remaining`, `basic_state`, `mgmt_state`, `flavor`, and `ExtraInfo`
(free-form quoted data from `WW_syslog.ps1`).

`install.ps1` also supports install/uninstall result payloads with the
normalized contract's `machine`/`EvtTime` context plus `exit_code`, `reason`,
and `version`. The concrete actions are `cpr_install_result` and
`cpr_uninstall_result`; these result actions are created by the installer
rather than the active tee profile. The current installer emitter does not
include `user`; see the drift list below.

## Known drift / discrepancies

The following were found by comparing the schema with RC2 emitters; the schema
was intentionally not changed in this documentation task:

1. DEFENDER `needle_hit` payloads emit `rule_match` and `rule_state`, but
   neither field is registered in `Optional` or `CanonicalCasing` in
   `haystack_msg_schema.psd1`.
2. The SESSION `needle_hit` payload omits the otherwise mandatory `user`
   field. This is a real emitter/mandatory-contract mismatch.
3. The legacy `network_state_change` payload uses `ts` and legacy fields
   rather than the normalized `EvtTime` contract; it is explicitly preserved
   as `event_class=legacy_haystack`.
4. The active tee profile includes `cpr_self_update_*`, ISE posture,
   blackhole, `captive_walled_garden`, `network_state`, and `tech_checkin`
   actions. Their fields are represented in the schema's shared field catalog,
   but the PSD1 does not enumerate action-to-field mappings; this document
   derives those mappings from `WW_tee_events.psd1` and call sites.
5. `cpr_install_result` and `cpr_uninstall_result` emit `machine`, `EvtTime`,
   `exit_code`, `reason`, and `version`, but omit mandatory `user`.

## Sources and maintenance

Primary source: `support_files/haystack_msg_schema.psd1`. Cross-checks:
`WW_tee_events.psd1`, `WW_tee.ps1`, `haystack_action.ps1`, `haystack.ps1`,
`main/*.ps1`, `WW_xml_vault.ps1`, the cap-portal runners, `WW_syslog.ps1`,
`install.ps1`, and `admin/Invoke-WhiteWalkerAction.ps1`. If code emits a new
field or action, update the authoritative PSD1 first (unless an owner-approved
decision says otherwise), then refresh this catalog and the query library.
