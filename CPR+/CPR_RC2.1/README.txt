CPR RC2 — experimental decomposition line

This directory is a new, in-progress CPR release line seeded from
CPR_3.14_RC1.25. It is not production-ready and is not a drop-in replacement
for RC1.25. The RC2 markers are `RC2.0` in install.ps1 and `3.14.0_RC2.0`
in WW_main.ps1.

## Main decomposition

`WW_main.ps1` is now a thin loader. It keeps the two deployed helper scripts
at their existing top-level locations, then dot-sources `main/` in this order:

1. Main.Common.ps1
2. Main.Configuration.ps1
3. Main.Logging.ps1
4. Main.State.ps1
5. Main.FlareGun.ps1
6. Main.Network.ps1
7. Main.CaptivePortal.ps1
8. Main.VpnState.ps1
9. Main.SsidChange.ps1
10. Main.SelfUpdate.ps1
11. Main.Entry.ps1

Main.Common.ps1 loads first: it holds dependency-free primitives (the
`Test-CprMapKey` / `Get-CprMapValue` safe map accessors) that every later file
may call. The rest of the order loads configuration and shared utilities
before libraries that call them, and loads the orchestration entry last. Main.Entry.ps1 exposes
`Invoke-WhiteWalkerMain`; the loader only invokes it when WW_main.ps1 is run
directly, so tests can dot-source the entry point without starting a run.
Functions and their bodies were moved from RC1.25 without behavior,
telemetry, or timing changes.

The actual grouping is: configuration; logging; state/cooldowns; FlareGun,
blackhole, and Cisco path helpers; network/connectivity; captive portal;
posture/VPN; SSID/trusted-SSID; self-update; and orchestration.

## Logs layout

Phase 2 consolidates all RC2 runtime logs under `logs/`, which deploys to
`C:\ProgramData\WhiteWalker\logs\`. The installer creates this directory and
preserves it during upgrades and uninstall. The phase-1 `WW_main.ps1` loader
remains the Task Scheduler entry point; `main/` is mirrored to the deployed
WhiteWalker root so the loader can source its libraries.

See `logs/README.md` for the complete runtime log and telemetry-queue
inventory. Tail scripts and diagnostics now read the same consolidated paths.

## Admin tools

`admin/` is a mirrored subdirectory (deployed to
`C:\ProgramData\WhiteWalker\admin\`) for tech-facing admin/diagnostic/action
tools, distinct from core runtime scripts. `Watch-WhiteWalkerLog.ps1` is the
first tool deployed there; more tooling is expected to follow.

## Captive-portal timing and behavior contract (RC2.2)

Every plausible captive-portal/preflight/runner tunable is declared in
`main/Main.Configuration.ps1` under "CAPTIVE-PORTAL / RUNNER TIMING AND
BEHAVIOR CONTRACT", with unit and consumer (MAIN/BASE/FULL) per value.
`Get-CprCapPortalTimingContract` returns the effective set; Main writes it
into the dispatch/remediation artifact as `timing_contract` BEFORE firing
Event 777/778, and both `WW_cap_portal_runner_base.ps1` and
`WW_cap_portal_runner.ps1` consume it at startup. The literals still present
in those two runners are FAIL-SAFE DEFAULTS ONLY, used when the artifact is
absent or unreadable (manual/legacy launch). Every path logs
`cap_portal_timing_contract source='dispatch_artifact'|'fallback_defaults'`.

Main's `$FlagPollInterval` was renamed `$MainPortalFlagPollIntervalSec` (how
often MAIN polls portal_complete.flag) so it is no longer confusable with
Base's `$CheckIntervalSec` (how often BASE polls connectivity). A
backward-compatible `$FlagPollInterval` alias is kept and documented in
Main.Configuration.ps1.

## Bounded network-settle readiness gate (RC2.2)

`Wait-CprNetworkReady` (main/Main.Network.ps1) runs immediately before the
authoritative preflight, and `Wait-BaseNetworkReady` does the same after
Base's fast network gate. Both poll cheap readiness signals (default-gateway
reachability, DNS resolution of the preflight host) and fire the probe the
moment one is observed. The wait is hard-capped by
`$NetworkReadyMaxWaitMs`; on expiry the probe runs anyway and the run records
`signal='not_confirmed'`. Evidence is logged as
`network_ready_gate network_ready_wait_ms=... signal=... attempts=...`
alongside the existing `preflight_timing network_ready_to_preflight_ms` line.
A longer fixed sleep was rejected: it would tax every healthy run, including
the corporate-wireless posture path.

## Friendly log viewer

`admin\Watch-WhiteWalkerLog.ps1` is an additive, built-in PowerShell 5.1 log
viewer. Run it without parameters for a numbered stream/action menu; the
existing `tail_*.ps1` scripts remain unchanged and available during
evaluation.

It is also reachable in-process from `admin\Invoke-WhiteWalkerAction.ps1`
(menu entry `W`): pick a stream, tail it live, and press Q or Esc to return
to the console main menu without exiting the console. A missing log is
reported and returns to the menu rather than throwing, and the action is
written to the admin actions log like every other console action.

The tailer tracks position by BYTE OFFSET. Rotation (the live log renamed to
`.1` and recreated at 1MB) and in-place truncation are detected when the
current length is less than the last known offset, and the reader resets to
the start of the new file deliberately - exactly once - instead of
re-spooling the whole log.

## Base captive-portal evidence pilot

Base mode emits independent passive-preflight and Cisco WebHelper EventID 301
evidence through `cap_portal_preflight_observation` and
`cap_portal_webhelper_navigation`.  Both were level-5 pilot events; they are
now registered in level 1 (the default) together with the FlareGun
lifecycle events (`flare_dispatched`, `flare_suppressed`, `flare_failed`,
`flare_runner_started`, `flare_runner_completed`) so the full Splunk chain
`dispatched -> runner started -> preflight observation -> webhelper navigation
-> runner completed` survives at a realistic steady-state tee level.  Flares
are per-run de-duped and cooldown-gated, so the added volume is small.
The active `WW_tee_events.psd1` is regenerated from `WW_tee_master.psd1` on every
install/upgrade (its Level is kept), so new tags arrive without manual steps.

Base also runs its own empirical `gateway.optum.com` probe, polled across the
observation window, detects ISE's non-standard "HTTP 200 with Location" as a
redirect, and classifies it (ISE_EMPLOYEE / ISE_GUEST / NON_ISE).  Base still
takes no action on that finding - it logs, ships, and hands it back to Main.

### Captive-portal evidence precedence

Normal clean-network, no-network and on-prem ISE classification still uses the
empirical `gateway.optum.com` preflight:

* HTTP 200/404 with no `Location` -> ONLINE, no captive-portal action.
* Any 2xx/3xx with a `Location` -> REDIRECT (this includes ISE's non-standard
  HTTP 200 + Location); protocol, FQDN and port are parsed from it.
* Timeout / DNS / transport failure -> INCONCLUSIVE.  It is NOT online and NOT
  proof that no portal exists.  Walled-garden gateway/DNS probing is fallback
  evidence only: it runs after an inconclusive preflight, never overrides a
  usable preflight result, and never blocks the Base handoff.

Cisco Secure Client EventID 301 is now first only after an active Cisco
WebHelper makes captive-portal ownership credible, or after
`enroll.cisco.com` has already redirected Main into NON_ISE remediation. Main
queries the actual Windows Event Log directly with a bounded wait; HayStack and
`haystack_syslog_queue.jsonl` are never control-plane dependencies. A fresh,
correlated, usable `navigated_url` is immediate portal evidence and suppresses
the PowerShell gateway probe while WebView2 owns the path. A missing event, a
no-URL/render-failed event, a stale/prior-network event, or an Event Log read
failure falls through fail-soft to the gateway preflight above.

The direct query uses the actual `Cisco Secure Client` channel,
`csc_webhelper` provider and EventID 301. `Main.Configuration.ps1` is the source
of truth for the 180-second lookback (increased modestly from 120 seconds), the
256-record per-query ceiling, 3-second bounded wait, 250ms poll interval and
180-second maximum event age. The larger lookback covers navigation emitted
before Main finishes startup; the record ceiling prevents an unbounded scan
while allowing a valid URL to survive a same-timestamp burst of no-URL records.
Records are ordered newest-first by time/RecordId, RecordId is the primary
dedupe identity, and a fallback identity is used only when RecordId is absent.
`webhelper_301_lookup` logs queried/examined/rejected/accepted counts, selected
RecordId/time and a truthful terminal reason.

Source precedence is `cisco_webhelper_301`, then `gateway_preflight`.
`haystack_log_fallback` is optional supporting diagnostics after a direct Event
Log read failure and can never suppress the gateway probe. Canonical portal URL
always uses WebHelper `navigated_url`; WebHelper `final_url` (usually
`msftconnecttest.com`) stays visible but is never substituted. Navigation is
portal evidence, not remediation success; Base/Full still require configured
connectivity validation after the user completes authentication. Missing 301
remains normal for on-prem `ISE_EMPLOYEE`, and Main still owns posture rescan
with no EventID 301 dependency.

### Phase timing and observation scheduling

Main logs stable `phase_timing` records for startup/bootstrap (including the
run header), the network-context snapshot with adapter/IP/gateway versus SSID
time, the first 301 lookup and timing-contract artifact write. Base logs
artifact-read and network-snapshot timing. Both keep
`network_ready_to_preflight_ms`, but it now measures from the explicit
network-ready landmark to the instant the gateway preflight starts; the
separate `startup_to_preflight_ms` and `preflight_duration_ms` fields prevent
startup/header work or probe duration from being misattributed to readiness.
A suppressed preflight is explicit (`gateway_preflight_ran=false`) rather than
reported as a successful probe.

Before this correction, a 10-second Base interval could appear as roughly
0/16/34/52/72 seconds because each cycle slept ten seconds after doing its
work. Base now logs `base_observe_cycle cycle=... work_ms=... sleep_ms=...
remaining_ms=...` and sleeps only the remainder of the target interval. Event
bodies already identified by RecordId are not reparsed, probe/validation
timeouts are capped by the remaining observation deadline, and the 120-second
window should end close to 120 seconds instead of routinely reaching 129/131
seconds. Exact startup and endpoint timing improvements require validation on a
managed Windows/Cisco endpoint; sandbox tests validate the calculations only.

Main persists that authoritative context as `dispatch_context` in the
remediation-state artifact immediately before firing Event 777/778; the Windows
event message text is unchanged.  Base reads it and keeps it separate from its
own later preflight and from optional WebHelper findings.

### ONLINE fast path, network snapshots, and wired telemetry

`$OnlineFastPathEnabled` explicitly gates the clean ONLINE path. After an
authoritative ONLINE preflight, Main still performs required VPN/on-prem
classification, state/flare work, blackhole cleanup, SSID handling, telemetry
and final cleanup, but never enters WebHelper lookup, redirect/walled-garden
tests, Base/Full dispatch, remediation-state creation, portal polling, or a
secondary preflight. `online_fast_path ran=... skipped='...'` records the
decision. `$OnlineFastPathRunMaintenance` defaults true; setting it false
defers noncritical self-update/HayStack/XmlVault maintenance while retaining
handback and blackhole safety cleanup.

Main captures one authoritative network snapshot per run. It includes capture
time, interface index/GUID/name, adapter class and state, IP/prefix, gateway,
SSID, DNS, MAC, DHCP lease metadata, and an interface+IP+gateway+SSID
fingerprint. `$NetworkSnapshotMaxAgeSec` (seconds, MAIN consumer) defaults to
30. Reuse requires a cheap targeted adapter/IP/default-route/SSID fingerprint
check. TTL expiry, missing identity, adapter loss, reconnect, IP/gateway/SSID
change, or synchronous self-update causes a full rebuild. Captive waits use the
cheap check and preserve `NETWORK_CHANGED`. Base remains a separate process and
captures/validates its own current identity before trusting Main's handoff.

`network_state` telemetry now emits adapter-derived `connection_type`. Active
Wi-Fi is `WiFi` whether or not SSID is available; active physical Ethernet with
a usable IP/default gateway is `Wired`; VPN/virtual/unknown and no usable local
network remain `Unknown`/`NoNetwork`. `ssid` is the actual Wi-Fi name or `N/A`;
Splunk must not infer wired connectivity from a missing SSID.

Accepted fresh direct EventID 301 evidence is carried into remediation. It
suppresses the initial remediation gateway pre-check that AlwaysOn/WebView2 is
known to block, but never suppresses post-auth connectivity validation and
therefore can never by itself claim remediation success.

Installer Task Scheduler removal and validation now take one scheduler snapshot
per phase and match exact task name/path, rather than invoking the expensive
provider once per task. Removal, deployment, registration, validation and
materially slow per-task actions emit `installer_phase_timing` /
`task_action_timing`. Self-update intentionally remains synchronous by default:
that preserves exclusive install execution, exit-code handling and reliable
flag/result logging; its download/extract/installer phases are logged separately
as maintenance rather than routing latency.

### Telemetry truthfulness and the sticky profile

`Write-TeeLog -PassThru` reports exactly one of `queued`,
`tag_not_in_profile`, `haystack_disabled`, `tee_disabled`, `access_denied` or
`error`, and the Base / full / FlareGun paths log that token.  The queue append
now creates `haystack_syslog_queue.jsonl` when missing, grants the local Users
group Modify once so USER-context Base and SYSTEM-context Main can both append,
retries briefly on concurrent writes, and reports `access_denied` instead of
losing the event silently.  Queue format and drain behavior are unchanged, and
telemetry remains fail-soft - it never blocks remediation or dispatch.

Every tee level is defined in ONE file, `WW_tee_master.psd1` (each level lists only
what it adds; level N includes every level below it).  `WW_set_tee_level.ps1 -Level N`
merges levels 1..N into the active `WW_tee_events.psd1` (header: Level,
ProfileVersion, Generated).  The installer reapplies the active Level from the new
master on every upgrade (previous file kept as `.bak`); a profile that has no Level
marker gets the default level (1); `Custom = $true` in a profile opts it out.  New tags
and fields (for example `classification`, `os_name`, `trace_id`) therefore reach
endpoints on upgrade; a tag missing from the profile is still reported truthfully
as `tag_not_in_profile`.

Changing the level without admin rights: create an empty file
`C:\Windows\Temp\cpr_tee_<1-5>.flag` (name only - content is ignored).  The next WW_main
run applies it, deletes the flag, sends a `tee_level_set` event and reverts to the
previous level after `$TeeFlagRevertHours` (336 hours = 14 days).  Use
`cpr_tee_<1-5>_keep.flag` to make the level stick (no revert, and it cancels a pending
revert).  Bad names or failures rename the flag to `.failed` (swept after 7 days).

Examples from `C:\ProgramData\WhiteWalker`:

```powershell
.\admin\Watch-WhiteWalkerLog.ps1
.\admin\Watch-WhiteWalkerLog.ps1 -Stream CapPortal -Last 100 -Wait
.\admin\Watch-WhiteWalkerLog.ps1 -Stream Main -Filter ERROR
.\admin\Watch-WhiteWalkerLog.ps1 -All -Last 50 -Wait
```

`ERROR` and `FATAL` lines are red, warnings are yellow, debug lines are dark
gray, and informational lines are gray. The JSON-lines telemetry queue is
displayed as a compact `EvtTime/action/machine/user/status/reason` summary.
Missing streams are reported without terminating the viewer. No external
modules or PowerShell Gallery installation is required.

## Tech action console

`admin\Invoke-WhiteWalkerAction.ps1` is the action-side companion to the log
viewer above: a numbered, menu-driven, zero-dependency PowerShell 5.1 console
for the handful of things a field tech or support engineer needs to actually
*do* to a WhiteWalker-managed endpoint, rather than just observe. It requires
elevation (`#Requires -RunAsAdministrator`), loops back to the main menu after
every action, and never exits on an error - every action is wrapped so a
failure is logged and reported instead of crashing the console.

Run it with no parameters from `C:\ProgramData\WhiteWalker\admin`:

```powershell
.\Invoke-WhiteWalkerAction.ps1
```

Menu actions:

1. **VPN Profile Restore** - touches `C:\Windows\Temp\xml_restore.flag` and
   instructs the tech to lock/unlock (or log off/on) to complete the restore
   from the local XML vault. Does not lock the workstation itself.
2. **Force XmlVault Sync (bypass cooldown)** - runs `WW_xml_vault.ps1 -Force`
   directly, bypassing the normal 24h sync cooldown for a manual refresh.
3. **Self-Update Trigger** - prompts for DEV or PROD channel, touches the
   matching self-update flag file, and tells the tech how to complete it.
4. **Tech Check-In (telemetry)** - fires a `tech_checkin` event via the
   existing `Write-TeeLog` pipeline, with an optional free-text note field.
   The event is **queued locally** to
   `logs\haystack_syslog_queue.jsonl` - it is not sent to Splunk immediately.
   HayStack drains that queue on its next wake (normally a lock/unlock or the
   `HayStack_Monitor` heartbeat) and ships it via `WW_syslog.ps1`. The action
   verifies the queue file actually changed: if the event was gated (e.g. the
   active tee profile is below level 2, where `tech_checkin` is first
   registered) or the write failed, it reports an actionable error instead of
   success and records it in `white_walker.admin_actions.log`.
5. **Needles Sync Check (diff, read-only)** - compares local `needles.cfg`
   against the NETLOGON share copy using the same version/hash comparison
   logic as `haystack.ps1`'s `Sync-NeedlesFile`, and reports in-sync /
   out-of-sync / share-unreachable. Performs no sync itself.
6. **New Needle Wizard** - guided prompts to build and append a new
   `NEEDLE|`/`SESSION|`/`DEFENDER|`/`HEADER|` line to `needles_local.cfg`,
   validated against the same rules `haystack.ps1`'s `Read-NeedleFile`
   enforces before it is ever written to disk. The append preserves the
   file's existing newline convention (LF or CRLF, defaulting to CRLF for a
   missing/empty file) instead of always introducing CRLF, and precedes the
   new needle with a `# Added via Invoke-WhiteWalkerAction.ps1 on <ISO-8601
   timestamp>` provenance comment. Write failures are caught, logged to
   `white_walker.admin_actions.log`, and reported instead of claiming success.
7. **Tee Log Level Picker** - lists levels 0-5 from `WW_tee_master.psd1` with their
   descriptions, shows the currently active profile, and regenerates the live
   `WW_tee_events.psd1` at the chosen level (via `WW_set_tee_level.ps1`) after confirming.
8. **Diagnostics & Test Tools Launcher** - a curated (not auto-discovered)
   submenu of the tech-usable scripts from `diagnostics\` and `tests\` (see
   the PR description for the full include/exclude list and reasoning;
   genuine Pester unit-test suites are excluded).
9. **Quick Actions** - force a HayStack reroll, clear stale flag files, force
   an immediate `WW_main.ps1` run, or clear Blackhole VPN hosts-file entries.

Every action writes to its own audit log,
`C:\ProgramData\WhiteWalker\logs\white_walker.admin_actions.log` (1MB/5-file
rotation, same pattern as `haystack.log`), separate from the Splunk-bound
`tech_checkin` telemetry event. Destructive/state-changing actions prompt for
confirmation first; the needles diff is read-only and does not prompt.


## Testing

`tests/CPR_RC2.Main.Tests.ps1` validates the loader order and decomposition
surface without executing Windows-only runtime helpers. Full WW_main-style
Pester suites may fail in a Linux sandbox because the runtime dot-sources
`C:\ProgramData\WhiteWalker\WW_csc_client_info.ps1`; that is a pre-existing
Windows-environment limitation.

-dl the zip that is pinned (i'll update it and the room name when we switch versions.

RC1.25 packaging and deployment notes
--------------------------------------
- The DEV `cpr_current.zip` production candidate must be staged and zipped
  from `tools/automation/win_ise_rescanner/CPR_3.14_RC1.25/`. The
  `tests/RC1.25.Package.Tests.ps1` guard verifies the package root and the
  `3.14.0_RC1.25` version markers before a roll.
- `install.ps1` is retained only at
  `C:\ProgramData\WhiteWalker\support_files\install.ps1` for uninstall use.
  Upgrade/uninstall removes a stale root-level copy without removing the
  support-files copy.
- SYSTEM-run tee producers load
  `C:\ProgramData\WhiteWalker\WW_haystack_schema.ps1` and resolve the
  interactive `domain\user` when available. `NO_INTERACTIVE_USER` means the
  probes succeeded but no session is logged in; `USER_UNKNOWN` means every
  probe failed. The log records the resolver source and failed probe names.

RC1.25 changelog
----------------
- Added an RC1.25 package source-of-truth/version guard.
- Removed stale root-level `install.ps1` copies during upgrade/uninstall.
- Added SYSTEM-context user resolution with helper deployment and diagnostics.

-Open an elevated powershell (ASAM Developer etc)

-unzip the file via file explorer

-(inside powershell) cd to the dir created CPR_3.14_RC<version>/CPR_3.14_RC<version> is normally how it is written out
-./install.ps1
-./install.ps1                 # install/upgrade
-./install.ps1 -Uninstall      # uninstall (aliases: -rm, -Remove)
-Let it complete the install
-from the same powershell cd c:\ProgramData\WhiteWalker\ #This is the main dir

#TO SEE LOGS (Note:Logs are generated as needed, so if you see no data (red powershell error) on a fresh install, this is expected.
tail_ww_log.ps1           #MAIN LOG
tail_ww_blackhole.ps1     #VPN BLACKHOLE LOG
tail_ww_cap_log.ps1       #CAP PORTAL LOG
tail_ww_haystack_log.ps1  #HAYSTACK LOG


WW_main.ps1 vars of Interest
# VPN Blackhole (on_prem hairpin prevention)
$BlackholeEnabled       = $false  # set to $true to enable VPN blackhole on on_prem flare

# HayStack Event Monitor (event log needle watcher)
$HaystackEnabled            = $false  # set to $true to enable HayStack event monitoring
# Deployed HayStack files (C:\ProgramData\WhiteWalker): haystack.ps1, haystack_action.ps1,
# needles.cfg, needles_local.cfg, WW_haystack_schema.ps1 (lint/validation helper + the
# shared user-context resolver), support_files\haystack_msg_schema.psd1 (master telemetry
# schema - defines mandatory fields EvtTime/machine/user/action and the full optional field
# catalog). RC1.25 deploys the schema to BOTH C:\ProgramData\WhiteWalker\ and
# C:\ProgramData\WhiteWalker\support_files\, and install.ps1 now warns if any required
# telemetry helper (WW_tee.ps1, WW_haystack_schema.ps1, WW_tee_events.psd1,
# haystack_msg_schema.psd1) is missing after deployment.


# HAYSTACK NEEDLE TYPES
needles.cfg (synced from NETLOGON) and needles_local.cfg (local test bed, never synced)
drive HayStack. Four directive types exist; the top-of-file comment block in needles.cfg
is the authoritative format reference.

  NEEDLE|LogName|EventID|XPathFilter|Label[|ExtendedLogging]  - Task Scheduler event trigger
  SESSION|StateChange|Label                                   - Task Scheduler session trigger
  DEFENDER|RuleNameMatch|IntervalHours|Label[|ExtendedLogging] - inline MDM firewall rule check
  HEADER|FieldName|Label[|RefreshHours=N][|SendHours=M]        - inline run-header telemetry

DEFENDER rule-name matching
  RuleNameMatch is LITERAL text (never a regex) and is matched as a SUBSTRING of the rule's
  Name= value - not as an exact full name. Matching is case-insensitive and separator-
  tolerant: both the configured value and the rule name are lowercased and stripped of every
  non-alphanumeric character (spaces, hyphen, underscore, slash, dot, repeated whitespace)
  before the substring test. This exists because the Defender/MDM team does not keep a stable
  naming convention: the configured "V2 - MsWebView2 Any Out" previously reported a false
  MISSING against the deployed rule "V2-MsWebView2 Any Out", and now matches correctly with
  no manual renaming of needles_local.cfg.

  Tradeoff: removing separators means a very short or generic value can collide with an
  unrelated rule (e.g. "Allow-Web" and "AllowWeb" normalize identically). Operators should
  choose a distinctive, stable, descriptive substring of the rule name to reduce false
  positives. An empty or whitespace-only RuleNameMatch - or one that normalizes away to
  nothing, such as "---" - is rejected at parse time and never matches anything.

  Output and telemetry are unchanged (PRESENT/MISSING, rule_match=/rule_state=), as is the
  six-hour per-label flag cadence.

HEADER needles (RC2)
  Purpose: let a tech opt a WW_main run-header field into HayStack/Tee/syslog telemetry by
  adding one line to needles_local.cfg or needles.cfg - no PowerShell edits. Before this,
  header context (Cisco Secure Client version, OS, model, serial, last boot, VPN profile)
  only ever existed as free-text lines in white_walker.main.log.

  Supported FieldName values (plus * for "all of them, bundled into one payload"):
    ww_version, os, model, serial, last_boot, csc_version, csc_source, vpn_profile

  Two independent intervals, so this never becomes telemetry spam:
    RefreshHours (default 6)  - how often Write-RunHeader recomputes the cached value.
                                When multiple needles name the same field, the shortest
                                interval wins so no consumer sees a stale value.
    SendHours    (default 24) - how often the cached value is actually shipped, independent
                                of refresh cadence.

  Consolidated cache: C:\ProgramData\WhiteWalker\header_cache.json
    ONE JSON file for all fields (not one file per field or per needle), holding each
    field's value, collected_at and last_sent_at, plus a per-Label last_sent_at for *
    bundles. Write-RunHeader (main\Main.Logging.ps1) refreshes due fields in a single
    write per run; haystack_action.ps1 reads it on each wake (event, session or heartbeat),
    ships anything whose SendHours has elapsed through Write-HaystackTelemetry ->
    Write-TeeLog, and stamps last_sent_at back. HayStack never probes the box itself.

  Telemetry: action="haystack_header_fields" with Label=, header_field= (the field name or
  *) and the value(s) as key="value" pairs. The tag must be present in the active
  WW_tee_events.psd1 profile (tee level 2 and above ship it) or it is silently dropped by
  the volume knob, exactly like every other tee tag.

  HEADER directives are inline-evaluated - they never produce Task Scheduler trigger XML,
  same as DEFENDER. An unknown/misspelled FieldName is skipped with a WARN in haystack.log.


# TESTING & DIAGNOSTICS
Captive Portal Simulations:
- tests/TEST_simulate_cap_portal.ps1
  Plumbing simulation (event trigger + runner path): writes synthetic remediation state,
  fires real FlareGun Event Log triggers (Event 778 for base runner, Event 777 for full runner),
  and polls for completion flag. Use this to validate WhiteWalker event wiring and runner execution
  without needing a live captive portal network.

  RC1.25 - three kinds of evidence, do not confuse them:
    1. FLARE          Windows Event Log record (Event 777/778). Dispatch only. Proves the
                      trigger fired; it is NOT telemetry and NOT a pass on its own.
    2. LEGACY QUEUE   action="network_state_change" with event_class="legacy_haystack".
                      Preserved for existing Splunk views. Carries no user/EvtTime/ssid -
                      it is NOT a normalized remediation outcome row.
    3. NORMALIZED TEE action="cap_portal_redirect" / "cap_portal_remediation_passed" /
                      "cap_portal_remediation_failed" from Write-TeeLog. These are the rows
                      dashboards should be built on.

  PASS criteria: the simulator reports PASS only when a normalized cap_portal_* event is
  found in the local queue AND carries every required field:
    EvtTime, action, machine, user, ssid, url, port, ip, gw, dns, vpn_state,
    portal_type, status, reason
  A field that the endpoint genuinely could not determine is present but empty (reported as
  a WARN, not a fabricated value). EvtTime is stamped locally at event creation, before
  queueing - the simulator verifies this explicitly.

  Limitations: it validates LOCAL queueing only (haystack_syslog_queue.jsonl), not syslog
  delivery or Splunk ingest; url/port/portal_type come from synthetic state while
  ip/gw/dns/ssid/vpn_state are read live from the box; and it is non-destructive - it never
  edits fleet toggles or tee profiles, so tee being disabled yields a correct FAIL.

  user= values: a resolved domain\user means an interactive session was found;
  NO_INTERACTIVE_USER means the probes worked but nobody is logged on; USER_UNKNOWN means
  every lookup probe failed and is a real defect worth investigating (check the WhiteWalker
  log for the failing probe name).

- tests/TEST_mock_cap_portal_flow.ps1
  High-fidelity, end-to-end captive portal flow mock that exercises real HTTP redirect
  detection, field classification, off-network queueing, and subsequent queue draining:
    1. Real HTTP Redirect Detection: stands up an ephemeral loopback System.Net.HttpListener
       that returns authentic HTTP 302 redirects (http://127.0.0.1:<port>/portal/login?from=cpr_mock).
       Executes the real Test-Redirect and Get-CaptivePortalRedirectTelemetry logic against it,
       parsing URLs, ports, and portal classification (NON_ISE).
    2. WDAC-Immune Browser Substitution: WDAC currently blocks WebView2 runtime execution
       for endpoints not on the always-on VPN profile, causing captive portal windows to render
       completely blank during user impersonation testing. This tool avoids WebView2 dependency:
         -BrowserMode Stub (default): simulates runner completion signaling (portal_complete.flag
           with SUCCESS_NATIVE or TIMEOUT_NATIVE) without launching any browser process.
         -BrowserMode Edge: launches full msedge.exe to allow visual inspection while keeping
           pass/fail verdicts strictly tied to telemetry evidence.
    3. Off-Network Queue-Then-Drain Path: temporarily forces C:\Windows\UHGLogs\state.json
       currentState to 'mock_captive' so Test-SyslogReachable returns false. Verifies that
       cap_portal_redirect and cap_portal_remediation_passed/failed tee events land in
       haystack_syslog_queue.jsonl (Write-TeeLog -PassThru Queued=$true). Then flips state
       to 'user_tun' and executes Drain-SyslogQueue, reporting sent/expired/failed/remaining counts.
       Guarantees state.json is restored to its exact original content even on abort/error.
    4. Pass/Fail Verification: validates local EvtTime and all 14 required normalized fields:
       EvtTime, action, machine, user, ssid, url, port, ip, gw, dns, vpn_state, portal_type, status, reason.
       Validates against support_files/haystack_msg_schema.psd1 via Test-HaystackMsgSchema.

  Differences from TEST_simulate_cap_portal.ps1:
    - TEST_simulate_cap_portal.ps1 tests event-wiring and runner dispatch plumbing: writes
      synthetic remediation state and fires FlareGun event triggers while on-network.
    - TEST_mock_cap_portal_flow.ps1 tests genuine detection and delivery: responds to real HTTP
      redirects, tests URL/port telemetry extraction, enforces off-network queueing, drains
      the queue upon simulated reconnection, and bypasses WebView2 WDAC blank-render blocks.

  Parameters:
    -Outcome <Pass|Fail>       : Pass simulates successful login & clearance; Fail simulates timeout.
    -BrowserMode <Stub|Edge>   : Stub (default, headless completion signal) or Edge (msedge.exe launch).
    -SsidMarker <string>       : Unambiguous synthetic marker (default: "CPR-MOCK-FLOW").
    -StateJsonPath <string>    : Path to state.json (default: C:\Windows\UHGLogs\state.json).
    -QueueFilePath <string>    : Path to syslog queue (default: C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl).
    -FlagFilePath <string>     : Path to completion flag (default: C:\ProgramData\WhiteWalker\portal_complete.flag).
    -SyslogServer <string>     : Syslog collector host (default: cpr-syslog.uhc.com).
    -SyslogPort <int>          : Syslog collector port (default: 514).
    -ProbePort <int>           : Loopback listener port (default: 0 = dynamic ephemeral port).

  Synthetic Marker Field & Splunk Exclusion:
    The tool tags all emitted events with ssid="CPR-MOCK-FLOW" (or custom -SsidMarker).
    Splunk queries to inspect mock run:
      index=cba_cpr_logging action IN ("cap_portal_redirect","cap_portal_remediation_passed","cap_portal_remediation_failed") ssid="CPR-MOCK-FLOW"
    Splunk query to EXCLUDE mock test runs from production / SLO metrics:
      index=cba_cpr_logging NOT ssid="CPR-MOCK-FLOW"

- tests/Test-HayStackSyslog.ps1 -SimulateCaptivePortal -DeliveryMode direct
  Direct transport simulation: sends synthetic captive portal telemetry directly to the syslog collector.
  Use this to validate network delivery, syslog ingestion, and Splunk index parsing.

================================================================================
RC2.1 CAPTIVE-PORTAL RECOVERY CHANGES
================================================================================

BASE -> FULL ESCALATION FLAG
  main/Main.Configuration.ps1 : $CapPortalBaseAllowFullEscalation
    $false (default) - Base observes only. On observation timeout it does NOT fire
                       Event 777 and does NOT launch the full runner. It writes a
                       TIMEOUT_OBSERVE_ONLY completion artifact, emits truthful
                       flare_runner_completed telemetry
                       (reason=native_timeout_observe_only_no_escalation) and
                       clears its remediation state.
    $true            - Preserves the legacy behaviour: Base timeout fires Event 777
                       and hands off to WW_cap_portal_runner.ps1.
  Full mode is unaffected; this flag only controls the Base -> Full handoff.
  Base is standalone and never inherits Main scope, so the value rides in the
  dispatch artifact (base_allow_full_escalation). If the property is missing or
  unparsable Base fails safe to NO escalation. The effective value is logged at
  Main dispatch (cap_portal_dispatch_settings) and at Base startup
  (cap_portal_base_escalation_policy).

STRICT LOCAL-NETWORK GATE
  Test-PlausibleLocalNetwork (main/Main.Network.ps1) now requires ALL of:
    - an active non-VPN physical adapter (when a connection type is known)
    - a non-empty IPv4 that is not APIPA (169.254/16), loopback or 0.0.0.0
    - a valid non-zero default gateway
    - for a Wi-Fi path, a currently connected SSID (wired may have no SSID)
  Reasons: no_network_info, no_active_adapter, no_ip, apipa_ip, invalid_ip,
  no_default_gateway, wifi_no_connected_ssid, valid_ip_and_gateway, evaluation_error.
  The gate runs BEFORE the walled-garden probe and before any suspected-portal
  classification. If it fails, Main returns no_net_transient, fires the
  no_net_transient flare only, and fires NO Event 778 and NO Event 777.
  Base re-checks the same gate at startup; if the network disappeared between
  dispatch and launch it exits in seconds with
  network_unavailable_before_observation and never escalates.

IMMEDIATE AUTHORITATIVE PREFLIGHT
  Invoke-WhiteWalkerMain now runs: run header -> stale-flag cleanup -> interrupt
  flag -> Get-NetworkInfo -> SSID cache -> WLANi03 IP wait -> DHCP settle ->
  APIPA bail -> Get-NwCheckResult (gateway.optum.com) -> preflight_timing log ->
  startup subsystems (self-update, blackhole task sync, HayStack reroll,
  XmlVault sync) -> network_state tee -> SSID change check -> MAC randomization.
  Slow non-routing-critical subsystem work moved into
  Invoke-WhiteWalkerStartupSubsystems, which is idempotent and is still invoked
  on every early return. If the early probe is 'unreachable' it is re-probed once
  after SSID/VPN handling settles, so SSID-change VPN teardown is not lost.
  Evidence line: preflight_timing network_ready_to_preflight_ms=<n>.
  Base performs its first preflight immediately after the fast network gate and
  before reading the handoff artifact; it does not shell vpncli.exe first.

TIMER PARITY (Main is source of truth)
  Main $CaptivePortalTimeout        = 120 s  observation/authentication window
  Main $CapPortalBaseTimeoutSeconds = 120 s  Base observation window  (parity)
  Main $CapPortalBaseCheckIntervalSec = 10 s Base poll interval       (parity)
  Base $ObserveTimeoutSec / $CheckIntervalSec default to the same literals and
  are overridden by base_observe_timeout_sec / base_check_interval_sec from the
  dispatch artifact when present. tests/CPR_RC2.CapPortalRecovery.Tests.ps1
  enforces this as an automated drift check.
  Full-runner-only waits with NO Base equivalent (deliberately not mirrored):
    $InitialWaitSeconds = 150  (WebView2 interactive authentication wait)
    $FinalWaitSeconds   = 30   (post-authentication stabilization)
  NOTE: $CapPortalBaseTimeoutSeconds was previously 1800 but was dead config -
  no code read it. It is corrected to the deployed Base literal, not shortened.
  Base is deadline-aware: sleeps and per-operation timeouts are capped by the
  remaining window so a 120 s window no longer overruns to 125/131 s.

ARTIFACT FRESHNESS AND IDENTITY
  Every dispatch/remediation artifact is written atomically (temp + move) by
  Write-CapPortalRemediationState and carries created_at, timestamp, run_id,
  correlation_id, runner_mode, ssid, ip, gw, dns, base_allow_full_escalation,
  base_observe_timeout_sec and base_check_interval_sec.
  Base rejects a handoff artifact that is older than 900 s (stale_handoff) or
  whose network identity conflicts with live context (network_context_mismatch,
  SSID for Wi-Fi, otherwise IP/gateway); both contexts are logged.
  Clear-CapPortalRemediationState never deletes an artifact whose run_id matches
  the current run. Base clears its state on exit, timeout and network loss unless
  the artifact is deliberately retained for an escalated full runner.
  The gateway.optum.com probe URL is NEVER promoted to a canonical portal URL.
  When no redirect was observed the artifact records probe_url plus empty
  url/fqdn/protocol/port and url_source=none_no_redirect_observed.
  EventID 301 / WebView2 navigation is evidence only. Completion never claims
  remediation without the authoritative connectivity verification passing.

USER-CONTEXT TELEMETRY SPOOL (no broad ACL grants)
  C:\ProgramData\WhiteWalker\logs\spool
    Created by install.ps1 (Initialize-TelemetrySpool, idempotent, repaired on
    upgrade). Authenticated Users (S-1-5-11) receive CreateFiles/AppendData/
    WriteData/ReadData/Synchronize with ObjectInherit only - no Modify, no
    Delete, no ChangePermissions, and nothing is granted on the script or
    configuration directories.
  Non-SYSTEM writers (Base and the full runner) write one atomic
  evt_<utc>_<guid>.json per event (temp + move), so concurrent writers cannot
  corrupt the canonical JSONL.
  SYSTEM drains the spool: haystack_action.ps1 Import-SyslogSpool ingests the
  files in creation order, validates JSON, appends to
  haystack_syslog_queue.jsonl and deletes each file after success. The queue
  format and downstream drain semantics are unchanged.
  Write-TeeLog -PassThru reports reason='spooled' distinctly from 'queued'.
  Base also writes a separate atomic handback artifact
  (logs\spool\cap_portal_base_handback.json) which Main consumes via
  Import-CapPortalUserHandback, so USER context never has to rewrite the
  SYSTEM-owned control state.
  On Linux/sandbox the spool path is inert (Test-TeeSpoolRequired is Windows-only)
  and the direct-append path behaves exactly as before.

ACTIVE TEE PROFILE STALENESS AND REPAIR
  The generated active WW_tee_events.psd1 carries Level and ProfileVersion markers
  (ProfileVersion = the master's MasterVersion). Get-WWActiveTeeProfileName reads the
  Level marker only; a profile without one reports unknown_level (no guessing).
  Test-WWTeeProfileStale reports: current, not_installed, unknown_level,
  reference_missing, unreadable, missing_tags, extra_tags, version_mismatch.
  Invoke-WWTeeProfileRefresh refreshes the active profile from the currently
  selected level, preserving the operator's chosen level. If the level cannot be
  determined reliably it refuses to guess and leaves the file unchanged.
  Admin menu: option T (admin/Invoke-WhiteWalkerAction.ps1) is the one-step
  repair. WW_diagnostics.ps1 Test-TeeProfileHealth surfaces staleness and spool
  presence in Test-AllDiagnostics.
  install.ps1 regenerates the active profile from the master at the SAME Level on
  every upgrade (previous file kept as WW_tee_events.psd1.bak); Custom = $true skips it.

PRESERVED PREFLIGHT / ISE CONTRACT
  Outside the credible active-WebHelper 301-first branch, gateway.optum.com
  remains authoritative. 200/404 with no Location = online;
  2xx/3xx with Location = redirect; isepsn = ISE_EMPLOYEE with Main owning the
  posture rescan and no EventID 301 dependency; isegst = ISE_GUEST; any other
  redirect = NON_ISE. Fresh direct EventID 301 navigated_url evidence has
  precedence only while Cisco WebHelper actively owns the captive-portal path.
  Walled-garden remains fallback evidence only.
