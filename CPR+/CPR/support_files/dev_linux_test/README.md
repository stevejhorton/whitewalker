# Linux test kit + pick-up-here notes

Dev tooling only. `support_files\` is not mirrored to endpoints (the installer copies named files out of it), so nothing here is deployed.
Last updated 2026-10-28 (end of the session that built the HayStack drain kick, installer HayStack registration and the suite clean-up).

## Run the Pester suite on Linux (no Windows needed)

    bash support_files/dev_linux_test/bootstrap.sh     # once: PowerShell 7.5.4 + Pester 5.6.1 built from source -> ~/.cpr-dev   (~10 s)
    bash support_files/dev_linux_test/run_all.sh       # every *.Tests.ps1, 4 at a time                                       (~2 min)

* Per-file detail: `~/.cpr-dev/results/<name>.txt` (`FAIL|<test path>|<message>` lines, then `SUMMARY|pass|fail|skip|notrun|container errors`).
* `CPR_DEV_HOME=/some/dir` moves the install; `OUT=/some/dir` moves the results.
* In a Claude Code session, first call `add_repo` for `pester/Pester` (the git proxy then serves the clone). PSGallery, NuGet and the dotnet SDK are blocked, which is why Pester is built from source and its C# is compiled in memory by `Add-Type`.
* To compare against an older commit: `git worktree add /tmp/base <sha>` then `bash run_all.sh /tmp/base/CPR+/CPR` with a different `OUT`. That is how regressions were told apart from older failures.

### What Linux can and cannot tell you
Most of the suite is static source checks and AST-loaded functions, which behave the same on Linux. Failures that are **Windows-only** show up as missing cmdlets, `cmd.exe`, `netsh`, Windows principals, jobs. Shims at the top of a few test files define stand-ins for `Get-WinEvent`, `Get-ScheduledTask` and `Unregister-ScheduledTask` so `Mock` works. A green Linux run is **not** a Windows run: run `Invoke-Pester` on a real box before trusting a release.

## State at hand-off (2026-10-28): 789 pass / 18 fail

| Failing | Count | Why | Needs |
|---|---|---|---|
| `BuildIdentity` "vpncli calls are time-bounded" (3) | 3 | launch real `cmd.exe` | run on Windows |
| `WW_cap_portal_runner.Tests` | 9 | Windows principal, jobs, `netsh`, Edge args | run on Windows; some may be stale |
| `WW_cap_portal_runner_base.Tests` "WebHelper 301" group | 6 | **code and tests disagree** (below) | Steve's decision |

The six decisions (old tests vs current code in `WW_cap_portal_runner_base.ps1`):
1. De-dupe key: code gives `fallback:t:<time>...`, test expects `pid:176`.
2. Outcome URL order: code = preflight redirect first, WebHelper only as corroboration (documented in `Get-BaseCapTelemetryUrl`); test expects WebHelper first.
3. Tag/field lists for `cap_portal_preflight_observation` and the WebHelper observation tag have grown past what the test lists.
4. Two tests assert `Write-TeeLog '<tag>'` literally; the code now goes through `Write-BaseCapTee`.
5. The wiring regex for `Get-CiscoWebHelperNavigationEvent -Since $webHelperSince -SeenProcessIds` no longer matches.
6. "Emits one final no-observation outcome outside the polling loop" looks for a string that moved.

## Built this session, untested on a real box
* **End-of-run drain kick** (`Invoke-HaystackDrainKick`, `Main.Entry.ps1`): after self-update, starts the `HayStack_Monitor` task so queued install/update results ship now. Gated on THIS run's corp-reachable verdict (`$shareOk`), not on `state.json` (can be stale; WW_syslog is UDP and reports success once the packet leaves). Falls back to running `haystack_action.ps1`. Toggle: `$HaystackDrainKick`. Log lines: `haystack_drain_kick started|skipped|failed`.
* **Installer registers and validates HayStack_Monitor** (`Register-HaystackMonitorTask`, `Test-Installation`): it has no task XML (created by `haystack.ps1 -reroll`) and `Remove-OldTasks` deletes it on every install. A failed registration fails validation.
* **`Test-RerollNeeded`** now re-registers the task when it is missing even if the stamp is current.
* HostScan detection and hold, native-redirect portal fields (tee master `RC2.1-m5`), untrusted-management-line fix (earlier in the session).

## Verify on the test box next
1. `Invoke-Pester` (Windows PowerShell 5.1 and/or 7) over `tests\` and the root `*.Tests.ps1`.
2. Roll, install, then run `Get-ScheduledTask -TaskPath \CPR\` : expect **9** tasks including `HayStack_Monitor`; the install log should show `Registered task: \CPR\HayStack_Monitor` and the validation line.
3. Self-update with the tee-keep flag: expect `haystack_drain_kick started task='\CPR\HayStack_Monitor'`, and `cpr_install_result` + `cpr_self_update_passed` in Splunk within a minute (`| eval indexed=strftime(_indextime,"%F %T")` to see lag).
4. Real HostScan connect on Xfinity: watch `vpn_hostscan_posturing_hold`, `vpn_hostscan_posture_active`, `vpn_client_connect_activity`.
5. A native (non-Always-On) redirect: send one real `cap_portal_redirect` row with `detection_source=native_redirect` and a populated `url=`.

## Open items (nothing built yet unless noted)
* `final_url_port`: in schema and tee master, never emitted by the 301 row (waiting for Steve's go).
* Add running CPR `version` to `cpr_self_update_triggered|passed|failed` rows (offered).
* Bound the self-update download and installer wait with timeouts (`download_timeout`, `installer_timeout`); held until a real hang is seen.
* XSD validation: AnyConnect XSD is copied to `main\` but `$XsdPath` points one level above it, and validation is off. Decide warn-only vs reject; needs a real production profile sample.
* Possible `vpncli_timeout` tee event.
* Hardening idea: HayStack's own wakes also trust `state.json`; a stale `user_tun` plus a UDP "success" on a dead path can drop rows. Fix = TCP syslog or a real reachability probe before draining.
* Docs: placeholder contacts remain in `cpr_user_guide.html` and `vpn_blackhole_info.html`; town-hall slide metrics unverified. The Nov 1 corporate spec-build session uses `docs/SPEC_BUILD_BRIEF.md` (in the repo, not shipped).
* Older backlog: installer downgrade-merge guard, retire `WW_migrate_legacy_tasks.ps1`, the duplicate `RUN END` line, the 13 s XmlVault observation, self-update `Copy-Item`/installer have no timeout.
* Repo layout: after the reorg the live tree is `CPR+/CPR/`. `CPR+/CPR_RC2.0.2/` is the previous copy (same source, same test fixes); keep them in step or retire one.
