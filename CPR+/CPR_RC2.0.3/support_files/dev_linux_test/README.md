# Linux test kit + pick-up-here notes

Dev tooling only. `support_files\` is not mirrored to endpoints (the installer copies named files out of it), so nothing here is deployed.
Last updated 2026-10-30 (RC2.0.3: content-based needle dedup, TTL needles, needle bundles, run-then-tail in the tech console). RC2.0.2 is frozen as the DEV soak build.

## Run the Pester suite on Linux (no Windows needed)

    bash support_files/dev_linux_test/bootstrap.sh     # once: PowerShell 7.5.4 + Pester 5.6.1 built from source -> ~/.cpr-dev   (~10 s)
    bash support_files/dev_linux_test/run_all.sh       # every *.Tests.ps1, 4 at a time                                       (~2 min)

* Per-file detail: `~/.cpr-dev/results/<name>.txt` (`FAIL|<test path>|<message>` lines, then `SUMMARY|pass|fail|skip|notrun|container errors`).
* `CPR_DEV_HOME=/some/dir` moves the install; `OUT=/some/dir` moves the results.
* In a Claude Code session, first call `add_repo` for `pester/Pester` (the git proxy then serves the clone). PSGallery, NuGet and the dotnet SDK are blocked, which is why Pester is built from source and its C# is compiled in memory by `Add-Type`.
* To compare against an older commit: `git worktree add /tmp/base <sha>` then `bash run_all.sh /tmp/base/CPR+/CPR` with a different `OUT`. That is how regressions were told apart from older failures.

### What Linux can and cannot tell you
Most of the suite is static source checks and AST-loaded functions, which behave the same on Linux. Failures that are **Windows-only** show up as missing cmdlets, `cmd.exe`, `netsh`, Windows principals, jobs. Shims at the top of a few test files define stand-ins for `Get-WinEvent`, `Get-ScheduledTask` and `Unregister-ScheduledTask` so `Mock` works. A green Linux run is **not** a Windows run: run `Invoke-Pester` on a real box before trusting a release.

## State at hand-off (2026-10-30, RC2.0.3): 908 pass / 5 fail on Linux (same 5 Windows-only failures as 2.0.2; 94 new tests). Earlier, 2026-10-28 (RC2.0.2): 814 pass / 5 fail on Linux; Windows 5.1 run was 811 pass / 14 fail before the fixes below

Remaining Linux-only failures (all pass on Windows): `BuildIdentity` "vpncli calls are time-bounded" (3, need real `cmd.exe`), `WW_cap_portal_runner.Tests` Windows-principal flag test and `Test-SiteReachability` timeout test (2).

Steve's call (2026-10-28): the Cisco Browser Killer is retired, so its unit tests were removed (the `CapPortalSkipBrowserKill` gating tests still guard the safe default while the code exists). The Edge-args and netsh tests now assert against the runner's own source. The six WebHelper-301 tests were rewritten to match the current code (record-based dedupe, newest record first, preflight-first URL precedence, `Write-BaseCapTee`, `classification` field, `Get-BaseCapMissingNavigationOutcome`). Windows 5.1 pitfalls fixed in tests: `.Count` on single objects needs `@()`, `Join-String` is PS7-only, `Get-WmiObject` must be mocked, non-SYSTEM Windows runs spool instead of writing the queue, leaked `$global:TeeEnabled`/`HaystackEnabled`.

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
* Repo layout: `CPR+/CPR_RC2.0.3/` is the source of truth. `CPR+/CPR/` is the staging folder `BUILD.ps1` / `roll_cpr_package.sh` regenerate (`rm -rf CPR/` first), so never edit it; it is tracked in git only by accident of `git add -A` and could go in `.gitignore`.
* `roll_cpr_package.sh` prunes `support_files/dev_linux_test` from the staged package, so this kit never reaches the NETLOGON zip.
