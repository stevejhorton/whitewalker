# CPR RC2 main libraries

The files in this directory are dot-sourced by `../WW_main.ps1` in this order:

1. `Main.Common.ps1` — shared primitives (safe dictionary accessors) with no dependencies.
2. `Main.Configuration.ps1` — release settings and feature switches.
3. `Main.Logging.ps1` — logging, run headers, and system context.
4. `Main.State.ps1` — state persistence and cooldowns.
5. `Main.FlareGun.ps1` — flare dispatch, blackhole, and Cisco task helpers.
6. `Main.Network.ps1` — adapter, connectivity, redirect, and walled-garden checks.
7. `Main.CaptivePortal.ps1` — captive portal detection, telemetry, and remediation.
8. `Main.VpnState.ps1` — posture service and VPN state/gatekeeper logic.
9. `Main.SsidChange.ps1` — trusted SSID, cache, notification, and SSID changes.
10. `Main.SelfUpdate.ps1` — self-update handling.
11. `Main.TeeFlag.ps1` — user-touchable `cpr_tee_<N>.flag` tee level + automatic revert.
12. `Main.Entry.ps1` — `Invoke-WhiteWalkerMain` orchestration.

The order is intentional: configuration and shared functions are available
before dependent libraries, while the orchestration is loaded last. Runtime
helpers such as `WW_tee.ps1`, `WW_haystack_schema.ps1`, and the captive portal
scripts remain top-level in this phase.
