# CPR RC2 runtime logs

The deployed runtime log directory is `C:\ProgramData\WhiteWalker\logs\`.
It is created by `install.ps1` and is intentionally not mirrored from the
package or removed during uninstall.

| File | Stream |
| --- | --- |
| `white_walker.main.log` | Main WhiteWalker orchestration |
| `white_walker_install.log` | Installer execution and validation |
| `white_walker.cap_portal.log` | Full captive-portal runner |
| `white_walker.cap_portal_base.log` | Base captive-portal runner |
| `haystack.log` | HayStack event monitoring and queue draining |
| `haystack_syslog_queue.jsonl` | Shared HayStack and tee telemetry queue |
| `white_walker.flaregun_system.log` | SYSTEM flare processing |
| `white_walker.flaregun_user.log` | User-context flare processing |
| `white_walker.xml_vault.log` | VPN XML vault operations |
| `Set-VpnHostsEntry.log` | VPN blackhole hosts-file changes |
| `WW_notify.log` | User notifications |
| `diag_yyyyMMdd_HHmmss.log` | Collected diagnostic reports |
| `white_walker.browser_test.log` | Browser diagnostic test output |
| `white_walker.admin_actions.log` | Admin action console audit trail |
