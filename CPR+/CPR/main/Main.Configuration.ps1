# CPR RC2 configuration and feature switches.
# Depends on: WW helper scripts loaded by WW_main.ps1.

# ------------------------------- Config ---------------------------------------
$ver                    = "3.14.0_RC2.1.0"
$initial_sleep          = 3     # seconds after DHCP before checks
$LogPath                = "C:\ProgramData\WhiteWalker\logs\white_walker.main.log"

# Network connection polling (for "Connect Automatically" unchecked scenarios)
$NetworkConnectionRetries = 2   # number of retries to wait for active connection
$NetworkConnectionWait    = 3   # seconds between retries

# DHCP lease sanity threshold (RC1.24).
# Enterprise DHCP scopes hand out leases measured in hours-to-days. A lease
# measured in seconds/low minutes means the scope or relay is misconfigured and
# the client renews constantly, which makes CPR's network-state checks re-trigger
# every cycle (looks like a CPR loop, root cause is upstream DHCP). 300s (5 min)
# sits well below any legitimate enterprise lease while still being long enough
# that short-but-valid lab/guest scopes don't produce noise.
$DhcpLeaseShortWarnSeconds = 300

# Authoritative per-run network snapshot. Owner: MAIN network discovery.
# Unit: seconds. Consumers: MAIN classification/captive wait and BASE's
# independent handoff validation. Reuse is allowed only after a cheap targeted
# identity check; TTL expiry, interface/IP/gateway/SSID change, reconnect, DHCP
# transition, unlock-triggered new run, or self-update invalidates the snapshot.
$NetworkSnapshotMaxAgeSec = 30

# ONLINE fast path. An authoritative ONLINE gateway preflight still performs
# tunnel/on-prem classification, state/flare emission, blackhole cleanup, SSID
# handling and final run cleanup. Portal-only evidence/remediation work is never
# entered. Maintenance remains synchronous by default for reliable result
# logging; installer/task optimizations keep that bounded.
$OnlineFastPathEnabled = $true
$OnlineFastPathRunMaintenance = $true

# NEW: Preflight check toggle
$UseNewPreflight        = $true   # RC1: nwcheck.optum.com is live and in posture redirect ACL
$NewPreflightURL        = "https://gateway.optum.com"
$LegacyPreflightURL     = "http://clients3.google.com/generate_204"

# ISE-specific redirect test
$ISERedirectTestURL     = "http://enroll.cisco.com"  # On-prem ISE posture redirect detection
$PostureComplianceTimeout = 20   # seconds to wait for posture compliance after rescan

# VPN stabilization
$VpnStateMaxWaitSeconds = 12     # how long to wait for vpncli to settle to Connected/Disconnected
$VpnIntermediateMaxWait = 30     # force disconnect if stuck in Reconnecting/Connecting/Unknown >30s
$VpnWakeDetection = $true        # detect wake from sleep and disconnect blocking VPN (smart disconnect)
$VpnWakeTimeWindow = 120         # seconds - if wake event within this window, consider it a wake scenario

# RC2.1 early VPN gate - runs at the TOP of every run, before any wait/sleep/preflight
$EarlyVpnGateEnabled        = $true  # disconnect blocking VPN on wake / SSID jump / no-IP before anything else
# Connected VPN + gateway preflight unreachable: poll for the state to leave Connected (stale
# Connected after a hop) or the DC to answer a ping, instead of probing blind.
$StaleConnectedMaxWaitSec   = 8
$StaleConnectedPollSec      = 2
$EarlyGateDisconnectWaitSec = 6      # max seconds to wait for vpncli to report Disconnected after an early disconnect
$PreflightRequiresSettledVpn = $true # skip gateway preflight unless VPN is Disconnected or Connected (it always fails otherwise)
$VpnConnectedShortCircuit   = $true  # VPN already Connected at the gate: skip preflight + cap-portal checks, flare tunnel flavor, exit
$VpnConnectedTrustOnWakeJump = $true  # Connected means Connected even right after a wake/SSID jump (no preflight). $false = old stale-guard: fall through to the normal path

# Rescan & flare behavior
$RescanOnlyOnRedirect   = $true
$FlareCooldownMinutes   = 1      # per-flare tag cooldown
$RescanCooldownMinutes  = 1      # rescan cooldown
$PostureWaitSeconds     = 12     # wait for posture service to appear on redirect
$StateRoot              = 'C:\Windows\UHGLogs'
$StateFile              = Join-Path $StateRoot 'state.json'

# Captive Portal Runner Mode
# Controls which cap portal runner script fires when a captive portal is detected.
# "full"   = WW_cap_portal_runner.ps1 (existing - kills Cisco browser, opens Edge, full UX)
# "base"   = WW_cap_portal_runner_base.ps1 (NEW - observer mode, lets Cisco Secure Client
#             handle captive portal natively; only intervenes if user not online within timeout)
# Pivot:   flip $CapPortalRunnerMode to swap behavior fleet-wide with zero other changes.
# AlwaysOn profiles (uhg_always_on.xml / uhg_always_on_elevated.xml) benefit most from "base".
# $vpnProfile is read from HKLM:\SYSTEM\UHG\DSM at run header time.
$CapPortalRunnerMode            = "base"   # "full" | "base"
$CapPortalBaseScriptPath        = "C:\ProgramData\WhiteWalker\WW_cap_portal_runner_base.ps1"
$CapPortalFullScriptPath        = "C:\ProgramData\WhiteWalker\WW_cap_portal_runner.ps1"

# -------------------------- Base/Main timer parity ----------------------------
# Audit (RC2.1): these two values were dead config - no code read them. The
# deployed WW_cap_portal_runner_base.ps1 used its own literals (120 / 10), which
# is what the endpoint logs show ("Observation window expired after 125s"), and
# the stale 1800 here never had any effect on any run. The owner set the Base
# timers to match Main, so Main is now the documented source of truth and the
# values are MIRRORED by the Base literals and asserted by a drift test
# (tests/CPR_RC2.CapPortalRecovery.Tests.ps1).
#
# Equivalent concepts:
#   $CapPortalBaseTimeoutSeconds  <-> Base $ObserveTimeoutSeconds   (observation /
#       authentication window). Same meaning as $CaptivePortalTimeout below, which
#       is Main's own "wait for the user to complete auth" window - both 120s.
#   $CapPortalBaseCheckIntervalSec <-> Base $CheckIntervalSec       (poll interval).
#
# NOT applicable to Base (full-runner only, WW_cap_portal_runner.ps1):
#   $InitialWaitSeconds = 150  - wait before launching the validation browser.
#   $FinalWaitSeconds   = 30   - post-auth stabilization wait after Edge launch.
# Base never launches a browser, so neither wait has a Base equivalent and
# neither is mirrored. Waits are never silently extended.
$CapPortalBaseTimeoutSeconds    = 120      # base runner observation window (mirrors Base $ObserveTimeoutSeconds)
$CapPortalBaseCheckIntervalSec  = 10       # base runner: connectivity poll interval while observing

# Base -> Full escalation switch (analogous to $CapPortalSkipBrowserKill).
# Controls ONLY whether the standalone Base observer is allowed to fire Event 777
# (captive_portal_browser) and hand off to WW_cap_portal_runner.ps1 when its
# observation window expires. Full mode behavior is completely unaffected.
#
# Default FALSE: Base is observe-only today. On timeout it writes an observe-only
# completion, emits truthful outcome/lifecycle telemetry, expires its state and
# exits - it does NOT fire 777 and does NOT launch the full runner.
#
# Base runs standalone (Task Scheduler, separate process) and never inherits this
# scope, so the effective value is carried through the dispatch/remediation
# artifact Main writes before firing 777/778. A missing/undefined property in that
# artifact is treated as FALSE (fail-safe: no escalation).
$CapPortalBaseAllowFullEscalation = $false

# Fleet-wide default change (flips the old workaround): WW_cap_portal_runner.ps1
# (full runner) used to always spend 20 seconds killing Cisco's own captive
# portal browser/WebHelper processes (Start-CiscoBrowserKiller) before opening
# Edge. Months of Cisco Secure Client + Defender remediation work have made
# Cisco's native browser/WebHelper handling of captive portal redirects
# reliable, so that kill is now counterproductive - it fights the very client
# behavior we fixed. Default TRUE skips the kill fleet-wide (an undefined
# value in the full runner, which runs standalone and does not dot-source
# this file, is treated the same as TRUE). Set to $false only to restore the
# legacy kill-then-Edge behavior for a specific box/cohort if a regression is
# found.
$CapPortalSkipBrowserKill       = $true

# Captive Portal Integration
$FlagFile               = "C:\ProgramData\WhiteWalker\portal_complete.flag"
$InterruptFile          = "C:\ProgramData\WhiteWalker\network_interrupt.flag"
$RemediationStateFile   = "C:\ProgramData\WhiteWalker\cap_portal_remediation_active.flag"  # NEW ER2: Track VPN stabilization need
$CaptivePortalTimeout   = 120    # seconds MAIN waits for the runner's portal_complete.flag result
# RENAMED (RC2.2, Required E). The old name $FlagPollInterval looked
# interchangeable with Base's $CheckIntervalSec but is a DIFFERENT concept:
#   $MainPortalFlagPollIntervalSec - how often MAIN polls portal_complete.flag
#   $CapPortalBaseCheckIntervalSec - how often BASE polls CONNECTIVITY
# The old name is kept below ONLY as a backward-compatible alias so a manually
# deployed/legacy script that still reads $FlagPollInterval keeps working; new
# code must use the explicit name.
$MainPortalFlagPollIntervalSec = 3   # seconds between portal_complete.flag checks (consumer: MAIN)
$FlagPollInterval       = $MainPortalFlagPollIntervalSec   # DEPRECATED ALIAS - do not use in new code
$CaptiveEventCooldown   = 1      # minutes between captive portal event triggers
$CaptiveEventLimit      = 3      # max events before showing user alert
$CaptiveFailureFlag     = "C:\ProgramData\WhiteWalker\captive_failure.flag"
$UserPromptedFlag       = "C:\ProgramData\WhiteWalker\user_prompted.flag"


# =============================================================================
# CAPTIVE-PORTAL / RUNNER TIMING AND BEHAVIOR CONTRACT  (RC2.2, Required E)
# =============================================================================
# Owner requirement: every plausible captive-portal/preflight/runner tunable is
# declared HERE so a run's timers can be tuned in one place. Each value below
# lists its UNIT and its CONSUMER:
#
#   MAIN  - WW_main.ps1 / main\*.ps1 (SYSTEM)
#   BASE  - WW_cap_portal_runner_base.ps1 (USER, standalone process)
#   FULL  - WW_cap_portal_runner.ps1 (USER, standalone process)
#
# BASE and FULL are launched by Task Scheduler and never inherit this scope, so
# Main writes the EFFECTIVE values into the dispatch/remediation artifact
# (timing_contract) BEFORE firing Event 777/778. The literals still present in
# those two scripts are FAIL-SAFE DEFAULTS ONLY - used when the artifact is
# absent or unreadable (manual/legacy launch) - and are asserted against this
# file by a drift test.
#
# No current effective value is changed by this consolidation: every number
# below is the value that was already in force, just declared in one place.
# The readiness-gate values are new (Required D).
# -----------------------------------------------------------------------------

# ---- Required D: bounded network-settle readiness gate ----------------------
# Live evidence: enroll.cisco.com redirected at 23:29:34 while the authoritative
# gateway.optum.com preflight fired at 23:29:39 and timed out INCONCLUSIVE. The
# path simply was not usable yet. A fixed sleep was rejected because it would
# delay every healthy run; instead cheap readiness signals are polled and the
# preflight fires the MOMENT one is observed, with a hard cap after which the
# probe runs anyway and the run records that readiness was never confirmed.
$NetworkReadyMaxWaitMs          = 8000   # ms, hard cap on the settle wait (consumer: MAIN, BASE)
$NetworkReadyPollIntervalMs     = 500    # ms between readiness polls (consumer: MAIN, BASE)
$NetworkReadyGatewayTimeoutMs   = 750    # ms per default-gateway reachability probe (consumer: MAIN, BASE)
$NetworkReadyDnsTimeoutMs       = 1500   # ms per preflight-host DNS resolution probe (consumer: MAIN, BASE)
$NetworkReadyEnabled            = $true  # bool, master switch for the readiness gate (consumer: MAIN, BASE)

# ---- BASE runner (fail-safe literals mirrored in WW_cap_portal_runner_base.ps1)
$CapPortalBasePreflightTimeoutMs   = 3000   # ms per Base empirical preflight probe (consumer: BASE)
$CapPortalBasePreflightMaxProbes   = 6      # count, preflight probes across the window (consumer: BASE)
$CapPortalBaseWebHelperLookbackSec = 180    # seconds of bounded EventID 301 pre-start lookback (consumer: BASE)

# ---- Cisco Secure Client EventID 301-first evidence -------------------------
# MAIN reads the Windows Event Log directly only after Cisco's active WebHelper
# makes captive-portal ownership credible, or after an enroll.cisco.com redirect
# has already entered the remediation branch. HayStack is never required.
$CapPortalWebHelper301FirstEnabled              = $true                 # bool, enable direct 301-first evidence (consumer: MAIN)
$CapPortalWebHelper301LogName                   = 'Cisco Secure Client' # Windows Event Log channel (consumer: MAIN)
$CapPortalWebHelper301ProviderName              = 'csc_webhelper'       # actual provider in the Cisco Secure Client channel (consumer: MAIN, BASE)
$CapPortalWebHelper301EventId                   = 301                   # Windows event ID (consumer: MAIN)
$CapPortalWebHelper301LookbackSec               = 180                   # seconds; modestly above 120 to cover pre-launch WebView2 bursts without an unbounded scan (consumer: MAIN)
$CapPortalWebHelper301MaxRecords                = 256                   # records per query; bounds noisy same-timestamp csc_webhelper bursts (consumer: MAIN, BASE)
$CapPortalWebHelper301WaitSec                   = 3                     # seconds, hard cap for direct Event Log polling (consumer: MAIN)
$CapPortalWebHelper301PollIntervalMs            = 250                   # milliseconds between direct Event Log polls (consumer: MAIN)
$CapPortalWebHelper301MaxAgeSec                 = 180                   # seconds, maximum accepted event age (consumer: MAIN, BASE)
$CapPortalWebHelper301NoUrlImmediatePreflight   = $true                 # bool, no navigated_url falls through immediately (consumer: MAIN)
$CapPortalWebHelper301SuppressPreflight         = $true                 # bool, usable active navigation suppresses gateway probe (consumer: MAIN, BASE)
$CapPortalWebHelper301HaystackFallbackEnabled   = $false                # bool, diagnostic haystack.log fallback after Event Log read failure only (consumer: MAIN)
$CapPortalWebHelper301HaystackLookbackSec       = 120                   # seconds of haystack.log diagnostic fallback lookback (consumer: MAIN)

# ---- Shared runner behavior -------------------------------------------------
$CapPortalHandoffMaxAgeSec      = 900     # seconds before a dispatch artifact is stale (consumer: BASE)
$CapPortalValidationSite        = "https://www.optum.com"  # url, post-auth validation (consumer: BASE, FULL)
$CapPortalSiteTimeoutSec        = 3       # seconds per Test-SiteReachability call (consumer: BASE, FULL)

# ---- FULL runner (fail-safe literals mirrored in WW_cap_portal_runner.ps1) ---
$CapPortalFullInitialWaitSec    = 150     # seconds waiting for interactive auth (consumer: FULL)
$CapPortalFullFinalWaitSec      = 30      # seconds post-auth stabilization (consumer: FULL)
$CapPortalFullCheckIntervalSec  = 5       # seconds between FULL connectivity checks (consumer: FULL)

function Get-CprCapPortalTimingContract {
    <#
    .SYNOPSIS
    The single effective captive-portal timing/behavior contract for this run.

    .DESCRIPTION
    Built from the variables above (never from literals) and written verbatim
    into the dispatch/remediation artifact as `timing_contract` so BASE and FULL
    consume Main's effective values instead of their own fail-safe defaults.
    #>
    return [ordered]@{
        main_captive_portal_timeout_sec    = $CaptivePortalTimeout
        main_flag_poll_interval_sec        = $MainPortalFlagPollIntervalSec
        main_initial_sleep_sec             = $initial_sleep
        main_captive_event_cooldown_min    = $CaptiveEventCooldown
        main_captive_event_limit           = $CaptiveEventLimit
        network_ready_enabled              = [bool]$NetworkReadyEnabled
        network_ready_max_wait_ms          = $NetworkReadyMaxWaitMs
        network_ready_poll_interval_ms     = $NetworkReadyPollIntervalMs
        network_ready_gateway_timeout_ms   = $NetworkReadyGatewayTimeoutMs
        network_ready_dns_timeout_ms       = $NetworkReadyDnsTimeoutMs
        base_observe_timeout_sec           = $CapPortalBaseTimeoutSeconds
        base_check_interval_sec            = $CapPortalBaseCheckIntervalSec
        base_preflight_timeout_ms          = $CapPortalBasePreflightTimeoutMs
        base_preflight_max_probes          = $CapPortalBasePreflightMaxProbes
        base_webhelper_lookback_sec        = $CapPortalBaseWebHelperLookbackSec
        webhelper_301_first_enabled        = [bool]$CapPortalWebHelper301FirstEnabled
        webhelper_301_log_name             = $CapPortalWebHelper301LogName
        webhelper_301_provider_name        = $CapPortalWebHelper301ProviderName
        webhelper_301_event_id             = $CapPortalWebHelper301EventId
        webhelper_301_lookback_sec         = $CapPortalWebHelper301LookbackSec
        webhelper_301_max_records          = $CapPortalWebHelper301MaxRecords
        webhelper_301_wait_sec             = $CapPortalWebHelper301WaitSec
        webhelper_301_poll_interval_ms     = $CapPortalWebHelper301PollIntervalMs
        webhelper_301_max_age_sec          = $CapPortalWebHelper301MaxAgeSec
        webhelper_301_no_url_immediate_preflight = [bool]$CapPortalWebHelper301NoUrlImmediatePreflight
        webhelper_301_suppress_preflight   = [bool]$CapPortalWebHelper301SuppressPreflight
        webhelper_301_haystack_fallback_enabled = [bool]$CapPortalWebHelper301HaystackFallbackEnabled
        webhelper_301_haystack_lookback_sec = $CapPortalWebHelper301HaystackLookbackSec
        handoff_max_age_sec                = $CapPortalHandoffMaxAgeSec
        validation_site                    = $CapPortalValidationSite
        site_reachability_timeout_sec      = $CapPortalSiteTimeoutSec
        full_initial_wait_sec              = $CapPortalFullInitialWaitSec
        full_final_wait_sec                = $CapPortalFullFinalWaitSec
        full_check_interval_sec            = $CapPortalFullCheckIntervalSec
        preflight_url                      = $NewPreflightURL
    }
}

# Ivanti flare exe (receives "/<tag>")
$flareExe               = "$env:SystemRoot\System32\rundll32.exe"

# FlareGun configuration (context-aware flare routing)
$FlareGunConfigPath     = "C:\ProgramData\WhiteWalker\WW_flaregun_config.json"

# Log rotation
$LogRotationMaxBytes    = 1MB     # rotate when log exceeds this size
$LogRotationKeep        = 5       # number of rotated logs to keep

# VPN Blackhole (on_prem hairpin prevention)
$BlackholeEnabled       = $false  # set to $true to enable VPN blackhole on on_prem flare
$BlackholeScriptPath    = "C:\ProgramData\WhiteWalker\Set-VpnHostsEntry.ps1"
$BlackholeFlagFile      = "C:\ProgramData\WhiteWalker\vpn_blocked.flag"
$BlackholeClearedFlagFile = "C:\ProgramData\WhiteWalker\vpn_blackhole_cleared.flag"  # marks "-rm already confirmed" while disabled - skips redundant -rm + Splunk noise on subsequent runs

# HayStack Event Monitor (event log needle watcher)
$HaystackEnabled               = $true  # set to $true to enable HayStack event monitoring
$HaystackScriptPath            = "C:\ProgramData\WhiteWalker\haystack.ps1"
$HaystackRerollCooldownMinutes = 60      # passed to haystack.ps1 -reroll as override if needed

# HayStack HEADER needles (opt-in structured run-header telemetry)
# One consolidated JSON cache holding every known run-header field with its
# value, collected_at and last_sent_at. Write-RunHeader refreshes due fields on
# each run; haystack_action.ps1 ships them when a HEADER needle's SendHours has
# elapsed. Defaults apply to any field no HEADER needle names explicitly.
$HeaderCacheFile                = "C:\ProgramData\WhiteWalker\header_cache.json"
$HeaderCacheDefaultRefreshHours = 6     # how often cached values are recomputed
$HeaderCacheDefaultSendHours    = 24    # documented default SendHours (enforced in haystack_action.ps1)
$HeaderNeedleFiles              = @(
    "C:\ProgramData\WhiteWalker\needles.cfg"
    "C:\ProgramData\WhiteWalker\needles_local.cfg"
)

# Tee logging (volume-knob event forwarding, routes through Haystack syslog queue)
$TeeEnabled    = $true
$TeeEventsFile = "C:\ProgramData\WhiteWalker\WW_tee_events.psd1"

# XmlVault subsystem (offline VPN XML backup and island self-heal)
# Syncs VPN profile XMLs from NETLOGON to local vault; restores from vault on island detection.
# Task lifecycle managed by Sync-XmlVaultTask - mirrors BlackholeShutdown pattern.
$XmlVaultEnabled     = $true   # set to $true to enable XmlVault sync and restore
$XmlVaultScriptPath  = "C:\ProgramData\WhiteWalker\WW_xml_vault.ps1"
$XmlVaultTaskName    = "WW_xml_vault"
$XmlVaultTaskXml     = "C:\ProgramData\WhiteWalker\triggers\WW_xml_vault.xml"

# Self-Update-Support (Needs admin) (pull cpr_current.zip from NETLOGON and run install.ps1)
# Flag files at C:\Windows\Temp\ are writable by all standard users - no admin required.
# DEV flag -> bin/DEV/cpr_current.zip | PROD flag -> bin/PROD/cpr_current.zip
$SelfUpdateEnabled           = $true
$SelfUpdateDevFlag           = "C:\Windows\Temp\cpr_update_dev.flag"
$SelfUpdateProdFlag          = "C:\Windows\Temp\cpr_update_prod.flag"
$SelfUpdateCooldownFlag      = "C:\ProgramData\WhiteWalker\cpr_update_ran.flag"
$SelfUpdateCooldownMinutes   = 10   # prevent re-trigger loop
$SelfUpdateRemoteBase        = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN\CPR\bin"
$SelfUpdateZipName           = "cpr_current.zip"
$SelfUpdateInstallScript     = "install.ps1"

# Task Scheduler folder that holds ALL CPR jobs (WW_* and HayStack_Monitor).
# KEEP IN SYNC with $CprTaskFolder in install.ps1 and $TsTaskPath in haystack.ps1
# (a Pester test enforces it). Existence checks read System32\Tasks\CPR directly.
$CprTaskFolder = "\CPR\"

# TEMPORARY pivot for WW_migrate_legacy_tasks.ps1 (run by install.ps1): removes CPR
# jobs from their old root / \HayStack\ locations. Set $false to turn it off.
# Retire the whole thing once no endpoint runs a pre-RC2.1 build (see that script's header).
$LegacyTaskMigrationEnabled = $true

# Blackhole Shutdown Task (register/unregister WW_blackhole_shutdown TS task)
# Task fires Set-VpnHostsEntry.ps1 -rm on system shutdown (Event ID 1074)
# Lifecycle managed by WW_main on each run - mirrors BlackholeEnabled state.
$BlackholeShutdownTaskName   = "WW_blackhole_shutdown"
$BlackholeShutdownTaskXml    = "C:\ProgramData\WhiteWalker\triggers\WW_blackhole_shutdown.xml"

# SSID change detection - disconnects VPN when network changes to prevent captive portal blocking
$SsidCacheFile          = "C:\ProgramData\WhiteWalker\ssid_last_known.flag"
$SsidChangedFlag        = "C:\ProgramData\WhiteWalker\ssid_changed.flag"
$VpnSsidChangeGraceSec  = 15    # seconds to wait for VPN to progress before force disconnect
$VpnSsidChangePollSec   = 3     # poll interval during grace window

# Walled-garden captive portal detection
$WalledGardenFlare      = "captive_walled_garden"  # flare tag for DNS-blocking portals
$MacCacheFile           = "C:\ProgramData\WhiteWalker\mac_last_known.flag"  # per-SSID MAC cache for randomization detection

# Optional adapter fallback: if vpncli is ambiguous, treat an "Up" Cisco virtual adapter as connected
$UseAdapterFallback     = $false

# Target domain/DC name for on-prem check
$DC_FQDN = "ms.ds.uhc.com"
$TestDC_DiagnosticMode  = $false   # $true = full verbose suffix classification log; $false = single compact summary line

# Trusted SSID list - on-prem tiebreaker for WiFi connections
# Tier 1: hardcoded fast path - checked first, zero I/O, covers ~99% of fleet
# Tier 2: trusted_ssids.cfg from NETLOGON - checked only when Tier 1 misses
# Wired (Ethernet) connections bypass SSID check entirely.
$HardcodedTrustedSsids       = @('WLANi03')   # fast path - no file I/O
$TrustedSsidEnabled          = $true           # set $false to bypass SSID check entirely
$TrustedSsidSyncEnabled      = $true           # set $false to disable NETLOGON sync
$TrustedSsidSyncCooldownHours = 4              # min hours between NETLOGON syncs
$TrustedSsidFile             = "C:\ProgramData\WhiteWalker\trusted_ssids.cfg"
$TrustedSsidSyncFlag         = "C:\ProgramData\WhiteWalker\trusted_ssids_sync.flag"
$RemoteTrustedSsidFile       = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN\CPR\trusted_ssids.cfg"

# End-of-run network re-check (last step, after maintenance): if the handled adapter's SSID/IP/gateway/link changed, say so and
# pop one capped re-run the current run has exited (IgnoreNew would drop a trigger fired mid-run).
$EndRunRecheckEnabled   = $true
$EndRunRerunMax         = 2      # max chained re-runs...
$EndRunRerunWindowSec   = 60     # ...within this many seconds
$EndRunRerunDelaySec    = 5      # detached starter waits this long so the current run has exited
$EndRunRerunStateFile   = "C:\ProgramData\WhiteWalker\rerun_chain.txt"
