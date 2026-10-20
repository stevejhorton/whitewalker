@{
    # =========================================================================
    # haystack_msg_schema.psd1
    # =========================================================================
    # Single source-of-truth schema for every key="value" telemetry payload
    # that WhiteWalker/CPR+ emits to the haystack syslog queue
    # (haystack_syslog_queue.jsonl) and, eventually, to Splunk
    # (index=cba_cpr_logging).
    #
    # Known emitters as of this schema version (search the repo for
    # "Invoke-SyslogSend" / "Write-SyslogQueue" / key="value" payload builders
    # if a new one shows up and isn't listed here):
    #   - WW_tee.ps1          (Write-TeeLog)      - ad-hoc nuggets, tag-gated
    #                                                by WW_tee_events.psd1 (includes
    #                                                tech_checkin, fired via
    #                                                admin\Invoke-WhiteWalkerAction.ps1)
    #   - haystack_action.ps1 (Write-HaystackHit) - needle_hit events
    #   - install.ps1         (Write-InstallResultEvent) - install/uninstall
    #                                                result events
    #
    # THIS FILE IS THE CONTRACT. It is the canonical artifact to hand off to
    # the Splunk/SIEM team so they know exactly what fields exist, what they
    # mean, and when they're populated. Any new emitter or field MUST be
    # added here (with a one-line description) before it ships.
    #
    # See also: WW_haystack_schema.ps1 (Test-HaystackMsgSchema) - the lint/
    # validation helper that enforces this file at runtime, and
    # support_files/HAYSTACK_SCHEMA_README.md for the full writeup.
    #
    # -------------------------------------------------------------------
    # VERSIONING
    # -------------------------------------------------------------------
    # SchemaVersion is a date stamp in ddMMMyy format (e.g. "01Oct26").
    # Bump it any time a field is ADDED, REMOVED, or RENAMED so the Splunk
    # team can track schema revisions over time. Do NOT bump it for
    # description-only edits.
    # =========================================================================
    SchemaVersion = "15Oct26"

    # -------------------------------------------------------------------
    # MANDATORY - must be present (non-empty) on EVERY message, regardless
    # of which script/function emitted it. A message missing any of these
    # cannot be reliably sorted/correlated in Splunk and MUST be treated as
    # unusable ("can't be sorted, can't be used") by Test-HaystackMsgSchema.
    # -------------------------------------------------------------------
    Mandatory = @{
        EvtTime = "ISO-8601 timestamp of when the underlying event occurred (not send/queue time)."
        machine = 'Hostname of the originating endpoint ($env:COMPUTERNAME).'
        user    = "User context associated with the event (interactive/logged-on user where resolvable). SYSTEM-only operations (e.g. unattended install/uninstall with no interactive session) MAY emit 'SYSTEM' or 'NO_INTERACTIVE_USER' - this is a documented, known gap pending Splunk team sign-off, not an empty/missing field."
        action  = "Event/action tag - every existing Splunk query in this repo filters on this field. Recommended as a 4th mandatory field since all current emitters already produce it; flagged here pending final Splunk-team naming confirmation alongside EvtTime/machine/user."
    }

    # -------------------------------------------------------------------
    # OPTIONAL - full catalog of fields emitted today, grouped by the
    # message family (emitter) that produces them, each with a 1-line
    # description. Test-HaystackMsgSchema flattens Mandatory + Optional
    # into a single "known fields" set for lint purposes - any key in a
    # payload that isn't in either bucket is flagged (warn, not fail) as a
    # possible typo/drift.
    # -------------------------------------------------------------------
    Optional = @{

        # --- haystack_action.ps1 : Write-HaystackHit (needle_hit events) ---
        Label     = "Needle label that matched (from needles.cfg/needles_local.cfg) - identifies which signature fired."
        EventID   = "Windows Event Log EventID of the matched event."
        LogName   = "Windows Event Log channel the matched event came from (e.g. Application, System)."
        Provider  = "Windows Event Log ProviderName of the matched event."
        body      = "Extended event message body - only present when a needle's ExtendedLogging mode is 1 (truncated 128 chars), 2, or all."

        # --- install.ps1 : Write-InstallResultEvent (install/uninstall results) ---
        exit_code = "Process exit code of the install/uninstall operation."
        reason    = "Short human-readable reason/status string for the event (install result, remediation outcome, etc.)."
        version   = 'CPR/WhiteWalker package version ($WW_Version) that performed the install/uninstall.'

        # --- WW_tee.ps1 : Write-TeeLog (ad-hoc tee nuggets) ---
        # Superset of every field currently referenced by the 'fields' lists
        # in tee_profiles/tee_level_*.psd1. WW_tee.ps1 does not itself
        # restrict which keys a caller may pass via -Data; this catalog
        # documents what's actually emitted today so Splunk/lint have a
        # single reference instead of re-deriving it from the profiles.
        url                   = "Captive portal / redirect URL involved in the event."
        port                  = "Network port relevant to the event (captive portal, etc.)."
        ssid                  = "Wireless SSID at event time, or N/A when unavailable/not applicable (including wired connections)."
        connection_type       = "Physical connection classification derived from adapter identity: WiFi, Wired, Unknown, or NoNetwork."
        vpn_state             = "CPR network state at event time (on_prem, user_tun, mgmt_tun, off_prem_no_vpn, captive_portal, off_prem_untrusted_ssid)."
        portal_type           = "Captive portal type/classification (e.g. walled_garden, standard_redirect)."
        status                = "Generic pass/fail/skip style status string for the tee'd sub-event."
        status_code           = "HTTP or protocol status code associated with a probe/check."
        classification        = "Classification result string for a probe/check (e.g. trusted SSID tiering). On cap_portal_preflight_observation rows this is the authoritative gateway.optum.com preflight classification: ONLINE (200/404 with no Location), REDIRECT (any 2xx/3xx with Location, including ISE's non-standard 200+Location) or INCONCLUSIVE (timeout/DNS/transport failure - never proof of a clean network)."
        channel               = "Self-update channel (DEV/PROD)."
        network_state         = "Network state at the time of a self-update evaluation."
        zip                   = "Self-update package filename/identifier."
        success               = "Boolean-ish success/failure flag for a self-update or similar operation."
        mode                  = "Operating mode for the tee'd sub-system (XmlVault sync/restore, cap_portal_runner mode, SSID tiering mode, etc.)."
        source                = "Trigger source for the tee'd sub-system (e.g. XmlVault trigger source)."
        profile_name          = "VPN profile name involved in an XmlVault or vpn_profile event."
        profile_count         = "Count of VPN profiles processed by XmlVault."
        psn_url               = "ISE PSN redirect URL detected during posture checks."
        duration_sec          = "Duration (seconds) of a timed sub-operation (posture remediation, cap_portal_runner result, etc.)."
        result                = "Generic result string for a tee'd operation (e.g. haystack reroll, cap_portal_runner result)."
        needle_count          = "Count of needles loaded/evaluated during a haystack reroll."
        gateway_ip            = "Captive portal gateway IP (walled-garden detection)."
        ip                    = "Endpoint IP address captured as part of a network_state snapshot."
        gw                    = "Default gateway IP captured as part of a network_state snapshot."
        dns                   = "DNS server(s) captured as part of a network_state snapshot."
        lease_sec             = "DHCP lease duration (seconds) of the primary adapter at network_state snapshot time; abnormally small values indicate a DHCP scope/relay misconfiguration."
        old_ssid              = "Previous SSID before an SSID-change event."
        new_ssid              = "New SSID after an SSID-change event."
        vpn_forced_disconnect = "Boolean-ish flag indicating whether an SSID change forced a VPN disconnect."
        vpn_state_was         = "Previous VPN state before a forced disconnect."
        process_name          = "Name of a process relevant to the tee'd event (e.g. a watched/terminated process)."
        pid                   = "Process ID relevant to the tee'd event."
        subsystem             = "Name of the CPR subsystem a tee'd task-sync event pertains to."
        operation             = "Operation name for a tee'd subsystem task-sync event."
        dc_reachable          = "Boolean-ish flag indicating whether a domain controller was reachable."
        tier                  = "Trust tier classification result for an SSID."
        trusted               = "Boolean-ish flag indicating whether an SSID is in the trusted list."
        event_id              = "Generic event identifier for a tee'd sub-event (lowercase variant - see also EventID above for needle-hit events). On flare lifecycle events this is the Windows Event Log ID configured for the flare tag (e.g. 777/778), empty when the tag has no configured event ID (legacy-direct dispatch)."
        seconds_since_wake    = "Seconds elapsed since the endpoint woke from sleep, for wake-detection events."
        service_found         = "Boolean-ish flag indicating whether an expected service was found running."
        wait_sec              = "Seconds waited for a service/condition before proceeding or timing out."
        tag                   = "Generic tag identifier for a tee'd sub-event (e.g. a flag/lock tag name)."
        minutes_remaining     = "Minutes remaining before a time-bound condition expires."
        basic_state           = "Basic (non-mgmt) network/VPN state snapshot value."
        mgmt_state            = "Management-tunnel state snapshot value."
        flavor                = "Variant/flavor classifier for a state snapshot event."

        # --- haystack_action.ps1 : Invoke-HeaderNeedleCheck (HEADER needles) ---
        # Opt-in structured shipping of WW_main run-header fields, cached in
        # C:\ProgramData\WhiteWalker\header_cache.json and released on each
        # HEADER needle's SendHours cadence. A needle naming one field emits
        # that field plus collected_at; FieldName=* emits every field below in
        # a single bundled payload.
        header_field          = "Run-header field a HEADER needle requested: one of ww_version/os/model/serial/last_boot/csc_version/csc_source/vpn_profile, or * for the all-fields bundle."
        collected_at          = "ISO-8601 time the cached run-header value was last recomputed by Write-RunHeader (single-field HEADER sends only)."
        ww_version            = "WhiteWalker/CPR release version string from the run header (e.g. 3.14.0_RC2.0)."
        os                    = "Operating system caption and version from the run header; on cap_portal_webhelper_navigation rows this is instead the Cisco WebHelper navigation OS/connectivity-target context parsed from EventID 301."
        model                 = "Endpoint manufacturer and model from the run header."
        serial                = "Endpoint BIOS serial number from the run header."
        last_boot             = "Last boot time of the endpoint from the run header."
        csc_version           = "Cisco Secure Client core version from the run header."
        csc_source            = "Where the Cisco Secure Client version was resolved from (manifest, update.txt, cache, or an error string)."
        vpn_profile           = "VPN profile name from HKLM:\SYSTEM\UHG\DSM, or NOT_SET when absent."

        # --- Captive portal event-family discriminator (RC1.25) ---
        event_class = 'Producer class of a captive-portal-related row: legacy_haystack marks the preserved legacy network_state_change queue event. Normalized cap_portal_* tee events do NOT carry this field - absence of event_class is what identifies a normalized outcome row. Windows Event Log flares (Event 777/778) are not queue events at all and never appear here.'
        fqdn        = "Captive portal host/FQDN parsed from the redirect URL."
        protocol    = "Captive portal URL scheme (http/https)."
        probe_url = "Configured captive-portal preflight URL passively observed by the Base runner."
        http_status = "HTTP response status from the passive Base preflight observation."
        redirect_url = "Location header observed by the passive Base preflight."
        duration_ms = "Duration in milliseconds of a bounded passive observation."
        navigated_url = "Actual Cisco WebHelper captive-portal URL navigated in EventID 301."
        final_url = "Cisco WebHelper EventID 301 final URL after navigation, often a connectivity-test URL."
        final_url_port = "Explicit port parsed from Cisco WebHelper final_url."
        process_id = "Cisco WebHelper EventID 301 process ID."
        thread_id = "Cisco WebHelper EventID 301 thread ID."
        ap_name = "Captive portal access-point name parsed from Cisco WebHelper navigation URL."
        ap_tags = "Captive portal access-point tags parsed from Cisco WebHelper navigation URL."
        ap_mac = "Captive portal access-point MAC parsed from Cisco WebHelper navigation URL."
        sip = "Portal session IP parsed from Cisco WebHelper navigation URL."
        org = "Portal organization value parsed from Cisco WebHelper navigation URL."
        ui = "Portal UI value parsed from Cisco WebHelper navigation URL."
        psid = "Portal session identifier parsed from Cisco WebHelper navigation URL."
        login_url = "Portal login URL parsed from Cisco WebHelper navigation URL."
        ma = "Client MAC value parsed from Cisco WebHelper navigation URL."
        api_domain = "Captive portal API domain parsed from Cisco WebHelper navigation URL."
        event_source = "Windows event source supplying structured captive-portal evidence."
        event_time = "Original event timestamp for structured captive-portal evidence."
        detection_source = "Canonical captive-portal evidence source: cisco_webhelper_301, gateway_preflight, or diagnostic-only haystack_log_fallback."
        redirect_type = "ISE/captive-portal classification of an observed redirect URL (ISE_EMPLOYEE / ISE_GUEST / NON_ISE / UNKNOWN), using the same isepsn/isegst matching Main uses. Base reports this; Base never acts on it."
        attempt = "1-based attempt number of the polled Base empirical preflight probe that produced this observation."
        os_name = "Client OS name parsed from the captive-portal navigation URL (cp_da_osname) in Cisco WebHelper EventID 301."
        os_version = "Client OS version parsed from the captive-portal navigation URL (cp_da_osversion) in Cisco WebHelper EventID 301."
        browser_name = "Browser name parsed from the captive-portal navigation URL (cp_da_browsername) in Cisco WebHelper EventID 301."
        browser_version = "Browser version parsed from the captive-portal navigation URL (cp_da_browserversion) in Cisco WebHelper EventID 301."
        device_type = "Device type parsed from the captive-portal navigation URL (cp_da_type) in Cisco WebHelper EventID 301."
        trace_id = "Portal-side trace identifier (traceId) parsed from the captive-portal navigation URL in Cisco WebHelper EventID 301, when present."
        event_record_id = "Windows event record ID of the corroborating Cisco WebHelper EventID 301 record. Part of the dedupe identity so multiple navigation stages from one PID are all retained."

        # --- FlareGun lifecycle (RC2) ---
        flare_tag = "FlareGun tag being dispatched (e.g. captive_portal_browser_base, no_net_transient)."
        context = "Dispatch context for the flare: USER (eventcreate for Task Scheduler pickup), SYSTEM (flare exe run directly), or legacy-direct (config missing or tag unknown)."
        dispatch_method = "How the flare was dispatched: eventcreate or flare_exe."
        runner = "Script name of the flare-launched runner emitting a lifecycle event (e.g. WW_cap_portal_runner_base)."

        # --- Generic / cross-cutting ---
        ExtraInfo = "Freeform quoted field appended by WW_syslog.ps1/Invoke-SyslogSend when -ExtraInfo is supplied; not covered by a standard field."

        # --- admin\Invoke-WhiteWalkerAction.ps1 : tech_checkin (manual tech action console) ---
        note = "Optional free-text note a tech supplies when manually firing a tech_checkin event via admin\Invoke-WhiteWalkerAction.ps1 (e.g. a ticket number or brief context). Empty string when no note was entered."
    }

    # -------------------------------------------------------------------
    # CANONICAL CASING
    # -------------------------------------------------------------------
    # Existing emitted casing is kept AS-IS (not normalized to one
    # convention) specifically so we do not break existing Splunk
    # dashboards/saved searches that already reference these exact field
    # names in production. Future emitters MUST use the casing below for
    # any field that already exists; new fields should pick a casing and
    # add it here + to Optional in the same change.
    # -------------------------------------------------------------------
    CanonicalCasing = @(
        "EvtTime", "machine", "user", "action",
        "Label", "EventID", "LogName", "Provider", "body",
        "exit_code", "reason", "version",
        "url", "port", "ssid", "connection_type", "vpn_state", "portal_type", "status",
        "status_code", "classification", "channel", "network_state", "zip",
        "success", "mode", "source", "detection_source", "profile_name", "profile_count",
        "psn_url", "duration_sec", "result", "needle_count", "gateway_ip",
        "ip", "gw", "dns", "lease_sec", "old_ssid", "new_ssid", "vpn_forced_disconnect",
        "vpn_state_was", "process_name", "pid", "subsystem", "operation",
        "dc_reachable", "tier", "trusted", "event_id", "seconds_since_wake",
        "service_found", "wait_sec", "tag", "minutes_remaining",
        "basic_state", "mgmt_state", "flavor", "event_class", "fqdn", "protocol",
        "probe_url", "http_status", "redirect_url", "duration_ms", "navigated_url",
        "final_url", "final_url_port", "process_id", "thread_id", "ap_name", "ap_tags",
        "ap_mac", "sip", "org", "ui", "psid", "login_url", "ma", "os", "api_domain",
        "event_source", "event_time", "redirect_type", "attempt",
        "os_name", "os_version", "browser_name", "browser_version", "device_type",
        "trace_id", "event_record_id",
        "flare_tag", "context", "dispatch_method", "runner",
        "header_field", "collected_at", "ww_version", "model", "serial",
        "last_boot", "csc_version", "csc_source", "vpn_profile",
        "ExtraInfo", "note"
    )
}
