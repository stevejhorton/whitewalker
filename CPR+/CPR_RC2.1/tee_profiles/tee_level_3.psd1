@{
    # RC2.1 (Required H): explicit identity markers. The active profile used to
    # be identified only by SHA256 equality with a reference file, which breaks
    # the moment the reference gains a new tag - making a genuinely stale active
    # profile indistinguishable from a custom one. Level is the operator's
    # CHOSEN volume knob and must be preserved across any refresh/repair;
    # ProfileVersion changes whenever the reference content changes, so a stale
    # active copy is detectable without guessing.
    Level          = 3
    ProfileVersion = 'RC2.1'
    # =========================================================================
    # tee_level_3.psd1 - + POSTURE DETAIL / MAC RANDOMIZATION / TRUSTED SSID
    # =========================================================================
    # Everything in level 2, plus the "why did this device behave the way it
    # did" detail layer - trusted SSID tiebreaker outcomes, MAC randomization
    # warnings, and walled-garden vs standard redirect classification detail.
    # Good for a team actively tuning fleet behavior, not just monitoring it.
    Events = @{

        # --- inherited from levels 1-2 ---
        cap_portal_redirect    = @{ action = 'cap_portal_redirect';    fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason') }
        cap_portal_remediation_passed = @{ action = 'cap_portal_remediation_passed'; fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason') }
        cap_portal_remediation_failed = @{ action = 'cap_portal_remediation_failed'; fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason') }
        cap_portal_preflight_observation = @{ action = 'cap_portal_preflight_observation'; fields = @('probe_url','status','http_status','redirect_url','redirect_type','classification','protocol','fqdn','port','duration_ms','attempt','reason','ssid','ip','gw','dns','vpn_state') }
        cap_portal_webhelper_navigation = @{ action = 'cap_portal_webhelper_navigation'; fields = @('detection_source','navigated_url','final_url','final_url_port','process_id','thread_id','ap_name','ap_tags','ap_mac','sip','org','ui','psid','login_url','ma','os','api_domain','os_name','os_version','browser_name','browser_version','device_type','trace_id','event_record_id','event_source','event_time','classification','protocol','fqdn','port','status','reason','ssid','ip','gw','dns','vpn_state') }
        ise_posture_redirect   = @{ action = 'ise_posture_redirect';   fields = @('psn_url','ssid') }
        ise_posture_compliant  = @{ action = 'ise_posture_compliant';  fields = @('duration_sec') }
        ise_posture_failed     = @{ action = 'ise_posture_failed';     fields = @('reason') }
        vpn_blackhole_add      = @{ action = 'vpn_blackhole_add';      fields = @('ssid','dc_reachable') }
        vpn_blackhole_remove   = @{ action = 'vpn_blackhole_remove';   fields = @('reason') }
        captive_walled_garden  = @{ action = 'captive_walled_garden';  fields = @('gateway_ip','ssid') }
        vpn_disconnect_forced  = @{ action = 'vpn_disconnect_forced';  fields = @('reason','vpn_state_was') }
        vpn_connected_triage   = @{ action = 'vpn_connected_triage';   fields = @('outcome','dc_reachable','preflight','vpn_state','waited_ms','wake','jump') }
        xml_vault_restore      = @{ action = 'xml_vault_restore';      fields = @('profile_name','reason') }
        xml_vault_triggered    = @{ action = 'xml_vault_triggered'; fields = @('mode','status','source','reason','profile_name','profile_count') }
        xml_vault_passed       = @{ action = 'xml_vault_passed';    fields = @('mode','status','source','reason','profile_name','profile_count') }
        xml_vault_failed       = @{ action = 'xml_vault_failed';    fields = @('mode','status','source','reason','profile_name','profile_count') }
	haystack_reroll_result = @{ action = 'haystack_reroll_result'; fields = @('result','needle_count','reason') }
        haystack_header_fields = @{ action = 'haystack_header_fields'; fields = @('Label','header_field','collected_at','ww_version','os','model','serial','last_boot','csc_version','csc_source','vpn_profile') }
        subsystem_task_sync_failed = @{ action = 'subsystem_task_sync_failed'; fields = @('subsystem','operation','reason') }
        vpn_profile_missing    = @{ action = 'vpn_profile_missing';    fields = @() }
        # --- FlareGun lifecycle (RC2): dispatched -> runner started -> preflight
        #     observation -> webhelper navigation -> runner completed. Promoted to
        #     level 3 (not pilot-only) because flares are per-run de-duped and
        #     cooldown-gated, so the volume is low and the chain is useless if any
        #     link is dropped.
        flare_dispatched       = @{ action = 'flare_dispatched';       fields = @('flare_tag','event_id','context','dispatch_method','status','reason','ssid','vpn_state') }
        flare_suppressed       = @{ action = 'flare_suppressed';       fields = @('flare_tag','event_id','context','dispatch_method','status','reason','ssid','vpn_state') }
        flare_failed           = @{ action = 'flare_failed';           fields = @('flare_tag','event_id','context','dispatch_method','status','reason','ssid','vpn_state') }
        flare_runner_started   = @{ action = 'flare_runner_started';   fields = @('runner','flare_tag','event_id','context','status','reason','duration_sec','ssid','ip','gw','dns','vpn_state') }
        flare_runner_completed = @{ action = 'flare_runner_completed'; fields = @('runner','flare_tag','event_id','context','status','reason','duration_sec','ssid','ip','gw','dns','vpn_state') }
        network_state          = @{ action = 'network_state';         fields = @('ip','gw','dns','ssid','connection_type','vpn_state','lease_sec') }
        ssid_changed           = @{ action = 'ssid_changed';           fields = @('old_ssid','new_ssid','vpn_forced_disconnect') }
        tech_checkin           = @{ action = 'tech_checkin';           fields = @('note') }

        # --- new at level 3 ---
        trusted_ssid_result = @{
            action = 'trusted_ssid_result'
            fields = @('ssid','tier','trusted')
            # Fires when: Test-SsidTrusted resolves a tier 1/2 verdict.
        }

        mac_randomization_warning = @{
            action = 'mac_randomization_warning'
            fields = @('ssid','mode')
            # Fires when: Get-MacRandomizationState reports daily/per_connection
            # mode (modes known to break captive portal re-auth).
        }

        posture_service_wait = @{
            action = 'posture_service_wait'
            fields = @('service_found','wait_sec')
            # Fires when: WW_main polls for csc_iseagent/ciscod.exe etc. before
            # invoking a rescan.
        }
    }
}
