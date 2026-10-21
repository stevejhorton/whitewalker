@{
    # RC2.1 (Required H): explicit identity markers. The active profile used to
    # be identified only by SHA256 equality with a reference file, which breaks
    # the moment the reference gains a new tag - making a genuinely stale active
    # profile indistinguishable from a custom one. Level is the operator's
    # CHOSEN volume knob and must be preserved across any refresh/repair;
    # ProfileVersion changes whenever the reference content changes, so a stale
    # active copy is detectable without guessing.
    Level          = 2
    ProfileVersion = 'RC2.1'
    # =========================================================================
    # tee_level_2.psd1 - CORE + NETWORK CONTEXT
    # =========================================================================
    # Everything in level 1, plus a per-run network-state snapshot. This is
    # the level where "build me a Splunk board of what our fleet's network
    # posture looks like right now" becomes possible - IP/GW/DNS/SSID on
    # every run, keyed by machine=.
    Events = @{

        # --- inherited from level 1 ---
        cap_portal_redirect    = @{ action = 'cap_portal_redirect';    fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason') }
        cap_portal_remediation_passed = @{ action = 'cap_portal_remediation_passed'; fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason') }
        cap_portal_remediation_failed = @{ action = 'cap_portal_remediation_failed'; fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason') }
        ise_posture_redirect   = @{ action = 'ise_posture_redirect';   fields = @('psn_url','ssid') }
        ise_posture_compliant  = @{ action = 'ise_posture_compliant';  fields = @('duration_sec') }
        ise_posture_failed     = @{ action = 'ise_posture_failed';     fields = @('reason') }
        vpn_blackhole_add      = @{ action = 'vpn_blackhole_add';      fields = @('ssid','dc_reachable') }
        vpn_blackhole_remove   = @{ action = 'vpn_blackhole_remove';   fields = @('reason') }
        captive_walled_garden  = @{ action = 'captive_walled_garden';  fields = @('gateway_ip','ssid') }
        vpn_disconnect_forced  = @{ action = 'vpn_disconnect_forced';  fields = @('reason','vpn_state_was') }
        vpn_connected_triage   = @{ action = 'vpn_connected_triage';   fields = @('outcome','dc_reachable','preflight','vpn_state','waited_ms','wake','jump') }
        network_changed_during_run = @{ action = 'network_changed_during_run'; fields = @('old_ssid','new_ssid','old_ip','new_ip','rerun') }
        xml_vault_restore      = @{ action = 'xml_vault_restore';      fields = @('profile_name','reason') }
        xml_vault_triggered    = @{ action = 'xml_vault_triggered'; fields = @('mode','status','source','reason','profile_name','profile_count') }
        xml_vault_passed       = @{ action = 'xml_vault_passed';    fields = @('mode','status','source','reason','profile_name','profile_count') }
        xml_vault_failed       = @{ action = 'xml_vault_failed';    fields = @('mode','status','source','reason','profile_name','profile_count') }
	haystack_reroll_result = @{ action = 'haystack_reroll_result'; fields = @('result','needle_count','reason') }
        subsystem_task_sync_failed = @{ action = 'subsystem_task_sync_failed'; fields = @('subsystem','operation','reason') }
        vpn_profile_missing    = @{ action = 'vpn_profile_missing';    fields = @() }

        # --- new at level 2 ---
        haystack_header_fields = @{
            action = 'haystack_header_fields'
            fields = @('Label','header_field','collected_at','ww_version','os','model','serial','last_boot','csc_version','csc_source','vpn_profile')
            # Fires when: a HEADER needle in needles.cfg/needles_local.cfg is
            # due to send (SendHours elapsed). Values come from the cached
            # run-header fields in header_cache.json; header_field names the
            # requested field, or * for the all-fields bundle.
        }

        network_state = @{
            action = 'network_state'
            fields = @('ip','gw','dns','ssid','connection_type','vpn_state','lease_sec')
            # Fires when: WW_main gathers Get-NetworkInfo each run - already
            # has IP/GW/DNS/SSID in hand, tee them alongside the existing
            # local log line rather than re-querying anything.
        }

        ssid_changed = @{
            action = 'ssid_changed'
            fields = @('old_ssid','new_ssid','vpn_forced_disconnect')
            # Fires when: Invoke-SsidChangeCheck detects a network change.
        }

        tech_checkin = @{
            action = 'tech_checkin'
            fields = @('note')
            # Fires when: a tech manually fires a check-in from
            # admin\Invoke-WhiteWalkerAction.ps1's Tech Check-In menu action.
        }
    }
}
