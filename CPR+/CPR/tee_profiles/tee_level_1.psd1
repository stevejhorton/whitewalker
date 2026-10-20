@{
    # RC2.1 (Required H): explicit identity markers. The active profile used to
    # be identified only by SHA256 equality with a reference file, which breaks
    # the moment the reference gains a new tag - making a genuinely stale active
    # profile indistinguishable from a custom one. Level is the operator's
    # CHOSEN volume knob and must be preserved across any refresh/repair;
    # ProfileVersion changes whenever the reference content changes, so a stale
    # active copy is detectable without guessing.
    Level          = 1
    ProfileVersion = 'RC2.1'
    # =========================================================================
    # tee_level_1.psd1 - CORE
    # =========================================================================
    # The load-bearing events - the handful of nuggets that matter most for
    # a global Splunk board: what state is the fleet in, and what is CPR
    # actively remediating right now. Low volume, high signal.
    #
    # Recommended as the default production profile.
    Events = @{

        cap_portal_redirect = @{
            action = 'cap_portal_redirect'
            fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason')
            # Fires when: WW_main detects a captive portal / non-ISE redirect
            # and is about to hand off to a cap portal runner.
        }

        cap_portal_remediation_passed = @{
            action = 'cap_portal_remediation_passed'
            fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason')
            # Fires when: captive portal pre-check or post-run verification
            # confirms network access is restored.
        }

        cap_portal_remediation_failed = @{
            action = 'cap_portal_remediation_failed'
            fields = @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason')
            # Fires when: remediation exits unsuccessfully (interrupt, timeout,
            # runner failure, verification failure, or explicit abort path).
        }

        cpr_self_update_triggered = @{
            action = 'cpr_self_update_triggered'
            fields = @('channel','status','network_state','reason')
            # Fires when: DEV/PROD update flag is detected and self-update is
            # evaluating eligibility.
        }

        cpr_self_update_passed = @{
            action = 'cpr_self_update_passed'
            fields = @('channel','status','network_state','reason','exit_code')
            # Fires when: update install.ps1 completes successfully.
        }

        cpr_self_update_failed = @{
            action = 'cpr_self_update_failed'
            fields = @('channel','status','network_state','reason','exit_code')
            # Fires when: update is skipped (deferred/disabled/cooldown) or
            # fails during package/install processing.
        }

        xml_vault_triggered = @{
            action = 'xml_vault_triggered'
            fields = @('mode','status','source','reason','profile_name','profile_count')
            # Fires when: XmlVault determines it will execute sync or restore.
        }

        xml_vault_passed = @{
            action = 'xml_vault_passed'
            fields = @('mode','status','source','reason','profile_name','profile_count')
            # Fires when: XmlVault sync completes cleanly or restore verification
            # confirms the destination XML exists.
        }

        xml_vault_failed = @{
            action = 'xml_vault_failed'
            fields = @('mode','status','source','reason','profile_name','profile_count')
            # Fires when: XmlVault encounters a meaningful sync/restore failure.
        }

        xml_vault_restore = @{
            action = 'xml_vault_restore'
            fields = @('profile_name','reason')
            # Fires when: XmlVault restores a VPN profile XML from local vault.
        }

        ise_posture_redirect = @{
            action = 'ise_posture_redirect'
            fields = @('psn_url','ssid')
            # Fires when: enroll.cisco.com test reveals an ISE PSN redirect -
            # device is about to be auto-rescanned.
        }

        ise_posture_compliant = @{
            action = 'ise_posture_compliant'
            fields = @('duration_sec')
            # Fires when: Test-ISEPostureCompliance confirms compliance after
            # an auto-rescan. duration_sec = how long remediation took.
        }

        ise_posture_failed = @{
            action = 'ise_posture_failed'
            fields = @('reason')
            # Fires when: posture rescan times out or ISE reports non-compliant.
        }

        vpn_blackhole_add = @{
            action = 'vpn_blackhole_add'
            fields = @('ssid','dc_reachable')
            # Fires when: Invoke-BlackholeAction sinkholes VPN headends
            # because the device is confirmed on-prem.
        }

        vpn_blackhole_remove = @{
            action = 'vpn_blackhole_remove'
            fields = @('reason')
            # Fires when: sinkhole entries are cleared (any non-on-prem state,
            # or startup safety -rm).
        }

        captive_walled_garden = @{
            action = 'captive_walled_garden'
            fields = @('gateway_ip','ssid')
            # Fires when: Test-WalledGarden detects a DNS-blocking portal
            # (Marriott/Wyndham-style) with no HTTP redirect.
        }

        vpn_disconnect_forced = @{
            action = 'vpn_disconnect_forced'
            fields = @('reason','vpn_state_was')
            # Fires when: WW_main force-disconnects VPN (SSID change grace
            # expired, wake-from-sleep intermediate-state timeout, etc.)
        }

        haystack_reroll_result = @{
            action = 'haystack_reroll_result'
            fields = @('result','needle_count','reason')
            # Fires when: haystack.ps1 reroll succeeds, fails, or is skipped.
        }

        subsystem_task_sync_failed = @{
            action = 'subsystem_task_sync_failed'
            fields = @('subsystem','operation','reason')
            # Fires when: WW_main cannot register/unregister critical TS tasks.
        }

        vpn_profile_missing = @{
            action = 'vpn_profile_missing'
            fields = @()
            # Fires when: Run header detects HKLM:\\SYSTEM\\UHG\\DSM VPN profile is not set.
        }
    }
}
