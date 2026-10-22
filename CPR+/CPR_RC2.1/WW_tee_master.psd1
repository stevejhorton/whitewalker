@{
    # =========================================================================
    # WW_tee_master.psd1 - THE ONE FILE that defines every tee log level.
    # =========================================================================
    # Each LnN section lists ONLY the tags that level ADDS. A level contains its
    # own tags plus every tag of all lower levels (level 3 = L1 + L2 + L3).
    # WW_set_tee_level.ps1 merges levels 1..N and writes the active
    # WW_tee_events.psd1 (flat, with Level / ProfileVersion / Generated header).
    #
    # TO ADD A TAG: put it in exactly ONE level section below. Nothing else to
    # edit - the installer, the cpr_tee_<N>.flag handler and the admin console all
    # call the same tool. Bump MasterVersion whenever any tag changes so a stale
    # active profile is detectable.
    #
    # Level 0 is SILENT and has no section. Plain data file: no code runs here.
    MasterVersion = 'RC2.1-m1'

    LevelDescriptions = @{
        L0 = 'SILENT - no events leave the box'
        L1 = 'CORE - fleet health, VPN/ISE, captive portal (all of it), XmlVault, self-update (recommended default)'
        L2 = 'CORE + NETWORK CONTEXT - adds per-run network state and SSID changes'
        L3 = '+ POSTURE DETAIL / FLARE LIFECYCLE / MAC RANDOMIZATION / TRUSTED SSID'
        L4 = 'RESERVED - currently identical to level 3 (room to grow)'
        L5 = 'EVERYTHING - debug / incident investigation'
    }

    Levels = @{
        L1 = @{
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

                vpn_connected_triage = @{
                    action = 'vpn_connected_triage'
                    fields = @('outcome','dc_reachable','preflight','vpn_state','waited_ms','wake','jump')
                    # Fires when: VPN reports Connected but the gateway preflight failed (RC2.1 triage).
                }

                network_changed_during_run = @{
                    action = 'network_changed_during_run'
                    fields = @('old_ssid','new_ssid','old_ip','new_ip','rerun')
                    # Fires when: SSID/IP/gateway changed while a run was in progress (end-of-run re-check).
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

                cap_portal_preflight_observation = @{ action = 'cap_portal_preflight_observation'; fields = @('probe_url','status','http_status','redirect_url','redirect_type','classification','protocol','fqdn','port','duration_ms','attempt','reason','ssid','ip','gw','dns','vpn_state') }

                cap_portal_webhelper_navigation = @{ action = 'cap_portal_webhelper_navigation'; fields = @('detection_source','navigated_url','final_url','final_url_port','process_id','thread_id','ap_name','ap_tags','ap_mac','sip','org','ui','psid','login_url','ma','os','api_domain','os_name','os_version','browser_name','browser_version','device_type','trace_id','event_record_id','event_source','event_time','classification','protocol','fqdn','port','status','reason','ssid','ip','gw','dns','vpn_state') }

                cap_portal_runner_result = @{
                    action = 'cap_portal_runner_result'
                    fields = @('mode','result','duration_sec')
                    # Fires when: full or base cap portal runner completes (success,
                    # timeout, or escalation from base->full).
                }

                tee_level_set = @{
                    action = 'tee_level_set'
                    fields = @('level','previous_level','source','result','reason')
                    # Fires when: the tee level is changed by a cpr_tee_<N>.flag, an automatic
                    # revert, the installer, or the admin console. Always in level 1 so every
                    # change (and every refusal) is visible in Splunk.
                }
            }
        }

        L2 = @{
            Events = @{

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

        L3 = @{
            Events = @{

                flare_dispatched = @{ action = 'flare_dispatched';       fields = @('flare_tag','event_id','context','dispatch_method','status','reason','ssid','vpn_state') }

                flare_suppressed = @{ action = 'flare_suppressed';       fields = @('flare_tag','event_id','context','dispatch_method','status','reason','ssid','vpn_state') }

                flare_failed = @{ action = 'flare_failed';           fields = @('flare_tag','event_id','context','dispatch_method','status','reason','ssid','vpn_state') }

                flare_runner_started = @{ action = 'flare_runner_started';   fields = @('runner','flare_tag','event_id','context','status','reason','duration_sec','ssid','ip','gw','dns','vpn_state') }

                flare_runner_completed = @{ action = 'flare_runner_completed'; fields = @('runner','flare_tag','event_id','context','status','reason','duration_sec','ssid','ip','gw','dns','vpn_state') }

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

        L4 = @{
            Events = @{
            }
        }

        L5 = @{
            Events = @{

                preflight_result = @{
                    action = 'preflight_result'
                    fields = @('url','status_code','classification')
                    # Fires on EVERY preflight check (gateway.optum.com) - high volume.
                }

                vpn_state_raw = @{
                    action = 'vpn_state_raw'
                    fields = @('basic_state','mgmt_state','flavor')
                    # Fires on every vpncli state parse - high volume, deep vpncli debug.
                }

                cisco_browser_killed = @{
                    action = 'cisco_browser_killed'
                    fields = @('process_name','pid')
                    # Fires on every interfering Cisco browser process killed.
                }

                wake_from_sleep_detected = @{
                    action = 'wake_from_sleep_detected'
                    fields = @('event_id','seconds_since_wake')
                    # Fires on Kernel-Power 1/107 wake correlation checks.
                }

                flare_cooldown_suppressed = @{
                    action = 'flare_cooldown_suppressed'
                    fields = @('tag','minutes_remaining')
                    # Fires whenever a flare is suppressed by cooldown - useful for
                    # tuning $FlareCooldownMinutes.
                }
            }
        }

    }
}
