# CPR / WhiteWalker Splunk query library

Replace `<MACHINE>` with the endpoint name. Replace `<SSID>` or any other
angle-bracketed value when a query uses one. These searches intentionally
exclude the transport's `send string` diagnostic text.

## All fields from one machine

```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> | table EvtTime,action,Label,* | dedup EvtTime | sort - EvtTime
```

For synthetic mock-flow traffic, add `ssid!="CPR-MOCK-FLOW"` when appropriate:

```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> ssid!="CPR-MOCK-FLOW" | table EvtTime,action,Label,* | dedup EvtTime | sort - EvtTime
```

## Ready-to-paste action queries

```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cap_portal_redirect" | table EvtTime,action,machine,user,ssid,url,port,ip,gw,dns,vpn_state,portal_type,status,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cap_portal_remediation_passed" | table EvtTime,action,machine,user,ssid,url,port,ip,gw,dns,vpn_state,portal_type,status,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cap_portal_remediation_failed" | table EvtTime,action,machine,user,ssid,url,port,ip,gw,dns,vpn_state,portal_type,status,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="needle_hit" | table EvtTime,action,machine,user,Label,EventID,LogName,Provider,rule_match,rule_state,body | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="haystack_header_fields" | table EvtTime,action,machine,user,Label,header_field,collected_at,ww_version,os,model,serial,last_boot,csc_version,csc_source,vpn_profile | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cpr_self_update_triggered" | table EvtTime,action,machine,user,channel,status,attempt,network_state,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cpr_self_update_passed" | table EvtTime,action,machine,user,channel,status,attempt,network_state,reason,exit_code | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cpr_self_update_failed" | table EvtTime,action,machine,user,channel,status,attempt,network_state,reason,exit_code | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="xml_vault_triggered" | table EvtTime,action,machine,user,mode,status,source,reason,profile_name,profile_count | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="xml_vault_passed" | table EvtTime,action,machine,user,mode,status,source,reason,profile_name,profile_count | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="xml_vault_failed" | table EvtTime,action,machine,user,mode,status,source,reason,profile_name,profile_count | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="xml_vault_restore" | table EvtTime,action,machine,user,profile_name,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="ise_posture_redirect" | table EvtTime,action,machine,user,psn_url,ssid | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="ise_posture_compliant" | table EvtTime,action,machine,user,duration_sec | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="ise_posture_failed" | table EvtTime,action,machine,user,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="vpn_disconnect_forced" | table EvtTime,action,machine,user,reason,vpn_state_was | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="vpn_profile_missing" | table EvtTime,action,machine,user | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="network_state" | table EvtTime,action,machine,user,ip,gw,dns,ssid,vpn_state,lease_sec | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="vpn_blackhole_add" | table EvtTime,action,machine,user,ssid,dc_reachable | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="vpn_blackhole_remove" | table EvtTime,action,machine,user,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="captive_walled_garden" | table EvtTime,action,machine,user,gateway_ip,ssid | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="haystack_reroll_result" | table EvtTime,action,machine,user,result,needle_count,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="subsystem_task_sync_failed" | table EvtTime,action,machine,user,subsystem,operation,reason | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="tech_checkin" | table EvtTime,action,machine,user,note | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cpr_install_result" | table EvtTime,action,machine,user,exit_code,reason,version | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="cpr_uninstall_result" | table EvtTime,action,machine,user,exit_code,reason,version | dedup EvtTime | sort - EvtTime
```
```spl
index=cba_cpr_logging NOT "send string" machine=<MACHINE> action="network_state_change" event_class="legacy_haystack" | table ts,action,event_class,machine,user,reason,ip,fqdn,protocol,port | dedup ts | sort - ts
```

## Field discovery

Use this form for each action when real data may contain fields not yet
documented. Replace `<ACTION>` with any action above:

```spl
index=cba_cpr_logging machine=<MACHINE> action="<ACTION>" | fieldsummary | table field, count, distinct_count, values
```

For a whole machine regardless of action:

```spl
index=cba_cpr_logging machine=<MACHINE> | fieldsummary | table field, count, distinct_count, values
```

The `needle_hit` query includes DEFENDER-only `rule_match` and `rule_state`
because those are emitted today even though they are recorded as known schema
drift in `docs/cpr_field_catalog.md`. Legacy rows use `ts`; normalized rows use
`EvtTime`.
