import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import server


class PipeWrenchTests(unittest.TestCase):
    def test_summarize(self):
        values = [{"status": "ok"}, {"status": "warning"}, {"status": "error"}, {"status": "odd"}]
        self.assertEqual(server.summarize(values), {"ok": 1, "warning": 2, "error": 1})

    def test_command_error_detection(self):
        self.assertIsNotNone(server.COMMAND_ERROR.search("ERROR: Command authorization failed"))
        self.assertIsNotNone(server.COMMAND_ERROR.search("% Invalid input detected"))
        self.assertIsNone(server.COMMAND_ERROR.search("CPU utilization for 5 seconds = 2%"))

    def test_hostname_validation_rejects_ports_and_paths(self):
        self.assertIsNotNone(server.HOSTNAME.fullmatch("asactc01vpn30"))
        self.assertIsNone(server.HOSTNAME.fullmatch("asactc01vpn30:2002"))
        self.assertIsNone(server.HOSTNAME.fullmatch("host/admin/config"))

    def test_unverified_context_is_scoped_to_asa_request(self):
        context = server.ssl_context({"verify_tls": False, "ca_bundle": ""})
        self.assertEqual(context.verify_mode, server.ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_health_metrics_extract_expected_values(self):
        results = [
            {"status": "ok", "command": "show running-config hostname", "output": "hostname asa-test"},
            {
                "status": "ok",
                "command": "show version",
                "output": "Cisco Adaptive Security Appliance Software Version 9.20(4)\nasa-test up 91 days 3 hours\nHardware: FPR-4215, 214632 MB RAM",
            },
            {"status": "ok", "command": "show failover", "output": "This host: Primary - Active"},
            {"status": "ok", "command": "show cpu usage", "output": "CPU utilization for 5 seconds = 7%"},
            {"status": "ok", "command": "show memory", "output": "Used memory: 2043462712 bytes (20%)"},
            {
                "status": "ok",
                "command": "show vpn-sessiondb summary",
                "output": "AnyConnect Client : 2113 : 945795 : 2384 : 1\nDevice Total VPN Capacity : 20000\nDevice Load : 11%",
            },
        ]
        metrics = {item["label"]: item["value"] for item in server.health_metrics(results)}
        self.assertEqual(metrics["Hostname"], "asa-test")
        self.assertEqual(metrics["Uptime"], "91 days 3 hours")
        self.assertEqual(metrics["HW Ver"], "FPR-4215")
        self.assertEqual(metrics["Memory used"], "20%")
        self.assertEqual(metrics["HA role"], "Primary - Active")
        self.assertEqual(metrics["Active VPN"], "2113")
        self.assertEqual(metrics["VPN capacity"], "20000")

    def test_capacity_summary_tallies_pool_license_and_configured_limit(self):
        results = [
            {
                "status": "ok",
                "command": "show running-config ip local pool",
                "output": "ip local pool EMP_1 10.0.0.1-10.0.0.10 mask 255.255.255.0\nip local pool EMP_2 10.0.0.20-10.0.0.30 mask 255.255.255.0",
            },
            {
                "status": "ok",
                "command": "show vpn-sessiondb summary",
                "output": "AnyConnect Client : 12 : 100 : 18 : 0\nDevice Total VPN Capacity : 20,000",
            },
            {
                "status": "ok",
                "command": "show running-config all vpn-sessiondb",
                "output": "vpn-sessiondb max-anyconnect-premium-or-essentials-limit 15000\nvpn-sessiondb max-other-vpn-limit 2000",
            },
        ]
        capacity = server.capacity_summary(results)
        self.assertEqual(capacity["pool_addresses"], 21)
        self.assertEqual(capacity["provisioned_capacity"], 20000)
        self.assertEqual(capacity["configured_limit"], 15000)
        self.assertEqual(capacity["effective_capacity"], 21)
        self.assertEqual(capacity["active_sessions"], 12)
        self.assertEqual(capacity["limiting_factor"], "address pools")
        self.assertFalse(capacity["missing"])

    def test_capacity_summary_does_not_double_count_overlapping_pools(self):
        results = [{
            "status": "ok",
            "command": "show running-config ip local pool",
            "output": "ip local pool ONE 192.0.2.1-192.0.2.10\nip local pool TWO 192.0.2.5-192.0.2.15",
        }]
        capacity = server.capacity_summary(results)
        self.assertEqual(capacity["pool_addresses"], 15)
        self.assertEqual(capacity["overlapping_addresses"], 6)

    def test_capacity_summary_identifies_external_dhcp_without_guessing_scope_size(self):
        results = [
            {"status": "ok", "command": "show running-config vpn-addr-assign", "output": "vpn-addr-assign dhcp\nno vpn-addr-assign local"},
            {"status": "ok", "command": "show running-config tunnel-group", "output": "tunnel-group VPN general-attributes\n dhcp-server 10.204.67.162\n dhcp-server 10.106.147.102"},
            {"status": "ok", "command": "show running-config group-policy", "output": "group-policy VPN attributes\n dhcp-network-scope 10.73.32.0"},
            {"status": "ok", "command": "show vpn-sessiondb summary", "output": "Device Total VPN Capacity : 20000"},
            {"status": "ok", "command": "show running-config all vpn-sessiondb", "output": "vpn-sessiondb max-anyconnect-premium-or-essentials-limit 15000"},
        ]
        capacity = server.capacity_summary(results)
        self.assertEqual(capacity["address_source"], "dhcp")
        self.assertEqual(capacity["dhcp_servers"], ["10.106.147.102", "10.204.67.162"])
        self.assertEqual(capacity["dhcp_scopes"], ["10.73.32.0"])
        self.assertIsNone(capacity["pool_addresses"])
        self.assertIsNone(capacity["effective_capacity"])
        self.assertEqual(capacity["unquantified"], ["external DHCP scope capacity"])
        self.assertNotIn("address pools", capacity["missing"])

    def test_capacity_summary_marks_local_and_dhcp_as_mixed(self):
        results = [
            {"status": "ok", "command": "show running-config ip local pool", "output": "ip local pool LOCAL 192.0.2.1-192.0.2.10"},
            {"status": "ok", "command": "show running-config tunnel-group", "output": " dhcp-server 10.0.0.10"},
        ]
        capacity = server.capacity_summary(results)
        self.assertEqual(capacity["address_source"], "mixed")
        self.assertEqual(capacity["pool_addresses"], 10)
        self.assertIsNone(capacity["effective_capacity"])

    def test_dhcp_only_headend_does_not_fail_local_pool_null_route_check(self):
        results = [
            {"status": "ok", "command": "show running-config ip local pool", "output": ""},
            {"status": "ok", "command": "show running-config route", "output": "route outside 0.0.0.0 0.0.0.0 192.0.2.1"},
            {"status": "ok", "command": "show running-config tunnel-group", "output": " dhcp-server 10.0.0.10"},
        ]
        result = server.pool_null_route_finding(results)
        self.assertEqual(result["status"], "ok")
        self.assertIn("external DHCP", result["output"])

    def test_capacity_totals_track_partial_coverage(self):
        totals = server.capacity_totals([
            {"status": "ok", "pool_addresses": 100, "provisioned_capacity": 200, "configured_limit": 150, "effective_capacity": 100, "active_sessions": 50},
            {"status": "warning", "pool_addresses": 75, "provisioned_capacity": 200, "configured_limit": None, "effective_capacity": None, "active_sessions": 25},
            {"status": "error"},
        ])
        self.assertEqual(totals["pool_addresses"], 175)
        self.assertEqual(totals["pool_addresses_devices"], 2)
        self.assertEqual(totals["configured_limit"], 150)
        self.assertEqual(totals["configured_limit_devices"], 1)
        self.assertEqual(totals["error_devices"], 1)

    def test_config_secret_redaction(self):
        source = "username bob password abc123 encrypted\nsnmp-server community public\npre-shared-key local letmein\n key aaa-secret\nsnmp-server user bob group v3 auth sha auth-secret priv aes 128 priv-secret"
        redacted = server.redact_config_secrets(source)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("public", redacted)
        self.assertNotIn("letmein", redacted)
        self.assertNotIn("aaa-secret", redacted)
        self.assertNotIn("auth-secret", redacted)
        self.assertNotIn("priv-secret", redacted)

    def test_standards_do_not_return_running_config(self):
        with patch.object(server, "asa_request", return_value="username hidden password secret\nntp server 10.0.0.1"):
            result = server.run_standards("asa1")
        self.assertGreaterEqual(result["summary"]["ok"], len(server.STANDARD_COMMANDS))
        self.assertNotIn("secret", json.dumps(result))

    def test_default_group_policy_requires_both_split_lists(self):
        results = [{
            "status": "ok",
            "command": "show running-config group-policy",
            "output": "group-policy DfltGrpPolicy internal\ngroup-policy DfltGrpPolicy attributes\n split-tunnel-network-list value SPLIT_TUNNEL_IP\n anyconnect-custom dynamic-split-exclude-domains value SPLIT_TUNNEL_DOMAINS\ngroup-policy Other internal",
        }]
        self.assertEqual(server.default_group_policy_finding(results)["status"], "ok")
        results[0]["output"] = results[0]["output"].replace(" anyconnect-custom", " no-anyconnect-custom")
        self.assertEqual(server.default_group_policy_finding(results)["status"], "warning")

    def test_ip_local_pools_require_covering_null_route(self):
        results = [
            {"status": "ok", "command": "show running-config ip local pool", "output": "ip local pool VPN 10.4.8.10-10.4.8.200 mask 255.255.255.0"},
            {"status": "ok", "command": "show running-config route", "output": "route Null0 10.4.8.0 255.255.255.0 1"},
        ]
        self.assertEqual(server.pool_null_route_finding(results)["status"], "ok")
        results[1]["output"] = "route Null0 10.4.9.0 255.255.255.0 1"
        self.assertEqual(server.pool_null_route_finding(results)["status"], "warning")

    def test_platform_specific_time_sync(self):
        version_41 = {"status": "ok", "command": "show version", "output": "Hardware: FPR-4115"}
        clock = {"status": "ok", "command": "show clock detail", "output": "14:13:05.591 UTC Sun Sep 13 2026\nTime source is SSPXRU-OS chassis [NTP]"}
        self.assertEqual(server.time_sync_finding([version_41, clock])["status"], "ok")
        clock["output"] = "14:13:05.591 UTC Sun Sep 13 2026\nTime source is SSPXRU-OS chassis [LOCAL]"
        self.assertEqual(server.time_sync_finding([version_41, clock])["status"], "warning")
        version_42 = {"status": "ok", "command": "show version", "output": "Hardware: FPR-4245"}
        ntp = {"status": "ok", "command": "show run ntp", "output": "ntp server 10.10.10.10 source outside"}
        self.assertEqual(server.time_sync_finding([version_42, ntp])["status"], "ok")

    def test_fpr4k_hardware_models_are_41xx(self):
        for model in ("FPR4K-SM-32S", "FPR4K-SM-36"):
            results = [{"status": "ok", "command": "show version", "output": f"Hardware:   {model}, 173570 MB RAM"}]
            self.assertEqual(server.hardware_model(results[0]["output"]), model)
            self.assertEqual(server.platform_family(results), "41xx")

    def test_fpr42_hardware_models_are_42xx(self):
        results = [{"status": "ok", "command": "show version", "output": "Hardware: FPR-4215, 214632 MB RAM"}]
        self.assertEqual(server.hardware_model(results[0]["output"]), "FPR-4215")
        self.assertEqual(server.platform_family(results), "42xx")

    def test_expired_certificates_are_classified_by_use(self):
        results = [
            {"status": "ok", "command": "show crypto ca certificates", "output": "Identity Certificate\n Associated Trustpoints: ACTIVE_CERT\n end date: 00:00:00 UTC Jan 1 2020\nCA Certificate\n Associated Trustpoints: OLD_CERT\n end date: 00:00:00 UTC Jan 1 2021"},
            {"status": "ok", "command": "show running-config ssl", "output": "ssl trust-point ACTIVE_CERT outside"},
            {"status": "ok", "command": "show running-config crypto", "output": ""},
            {"status": "ok", "command": "show running-config webvpn", "output": ""},
        ]
        findings = server.certificate_findings(results, datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(findings[0]["status"], "error")
        self.assertEqual(findings[1]["status"], "warning")

    def test_save_snapshot_has_version_first_and_sortable_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary)
            run = {"action": "health", "device": "asa1", "captured_at": "2026-09-12T12:30:45Z", "results": [], "metrics": [], "summary": {"ok": 0, "warning": 0, "error": 0}}
            with patch.object(server, "ARCHIVES", archive), patch.object(server, "BASELINES", archive / "baselines"), patch.object(server, "BATCHES", archive / "batches"):
                saved = server.save_snapshot(run)
                path = archive / f"{saved['snapshot_id']}.json"
                self.assertTrue(path.name.startswith("20260912123045_asa1_health_"))
                self.assertTrue(path.read_text(encoding="utf-8").startswith('{\n  "snapshot_version": 1,'))

    def test_gold_compare_ignores_line_order_and_spacing(self):
        current = {"results": [{"label": "DNS", "command": "show dns", "output": "dns  a\ndns b"}]}
        baseline = {"baseline_id": "42xx__amer", "name": "42xx / amer", "results": [{"label": "DNS", "command": "show dns", "output": "dns b\n dns a"}]}
        self.assertTrue(server.compare_runs(current, baseline)["matched"])

    def test_gold_compare_parameterizes_ip_addresses(self):
        current = {"results": [{"label": "Routes", "command": "show route", "output": "route outside 10.1.2.0 255.255.255.0 10.1.2.1"}]}
        baseline = {"results": [{"label": "Routes", "command": "show route", "output": "route outside 172.20.4.0 255.255.252.0 172.20.4.1"}]}
        self.assertTrue(server.compare_runs(current, baseline)["matched"])


if __name__ == "__main__":
    unittest.main()
