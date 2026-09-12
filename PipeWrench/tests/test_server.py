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
                "output": "Cisco Adaptive Security Appliance Software Version 9.20(4)\nasa-test up 91 days 3 hours",
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
        self.assertEqual(metrics["Memory used"], "20%")
        self.assertEqual(metrics["HA role"], "Primary - Active")
        self.assertEqual(metrics["Active VPN"], "2113")
        self.assertEqual(metrics["VPN capacity"], "20000")

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
        clock = {"status": "ok", "command": "show clock detail", "output": "Clock synchronized to chassis"}
        self.assertEqual(server.time_sync_finding([version_41, clock])["status"], "ok")
        version_42 = {"status": "ok", "command": "show version", "output": "Hardware: FPR-4245"}
        ntp = {"status": "ok", "command": "show ntp", "output": "Clock is synchronized, stratum 3"}
        self.assertEqual(server.time_sync_finding([version_42, ntp])["status"], "ok")

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
