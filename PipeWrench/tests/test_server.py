import json
import unittest
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
        source = "username bob password abc123 encrypted\nsnmp-server community public\npre-shared-key local letmein"
        redacted = server.redact_config_secrets(source)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("public", redacted)
        self.assertNotIn("letmein", redacted)

    def test_standards_do_not_return_running_config(self):
        with patch.object(server, "asa_request", return_value="username hidden password secret\nntp server 10.0.0.1"):
            result = server.run_standards("asa1")
        self.assertEqual(result["summary"]["ok"], len(server.STANDARD_COMMANDS))
        self.assertNotIn("secret", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
