import json
import unittest
from pathlib import Path

import linters


ROOT = Path(__file__).resolve().parents[1]
RULES = json.loads((ROOT / "lint_rules.json").read_text(encoding="utf-8"))


class LinterTests(unittest.TestCase):
    def test_ip_split_parser_extracts_version_and_validates_entries(self):
        output = "\n".join([
            "access-list SPLIT_TUNNEL_IP remark *** update:3feb26 ***",
            "access-list SPLIT_TUNNEL_IP standard permit 10.20.0.0 255.255.0.0",
            "access-list SPLIT_TUNNEL_IP standard permit host 192.0.2.4",
        ])
        version, entries, invalid = linters.split_ip_entries(output)
        self.assertEqual(version, "3feb26")
        self.assertEqual(len(entries), 2)
        self.assertEqual(invalid, [])

    def test_dynamic_split_parser_separates_version_marker(self):
        output = "anyconnect-custom-data dynamic-split-exclude-domains SPLIT_TUNNEL_DOMAINS example.com,21.may.26.optum.com,example.org,"
        domains, markers, invalid = linters.split_domain_entries(output)
        self.assertEqual(domains, ["example.com", "example.org"])
        self.assertEqual(markers, ["21.may.26.optum.com"])
        self.assertEqual(invalid, [])
        self.assertEqual(linters.first_dynamic_split_value(output), "example.com")

    def test_dynamic_split_marker_must_be_first(self):
        result = {"label": "Access lists(SPLIT_TUNNEL_DOMAINS)", "status": "ok", "output": "anyconnect-custom-data dynamic-split-exclude-domains SPLIT_TUNNEL_DOMAINS example.com,21.may.26.optum.com,"}
        finding = linters.split_tunnel_findings([result])[1]
        self.assertEqual(finding["status"], "warning")
        self.assertIn("not the first", finding["output"])

    def test_real_42xx_snapshot_only_has_known_dynamic_list_warning(self):
        path = ROOT / "archives" / "20260913042827_asaatc01vpn21_standards_6e826238.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        raw = [item for item in data["results"] if item.get("command") != linters.COMPLIANCE_COMMAND]
        warnings = [item["label"] for item in linters.lint_results(raw, RULES) if item["status"] != "ok"]
        self.assertEqual(warnings, ["Dynamic split-tunnel list"])

    def test_real_41xx_snapshot_flags_weak_ssh_and_dynamic_list(self):
        path = ROOT / "archives" / "20260913045312_asactc01vpn29_standards_23ca7ca6.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        raw = [item for item in data["results"] if item.get("command") != linters.COMPLIANCE_COMMAND]
        warnings = [item["label"] for item in linters.lint_results(raw, RULES) if item["status"] != "ok"]
        self.assertEqual(warnings, ["SSH lint", "Dynamic split-tunnel list"])

    def test_rule_only_sections_do_not_participate_in_gold_comparison(self):
        comparison = RULES["gold_comparison"]
        self.assertIsNone(linters.comparable_value("Certificates", "anything", comparison))

    def test_snmp_engine_id_is_device_specific(self):
        comparison = RULES["gold_comparison"]
        first = "snmp-server user netshaaes globalEnforcePriv v3 engineID AAA encrypted auth sha ******** priv aes 128 ********"
        second = "snmp-server user netshaaes globalEnforcePriv v3 engineID BBB encrypted auth sha ******** priv aes 128 ********"
        self.assertEqual(
            linters.comparable_value("SNMP users & hosts", first, comparison),
            linters.comparable_value("SNMP users & hosts", second, comparison),
        )

    def test_split_gold_comparison_ignores_version_but_not_membership(self):
        comparison = RULES["gold_comparison"]
        old_ip = "access-list SPLIT_TUNNEL_IP remark *** update:3feb26 ***\naccess-list SPLIT_TUNNEL_IP standard permit host 192.0.2.10"
        new_ip = "access-list SPLIT_TUNNEL_IP remark *** update:10sep26 ***\naccess-list SPLIT_TUNNEL_IP standard permit host 192.0.2.10"
        changed_ip = new_ip + "\naccess-list SPLIT_TUNNEL_IP standard permit host 192.0.2.11"
        self.assertEqual(
            linters.comparable_value("Access lists(SPLIT_TUNNEL_IP)", old_ip, comparison),
            linters.comparable_value("Access lists(SPLIT_TUNNEL_IP)", new_ip, comparison),
        )
        self.assertNotEqual(
            linters.comparable_value("Access lists(SPLIT_TUNNEL_IP)", old_ip, comparison),
            linters.comparable_value("Access lists(SPLIT_TUNNEL_IP)", changed_ip, comparison),
        )

    def test_dynamic_gold_comparison_ignores_version_marker(self):
        comparison = RULES["gold_comparison"]
        prefix = "anyconnect-custom-data dynamic-split-exclude-domains SPLIT_TUNNEL_DOMAINS "
        old = prefix + "01.jan.26.optum.com,example.com"
        new = prefix + "21.may.26.optum.com,example.com"
        self.assertEqual(
            linters.comparable_value("Access lists(SPLIT_TUNNEL_DOMAINS)", old, comparison),
            linters.comparable_value("Access lists(SPLIT_TUNNEL_DOMAINS)", new, comparison),
        )


if __name__ == "__main__":
    unittest.main()
