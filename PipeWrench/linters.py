"""Semantic standards linters for captured Cisco ASA configuration sections."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


COMPLIANCE_COMMAND = "PIPEWRENCH COMPLIANCE"
DOMAIN_MARKER = re.compile(r"^\d{2}\.[a-z]{3}\.\d{2}\.optum\.com$", re.IGNORECASE)
IP_VERSION = re.compile(r"(?i)\bupdate\s*:\s*(\d{1,2}[a-z]{3}\d{2,4})\b")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


def output_for(results: list[dict[str, Any]], label: str) -> str:
    for item in results:
        if item.get("label") == label and item.get("status") == "ok":
            return str(item.get("output", ""))
    return ""


def finding(label: str, status: str, detail: str) -> dict[str, Any]:
    return {"label": label, "command": COMPLIANCE_COMMAND, "status": status, "output": detail}


def required_section_findings(results: list[dict[str, Any]], rules: dict[str, Any]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    passed: list[str] = []
    for section, spec in rules.get("sections", {}).items():
        output = output_for(results, section)
        if not output:
            failures.append(finding(f"{section} lint", "warning", "Section output was unavailable."))
            continue
        missing = [name for name, pattern in spec.get("required", []) if not re.search(pattern, output, re.IGNORECASE | re.MULTILINE)]
        for name, pattern, minimum in spec.get("minimum_matches", []):
            if len(re.findall(pattern, output, re.IGNORECASE | re.MULTILINE)) < int(minimum):
                missing.append(name)
        forbidden = [name for name, pattern in spec.get("forbidden", []) if re.search(pattern, output, re.IGNORECASE | re.MULTILINE)]
        problems = [f"missing {name}" for name in missing] + [f"forbidden {name}" for name in forbidden]
        if problems:
            failures.append(finding(f"{section} lint", "warning", "\n".join(problems)))
        else:
            passed.append(section)
    if passed:
        failures.insert(0, finding("Section lint summary", "ok", f"{len(passed)} rule-driven sections passed:\n" + ", ".join(passed)))
    return failures


def split_ip_entries(output: str) -> tuple[str | None, list[str], list[str]]:
    version = None
    entries: list[str] = []
    invalid: list[str] = []
    for line in output.splitlines():
        if " remark " in line.lower():
            match = IP_VERSION.search(line)
            if match:
                version = match.group(1).lower()
            continue
        match = re.match(r"(?i)^access-list\s+SPLIT_TUNNEL_IP\s+standard\s+permit\s+(.+?)\s*$", line)
        if not match:
            continue
        value = re.sub(r"\s+", " ", match.group(1).strip()).lower()
        try:
            if value.startswith("host "):
                ipaddress.ip_address(value.split()[1])
            else:
                address, mask = value.split()[:2]
                ipaddress.ip_network(f"{address}/{mask}", strict=False)
            entries.append(value)
        except (ValueError, IndexError):
            invalid.append(value)
    return version, entries, invalid


def split_domain_entries(output: str) -> tuple[list[str], list[str], list[str]]:
    domains: list[str] = []
    invalid: list[str] = []
    markers: list[str] = []
    prefix = re.compile(r"(?i)^anyconnect-custom-data\s+dynamic-split-exclude-domains\s+SPLIT_TUNNEL_DOMAINS\s+")
    for line in output.splitlines():
        content = prefix.sub("", line.strip())
        if content == line.strip():
            continue
        for value in content.split(","):
            domain = value.strip().lower().rstrip(".")
            if not domain:
                continue
            if DOMAIN_MARKER.fullmatch(domain):
                markers.append(domain)
            elif DOMAIN.fullmatch(domain):
                domains.append(domain)
            else:
                invalid.append(domain)
    return domains, markers, invalid


def first_dynamic_split_value(output: str) -> str | None:
    prefix = re.compile(r"(?i)^anyconnect-custom-data\s+dynamic-split-exclude-domains\s+SPLIT_TUNNEL_DOMAINS\s+")
    for line in output.splitlines():
        content = prefix.sub("", line.strip())
        if content == line.strip():
            continue
        for value in content.split(","):
            if value.strip():
                return value.strip().lower().rstrip(".")
    return None


def split_tunnel_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ip_output = output_for(results, "Access lists(SPLIT_TUNNEL_IP)")
    version, ip_entries, invalid_ips = split_ip_entries(ip_output)
    ip_duplicates = sorted({entry for entry in ip_entries if ip_entries.count(entry) > 1})
    ip_problems = []
    if not version:
        ip_problems.append("missing update:<date> remark")
    if not ip_entries:
        ip_problems.append("no split-tunnel IP entries parsed")
    if invalid_ips:
        ip_problems.append(f"{len(invalid_ips)} invalid entries")
    if ip_duplicates:
        ip_problems.append(f"{len(ip_duplicates)} duplicate entries")
    findings.append(finding("IP split-tunnel list", "warning" if ip_problems else "ok", "; ".join(ip_problems) if ip_problems else f"Version {version}; {len(ip_entries)} valid unique entries."))

    domain_output = output_for(results, "Access lists(SPLIT_TUNNEL_DOMAINS)")
    domains, markers, invalid_domains = split_domain_entries(domain_output)
    duplicates = sorted({domain for domain in domains if domains.count(domain) > 1})
    domain_problems = []
    if len(markers) != 1:
        domain_problems.append(f"expected one dd.mmm.yy.optum.com version marker, found {len(markers)}")
    elif first_dynamic_split_value(domain_output) != markers[0]:
        domain_problems.append("version marker is not the first dynamic split entry")
    if not domains:
        domain_problems.append("no dynamic split domains parsed")
    if invalid_domains:
        domain_problems.append(f"{len(invalid_domains)} invalid domains")
    if duplicates:
        domain_problems.append(f"{len(duplicates)} duplicate domains: " + ", ".join(duplicates[:5]))
    findings.append(finding("Dynamic split-tunnel list", "warning" if domain_problems else "ok", "; ".join(domain_problems) if domain_problems else f"Version {markers[0]}; {len(domains)} valid unique domains."))
    return findings


def policy_link_finding(results: list[dict[str, Any]]) -> dict[str, Any]:
    tunnel_text = output_for(results, "Tunnel groups")
    policy_text = output_for(results, "Group policies")
    if not tunnel_text or not policy_text:
        return finding("Tunnel-group policy links", "warning", "Tunnel-group or group-policy output was unavailable.")
    policies = set(re.findall(r"(?im)^group-policy\s+(\S+)\s+(?:internal|attributes)\b", policy_text))
    referenced = set(re.findall(r"(?im)^\s*default-group-policy\s+(\S+)\s*$", tunnel_text))
    missing = sorted(referenced - policies, key=str.lower)
    return finding("Tunnel-group policy links", "warning" if missing else "ok", "Missing referenced policies: " + ", ".join(missing) if missing else f"All {len(referenced)} referenced group policies exist.")


def lint_results(results: list[dict[str, Any]], rules: dict[str, Any]) -> list[dict[str, Any]]:
    return [*required_section_findings(results, rules), *split_tunnel_findings(results), policy_link_finding(results)]


def semantic_lines(label: str, output: str, parameterize_ips: bool = False) -> set[str]:
    lines: set[str] = set()
    for line in output.splitlines():
        line = re.sub(r"\s+", " ", line.strip()).lower()
        if not line or line == "!":
            continue
        if parameterize_ips:
            line = re.sub(r"(?<![a-f0-9:])(?:\d{1,3}\.){3}\d{1,3}(?![a-f0-9:])", "<ipv4>", line)
            line = re.sub(r"(?<![a-f0-9:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:]{0,4}(?![a-f0-9:])", "<ipv6>", line)
        if label == "SSL":
            line = re.sub(r"^(ssl trust-point)\s+\S+", r"\1 <trustpoint>", line)
        elif label == "SNMP users & hosts":
            line = re.sub(r"\bengineid\s+\S+", "engineid <device-engine-id>", line)
        elif label == "WebVPN":
            line = re.sub(r"https://[^/\s]+", "https://<vpn-host>", line)
        elif label == "IP" and line.startswith("ip address "):
            line = "ip address <device-address>"
        elif label == "Names" and line.startswith("name "):
            line = "name <ipv4> <device-name>"
        lines.add(line)
    return lines


def comparable_value(label: str, output: str, comparison: dict[str, Any]) -> set[str] | None:
    if label in comparison.get("rule_only", []):
        return None
    if label in comparison.get("split_ip", []):
        _version, entries, _invalid = split_ip_entries(output)
        return set(entries)
    if label in comparison.get("split_domains", []):
        domains, _markers, _invalid = split_domain_entries(output)
        return set(domains)
    if label in comparison.get("semantic", []):
        return semantic_lines(label, output, label in comparison.get("parameterize_ips", []))
    return None
