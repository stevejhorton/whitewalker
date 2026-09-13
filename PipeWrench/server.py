#!/usr/bin/env python3
"""PipeWrench local web server and read-only Cisco ASA HTTP proxy."""

from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import json
import mimetypes
import re
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import linters


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
ARCHIVES = ROOT / "archives"
BASELINES = ROOT / "baselines"
BATCHES = ROOT / "batches"
APP_VERSION = "0.4.0"
SNAPSHOT_VERSION = 1
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]+$")
BATCH_LOCK = threading.Lock()

HEALTH_COMMANDS = [
    ("Hostname", "show running-config hostname"),
    ("Version & uptime", "show version"),
    ("Failover", "show failover"),
    ("Interfaces", "show interface ip brief"),
    ("CPU", "show cpu usage"),
    ("Memory", "show memory"),
    ("VPN load-balancing", "show vpn load-balancing"),
    ("VPN sessions", "show vpn-sessiondb summary"),
    ("Clock", "show clock detail"),
]

STANDARD_COMMANDS = [
    ("Version & platform", "show version"),
    ("AAA servers", "show running-config aaa-server"),
    ("SNMP users & hosts", "show running-config snmp-server"),
    ("SSL", "show running-config ssl"),
    ("SSH", "show running-config ssh"),
    ("WebVPN", "show running-config webvpn"),
    ("IP", "show running-config ip"),
    ("Clock detail", "show clock detail"),
    ("Logging", "show running-config logging"),
    ("Banners", "show running-config banner"),
    ("Management access", "show running-config management-access"),
    ("Access lists(ALL)", "show running-config access-list"),
    ("Access lists(SPLIT_TUNNEL_IP)", "show running-config access-list SPLIT_TUNNEL_IP"),
    ("Access lists(SPLIT_TUNNEL_DOMAINS)", "show running-config anyconnect-custom-data | grep SPLIT"),
    ("ASDM", "show running-config asdm"),
    ("Crypto", "show running-config crypto"),
    ("Certificates", "show crypto ca certificates"),
    ("VPN capacity & sessions", "show vpn-sessiondb summary"),
    ("VPN load-balancing", "show vpn load-balancing"),
    ("Names", "show running-config names"),
    ("VPN address assignment", "show running-config vpn-addr-assign"),
    ("IP local pools", "show running-config ip local pool"),
    ("Routes", "show running-config route"),
    ("DNS", "show running-config dns"),
    ("Usernames", "show running-config username"),
    ("Domain name", "show running-config domain-name"),
    ("HTTP", "show running-config http"),
    ("MTU", "show running-config mtu"),
    ("ICMP", "show running-config icmp"),
    ("Tunnel groups", "show running-config tunnel-group"),
    ("Group policies", "show running-config group-policy"),
]

COMMAND_ERROR = re.compile(
    r"(?:^|\n)\s*(?:ERROR:|%\s*Invalid|Invalid input|Command rejected|Authorization denied)",
    re.IGNORECASE,
)
HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


def read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return fallback


def config() -> dict[str, Any]:
    values = read_json(ROOT / "config.json", {})
    return {
        "listen_host": values.get("listen_host", "127.0.0.1"),
        "listen_port": int(values.get("listen_port", 8765)),
        "asa_port": int(values.get("asa_port", 2002)),
        "verify_tls": bool(values.get("verify_tls", True)),
        "ca_bundle": values.get("ca_bundle", ""),
        "request_timeout_seconds": int(values.get("request_timeout_seconds", 25)),
        "batch_workers": max(1, min(int(values.get("batch_workers", 2)), 4)),
    }


def lint_config() -> dict[str, Any]:
    return read_json(ROOT / "lint_rules.json", {})


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def vars_config() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_lines(ROOT / "VARS"):
        key, separator, value = line.partition("=")
        if separator and key.strip() in {"CREDENTIAL_DIR"}:
            values[key.strip()] = value.strip().strip('"\'')
    return values


def credential_paths() -> tuple[Path, Path]:
    configured = vars_config().get("CREDENTIAL_DIR", "~/creds")
    directory = Path(configured).expanduser()
    if not directory.is_absolute():
        directory = ROOT / directory
    return directory / "un.txt", directory / "pw.txt"


def devices() -> list[str]:
    merged = read_lines(ROOT / "headends.txt") + read_lines(ROOT / "headends.local.txt")
    return sorted({item.lower(): item for item in merged if HOSTNAME.fullmatch(item)}.values(), key=str.lower)


def credential_status() -> dict[str, Any]:
    username_path, password_path = credential_paths()
    ready = username_path.is_file() and password_path.is_file()
    updated = None
    if password_path.is_file():
        updated = datetime.fromtimestamp(password_path.stat().st_mtime, timezone.utc).isoformat()
    return {"ready": ready, "password_updated": updated}


def credentials() -> tuple[str, str]:
    username_path, password_path = credential_paths()
    try:
        username = username_path.read_text(encoding="utf-8").strip()
        password = password_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Create un.txt and pw.txt in {username_path.parent} or update CREDENTIAL_DIR in VARS.") from exc
    if not username or not password:
        raise RuntimeError("un.txt and pw.txt must each contain a value.")
    return username, password


def ssl_context(settings: dict[str, Any]) -> ssl.SSLContext:
    if not settings["verify_tls"]:
        return ssl._create_unverified_context()  # Lab-only option controlled by config.json.
    ca_bundle = settings["ca_bundle"]
    return ssl.create_default_context(cafile=ca_bundle or None)


def asa_request(device: str, path: str, method: str = "GET", body: bytes | None = None) -> str:
    if device not in devices():
        raise RuntimeError("Select a headend from the configured device list.")
    settings = config()
    username, password = credentials()  # Intentionally reread on every call.
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    url = f"https://{device}:{settings['asa_port']}{path}"
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Basic {token}",
            "User-Agent": "ASDM",
            "Accept": "text/plain, */*",
        },
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=settings["request_timeout_seconds"],
            context=ssl_context(settings),
        ) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"ASA returned HTTP {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach {device}:{settings['asa_port']} — {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError(f"Timed out connecting to {device}:{settings['asa_port']}.") from exc


def execute_command(device: str, label: str, command: str) -> dict[str, Any]:
    command_path = "/admin/exec/" + urllib.parse.quote_plus(command, safe="")
    try:
        output = asa_request(device, command_path).strip()
        failed = bool(COMMAND_ERROR.search(output))
        return {
            "label": label,
            "command": command,
            "status": "error" if failed else "ok",
            "output": output or "Command completed with no output.",
        }
    except RuntimeError as exc:
        return {"label": label, "command": command, "status": "error", "output": str(exc)}


def result_output(results: list[dict[str, Any]], command: str) -> str:
    for result in results:
        if result.get("command") == command and result.get("status") == "ok":
            return str(result.get("output", ""))
    return ""


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def hardware_model(version_output: str) -> str | None:
    """Return the ASA Hardware field through, but not including, its first comma."""
    return first_match(r"^\s*Hardware\s*:\s*([^,\r\n]+)", version_output)


def health_metrics(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    hostname_output = result_output(results, "show running-config hostname")
    version_output = result_output(results, "show version")
    failover_output = result_output(results, "show failover")
    cpu_output = result_output(results, "show cpu usage")
    memory_output = result_output(results, "show memory")
    vpn_output = result_output(results, "show vpn-sessiondb summary")

    candidates = [
        ("Hostname", first_match(r"^hostname\s+(\S+)", hostname_output), "ASA identity"),
        (
            "Uptime",
            first_match(r"^[A-Za-z0-9._-]+\s+up\s+(.+)$", version_output),
            "Since last restart",
        ),
        (
            "HW Ver",
            hardware_model(version_output),
            "Hardware platform",
        ),
        (
            "ASA version",
            first_match(r"Adaptive Security Appliance Software Version\s+([^\r\n]+)", version_output),
            "Running software",
        ),
        ("CPU", first_match(r"CPU utilization for 5 seconds\s*=\s*(\d+%)", cpu_output), "Five-second utilization"),
        ("Memory used", first_match(r"^Used memory:\s+.*?\((\d+%)\)", memory_output), "Current utilization"),
        ("HA role", first_match(r"^This host:\s+(.+)$", failover_output), "Local failover state"),
        ("Active VPN", first_match(r"^AnyConnect Client\s*:\s*(\d+)\s*:", vpn_output), "AnyConnect sessions"),
        ("VPN capacity", first_match(r"Device Total VPN Capacity\s*:\s*(\d+)", vpn_output), "Maximum supported"),
        ("VPN load", first_match(r"Device Load\s*:\s*(\d+%)", vpn_output), "Current utilization"),
    ]
    return [
        {"label": label, "value": value, "detail": detail}
        for label, value, detail in candidates
        if value is not None
    ]


def redact_config_secrets(output: str) -> str:
    """Keep configuration review useful without returning reusable secrets."""
    patterns = [
        (r"(?im)(\bpassword\s+)\S+", r"\1********"),
        (r"(?im)(^\s*secret\s+|\ssecret\s+)\S+", r"\1********"),
        (r"(?im)(\bpre-shared-key(?:\s+local|\s+remote)?\s+)\S+", r"\1********"),
        (r"(?im)(\bsnmp-server\s+community\s+)\S+", r"\1********"),
        (r"(?im)^(\s*(?:key|ldap-login-password|radius-common-pw|nt-encrypted-password)\s+)\S+", r"\1********"),
        (r"(?im)(\bauth\s+(?:md5|sha(?:-\d+)?)\s+)\S+", r"\1********"),
        (r"(?im)(\bpriv\s+(?:aes(?:\s+\d+)?|des|3des)\s+)\S+", r"\1********"),
    ]
    redacted = output
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def run_health(device: str) -> dict[str, Any]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(execute_command, device, label, command) for label, command in HEALTH_COMMANDS]
        results = [future.result() for future in futures]
    if platform_family(results) == "42xx":
        results.append(execute_command(device, "NTP", "show run ntp"))
    return decorate_run({
        "action": "health",
        "device": device,
        "metrics": health_metrics(results),
        "results": results,
        "summary": summarize(results),
    })


def run_standards(device: str) -> dict[str, Any]:
    # Keep concurrency deliberately low; this is a broad review against one production ASA.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(execute_command, device, label, command) for label, command in STANDARD_COMMANDS]
        results = [future.result() for future in futures]
    if platform_family(results) == "42xx":
        results.append(execute_command(device, "NTP", "show run ntp"))
    for result in results:
        if result.get("status") == "ok":
            result["output"] = redact_config_secrets(str(result.get("output", "")))
    results = compliance_findings(results) + linters.lint_results(results, lint_config()) + results
    return decorate_run({
        "action": "standards",
        "device": device,
        "metrics": health_metrics(results),
        "results": results,
        "summary": summarize(results),
    })


def summarize(results: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"ok": 0, "warning": 0, "error": 0}
    for result in results:
        status = result.get("status", "warning")
        summary[status if status in summary else "warning"] += 1
    return summary


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def decorate_run(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["pipewrench_version"] = APP_VERSION
    payload["captured_at"] = utc_now()
    payload["platform"] = platform_family(payload.get("results", []))
    return payload


def platform_family(results: list[dict[str, Any]]) -> str:
    model = hardware_model(result_output(results, "show version"))
    if not model:
        return "unknown"
    normalized = model.upper()
    if normalized.startswith("FPR4K-") or normalized.startswith("FPR-41"):
        return "41xx"
    if normalized.startswith("FPR-42"):
        return "42xx"
    return model


def finding(label: str, status: str, detail: str) -> dict[str, Any]:
    return {"label": label, "command": "PIPEWRENCH COMPLIANCE", "status": status, "output": detail}


def certificate_findings(results: list[dict[str, Any]], now: datetime | None = None) -> list[dict[str, Any]]:
    cert_text = result_output(results, "show crypto ca certificates")
    if not cert_text:
        return [finding("Certificate lifecycle", "warning", "Certificate output was unavailable; expiry and usage could not be checked.")]
    config_text = "\n".join(
        str(item.get("output", "")) for item in results
        if item.get("command") in {"show running-config ssl", "show running-config crypto", "show running-config webvpn"}
    )
    usage_text = "\n".join(
        line for line in config_text.splitlines()
        if not re.match(r"(?i)^\s*crypto\s+ca\s+(?:trustpoint|certificate\s+chain)\b", line)
    )
    now = now or datetime.now(timezone.utc)
    blocks = re.split(r"(?=^\s*(?:CA\s+|Identity\s+)?Certificate\b)", cert_text, flags=re.MULTILINE)
    expired_used: list[str] = []
    expired_unused: list[str] = []
    for block in blocks:
        end = first_match(r"(?:end date|not after)\s*:\s*(.+)$", block)
        if not end:
            continue
        parsed = None
        for fmt in ("%H:%M:%S %Z %b %d %Y", "%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S%z"):
            try:
                parsed = datetime.strptime(end.strip(), fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                break
            except ValueError:
                pass
        if not parsed or parsed >= now:
            continue
        trustpoint = first_match(r"(?:Associated Trustpoints|Trustpoint)\s*:\s*(\S+)", block)
        serial = first_match(r"Serial Number\s*:\s*(\S+)", block) or "unknown-serial"
        identity = trustpoint or serial
        in_use = bool(trustpoint and re.search(rf"\b{re.escape(trustpoint)}\b", usage_text, re.IGNORECASE))
        (expired_used if in_use else expired_unused).append(f"{identity} (expired {end.strip()})")
    output: list[dict[str, Any]] = []
    if expired_used:
        output.append(finding("Expired certificates in use", "error", "\n".join(expired_used)))
    else:
        output.append(finding("Certificates in use", "ok", "No expired certificates referenced by SSL, crypto, or WebVPN configuration were found."))
    if expired_unused:
        output.append(finding("Expired certificate cleanup", "warning", "Candidates for review/removal:\n" + "\n".join(expired_unused)))
    else:
        output.append(finding("Expired certificate cleanup", "ok", "No clearly unused expired certificates were found."))
    return output


def default_group_policy_finding(results: list[dict[str, Any]]) -> dict[str, Any]:
    text = result_output(results, "show running-config group-policy")
    if not text:
        return finding("DfltGrpPolicy split tunnels", "warning", "Group-policy output was unavailable.")
    match = re.search(r"(?ims)^group-policy\s+DfltGrpPolicy\s+attributes\s*$\n(.*?)(?=^group-policy\s+\S+|\Z)", text)
    block = match.group(1) if match else ""
    ip_split = bool(re.search(r"(?im)^\s*split-tunnel-network-list\s+value\s+\S+", block))
    dynamic_split = bool(re.search(r"(?im)^\s*anyconnect-custom\s+dynamic-split-(?:include|exclude)-domains\s+value\s+\S+", block))
    missing = [name for name, present in (("IP split tunnel list", ip_split), ("dynamic split tunnel list", dynamic_split)) if not present]
    return finding("DfltGrpPolicy split tunnels", "warning" if missing else "ok", "Missing: " + ", ".join(missing) if missing else "Both IP and dynamic split tunnel lists are assigned.")


def pool_null_route_finding(results: list[dict[str, Any]]) -> dict[str, Any]:
    pool_text = result_output(results, "show running-config ip local pool")
    route_text = result_output(results, "show running-config route")
    if not pool_text or not route_text:
        return finding("VPN pool Null0 routes", "warning", "IP local pool or route output was unavailable.")
    null_networks: list[ipaddress.IPv4Network] = []
    for address, mask in re.findall(r"(?im)^route\s+Null0\s+(\d+(?:\.\d+){3})\s+(\d+(?:\.\d+){3})\b", route_text):
        try:
            null_networks.append(ipaddress.ip_network(f"{address}/{mask}", strict=False))
        except ValueError:
            pass
    missing: list[str] = []
    pools = re.findall(r"(?im)^ip\s+local\s+pool\s+(\S+)\s+(\d+(?:\.\d+){3})-(\d+(?:\.\d+){3})", pool_text)
    for name, start, end in pools:
        try:
            first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
            covered = any(first in network and last in network for network in null_networks)
        except ValueError:
            covered = False
        if not covered:
            missing.append(f"{name}: {start}-{end}")
    if not pools:
        return finding("VPN pool Null0 routes", "warning", "No DHCP-style IP local pool ranges could be parsed.")
    return finding("VPN pool Null0 routes", "warning" if missing else "ok", "Pools without a covering Null0 route:\n" + "\n".join(missing) if missing else "Every parsed IP local pool is covered by a Null0 route.")


def time_sync_finding(results: list[dict[str, Any]]) -> dict[str, Any]:
    family = platform_family(results)
    if family == "41xx":
        text = result_output(results, "show clock detail")
        synced = bool(re.search(r"(?i)(?:sync\w*.*chassis|chassis.*sync\w*)", text))
        return finding("Time synchronization", "ok" if synced else "warning", "Clock reports synchronization to the chassis." if synced else "41xx clock output did not confirm synchronization to the chassis.")
    if family == "42xx":
        text = result_output(results, "show run ntp")
        configured = bool(text and re.search(r"(?im)^\s*ntp\s+", text))
        return finding("Time synchronization", "ok" if configured else "warning", "The 42xx returned NTP configuration." if configured else "The 42xx did not return usable NTP configuration.")
    return finding("Time synchronization", "warning", "Platform family could not be determined, so the platform-specific time check was skipped.")


def compliance_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [time_sync_finding(results), default_group_policy_finding(results), pool_null_route_finding(results), *certificate_findings(results)]


def ensure_data_dirs() -> None:
    for directory in (ARCHIVES, BASELINES, BATCHES):
        directory.mkdir(exist_ok=True)


def safe_slug(value: str, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-").lower()
    return cleaned[:80] or fallback


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def save_snapshot(run: dict[str, Any]) -> dict[str, Any]:
    if run.get("action") not in {"health", "standards"} or not run.get("device") or not isinstance(run.get("results"), list):
        raise ValueError("Only completed PipeWrench inspection results can be archived.")
    ensure_data_dirs()
    captured = str(run.get("captured_at") or utc_now())
    stamp = re.sub(r"[^0-9]", "", captured)[:14] or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    snapshot_id = f"{stamp}_{safe_slug(str(run['device']))}_{safe_slug(str(run['action']))}_{uuid.uuid4().hex[:8]}"
    safe_results = []
    for item in run["results"]:
        safe_item = dict(item)
        safe_item["output"] = redact_config_secrets(str(safe_item.get("output", "")))
        safe_results.append(safe_item)
    document = {
        "snapshot_version": SNAPSHOT_VERSION,
        "pipewrench_version": str(run.get("pipewrench_version") or APP_VERSION),
        "snapshot_id": snapshot_id,
        "captured_at": captured,
        "device": str(run["device"]),
        "action": str(run["action"]),
        "platform": str(run.get("platform") or platform_family(run["results"])),
        "metrics": run.get("metrics", []),
        "summary": run.get("summary", summarize(safe_results)),
        "results": safe_results,
    }
    write_json(ARCHIVES / f"{snapshot_id}.json", document)
    return snapshot_metadata(document)


def snapshot_metadata(document: dict[str, Any]) -> dict[str, Any]:
    metadata = {key: document.get(key) for key in ("snapshot_id", "captured_at", "device", "action", "platform", "summary")}
    if metadata.get("platform") in {None, "", "unknown"}:
        metadata["platform"] = platform_family(document.get("results", []))
    return metadata


def list_snapshots() -> list[dict[str, Any]]:
    ensure_data_dirs()
    items = [snapshot_metadata(read_json(path, {})) for path in ARCHIVES.glob("*.json")]
    return sorted((item for item in items if item.get("snapshot_id")), key=lambda item: str(item.get("captured_at", "")), reverse=True)


def load_named_json(directory: Path, item_id: str) -> dict[str, Any]:
    if not SAFE_ID.fullmatch(item_id):
        raise ValueError("Invalid item identifier.")
    path = directory / f"{item_id}.json"
    if not path.is_file():
        raise ValueError("Saved item was not found.")
    value = read_json(path, {})
    if not isinstance(value, dict):
        raise ValueError("Saved item is invalid.")
    if directory == ARCHIVES and value.get("platform") in {None, "", "unknown"}:
        value["platform"] = platform_family(value.get("results", []))
    if directory == ARCHIVES and value.get("action") == "standards":
        raw_results = [item for item in value.get("results", []) if item.get("command") != linters.COMPLIANCE_COMMAND]
        value["results"] = compliance_findings(raw_results) + linters.lint_results(raw_results, lint_config()) + raw_results
        value["summary"] = summarize(value["results"])
    return value


def compare_runs(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    comparison = lint_config().get("gold_comparison", {})
    current_sections = {item.get("label"): item for item in current.get("results", []) if item.get("command") != linters.COMPLIANCE_COMMAND}
    gold_sections = {item.get("label"): item for item in baseline.get("results", []) if item.get("command") != linters.COMPLIANCE_COMMAND}
    findings = []
    compared = 0
    for label in sorted(set(current_sections) | set(gold_sections), key=str.lower):
        current_item = current_sections.get(label)
        gold_item = gold_sections.get(label)
        sample = current_item or gold_item or {}
        if linters.comparable_value(str(label), str(sample.get("output", "")), comparison) is None:
            continue
        compared += 1
        if not current_item or not gold_item:
            detail = "Section is missing from the current result." if not current_item else "Section does not exist in the gold profile."
            findings.append(finding(str(label), "warning", detail))
            continue
        current_value = linters.comparable_value(str(label), str(current_item.get("output", "")), comparison) or set()
        gold_value = linters.comparable_value(str(label), str(gold_item.get("output", "")), comparison) or set()
        removed = sorted(gold_value - current_value)
        added = sorted(current_value - gold_value)
        if removed or added:
            detail = [f"Semantic difference: {len(removed)} missing, {len(added)} additional."]
            if removed:
                detail.append("Missing: " + "; ".join(removed[:5]))
            if added:
                detail.append("Additional: " + "; ".join(added[:5]))
            findings.append(finding(str(label), "warning", "\n".join(detail)))
    return {
        "baseline_id": baseline.get("baseline_id"),
        "baseline_name": baseline.get("name"),
        "matched": not findings,
        "compared_sections": compared,
        "rule_only_sections": comparison.get("rule_only", []),
        "findings": findings,
    }


def create_baseline(snapshot_id: str, platform: str, location: str) -> dict[str, Any]:
    snapshot = load_named_json(ARCHIVES, snapshot_id)
    if snapshot.get("action") != "standards":
        raise ValueError("Only a standards snapshot can become a gold profile.")
    platform, location = safe_slug(platform, "unknown"), safe_slug(location, "global")
    baseline_id = f"{platform}__{location}"
    document = dict(snapshot)
    document.update({"baseline_id": baseline_id, "name": f"{platform} / {location}", "platform": platform, "location": location, "set_at": utc_now()})
    write_json(BASELINES / f"{baseline_id}.json", document)
    return baseline_metadata(document)


def baseline_metadata(document: dict[str, Any]) -> dict[str, Any]:
    return {key: document.get(key) for key in ("baseline_id", "name", "platform", "location", "device", "captured_at", "set_at")}


def list_baselines() -> list[dict[str, Any]]:
    ensure_data_dirs()
    return sorted((baseline_metadata(read_json(path, {})) for path in BASELINES.glob("*.json")), key=lambda item: str(item.get("name", "")))


def run_batch(batch_id: str, selected_devices: list[str], action: str, baseline_id: str) -> None:
    path = BATCHES / f"{batch_id}.json"
    baseline = load_named_json(BASELINES, baseline_id) if baseline_id else None

    def run_one(device: str) -> dict[str, Any]:
        run = run_health(device) if action == "health" else run_standards(device)
        snapshot = save_snapshot(run)
        comparison = compare_runs(run, baseline) if baseline else None
        return {"device": device, "snapshot_id": snapshot["snapshot_id"], "summary": run["summary"], "comparison": comparison}

    with concurrent.futures.ThreadPoolExecutor(max_workers=config()["batch_workers"]) as pool:
        futures = {pool.submit(run_one, device): device for device in selected_devices}
        for future in concurrent.futures.as_completed(futures):
            device = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"device": device, "error": str(exc)}
            with BATCH_LOCK:
                job = read_json(path, {})
                job.setdefault("results", []).append(result)
                job["completed"] = len(job["results"])
                if job["completed"] == job["total"]:
                    job["status"] = "completed"
                    job["completed_at"] = utc_now()
                write_json(path, job)


def create_batch(selected_devices: list[str], action: str, baseline_id: str = "") -> dict[str, Any]:
    if not isinstance(selected_devices, list) or not all(isinstance(item, str) for item in selected_devices):
        raise ValueError("Headends must be supplied as a list.")
    allowed = set(devices())
    selected = list(dict.fromkeys(selected_devices))
    if not selected or any(device not in allowed for device in selected):
        raise ValueError("Choose one or more configured headends.")
    if action not in {"health", "standards"}:
        raise ValueError("That action is not available.")
    if baseline_id:
        load_named_json(BASELINES, baseline_id)
    ensure_data_dirs()
    batch_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]
    job = {"batch_id": batch_id, "created_at": utc_now(), "status": "running", "action": action, "baseline_id": baseline_id or None, "devices": selected, "total": len(selected), "completed": 0, "results": []}
    write_json(BATCHES / f"{batch_id}.json", job)
    threading.Thread(target=run_batch, args=(batch_id, selected, action, baseline_id), daemon=True).start()
    return job


def list_batches() -> list[dict[str, Any]]:
    ensure_data_dirs()
    jobs = [read_json(path, {}) for path in BATCHES.glob("*.json")]
    return sorted((job for job in jobs if job.get("batch_id")), key=lambda job: str(job.get("created_at", "")), reverse=True)


class PipeWrenchHandler(BaseHTTPRequestHandler):
    server_version = f"PipeWrench/{APP_VERSION}"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stdout.write(f"[{self.log_date_time_string()}] {fmt % args}\n")

    def send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        # Standards snapshots can contain large ACL and crypto sections.
        if length > 25_000_000:
            raise ValueError("Request is too large.")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/devices":
            self.send_json({"devices": devices(), "default_port": config()["asa_port"]})
            return
        if path == "/api/status":
            self.send_json({"credentials": credential_status(), "tls_verify": config()["verify_tls"], "version": APP_VERSION})
            return
        if path == "/api/snapshots":
            self.send_json({"snapshots": list_snapshots()})
            return
        if path.startswith("/api/snapshots/"):
            self.send_json(load_named_json(ARCHIVES, path.rsplit("/", 1)[-1]))
            return
        if path == "/api/baselines":
            self.send_json({"baselines": list_baselines()})
            return
        if path == "/api/batches":
            self.send_json({"batches": list_batches()})
            return
        if path.startswith("/api/batches/"):
            self.send_json(load_named_json(BATCHES, path.rsplit("/", 1)[-1]))
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        try:
            payload = self.read_json_body()
            if path == "/api/devices":
                self.add_device(payload)
            elif path == "/api/run":
                self.run_action(payload)
            elif path == "/api/snapshots":
                self.send_json(save_snapshot(payload), HTTPStatus.CREATED)
            elif path == "/api/baselines":
                self.send_json(
                    create_baseline(
                        str(payload.get("snapshot_id", "")),
                        str(payload.get("platform", "")),
                        str(payload.get("location", "")),
                    ),
                    HTTPStatus.CREATED,
                )
            elif path == "/api/compare":
                current = load_named_json(ARCHIVES, str(payload.get("snapshot_id", "")))
                baseline = load_named_json(BASELINES, str(payload.get("baseline_id", "")))
                self.send_json(compare_runs(current, baseline))
            elif path == "/api/batches":
                self.send_json(
                    create_batch(
                        payload.get("devices", []),
                        str(payload.get("action", "standards")),
                        str(payload.get("baseline_id", "")),
                    ),
                    HTTPStatus.ACCEPTED,
                )
            else:
                self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
        except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def add_device(self, payload: dict[str, Any]) -> None:
        hostname = str(payload.get("hostname", "")).strip()
        if not HOSTNAME.fullmatch(hostname):
            raise ValueError("Enter a short name or hostname without a port.")
        if hostname.lower() not in {item.lower() for item in devices()}:
            local_file = ROOT / "headends.local.txt"
            with local_file.open("a", encoding="utf-8") as handle:
                handle.write(hostname + "\n")
        self.send_json({"devices": devices(), "added": hostname}, HTTPStatus.CREATED)

    def run_action(self, payload: dict[str, Any]) -> None:
        device = str(payload.get("device", ""))
        action = str(payload.get("action", "health"))
        if device not in devices():
            raise ValueError("Select a configured headend.")
        if action == "health":
            result = run_health(device)
        elif action == "standards":
            result = run_standards(device)
        else:
            raise ValueError("That action is not available.")
        self.send_json(result)

    def serve_static(self, path: str) -> None:
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        candidate = (STATIC / relative).resolve()
        if STATIC.resolve() not in candidate.parents and candidate != STATIC.resolve():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not candidate.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        data = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    ensure_data_dirs()
    settings = config()
    server = ThreadingHTTPServer((settings["listen_host"], settings["listen_port"]), PipeWrenchHandler)
    print(f"PipeWrench is running at http://{settings['listen_host']}:{settings['listen_port']}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPipeWrench stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
