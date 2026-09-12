#!/usr/bin/env python3
"""PipeWrench local web server and read-only Cisco ASA HTTP proxy."""

from __future__ import annotations

import base64
import concurrent.futures
import json
import mimetypes
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

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
    }


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def devices() -> list[str]:
    merged = read_lines(ROOT / "headends.txt") + read_lines(ROOT / "headends.local.txt")
    return sorted({item.lower(): item for item in merged if HOSTNAME.fullmatch(item)}.values(), key=str.lower)


def credential_status() -> dict[str, Any]:
    username_path = ROOT / "un.txt"
    password_path = ROOT / "pw.txt"
    ready = username_path.is_file() and password_path.is_file()
    updated = None
    if password_path.is_file():
        updated = datetime.fromtimestamp(password_path.stat().st_mtime, timezone.utc).isoformat()
    return {"ready": ready, "password_updated": updated}


def credentials() -> tuple[str, str]:
    try:
        username = (ROOT / "un.txt").read_text(encoding="utf-8").strip()
        password = (ROOT / "pw.txt").read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise RuntimeError("Create un.txt and pw.txt in the PipeWrench folder.") from exc
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
        (r"(?im)(\bsecret\s+)\S+", r"\1********"),
        (r"(?im)(\bpre-shared-key(?:\s+local|\s+remote)?\s+)\S+", r"\1********"),
        (r"(?im)(\bsnmp-server\s+community\s+)\S+", r"\1********"),
    ]
    redacted = output
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def run_health(device: str) -> dict[str, Any]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(execute_command, device, label, command) for label, command in HEALTH_COMMANDS]
        results = [future.result() for future in futures]
    return {
        "action": "health",
        "device": device,
        "metrics": health_metrics(results),
        "results": results,
        "summary": summarize(results),
    }


def run_standards(device: str) -> dict[str, Any]:
    # Keep concurrency deliberately low; this is a broad review against one production ASA.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(execute_command, device, label, command) for label, command in STANDARD_COMMANDS]
        results = [future.result() for future in futures]
    for result in results:
        if result.get("status") == "ok":
            result["output"] = redact_config_secrets(str(result.get("output", "")))
    return {
        "action": "standards",
        "device": device,
        "metrics": health_metrics(results),
        "results": results,
        "summary": summarize(results),
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"ok": 0, "warning": 0, "error": 0}
    for result in results:
        status = result.get("status", "warning")
        summary[status if status in summary else "warning"] += 1
    return summary


class PipeWrenchHandler(BaseHTTPRequestHandler):
    server_version = "PipeWrench/0.2"

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
        if length > 16_384:
            raise ValueError("Request is too large.")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/devices":
            self.send_json({"devices": devices(), "default_port": config()["asa_port"]})
            return
        if path == "/api/status":
            self.send_json({"credentials": credential_status(), "tls_verify": config()["verify_tls"]})
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
            else:
                self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
        except (ValueError, json.JSONDecodeError) as exc:
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
