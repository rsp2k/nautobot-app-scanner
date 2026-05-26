#!/usr/bin/env python3
"""Reference remote scanner agent for nautobot-app-scanner.

Stateless poll-and-execute loop. Configuration is entirely via environment
variables — drop this into a container, give it the Nautobot URL + agent
token + agent ID, and it starts working.

Wire format is the agent-protocol documented in docs/agent-protocol.md:

  1. POST /agents/<id>/checkin/      every CHECKIN_INTERVAL seconds (background)
  2. GET  /agents/<id>/pending-scans/ every POLL_INTERVAL seconds
  3. For each returned scan, run nmap with the profile args + targets, then
     POST the raw XML back to /scans/<scan-id>/ingest/ with the matching
     X-Ingestion-Token header.

Standard library only — no `requests`, no `aiohttp`, just `urllib.request`
and `subprocess`. The container image lands at ~100 MB — most of that is
nmap-scripts; the agent itself is a single file.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import signal
import socket
import ssl
import subprocess  # noqa: S404 — calling a known binary with controlled args
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

LOG = logging.getLogger("scanner-agent")


# ----------------------------------------------------------------------------
# Configuration — all from environment
# ----------------------------------------------------------------------------


def env(name: str, default: str | None = None, required: bool = False) -> str:
    """Read a string env var with optional required-check."""
    value = os.environ.get(name, default)
    if required and not value:
        LOG.error("Missing required env var: %s", name)
        sys.exit(2)
    return value or ""


def env_int(name: str, default: int) -> int:
    """Read an int env var with default fallback on missing/invalid."""
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        LOG.warning("Env %s=%r is not an int, using default %d", name, raw, default)
        return default


def env_bool(name: str, default: bool) -> bool:
    """Read a boolean env var (truthy: '1', 'true', 'yes', 'on')."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# ----------------------------------------------------------------------------
# HTTP client (stdlib)
# ----------------------------------------------------------------------------


class NautobotClient:
    """Thin HTTP wrapper around the three agent endpoints."""

    def __init__(self, base_url: str, agent_id: str, token: str, verify_tls: bool = True):
        self.base = base_url.rstrip("/")
        self.agent_id = agent_id
        self.token = token
        # Pre-built SSL context: skip verification if requested (dev/self-signed).
        self.ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, body: bytes | None = None, extra_headers: dict | None = None) -> dict | list | None:
        url = f"{self.base}{path}"
        headers = {
            "Authorization": f"Token {self.token}",
            "Accept": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)
        if body is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/octet-stream"

        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=120) as resp:  # noqa: S310 — token-auth controlled URL
                payload = resp.read()
                if not payload:
                    return None
                return json.loads(payload)
        except urllib.error.HTTPError as exc:
            # Read body for error context — server returns JSON {"detail": "..."}.
            err_body = exc.read().decode("utf-8", errors="replace")[:500]
            LOG.warning("HTTP %s %s → %d: %s", method, path, exc.code, err_body)
            raise

    def checkin(self, version: str, capabilities: dict) -> None:
        body = json.dumps({"version": version, "capabilities": capabilities}).encode("utf-8")
        self._request("POST", f"/api/plugins/scanner/agents/{self.agent_id}/checkin/", body,
                      extra_headers={"Content-Type": "application/json"})

    def get_pending_scans(self) -> list[dict]:
        result = self._request("GET", f"/api/plugins/scanner/agents/{self.agent_id}/pending-scans/")
        return result or []

    def ingest(self, scan_id: str, ingestion_token: str, raw_xml: str) -> dict:
        return self._request(
            "POST",
            f"/api/plugins/scanner/scans/{scan_id}/ingest/",
            body=raw_xml.encode("utf-8"),
            extra_headers={
                "Content-Type": "application/xml",
                "X-Ingestion-Token": ingestion_token,
            },
        )


# ----------------------------------------------------------------------------
# nmap execution
# ----------------------------------------------------------------------------


def build_argv(scan: dict, nmap_bin: str) -> list[str]:
    """Compose nmap argv from a pending-scan payload."""
    profile = scan["profile"]
    argv = [nmap_bin, "-oX", "-"]
    argv.extend(shlex.split(profile.get("nmap_arguments", "") or ""))
    argv.append(f"-{profile.get('timing_template', 'T3')}")
    scripts = profile.get("enabled_scripts") or []
    if scripts:
        argv.extend(["--script", ",".join(scripts)])
    argv.extend(scan["targets"].get("prefixes", []))
    argv.extend(scan["targets"].get("ipaddresses", []))
    # Raw IPs/CIDRs from ad-hoc rescans (server-side migration 0011, added
    # 2026-05-26). Older agents that pre-date this field just ignore it —
    # the server treats it as optional. Newer agents append it to the nmap
    # target list alongside the IPAM-anchored targets.
    argv.extend(scan["targets"].get("raw_ips", []))
    return argv


def run_nmap(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """Run nmap, return (returncode, stdout, stderr). Truncates stderr to 4 KB."""
    LOG.info("Running: %s", shlex.join(argv))
    try:
        result = subprocess.run(  # noqa: S603 — argv validated upstream
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        LOG.error("nmap exceeded %ds timeout", timeout)
        return (124, "", f"timeout after {timeout}s")
    except FileNotFoundError:
        LOG.error("nmap binary not found at %s", argv[0])
        return (127, "", "nmap not found")
    return (result.returncode, result.stdout, (result.stderr or "")[:4096])


# ----------------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------------


def capabilities() -> dict:
    """Probe local environment for things Nautobot might want to know."""
    caps = {"hostname": socket.gethostname()}
    try:
        result = subprocess.run(  # noqa: S607,S603 — fixed argv, no shell
            ["nmap", "--version"], capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode == 0:
            first_line = (result.stdout or "").splitlines()[0] if result.stdout else ""
            caps["nmap_version"] = first_line
    except (FileNotFoundError, subprocess.TimeoutExpired):
        caps["nmap_version"] = "missing"
    return caps


def checkin_loop(client: NautobotClient, version: str, interval: int, stop: threading.Event) -> None:
    """Background heartbeat — runs until `stop` is set."""
    while not stop.is_set():
        try:
            client.checkin(version, capabilities())
            LOG.debug("checkin ok")
        except Exception as exc:  # noqa: BLE001 — keep alive across network blips
            LOG.warning("checkin failed: %s", exc)
        stop.wait(interval)


def poll_and_execute(client: NautobotClient, scan_timeout: int, nmap_bin: str) -> None:
    """One iteration of pending-scans → run → ingest."""
    try:
        scans = client.get_pending_scans()
    except Exception as exc:  # noqa: BLE001
        LOG.warning("poll failed: %s", exc)
        return

    if not scans:
        return

    LOG.info("Picked up %d pending scan(s)", len(scans))
    for scan in scans:
        scan_id = scan.get("id", "<unknown>")
        ingestion_token = scan.get("ingestion_token", "")
        try:
            uuid.UUID(ingestion_token)  # validate
        except ValueError:
            LOG.warning("Skipping scan %s: invalid ingestion_token", scan_id)
            continue

        argv = build_argv(scan, nmap_bin)
        rc, xml, err = run_nmap(argv, scan_timeout)
        if rc != 0:
            # We could POST a "failed" sentinel, but the protocol doesn't have
            # one — the server-side MarkStaleAgents job will eventually clean up
            # never-ingested scans. For now, log and move on.
            LOG.error("nmap rc=%d for scan %s: %s", rc, scan_id, err[:200])
            continue

        try:
            response = client.ingest(scan_id, ingestion_token, xml)
            LOG.info("Ingested scan %s: %s", scan_id, response)
        except urllib.error.HTTPError as exc:
            LOG.error("ingest HTTP error for scan %s: %d", scan_id, exc.code)


def main() -> int:
    """Entry point — wire config, start checkin thread, run forever."""
    logging.basicConfig(
        level=os.environ.get("AGENT_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    )

    nautobot_url = env("NAUTOBOT_URL", required=True)
    agent_id = env("AGENT_ID", required=True)
    token = env("AGENT_TOKEN", required=True)
    verify_tls = env_bool("VERIFY_TLS", True)
    poll_interval = env_int("POLL_INTERVAL_SECONDS", 30)
    checkin_interval = env_int("CHECKIN_INTERVAL_SECONDS", 60)
    scan_timeout = env_int("SCAN_TIMEOUT_SECONDS", 3600)
    nmap_bin = env("NMAP_BIN", "/usr/bin/nmap")
    version = env("AGENT_VERSION", "reference-agent/1.0")

    client = NautobotClient(nautobot_url, agent_id, token, verify_tls=verify_tls)
    LOG.info("Starting agent %s → %s (poll=%ds checkin=%ds)",
             agent_id, nautobot_url, poll_interval, checkin_interval)

    stop = threading.Event()

    def handle_signal(signum, frame):  # noqa: ARG001
        LOG.info("Received signal %d, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Eager first checkin so the agent appears online right away.
    try:
        client.checkin(version, capabilities())
    except Exception as exc:  # noqa: BLE001
        LOG.warning("initial checkin failed (continuing anyway): %s", exc)

    checkin_thread = threading.Thread(
        target=checkin_loop, args=(client, version, checkin_interval, stop), daemon=True,
    )
    checkin_thread.start()

    while not stop.is_set():
        poll_and_execute(client, scan_timeout, nmap_bin)
        stop.wait(poll_interval)

    LOG.info("Agent stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
