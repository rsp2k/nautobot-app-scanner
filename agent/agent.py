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

    def ingest(
        self,
        scan_id: str,
        ingestion_token: str,
        raw_body: str,
        tool: str = "nmap",
        content_type: str = "application/xml",
    ) -> dict:
        """POST raw tool output to the ingest endpoint.

        Phase G: ``tool`` + ``content_type`` parameters were added so non-nmap
        tools can ingest their own output formats (dig text, masscan JSON,
        etc.). Older agent calls that pass only the first three positional
        args still work — defaults preserve the nmap-XML contract.
        """
        return self._request(
            "POST",
            f"/api/plugins/scanner/scans/{scan_id}/ingest/",
            body=raw_body.encode("utf-8"),
            extra_headers={
                "Content-Type": content_type,
                "X-Ingestion-Token": ingestion_token,
                # Phase G: server-side parser dispatch reads this header to
                # pick the right parser. Default "nmap" preserves back-compat
                # if a future caller forgets to pass it.
                "X-Tool": tool,
            },
        )


# ----------------------------------------------------------------------------
# Tool registry — pluggable dispatch
# ----------------------------------------------------------------------------
#
# Each entry maps a tool name (matching server-side ToolChoices) to:
#   (argv_builder, content_type)
# where argv_builder(scan: dict) -> list[str] composes the argv from the
# pending-scan payload, and content_type is the HTTP header value the
# agent uses when POSTing the captured stdout back via client.ingest().
#
# Adding a new tool (`mtr`, `curl`, `openssl`, etc.) is purely additive:
# write a build_<tool>_argv() function and register it here. The server's
# parser.PARSERS dict must contain a matching key, otherwise the ingest
# returns 400.


def _all_targets(scan: dict) -> list[str]:
    """Collect prefix + IP + raw-IP targets from the pending-scan payload."""
    targets = scan.get("targets", {})
    out: list[str] = []
    out.extend(targets.get("prefixes", []))
    out.extend(targets.get("ipaddresses", []))
    out.extend(targets.get("raw_ips", []))
    return out


def build_nmap_argv(scan: dict) -> list[str]:
    """Compose nmap argv from a pending-scan payload.

    Includes Phase I pentest flags when present. The server gates these
    fields behind the ``use_pentest_profiles`` permission, so if they
    arrive in the payload at all, dispatch has been authorized — the
    agent does not re-check.
    """
    profile = scan["profile"]
    nmap_bin = os.environ.get("NMAP_BIN", "/usr/bin/nmap")
    argv = [nmap_bin, "-oX", "-"]
    argv.extend(shlex.split(profile.get("nmap_arguments", "") or ""))
    argv.append(f"-{profile.get('timing_template', 'T3')}")
    scripts = profile.get("enabled_scripts") or []
    if scripts:
        argv.extend(["--script", ",".join(scripts)])

    # Phase I: pentest flags. Each maps directly to an nmap argument.
    # Older agent versions (pre-Phase-I) silently skip this block; older
    # server versions don't include the "pentest" sub-dict, so .get()
    # returns an empty dict and nothing is appended.
    pentest = profile.get("pentest") or {}
    if pentest.get("decoy_addresses"):
        argv.extend(["-D", str(pentest["decoy_addresses"])])
    if pentest.get("mtu"):
        # --mtu N overrides -f; nmap requires a multiple of 8 (validated server-side)
        argv.extend(["--mtu", str(int(pentest["mtu"]))])
    elif pentest.get("fragment_packets"):
        argv.append("-f")
    if pentest.get("source_port"):
        argv.extend(["--source-port", str(int(pentest["source_port"]))])
    if pentest.get("idle_scan_zombie"):
        argv.extend(["-sI", str(pentest["idle_scan_zombie"])])

    argv.extend(_all_targets(scan))
    return argv


def build_dig_argv(scan: dict) -> list[str]:
    """Compose dig argv from a pending-scan payload.

    dig takes one target per invocation, but we run it once with all
    targets appended — dig accepts that and writes their answers
    sequentially. The server-side parser groups records by name; for
    Phase G we don't try to split them per target (see parser.py).
    """
    profile = scan["profile"]
    dig_bin = os.environ.get("DIG_BIN", "/usr/bin/dig")
    argv = [dig_bin]
    # tool_arguments holds the dig-specific args (e.g. "+noall +answer ANY").
    # nmap_arguments stays empty for dig profiles.
    argv.extend(shlex.split(profile.get("tool_arguments", "") or ""))
    argv.extend(_all_targets(scan))
    return argv


def build_drill_argv(scan: dict) -> list[str]:
    """Compose drill argv from a pending-scan payload.

    drill (NLnet Labs / ldns) is similar to dig in shape but has
    first-class DNSSEC support — `drill -DT example.com` does a full
    DNSSEC trace+chase in one shot, surfacing chain breaks that dig's
    verbose flags make hard to read. Same target-list-as-positional
    pattern as dig.
    """
    profile = scan["profile"]
    drill_bin = os.environ.get("DRILL_BIN", "/usr/bin/drill")
    argv = [drill_bin]
    argv.extend(shlex.split(profile.get("tool_arguments", "") or ""))
    argv.extend(_all_targets(scan))
    return argv


# (argv_builder, content_type) per tool. Server's X-Tool header
# dispatches the parser; here we pick the right binary + headers.
TOOL_REGISTRY = {
    "nmap": (build_nmap_argv, "application/xml"),
    "dig": (build_dig_argv, "text/plain"),
    "drill": (build_drill_argv, "text/plain"),
}


def run_tool(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """Run any tool, return (returncode, stdout, stderr).

    Generalized from the old run_nmap(): every supported tool produces
    its output on stdout, so a single dispatch is fine. Truncates
    stderr to 4 KB to bound log volume on chatty failures.
    """
    LOG.info("Running: %s", shlex.join(argv))
    try:
        result = subprocess.run(  # noqa: S603 — argv built from trusted profile fields
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        LOG.error("%s exceeded %ds timeout", argv[0], timeout)
        return (124, "", f"timeout after {timeout}s")
    except FileNotFoundError:
        LOG.error("binary not found: %s", argv[0])
        return (127, "", f"{argv[0]} not found")
    return (result.returncode, result.stdout, (result.stderr or "")[:4096])


# ----------------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------------


def capabilities() -> dict:
    """Probe local environment for things Nautobot might want to know.

    Returns a hostname + version-string for each tool the registry
    advertises. A "missing" value lets the server filter scan dispatch
    to agents that actually have the binary installed (a netshoot-based
    agent will have all of them; a stripped-down agent might have only
    nmap).
    """
    caps: dict[str, str] = {"hostname": socket.gethostname()}
    for tool in TOOL_REGISTRY.keys():
        caps[f"{tool}_version"] = _probe_tool_version(tool)
    return caps


def _probe_tool_version(tool: str) -> str:
    """Return the first line of `<tool> --version`, or 'missing' if absent.

    Defensive against every plausible failure mode so the capabilities
    probe never crashes the agent: FileNotFoundError when the binary
    isn't installed, TimeoutExpired when the tool hangs (rare for
    --version but possible for tools that try to open a network socket
    on start), PermissionError when file caps without NET_RAW in the
    process bounding set prevent execve.
    """
    try:
        result = subprocess.run(  # noqa: S603 — fixed binary name, no shell
            [tool, "--version"], capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode == 0:
            text = result.stdout or result.stderr or ""
            first_line = text.splitlines()[0] if text else ""
            return first_line[:128]
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
        pass
    return "missing"


def checkin_loop(client: NautobotClient, version: str, interval: int, stop: threading.Event) -> None:
    """Background heartbeat — runs until `stop` is set."""
    while not stop.is_set():
        try:
            client.checkin(version, capabilities())
            LOG.debug("checkin ok")
        except Exception as exc:  # noqa: BLE001 — keep alive across network blips
            LOG.warning("checkin failed: %s", exc)
        stop.wait(interval)


def poll_and_execute(client: NautobotClient, scan_timeout: int) -> None:
    """One iteration of pending-scans → run → ingest, dispatching by tool."""
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

        # Phase G: pick the tool from the scan payload (server sends the
        # field starting with migration 0015). Default "nmap" so an agent
        # talking to a pre-Phase-G server still works.
        tool = (scan.get("tool") or "nmap").lower()
        entry = TOOL_REGISTRY.get(tool)
        if entry is None:
            LOG.error(
                "Skipping scan %s: tool %r not in this agent's registry "
                "(supported: %s)",
                scan_id, tool, sorted(TOOL_REGISTRY.keys()),
            )
            continue
        argv_builder, content_type = entry

        argv = argv_builder(scan)
        rc, output, err = run_tool(argv, scan_timeout)
        if rc != 0:
            # No "failed" sentinel in the protocol — the server's
            # MarkStaleAgents job eventually GCs never-ingested scans.
            # For now, log and move on.
            LOG.error("%s rc=%d for scan %s: %s", tool, rc, scan_id, err[:200])
            continue

        try:
            response = client.ingest(
                scan_id, ingestion_token, output,
                tool=tool, content_type=content_type,
            )
            LOG.info("Ingested %s scan %s: %s", tool, scan_id, response)
        except urllib.error.HTTPError as exc:
            LOG.error("ingest HTTP error for %s scan %s: %d", tool, scan_id, exc.code)


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
    # NMAP_BIN + DIG_BIN are still read by the per-tool argv builders;
    # they're no longer threaded through main() because the tool registry
    # is now the dispatch surface.
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
        poll_and_execute(client, scan_timeout)
        stop.wait(poll_interval)

    LOG.info("Agent stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
