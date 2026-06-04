"""Local backend — runs probe-tool inside the Nautobot Celery worker.

Synchronous: `dispatch()` blocks until parse + persist are done. Uses
`subprocess.run` (NOT asyncio) because the Celery worker is sync and
mixing event loops with the worker's own pool causes deadlocks.

Tool dispatch: ``scan.profile.tool`` selects the binary + argv
shape via the same conventions the remote agent uses. nmap stays the
default for back-compat; testssl / ssh-audit / dig / drill / curl /
mtr / masscan / openssl-s_client each have their own argv pattern.

Tool binaries are expected at conventional paths inside the worker
container — the dev Dockerfile installs nmap; Phase L adds testssl.sh
and ssh-audit. Production deploys are responsible for their own
packaging. Overridable via env vars (NMAP_BIN, TESTSSL_BIN, etc.).
"""

from __future__ import annotations

import gzip
import logging
import os
import shlex
import subprocess  # noqa: S404 — running a known binary with controlled args
from io import BytesIO
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone

from nautobot_scanner.backends.base import ScannerBackend
from nautobot_scanner.choices import ScanStateChoices
from nautobot_scanner.parser import dispatch_parser, persist

if TYPE_CHECKING:
    from nautobot_scanner.models import Scan

logger = logging.getLogger(__name__)

NMAP_BIN = "/usr/bin/nmap"

# Per-tool binary path env vars + defaults. Mirrors the agent's
# convention so operators can override the same way in both places.
_TOOL_BIN_ENV = {
    "nmap": ("NMAP_BIN", "/usr/bin/nmap"),
    "dig": ("DIG_BIN", "/usr/bin/dig"),
    "drill": ("DRILL_BIN", "/usr/bin/drill"),
    "curl": ("CURL_BIN", "/usr/bin/curl"),
    "mtr": ("MTR_BIN", "/usr/bin/mtr"),
    "masscan": ("MASSCAN_BIN", "/usr/bin/masscan"),
    "openssl-s_client": ("OPENSSL_BIN", "/usr/bin/openssl"),
    "testssl": ("TESTSSL_BIN", "/usr/bin/testssl"),
    "ssh-audit": ("SSH_AUDIT_BIN", "/usr/local/bin/ssh-audit"),
}


def _tool_bin(tool: str) -> str:
    env_var, default = _TOOL_BIN_ENV.get(tool, ("", ""))
    return os.environ.get(env_var, default)


class LocalBackend(ScannerBackend):
    """Executes nmap in-process via subprocess."""

    # Tools whose return code != 0 doesn't indicate failure — they use
    # exit codes to signal severity. ssh-audit returns 2/3/4 to flag
    # warn/info/fail-class findings; masscan returns 1 in normal "no
    # listener" cases. The wrapper shell `|| true` in the argv builders
    # already masks these, but keeping the allow-list as a server-side
    # safety net.
    _TOLERATE_NONZERO_EXIT = frozenset({"ssh-audit"})

    def dispatch(self, scan: Scan) -> None:
        """Run the profile's tool, parse output, persist results."""
        targets = self._collect_targets(scan)
        if not targets:
            self._fail(scan, "No targets specified — add prefixes or IP addresses to the scan.")
            return

        tool = scan.profile.tool or "nmap"
        argv = self._build_argv(scan, targets, tool)
        timeout = settings.PLUGINS_CONFIG.get("nautobot_scanner", {}).get(
            "local_scan_timeout_seconds",
            3600,
        )

        scan.status = ScanStateChoices.RUNNING
        scan.started_at = timezone.now()
        scan.save(update_fields=["status", "started_at"])

        logger.info("LocalBackend dispatching %s [tool=%s] with: %s", scan.pk, tool, shlex.join(argv))

        try:
            result = subprocess.run(  # noqa: S603 — argv is constructed from validated inputs
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._fail(scan, f"{tool} exceeded timeout of {timeout}s")
            return
        except FileNotFoundError:
            self._fail(scan, f"{tool} binary not found — install it in the worker image")
            return

        if result.returncode != 0 and tool not in self._TOLERATE_NONZERO_EXIT:
            err = (result.stderr or "").strip()[:2000]
            self._fail(scan, f"{tool} exited {result.returncode}: {err}")
            return

        try:
            parsed_report, parsed = dispatch_parser(tool, result.stdout, targets)
        except ValueError as exc:
            self._fail(scan, f"Parser rejected {tool} output: {exc}")
            # Keep raw output around for debugging.
            if tool == "nmap":
                self._save_raw_xml(scan, result.stdout)
            else:
                self._save_raw_output(scan, result.stdout, ext="json")
            return

        # Save raw output to the right field. nmap → raw_xml (XML),
        # everyone else → raw_output (gzipped text/JSON). Mutually
        # exclusive per ADR-013 design.
        if tool == "nmap":
            self._save_raw_xml(scan, result.stdout)
        else:
            ext = "json" if tool in ("masscan", "mtr", "testssl", "ssh-audit") else "txt"
            self._save_raw_output(scan, result.stdout, ext=ext)

        summary = persist(scan, parsed, report=parsed_report)
        scan.summary = summary
        scan.tool_used = tool
        scan.status = ScanStateChoices.COMPLETED
        scan.completed_at = timezone.now()
        scan.ingestion_token = None  # one-shot, clear after success
        scan.save(update_fields=["summary", "tool_used", "status", "completed_at", "ingestion_token"])
        logger.info("LocalBackend completed %s [tool=%s]: %s", scan.pk, tool, summary)

    @staticmethod
    def _collect_targets(scan: Scan) -> list[str]:
        """Build the nmap target list from M2M Prefixes + IPAddresses + raw IPs."""
        targets: list[str] = []
        for prefix in scan.target_prefixes.all():
            targets.append(str(prefix.prefix))
        for ip in scan.target_ipaddresses.all():
            # Strip mask — nmap accepts either, but bare IPs render cleaner
            # in logs and the resulting XML.
            targets.append(str(ip.host))
        # Raw IPs / CIDRs from ad-hoc rescans that bypass IPAM (see
        # DiscoveredHostRescanView). Trust the strings — they came from
        # our own DiscoveredHost records.
        for raw in (scan.target_raw_ips or []):
            targets.append(str(raw))
        return targets

    @staticmethod
    def _build_argv(scan: Scan, targets: list[str], tool: str) -> list[str]:
        """Compose the final argv. nmap stays the rich-flag path; non-nmap
        tools each have their own builder mirroring the agent's TOOL_REGISTRY.

        Per-tool builders are colocated here (rather than imported from the
        agent module) so the LocalBackend doesn't depend on the agent
        package's Python path being installed inside Nautobot — a separation
        ADR-013 preserves.
        """
        if tool == "nmap":
            argv = [_tool_bin("nmap"), "-oX", "-"]
            argv.extend(shlex.split(scan.profile.nmap_arguments or ""))
            argv.append(f"-{scan.profile.timing_template}")
            scripts = scan.profile.enabled_scripts or []
            if scripts:
                argv.extend(["--script", ",".join(scripts)])
            argv.extend(targets)
            return argv

        # Non-nmap path: profile.tool_arguments + tool-specific defaults.
        tool_args = shlex.split(scan.profile.tool_arguments or "")

        if tool == "dig":
            return [_tool_bin("dig"), *tool_args, *targets]
        if tool == "drill":
            return [_tool_bin("drill"), *tool_args, *targets]
        if tool == "curl":
            return [
                _tool_bin("curl"), "-sS", "-D", "/dev/stderr", "-o", "/dev/null",
                "-w", "STATUS=%{http_code} SIZE=%{size_download} "
                      "TIME=%{time_total} REDIRECTS=%{num_redirects} URL=%{url_effective}\n",
                *tool_args, *targets,
            ]
        if tool == "mtr":
            return [_tool_bin("mtr"), "-j", "-c", "10", "-n", *tool_args, *targets]
        if tool == "masscan":
            return [_tool_bin("masscan"), "-oJ", "-", "--rate", "10000", *tool_args, *targets]
        if tool == "openssl-s_client":
            # Mirror agent's sentinel-delimited multi-target wrapper.
            args = tool_args or shlex.split("-showcerts -tls1_3")
            quoted_args = " ".join(shlex.quote(a) for a in args)
            parts = []
            for t in targets:
                parts.append(
                    f'echo "===TARGET={t}==="; '
                    f'{shlex.quote(_tool_bin("openssl-s_client"))} s_client -connect {shlex.quote(t)} '
                    f'{quoted_args} </dev/null 2>&1',
                )
            return ["sh", "-c", " ; ".join(parts) if parts else ":"]
        if tool == "testssl":
            # testssl writes its progress text to stdout regardless of
            # --jsonfile, so /dev/stdout for --jsonfile produces interleaved
            # garbage. Use a real temp file, redirect both progress
            # streams to /dev/null, then cat the JSON file out.
            quoted_args = " ".join(shlex.quote(a) for a in tool_args)
            testssl_bin = shlex.quote(_tool_bin("testssl"))
            if len(targets) == 1:
                return [
                    "sh", "-c",
                    f"TMP=$(mktemp /tmp/testssl-XXXXXX.json) && trap 'rm -f $TMP' EXIT && "
                    f"{testssl_bin} --jsonfile $TMP --quiet --color 0 "
                    f"{quoted_args} {shlex.quote(targets[0])} >/dev/null 2>&1 && "
                    f"cat $TMP",
                ]
            # Multi-target: separate temp file per run, then merge arrays.
            cmds = []
            for i, t in enumerate(targets):
                cmds.append(
                    f"TMP{i}=$(mktemp /tmp/testssl-XXXXXX.json) && "
                    f"{testssl_bin} --jsonfile $TMP{i} --quiet --color 0 "
                    f"{quoted_args} {shlex.quote(t)} >/dev/null 2>&1",
                )
            cat_cmd = " ; ".join(f"cat $TMP{i}" for i in range(len(targets)))
            rm_cmd = " ; ".join(f"rm -f $TMP{i}" for i in range(len(targets)))
            cmds_str = " && ".join(cmds)
            return [
                "sh", "-c",
                f"({cmds_str}) && "
                f"( {cat_cmd} ) | "
                # awk merges multiple JSON arrays into one: ][ → ,
                "awk 'BEGIN{RS=\"\"} {gsub(/\\][[:space:]]*\\[/,\",\"); print}' ; "
                f"{rm_cmd}",
            ]
        if tool == "ssh-audit":
            quoted_args = " ".join(shlex.quote(a) for a in tool_args)
            if len(targets) == 1:
                return [
                    "sh", "-c",
                    f"{shlex.quote(_tool_bin('ssh-audit'))} -j {quoted_args} "
                    f"{shlex.quote(targets[0])} 2>/dev/null || true",
                ]
            parts = [
                f"{shlex.quote(_tool_bin('ssh-audit'))} -j {quoted_args} {shlex.quote(t)} 2>/dev/null || true"
                for t in targets
            ]
            joined = " ; echo ',' ; ".join(parts)
            return [
                "sh", "-c",
                f"( echo '[' ; {joined} ; echo ']' )",
            ]

        msg = f"LocalBackend has no argv builder for tool={tool!r}"
        raise ValueError(msg)

    @staticmethod
    def _save_raw_xml(scan: Scan, xml: str) -> None:
        """Gzip and attach the raw nmap XML to the Scan record."""
        if not xml:
            return
        buf = BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(xml.encode("utf-8"))
        scan.raw_xml.save(
            f"scan-{scan.pk}.xml.gz",
            ContentFile(buf.getvalue()),
            save=False,
        )
        scan.raw_xml_size = len(xml.encode("utf-8"))
        scan.save(update_fields=["raw_xml", "raw_xml_size"])

    @staticmethod
    def _save_raw_output(scan: Scan, output: str, ext: str = "txt") -> None:
        """Gzip + attach non-XML tool output (dig text, masscan JSON, etc.).

        Sibling of _save_raw_xml — kept separate so nmap-shaped tooling
        that reads scan.raw_xml directly isn't confused by non-nmap
        bytes. The `ext` argument signals the format ('txt' for dig,
        'json' for masscan); future tooling can dispatch on the file
        extension when re-opening.
        """
        if not output:
            return
        buf = BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(output.encode("utf-8"))
        scan.raw_output.save(
            f"scan-{scan.pk}.{ext}.gz",
            ContentFile(buf.getvalue()),
            save=False,
        )
        scan.raw_output_size = len(output.encode("utf-8"))
        scan.save(update_fields=["raw_output", "raw_output_size"])

    @staticmethod
    def _fail(scan: Scan, message: str) -> None:
        """Mark scan failed with an error message — single point of update."""
        logger.warning("LocalBackend failing scan %s: %s", scan.pk, message)
        scan.status = ScanStateChoices.FAILED
        scan.error_message = message
        scan.completed_at = timezone.now()
        scan.ingestion_token = None
        scan.save(update_fields=["status", "error_message", "completed_at", "ingestion_token"])
