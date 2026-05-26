"""Local backend — runs nmap inside the Nautobot Celery worker.

Synchronous: `dispatch()` blocks until parse + persist are done. Uses
`subprocess.run` (NOT asyncio) because the Celery worker is sync and
mixing event loops with the worker's own pool causes deadlocks.

The nmap binary is expected at /usr/bin/nmap inside the worker container.
The dev Dockerfile installs it via apt; production deploys are
responsible for their own packaging.
"""

from __future__ import annotations

import gzip
import logging
import shlex
import subprocess  # noqa: S404 — running a known binary with controlled args
from io import BytesIO
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone

from nautobot_scanner.backends.base import ScannerBackend
from nautobot_scanner.choices import ScanStateChoices
from nautobot_scanner.parser import parse_xml_with_report, persist

if TYPE_CHECKING:
    from nautobot_scanner.models import Scan

logger = logging.getLogger(__name__)

NMAP_BIN = "/usr/bin/nmap"


class LocalBackend(ScannerBackend):
    """Executes nmap in-process via subprocess."""

    def dispatch(self, scan: Scan) -> None:
        """Run nmap, parse output, persist results — all in this call."""
        targets = self._collect_targets(scan)
        if not targets:
            self._fail(scan, "No targets specified — add prefixes or IP addresses to the scan.")
            return

        argv = self._build_argv(scan, targets)
        timeout = settings.PLUGINS_CONFIG.get("nautobot_scanner", {}).get(
            "local_scan_timeout_seconds",
            3600,
        )

        scan.status = ScanStateChoices.RUNNING
        scan.started_at = timezone.now()
        scan.save(update_fields=["status", "started_at"])

        logger.info("LocalBackend dispatching %s with: %s", scan.pk, shlex.join(argv))

        try:
            result = subprocess.run(  # noqa: S603 — argv is constructed from validated inputs
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._fail(scan, f"nmap exceeded timeout of {timeout}s")
            return
        except FileNotFoundError:
            self._fail(scan, f"nmap binary not found at {NMAP_BIN} — install it in the worker image")
            return

        if result.returncode != 0:
            err = (result.stderr or "").strip()[:2000]
            self._fail(scan, f"nmap exited {result.returncode}: {err}")
            return

        try:
            parsed_report, parsed = parse_xml_with_report(result.stdout)
        except ValueError as exc:
            self._fail(scan, f"Parser rejected nmap output: {exc}")
            self._save_raw_xml(scan, result.stdout)  # keep XML for debugging
            return

        self._save_raw_xml(scan, result.stdout)
        summary = persist(scan, parsed, report=parsed_report)
        scan.summary = summary
        scan.status = ScanStateChoices.COMPLETED
        scan.completed_at = timezone.now()
        scan.ingestion_token = None  # one-shot, clear after success
        scan.save(update_fields=["summary", "status", "completed_at", "ingestion_token"])
        logger.info("LocalBackend completed %s: %s", scan.pk, summary)

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
    def _build_argv(scan: Scan, targets: list[str]) -> list[str]:
        """Compose the final argv: nmap + profile args + timing + -oX - + targets."""
        argv = [NMAP_BIN, "-oX", "-"]
        # Profile flags (raw string from the user — we shlex-split it).
        profile_args = shlex.split(scan.profile.nmap_arguments or "")
        argv.extend(profile_args)
        # Timing template (T0..T5). Always append so the profile string
        # doesn't have to repeat it.
        argv.append(f"-{scan.profile.timing_template}")
        # NSE scripts from the profile's enabled_scripts list.
        scripts = scan.profile.enabled_scripts or []
        if scripts:
            argv.extend(["--script", ",".join(scripts)])
        argv.extend(targets)
        return argv

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
    def _fail(scan: Scan, message: str) -> None:
        """Mark scan failed with an error message — single point of update."""
        logger.warning("LocalBackend failing scan %s: %s", scan.pk, message)
        scan.status = ScanStateChoices.FAILED
        scan.error_message = message
        scan.completed_at = timezone.now()
        scan.ingestion_token = None
        scan.save(update_fields=["status", "error_message", "completed_at", "ingestion_token"])
