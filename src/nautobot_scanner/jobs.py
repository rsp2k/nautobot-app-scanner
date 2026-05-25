"""Nautobot Jobs that drive the scanner from the UI.

Three Jobs are registered:

- ``RunScan`` — full form: pick agent + profile + a set of Prefixes and/or
  IPAddresses, dispatches via the agent's backend.
- ``ScanPrefix`` — convenience wrapper that takes a single Prefix and the
  default agent + profile (first ones found, alphabetical).
- ``MarkStaleAgents`` — periodic housekeeping. Flips ``ScannerAgent.status``
  to "Offline" when ``last_seen`` is older than 3 × the configured checkin
  interval. Schedule it via Nautobot's built-in job scheduler.
"""

from __future__ import annotations

import datetime
import logging

from django.conf import settings
from django.utils import timezone
from nautobot.apps.jobs import BooleanVar, Job, MultiObjectVar, ObjectVar, register_jobs
from nautobot.dcim.models import Location  # noqa: F401 — needed for namespace resolution
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.choices import ScanStateChoices
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

logger = logging.getLogger(__name__)


name = "Scanner"  # pylint: disable=invalid-name  # Nautobot picks this up as the group label


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


def _has_overlapping_scan(agent: ScannerAgent, prefixes, ipaddresses) -> bool:
    """True if a running Scan on this agent already covers any of these targets.

    Cheap check — exact overlap by FK membership, not subnet arithmetic.
    Good enough to catch the "user double-clicked Run" case; doesn't try
    to detect "scan of /16 already covers this /24" relationships.
    """
    candidate = Scan.objects.filter(
        agent=agent,
        status__in=[ScanStateChoices.PENDING, ScanStateChoices.RUNNING],
    )
    if prefixes:
        if candidate.filter(target_prefixes__in=prefixes).exists():
            return True
    if ipaddresses:
        if candidate.filter(target_ipaddresses__in=ipaddresses).exists():
            return True
    return False


# ----------------------------------------------------------------------------
# RunScan — the main user-facing dispatch
# ----------------------------------------------------------------------------


class RunScan(Job):
    """Dispatch a scan against the chosen targets using the chosen agent + profile."""

    agent = ObjectVar(
        model=ScannerAgent,
        description="Which agent will execute the scan.",
    )
    profile = ObjectVar(
        model=ScanProfile,
        description="The nmap argument profile to use.",
    )
    target_prefixes = MultiObjectVar(
        model=Prefix,
        required=False,
        description="IPAM Prefixes to scan (each becomes a target argument to nmap).",
    )
    target_ipaddresses = MultiObjectVar(
        model=IPAddress,
        required=False,
        description="Individual IPAddresses to scan in addition to / instead of Prefixes.",
    )
    allow_overlap = BooleanVar(
        default=False,
        description=(
            "Allow dispatching a second scan even if a pending/running scan on this agent "
            "already targets one of these prefixes or IPs. Default off — re-clicking Run "
            "won't accidentally fire duplicate scans."
        ),
    )

    class Meta:
        """Meta options for the Nautobot Job runner."""

        name = "Run Scan"
        description = (
            "Create a Scan record and dispatch it to the selected agent. "
            "Local agents run nmap synchronously in this worker; remote agents "
            "are flipped to 'pending' and pick the scan up via their poll loop."
        )
        has_sensitive_variables = False
        # Don't auto-commit if the run() raises — the ORM Scan record is
        # rolled back, no orphan state left behind.
        commit_default = True

    def run(self, agent, profile, target_prefixes=None, target_ipaddresses=None, allow_overlap=False):
        """Create the Scan, dispatch through the agent's backend, log a link."""
        target_prefixes = list(target_prefixes or [])
        target_ipaddresses = list(target_ipaddresses or [])

        if not target_prefixes and not target_ipaddresses:
            self.logger.error("Must specify at least one target prefix or IP address.")
            raise ValueError("No targets specified.")

        if not allow_overlap and _has_overlapping_scan(agent, target_prefixes, target_ipaddresses):
            self.logger.error(
                "Agent %s already has a pending/running scan covering one of these targets. "
                "Check the Scans list or re-run with allow_overlap=True.",
                agent.name,
            )
            raise ValueError("Overlapping scan in progress on this agent.")

        scan = Scan.objects.create(
            agent=agent,
            profile=profile,
            job_result=self.job_result,
        )
        scan.target_prefixes.set(target_prefixes)
        scan.target_ipaddresses.set(target_ipaddresses)

        self.logger.info(
            "Created scan %s on agent %s with profile %s (%d prefix targets, %d IP targets).",
            scan.pk,
            agent.name,
            profile.name,
            len(target_prefixes),
            len(target_ipaddresses),
        )

        backend = get_backend(agent)
        backend.dispatch(scan)

        # Re-read so we report the post-dispatch state (LocalBackend completes
        # synchronously; RemoteBackend leaves status=pending).
        scan.refresh_from_db()
        self.logger.info(
            "Scan %s finished dispatch — status=%s, summary=%s",
            scan.pk,
            scan.status,
            scan.summary,
        )
        return str(scan.pk)


# ----------------------------------------------------------------------------
# ScanPrefix — quick action on a single Prefix
# ----------------------------------------------------------------------------


class ScanPrefix(Job):
    """One-click discovery scan against a single Prefix using the default agent + profile."""

    prefix = ObjectVar(
        model=Prefix,
        description="The Prefix to scan.",
    )
    agent = ObjectVar(
        model=ScannerAgent,
        required=False,
        description="Optional override; defaults to the first agent (alphabetical).",
    )
    profile = ObjectVar(
        model=ScanProfile,
        required=False,
        description="Optional override; defaults to the first profile (alphabetical).",
    )

    class Meta:
        """Meta options."""

        name = "Scan Prefix"
        description = "Convenience wrapper around Run Scan for one-Prefix-at-a-time use."
        has_sensitive_variables = False
        commit_default = True

    def run(self, prefix, agent=None, profile=None):
        """Resolve defaults if not specified, then delegate to the RunScan logic."""
        if agent is None:
            agent = ScannerAgent.objects.order_by("name").first()
            if agent is None:
                self.logger.error("No ScannerAgent records exist — create one before scanning.")
                raise ValueError("No agent available.")
        if profile is None:
            profile = ScanProfile.objects.order_by("name").first()
            if profile is None:
                self.logger.error("No ScanProfile records exist — create one before scanning.")
                raise ValueError("No profile available.")

        scan = Scan.objects.create(agent=agent, profile=profile, job_result=self.job_result)
        scan.target_prefixes.add(prefix)
        self.logger.info("ScanPrefix dispatching %s on agent %s", prefix.prefix, agent.name)
        get_backend(agent).dispatch(scan)
        scan.refresh_from_db()
        self.logger.info("Done — status=%s, %s", scan.status, scan.summary)
        return str(scan.pk)


# ----------------------------------------------------------------------------
# MarkStaleAgents — periodic housekeeping
# ----------------------------------------------------------------------------


class MarkStaleAgents(Job):
    """Flip ScannerAgents to 'Offline' status when their last_seen is too old.

    Run this on a schedule (Nautobot's built-in scheduler — set a 5-minute
    interval in the Job's scheduled-run UI). Idempotent: agents already
    marked offline stay offline; agents that have checked in recently
    stay whatever status they were.
    """

    class Meta:
        """Meta options."""

        name = "Mark Stale Agents Offline"
        description = (
            "Set ScannerAgent.status='Offline' for remote agents whose last_seen is "
            "older than 3 × the configured checkin interval. Schedule via the job runner."
        )
        has_sensitive_variables = False
        commit_default = True

    def run(self):
        """Walk all remote agents and offline the ones that have aged past their own threshold."""
        cfg = settings.PLUGINS_CONFIG.get("nautobot_scanner", {})
        global_interval = cfg.get("agent_checkin_interval_seconds", 60)

        try:
            offline_status = Status.objects.get(name="Offline")
        except Status.DoesNotExist:
            self.logger.error(
                "Status 'Offline' not found. The post_migrate signal usually creates "
                "the association — re-run `nautobot-server migrate` to repair.",
            )
            raise

        now = timezone.now()
        # Candidates: remote agents that have ever checked in and aren't already offline.
        candidates = (
            ScannerAgent.objects.filter(agent_type="remote")
            .exclude(status=offline_status)
            .exclude(last_seen__isnull=True)
        )

        flipped: list[tuple[str, int]] = []  # (name, seconds_since_last_seen)
        for agent in candidates:
            interval = agent.expected_checkin_interval_seconds or global_interval
            age_seconds = (now - agent.last_seen).total_seconds()
            if age_seconds > 3 * interval:
                agent.status = offline_status
                agent.save(update_fields=["status"])
                flipped.append((agent.name, int(age_seconds)))

        if not flipped:
            self.logger.info("No stale agents (checked %d remote agent(s)).", candidates.count())
            return "0"

        for name_, age in flipped:
            self.logger.warning("Marked %s offline — %ds since last checkin.", name_, age)
        return str(len(flipped))


# ----------------------------------------------------------------------------
# Registration — picked up by Nautobot's job-discovery at startup
# ----------------------------------------------------------------------------

jobs = [RunScan, ScanPrefix, MarkStaleAgents]
register_jobs(*jobs)
