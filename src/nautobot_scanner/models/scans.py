"""Scan execution model.

A `Scan` represents one execution: an agent + profile + a set of IPAM targets
(prefixes and/or specific IPAddresses). It holds the lifecycle state, the
optional gzipped raw nmap XML, and a one-shot ingestion_token used by remote
agents to POST their results back without replay vulnerability.

Named `Scan` rather than `ScanJob` to avoid colliding with Nautobot's
`extras.jobs.Job` namespace.
"""

import uuid

from django.db import models
from nautobot.apps.models import PrimaryModel
from nautobot.extras.utils import extras_features

from nautobot_scanner.choices import ScanStateChoices


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class Scan(PrimaryModel):
    """One nmap scan execution against a set of IPAM targets."""

    agent = models.ForeignKey(
        to="nautobot_scanner.ScannerAgent",
        on_delete=models.PROTECT,
        related_name="scans",
    )
    profile = models.ForeignKey(
        to="nautobot_scanner.ScanProfile",
        on_delete=models.PROTECT,
        related_name="scans",
    )
    target_prefixes = models.ManyToManyField(
        to="ipam.Prefix",
        related_name="scans",
        blank=True,
    )
    target_ipaddresses = models.ManyToManyField(
        to="ipam.IPAddress",
        related_name="scans",
        blank=True,
    )
    target_raw_ips = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Raw IP/CIDR strings to scan that aren't IPAM-committed (e.g. "
            "ad-hoc rescans triggered from a DiscoveredHost detail page). "
            "Appended to the nmap target list alongside target_prefixes + "
            "target_ipaddresses. Avoids polluting IPAM with throw-away entries."
        ),
    )
    status = models.CharField(
        max_length=16,
        choices=ScanStateChoices,
        default=ScanStateChoices.PENDING,
        db_index=True,
    )
    cancel_requested = models.BooleanField(
        default=False,
        help_text="Remote agents poll this between hosts; set true to halt cleanly.",
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(
        default=dict,
        blank=True,
        help_text="Counts of discovered hosts/ports/findings, populated at ingest.",
    )
    # Unique=True with null=True is fine in Postgres (NULL ≠ NULL for uniqueness).
    # Cleared after successful ingest so the token can never be replayed.
    ingestion_token = models.UUIDField(
        null=True,
        blank=True,
        unique=True,
        default=uuid.uuid4,
        help_text="One-shot token required on POST /ingest/. Cleared after ingest.",
    )
    raw_xml = models.FileField(
        upload_to="scanner/xml/%Y/%m/",
        null=True,
        blank=True,
        help_text="Gzipped nmap XML for forensics and parser-bug recovery.",
    )
    raw_xml_size = models.PositiveIntegerField(default=0, help_text="Uncompressed XML size in bytes.")
    job_result = models.ForeignKey(
        to="extras.JobResult",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text="Links back to the Nautobot Job run that dispatched this scan.",
    )
    error_message = models.TextField(
        blank=True,
        help_text="Populated when status=failed; ingest/dispatch error details.",
    )
    # ----- Scan provenance, captured from the nmap XML at ingest time -----
    # Why: scans are bitemporal and long-lived. Operators do go back to old
    # scans to ask "what did nmap actually run?" — without these fields the
    # answer requires unpacking the gzipped XML by hand. Storing them on the
    # row makes the audit trail one query away instead of one shell pivot.
    nmap_command = models.TextField(
        blank=True,
        help_text="Full nmap command-line as reported by the XML (provenance + reproduction).",
    )
    nmap_version = models.CharField(
        max_length=32,
        blank=True,
        help_text="nmap binary version that produced this scan (e.g. '7.94').",
    )
    xml_version = models.CharField(
        max_length=16,
        blank=True,
        help_text="nmap XML schema version (forensic value when parsers drift between nmap releases).",
    )
    ports_scanned = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=(
            "Number of ports scanned per host as reported by nmap (the "
            "denominator for ports_open). Distinguishes 'scanned 1000 found "
            "10 open' from 'scanned 100 found 10 open'."
        ),
    )

    class Meta:
        """Meta options."""

        ordering = ("-started_at", "-created")
        verbose_name = "scan"
        verbose_name_plural = "scans"
        indexes = [
            models.Index(fields=["agent", "status"]),
            models.Index(fields=["status", "started_at"]),
        ]

    def __str__(self) -> str:
        """Short, scannable label — agent + profile + relative time."""
        short = str(self.pk)[:8]
        when = self.started_at.strftime("%b %-d %H:%M") if self.started_at else "queued"
        return f"{self.agent.name} · {self.profile.name} · {when} ({short})"

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock scan duration, or None if not finished."""
        if not self.started_at or not self.completed_at:
            return None
        return (self.completed_at - self.started_at).total_seconds()
