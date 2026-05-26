"""Scan result models — what nmap actually found.

`DiscoveredHost` is a PrimaryModel (gets its own page, can be promoted to an
IPAM IPAddress). `DiscoveredPort`, `NseFinding`, and
`TraceRouteHop` are BaseModel child records — they only exist in the context
of their parent and don't need standalone UI/API surfaces (they're rendered
nested in the host's detail page).

`DiscoveredHost` is **bitemporal** — every row carries two independent
time dimensions tracking when the fact was observed and when we believed
it to be true:

- ``valid_during``: wire-time. The window during which nmap was actually
  collecting data for this host (typically the parent scan's
  ``[started_at, completed_at]`` range).
- ``recorded_during``: belief-time. ``[ingest_time, ∞)`` while the row is
  the current belief; ``[ingest_time, supersede_time)`` once a re-parse
  has produced a fresher belief about the same ``(scan, ip)``.
- ``entry_id``: per-row UUID distinguishing successive beliefs.

This lets us re-parse old scans without losing prior beliefs (the diff
between "what scan #42 said in March" and "what it says now after we
fixed a parser bug" stays queryable), and lets the diff view answer
"as of belief-time T, what did we know" — not just "what do we know
now". Pattern matches l2trace.warehack.ing's tier-4 bitemporal model.
"""

import datetime
import uuid

from django.contrib.postgres.fields import DateTimeRangeField
from django.db import models
from django.utils import timezone
from nautobot.apps.constants import CHARFIELD_MAX_LENGTH
from nautobot.apps.models import BaseModel, PrimaryModel
from nautobot.extras.utils import extras_features
from nautobot.core.models.querysets import RestrictedQuerySet
from nautobot.ipam.fields import VarbinaryIPField
from psycopg2.extras import DateTimeTZRange

from nautobot_scanner.choices import HostStateChoices, PortStateChoices, ProtocolChoices, SeverityChoices


def _open_belief_window() -> DateTimeTZRange:
    """Default for ``DiscoveredHost.recorded_during`` — open-ended at now()."""
    return DateTimeTZRange(lower=timezone.now(), upper=None, bounds="[)")


class DiscoveredHostQuerySet(RestrictedQuerySet):
    """Bitemporal query helpers for DiscoveredHost.

    Inherits from Nautobot's RestrictedQuerySet (not plain models.QuerySet)
    so .restrict(user, "view") works — that's the method Nautobot's
    ObjectsTablePanel calls on every nested queryset to apply
    permission-based row filtering. Forgetting this inheritance breaks
    every panel that renders DiscoveredHost rows (Scan detail, Device
    detail, IPAddress detail) with a 500.

    ``objects`` (the default manager) still returns *all* rows including
    superseded beliefs — matches Django's "manager.all() returns all rows"
    expectation, important because Nautobot internals (admin, serializers,
    list viewsets) assume this contract.

    Callers that want "what do we currently believe?" use ``.current()``;
    callers asking "what did we believe at time T?" use ``.as_of(dt)``.
    The viewset queryset wires this in so the UI lists default to current
    beliefs by default — the all-beliefs view is opt-in via a filter param.
    """

    def current(self):
        """Only rows representing the currently-held belief.

        A row is "current" iff its ``recorded_during`` upper bound is NULL
        (open-ended). Pre-belief-supersede rows have a concrete upper bound
        and are excluded.
        """
        # Range fields support `__endswith=None` and `__contains=now` lookups.
        # `contains(now())` is semantically "is this belief still in force?" —
        # which is exactly the question and reads more naturally.
        return self.filter(recorded_during__contains=timezone.now())

    def as_of(self, dt: datetime.datetime):
        """Rows representing what we believed at the given recorded-time."""
        return self.filter(recorded_during__contains=dt)

    def for_wire_time(self, dt: datetime.datetime):
        """Rows whose wire-time observation window contains the given moment.

        Returns ALL beliefs (current AND historical) for any observation
        whose ``valid_during`` includes ``dt``. Chain with ``.current()`` or
        ``.as_of(T)`` to scope by recording-time.
        """
        return self.filter(valid_during__contains=dt)


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class DiscoveredHost(PrimaryModel):
    """One host nmap reported during a scan.

    Identity is `(scan, ip_address)` — the same IP discovered across multiple
    scans yields multiple rows so we have a history per scan. `linked_ipaddress`
    is set by the Promote-to-IPAddress workflow; `linked_device` is auto-resolved
    at ingest time by matching the IP against `Device.primary_ip4/6`.
    """

    scan = models.ForeignKey(
        to="nautobot_scanner.Scan",
        on_delete=models.CASCADE,
        related_name="hosts",
    )
    ip_address = VarbinaryIPField(
        db_index=True,
        help_text="IPv4 or IPv6 address as reported by nmap.",
    )
    mac_address = models.CharField(
        max_length=17,
        blank=True,
        help_text="Layer-2 MAC if nmap could resolve it (ARP for IPv4, NDP for IPv6).",
    )
    mac_vendor = models.CharField(
        max_length=128,
        blank=True,
        db_index=True,
        help_text=(
            "Manufacturer resolved from the MAC's OUI via the IEEE registry "
            "bundled with netaddr. Filled at ingest; empty when MAC is unknown "
            "or OUI isn't in the registry (rare — typically VM-generated MACs "
            "with locally-administered bit set)."
        ),
    )
    hostname = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)
    os_family = models.CharField(
        max_length=64,
        blank=True,
        help_text="High-level OS guess (Linux, Windows, BSD, etc.) from nmap -O.",
    )
    os_type = models.CharField(
        max_length=128,
        blank=True,
        help_text="Specific OS string (e.g. 'Linux 5.x', 'Windows Server 2019').",
    )
    os_accuracy = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="0-100 confidence in OS guess (nmap's accuracy attribute).",
    )
    host_state = models.CharField(
        max_length=16,
        choices=HostStateChoices,
        default=HostStateChoices.UNKNOWN,
        db_index=True,
    )
    linked_ipaddress = models.ForeignKey(
        to="ipam.IPAddress",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_index=True,
        related_name="discovered_hosts",
        help_text="Populated by the Promote-to-IPAddress action.",
    )
    linked_device = models.ForeignKey(
        to="dcim.Device",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_index=True,
        related_name="discovered_hosts",
        help_text="Auto-resolved at ingest by matching ip_address against Device.primary_ip4/6.",
    )

    # ------------------------------------------------------------------
    # Topology + uptime hints that nmap exposes alongside every host scan.
    # All nullable — populated only when the underlying probe gathered them
    # (distance from traceroute or even ping, uptime + tcp_sequence_class
    # from -O runs). Cheap data for the win.
    # ------------------------------------------------------------------
    distance_hops = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="Network hops to this host (matches len(traceroute_hops) when -O traceroute ran).",
    )
    uptime_seconds = models.PositiveBigIntegerField(
        null=True,
        blank=True,
        help_text="Seconds since last boot, derived from TCP timestamps during nmap -O.",
    )
    last_boot_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text=(
            "Absolute boot timestamp = (scan.completed_at - uptime_seconds). "
            "Stored so DB filters like 'booted in last hour' work without "
            "subtracting at query time."
        ),
    )
    tcp_sequence_class = models.CharField(
        max_length=64,
        blank=True,
        help_text=(
            "TCP ISN classification from nmap -O (e.g. 'random positive increments', "
            "'trivial time dependency'). OS-family signal independent of os_family."
        ),
    )

    # ------------------------------------------------------------------
    # Bitemporal axes (tier-4 pattern from l2trace.warehack.ing).
    # ------------------------------------------------------------------
    valid_during = DateTimeRangeField(
        null=True,
        blank=True,
        help_text=(
            "Wire-time range when the host was actually observed. Typically "
            "[scan.started_at, scan.completed_at]. NULL only for rows backfilled "
            "from scans without timestamps (legacy data, malformed XML)."
        ),
    )
    recorded_during = DateTimeRangeField(
        default=_open_belief_window,
        help_text=(
            "Belief-time range. [ingest_time, ∞) while this row is the current "
            "belief; the upper bound is closed when a re-parse of the same scan "
            "produces a fresher belief about the same (scan, ip_address)."
        ),
    )
    entry_id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        db_index=True,
        help_text=(
            "Unique per row — distinguishes successive beliefs about the same "
            "(scan, ip_address) observation. Stable across migrations."
        ),
    )

    objects = models.Manager.from_queryset(DiscoveredHostQuerySet)()

    class Meta:
        """Meta options.

        Note: the historical ``unique_together = (("scan", "ip_address"),)`` is
        replaced with a partial unique index in migration 0007 — uniqueness
        only applies to currently-believed rows (those whose ``recorded_during``
        upper bound is NULL). Multiple historical-belief rows for the same
        (scan, ip) are expected and supported.
        """

        ordering = ("ip_address",)
        verbose_name = "discovered host"
        verbose_name_plural = "discovered hosts"
        indexes = [
            models.Index(fields=["ip_address", "host_state"]),
        ]

    def __str__(self) -> str:
        """Display string."""
        return f"{self.ip_address} ({self.hostname or self.host_state})"

    @property
    def open_port_count(self) -> int:
        """Count of open ports on this host.

        Falls back to a per-row query when the queryset wasn't annotated;
        the standalone list view annotates with Count() to avoid N+1, so
        this only runs row-by-row for nested-panel contexts where a
        handful of hosts are shown.
        """
        # If the viewset annotated us with `_open_port_count`, use that;
        # otherwise issue the count query directly.
        cached = getattr(self, "_open_port_count", None)
        if cached is not None:
            return cached
        return self.ports.filter(state="open").count()

    @property
    def vulnerability_count(self) -> int:
        """Count of NSE findings (port-scope + host-scope) for this host.

        Counts both per-port findings (vulners, ssl-cert, http-title) AND
        host-scope findings (smb-os-discovery, snmp-info). The name stays
        ``vulnerability_count`` for column-label backward compatibility,
        but the count reflects every NSE finding regardless of severity.
        """
        cached = getattr(self, "_vulnerability_count", None)
        if cached is not None:
            return cached
        from nautobot_scanner.models import NseFinding

        port_scope = NseFinding.objects.filter(discovered_port__discovered_host=self).count()
        host_scope = NseFinding.objects.filter(discovered_host=self).count()
        return port_scope + host_scope


class DiscoveredPort(BaseModel):
    """One port nmap reported on a DiscoveredHost.

    Fingerprint fields (`product`, `version`, `extra_info`, `cpe`) live here
    rather than on a separate ServiceFingerprint model — nmap's `-sV` pass
    always produces them alongside `service_name`/`banner`, so splitting them
    would require an extra join on every render with zero benefit.
    """

    discovered_host = models.ForeignKey(
        to="nautobot_scanner.DiscoveredHost",
        on_delete=models.CASCADE,
        related_name="ports",
    )
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=8, choices=ProtocolChoices)
    state = models.CharField(max_length=16, choices=PortStateChoices)
    # Widened to CHARFIELD_MAX_LENGTH after a real-world scan hit the prior
    # 64-char ceiling on version strings — consumer routers and IoT devices
    # return banners with full module manifests and build metadata that
    # routinely exceed 64 chars (e.g. "Apache 2.4.41 ((Ubuntu) mod_jk/1.2.45
    # mod_perl/2.0.11 Perl/v5.30.0)"). service_name widened in sympathy.
    service_name = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)
    banner = models.TextField(blank=True)
    product = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)
    version = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)
    extra_info = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)
    cpe = models.JSONField(
        default=list,
        blank=True,
        help_text="List of CPE strings emitted by nmap -sV (e.g. ['cpe:/a:apache:httpd:2.4.41']).",
    )

    # ------------------------------------------------------------------
    # Richer state-reason data nmap exposes per port. These distinguish
    # "host is silent" from "firewall is blocking us" — invaluable when
    # debugging why a scan reports filtered/closed/no-response on a port
    # that the operator KNOWS is open inside the segment.
    # ------------------------------------------------------------------
    state_reason = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        help_text=(
            "Why nmap chose this state — 'syn-ack' (open), 'no-response' "
            "(filtered, no packet back), 'port-unreach' (closed via ICMP), "
            "'tcp-rst' (closed via RST), etc. Filterable to slice firewall vs "
            "true-closed populations."
        ),
    )
    state_reason_ttl = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="TTL of the responding packet. Mismatched TTLs hint at firewall interposition.",
    )
    state_reason_ip = VarbinaryIPField(
        null=True,
        blank=True,
        help_text=(
            "IP that actually sent the response — often differs from the target IP when "
            "an intermediate firewall is rewriting/responding on the host's behalf."
        ),
    )
    tunnel = models.CharField(
        max_length=16,
        blank=True,
        help_text=(
            "'ssl' for TLS-wrapped services (HTTPS on 443, SMTPS on 465, IMAPS on 993). "
            "Empty for plain services. Drives 'is this port speaking TLS?' filters "
            "without parsing the service_name string."
        ),
    )
    service_fp = models.TextField(
        blank=True,
        help_text=(
            "Raw nmap service fingerprint string. Useful when service_name is generic "
            "('unknown') and you want to submit the fingerprint to nmap upstream."
        ),
    )

    class Meta:
        """Meta options."""

        ordering = ("discovered_host", "protocol", "port")
        verbose_name = "discovered port"
        verbose_name_plural = "discovered ports"
        unique_together = (("discovered_host", "port", "protocol"),)

    def __str__(self) -> str:
        """Display string."""
        return f"{self.port}/{self.protocol} {self.state}"


class NseFinding(BaseModel):
    """One NSE-script finding (vulnerability OR informational).

    Renamed from ``VulnerabilityFinding`` in migration 0009 — the original
    name implied this was strictly vulnerability data, but nmap's NSE
    catalog produces a lot of informational output too (ssl-cert,
    http-title, smb-os-discovery) that doesn't have a CVE attached. The
    ``severity`` field (``info``/``low``/.../``critical``) is what
    actually distinguishes the two.

    Findings attach to **either** a ``DiscoveredPort`` (per-port scripts
    like ``vulners``, ``ssl-cert``, ``http-title``) **or** a
    ``DiscoveredHost`` (host-scope scripts like ``smb-os-discovery``,
    ``snmp-info``, ``ssh-hostkey``). A CheckConstraint enforces that
    exactly one of the two FKs is set per row.
    """

    discovered_port = models.ForeignKey(
        to="nautobot_scanner.DiscoveredPort",
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
        null=True,
        blank=True,
        help_text="Set when this finding came from a per-port NSE script. Mutually exclusive with discovered_host.",
    )
    discovered_host = models.ForeignKey(
        to="nautobot_scanner.DiscoveredHost",
        on_delete=models.CASCADE,
        related_name="host_findings",
        null=True,
        blank=True,
        help_text="Set when this finding came from a host-scope NSE script. Mutually exclusive with discovered_port.",
    )
    nse_script = models.CharField(
        max_length=128,
        help_text="Name of the NSE script that produced the finding (e.g. 'vulners', 'ssl-cert', 'smb-os-discovery').",
    )
    output = models.TextField(help_text="Raw script output — may contain CVE IDs, scores, exploit URLs, or just informational text.")
    severity = models.CharField(
        max_length=16,
        choices=SeverityChoices,
        default=SeverityChoices.UNKNOWN,
        db_index=True,
    )
    references = models.JSONField(
        default=list,
        blank=True,
        help_text="Parsed reference URLs (CVE links, exploit-db entries, vendor advisories).",
    )

    class Meta:
        """Meta options."""

        ordering = ("-severity", "nse_script")
        verbose_name = "NSE finding"
        verbose_name_plural = "NSE findings"
        constraints = [
            # Exactly-one-parent: exposes the design contract at the schema
            # level so future bugs that try to set both FKs (or neither) fail
            # at insert rather than producing orphan or duplicate-parent rows.
            models.CheckConstraint(
                check=(
                    models.Q(discovered_port__isnull=False, discovered_host__isnull=True)
                    | models.Q(discovered_port__isnull=True, discovered_host__isnull=False)
                ),
                name="nsefinding_exactly_one_parent",
            ),
        ]

    def __str__(self) -> str:
        """Display string."""
        return f"{self.nse_script} ({self.severity})"


class TraceRouteHop(BaseModel):
    """One hop in the path nmap traced to a DiscoveredHost.

    Anchored to the host (not the scan) because the host's FK transitively
    gives us the scan — dual FKs invite drift between the two.
    """

    discovered_host = models.ForeignKey(
        to="nautobot_scanner.DiscoveredHost",
        on_delete=models.CASCADE,
        related_name="traceroute_hops",
    )
    hop_number = models.PositiveSmallIntegerField()
    hop_ip = VarbinaryIPField(db_index=True)
    hop_hostname = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)
    rtt_ms = models.FloatField(
        null=True,
        blank=True,
        help_text="Round-trip time in milliseconds; null if hop did not respond.",
    )

    class Meta:
        """Meta options."""

        ordering = ("discovered_host", "hop_number")
        verbose_name = "traceroute hop"
        verbose_name_plural = "traceroute hops"
        unique_together = (("discovered_host", "hop_number"),)

    def __str__(self) -> str:
        """Display string."""
        return f"hop {self.hop_number}: {self.hop_ip}"
