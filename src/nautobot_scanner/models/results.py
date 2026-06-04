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

from django.contrib.contenttypes.models import ContentType
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
    # ----- OS classification depth -----
    # `os_family` + `os_type` keep the top-line summary; these expose what
    # nmap's NmapOSClass actually carries. `os_cpe` is the bridge to CVE
    # databases; `os_device_type` powers the "show me all printers" filter.
    os_vendor = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        help_text="OS vendor from nmap's osclass (Microsoft, Apple, Linux, Cisco, ...).",
    )
    os_device_type = models.CharField(
        max_length=32,
        blank=True,
        db_index=True,
        help_text=(
            "Device class from nmap's osclass type attribute: "
            "'general purpose', 'router', 'printer', 'firewall', "
            "'switch', 'storage-misc', 'webcam', etc."
        ),
    )
    os_gen = models.CharField(
        max_length=32,
        blank=True,
        help_text="OS generation/version string from nmap's osclass osgen (e.g. '10', '7', '2.4.X').",
    )
    os_cpe = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "List of CPE strings nmap associates with the OS match "
            "(e.g. ['cpe:/o:microsoft:windows_10']). Bridges to CVE databases."
        ),
    )
    os_alternative_matches = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Alternative OS guesses beyond the top match, as "
            "[{'name': str, 'accuracy': int}, ...]. Tells operators "
            "whether the top guess was 95% top / 92% next (close call) "
            "vs 90% top / 50% next (clear)."
        ),
    )
    # ----- Phase F completeness sweep -----
    # Full PTR list (we keep ``hostname`` as the denormalized first-one for
    # table cells); ipsequence is the OS-fingerprinting companion to the
    # TCP sequence class we already capture; extraports is nmap's bulk
    # "997 ports filtered (no-response)" summary line.
    hostnames = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Full list of hostnames nmap reported (PTR + user-supplied). "
            "The denormalized first one stays in `hostname` for table display."
        ),
    )
    ip_sequence_class = models.CharField(
        max_length=64,
        blank=True,
        help_text=(
            "IP ID sequence class from nmap's IP sequence prediction "
            "(e.g. 'All zeros', 'Incremental', 'Randomized'). OS "
            "fingerprinting signal complementary to tcp_sequence_class."
        ),
    )
    extraports = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "nmap's 'extraports' summary line — when most scanned ports "
            "share a single state ('Not shown: 997 filtered tcp ports'), "
            "nmap collapses them. Shape: {state, count, reasons: [{reason, count}, ...]}."
        ),
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

    @property
    def port_findings(self):
        """All port-scope ``NseFinding`` rows attached to this host's ports.

        The two-hop reverse (NseFinding → DiscoveredPort → DiscoveredHost)
        as a single queryset so templates and viewsets can iterate or
        count without nested loops. Mirrors the ``host_findings`` reverse
        manager which goes through the direct FK; together they cover
        both NSE scopes per ADR-012 (see docs/dev/architecture.md).
        """
        from nautobot_scanner.models import NseFinding

        return NseFinding.objects.filter(discovered_port__discovered_host=self)

    @property
    def dns_records_pointing_here(self) -> dict:
        """A/AAAA records in nautobot-app-dns-models that resolve to this host.

        Returns ``{"a": [<ARecord>...], "aaaa": [<AAAARecord>...]}``.
        Empty lists when nothing resolves here (or when dns-models is
        not installed). Used by the DiscoveredHost detail panel to
        surface the killer cross-ref: "the DNS layer says these names
        point at the IP we're scanning."

        Lookup is by-IPAddress, not by-IP-string — dns-models stores
        the FK to ``ipam.IPAddress``, so a Cloudflare edge IP we've
        SEEN in DNS but never PROMOTED to IPAM won't show up here.
        That matches the v1 promotion policy (don't auto-pollute IPAM
        from DNS) — once the operator creates the IPAddress and
        re-runs the scan, this property starts returning the record.
        """
        try:
            from nautobot.ipam.models import IPAddress
            from nautobot_dns_models.models import AAAARecord, ARecord
        except ImportError:
            return {"a": [], "aaaa": []}
        ip_str = str(self.ip_address)
        ip_objs = IPAddress.objects.filter(host=ip_str)
        if not ip_objs.exists():
            return {"a": [], "aaaa": []}
        return {
            "a": list(ARecord.objects.filter(ip_address__in=ip_objs).select_related("zone")),
            "aaaa": list(AAAARecord.objects.filter(ip_address__in=ip_objs).select_related("zone")),
        }


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
    # Phase F: how nmap identified the service + with what confidence.
    # Distinguishes "looked up port number in nmap-services" (cheap, often
    # wrong) from "actually fingerprinted the service" (slow but reliable).
    service_method = models.CharField(
        max_length=16,
        blank=True,
        help_text=(
            "How nmap identified the service: 'table' (looked up port number "
            "in nmap-services — fast but often wrong for non-standard ports), "
            "'probed' (sent -sV probes and parsed responses — reliable)."
        ),
    )
    service_conf = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text=(
            "nmap's confidence in the service identification (1-10). "
            "Low values indicate the match was port-table-only or a "
            "weak fingerprint match."
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
    elements = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Structured key-value data emitted by the NSE script "
            "alongside the text output. ssl-cert populates "
            "cert.validity.notAfter; smb-os-discovery populates os.fqdn; "
            "http-headers populates each header as a key. Empty dict "
            "for scripts that emit text only."
        ),
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

    def get_absolute_url(self, api=False):
        """Detail-page URL — used by django-tables2 linkify and template `{{ obj.get_absolute_url }}`."""
        from django.urls import reverse
        return reverse("plugins:nautobot_scanner:nsefinding", kwargs={"pk": self.pk})


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


class DnsRecordProvenance(BaseModel):
    """Source-of-truth log for DNS records promoted from dig/drill findings.

    nautobot-app-dns-models (>= 2.1.2, bitemporal fork) stores the
    canonical "current state" of each DNS record plus a full belief
    history via the BitemporalMixin. This provenance log adds the
    *causal* axis the bitemporal store can't carry on its own:

    1. **Which finding caused this belief?** dns-models' bitemporal
       rotation captures *when* a belief changed (recorded_during /
       valid_during) but not *what* triggered it. Provenance closes
       the loop: every promotion writes one row joining the scan
       finding to the freshly-rotated belief.
    2. **What did the wire actually say?** Two upstream constraints
       still clip data on write (TTL ≥ 300s, TXTRecord.text ≤ 256).
       The raw wire values stay here so audit / diff still has the
       truth — even after the canonical record has been rounded to
       fit the model. These fields can be dropped once nautobot-dns-
       models 2.2.0 lifts the constraints (queued upstream).

    ### Why `record_entry_id`, not `record_id`

    The bitemporal mixin's sequenced-amend pattern rebinds ``pk`` on
    every belief change. Django's GenericForeignKey is hardcoded to
    use the target's pk, which means after an amend a GFK would
    silently follow the *successor* — losing the "this is the
    specific belief we saw at scan time" identity that's the whole
    point of provenance.

    The fork's ``entry_id`` is stable for one belief row's lifetime,
    so we store ``(record_type, record_entry_id)`` and resolve
    through the typed model's ``all_versions`` manager. See the
    ``record`` property below.

    Each re-scan creates a NEW provenance row even if the canonical
    record's belief window didn't rotate — that gives us the
    recurrence history independent of whether the underlying data
    actually changed.
    """

    record_type = models.ForeignKey(
        to=ContentType,
        on_delete=models.CASCADE,
        related_name="+",
        help_text="Content type of the canonical DNS record (ARecord, MXRecord, ...).",
    )
    record_entry_id = models.UUIDField(
        db_index=True,
        help_text=(
            "BitemporalMixin.entry_id of the specific belief row this "
            "promotion observed. Stable across amends (unlike pk, which "
            "rebinds on every sequenced-amend save)."
        ),
    )

    finding = models.ForeignKey(
        to="nautobot_scanner.NseFinding",
        on_delete=models.CASCADE,
        related_name="dns_promotions",
        help_text="The dig/drill NseFinding that produced this observation.",
    )
    observed_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text="When the parser dispatched this record into dns-models.",
    )
    record_type_label = models.CharField(
        max_length=16,
        help_text="DNS record type as seen on the wire (A, AAAA, CNAME, MX, NS, TXT, PTR, SRV).",
    )
    raw_value = models.CharField(
        max_length=512,
        help_text=(
            "Value field as the parser saw it on the wire — before any "
            "upstream truncation (TXTRecord.text caps at 256). Becomes "
            "redundant once dns-models 2.2.0 widens TXT to TextField."
        ),
    )
    raw_ttl = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=(
            "TTL as the parser saw it on the wire — before any clipping "
            "(dns-models enforces a 300s floor). null when the source "
            "tool did not emit a TTL. Becomes redundant once dns-models "
            "2.2.0 lifts the floor to 0."
        ),
    )

    class Meta:
        """Meta options."""

        ordering = ("-observed_at",)
        verbose_name = "DNS record provenance"
        verbose_name_plural = "DNS record provenances"
        indexes = [
            # Lookup pattern: "show me the history of this belief" —
            # filter by (record_type, record_entry_id), sort by observed_at desc.
            models.Index(
                fields=["record_type", "record_entry_id", "-observed_at"],
                name="dnsprov_record_recent_idx",
            ),
        ]

    def __str__(self) -> str:
        """Display string."""
        return f"{self.record_type_label} {self.raw_value} @ {self.observed_at:%Y-%m-%d %H:%M}"

    @property
    def record(self):
        """Resolve the canonical DNS record (including superseded beliefs).

        Goes through the typed model's ``all_versions`` manager so we can
        find rows whose ``recorded_during`` window has been closed — that's
        the whole point of using entry_id over pk. Returns None if the
        record's been hard-deleted.

        Cached per-instance so a template's repeated ``{{ p.record }}``
        accesses don't hit the DB more than once.
        """
        cached = self.__dict__.get("_resolved_record")
        if cached is not None:
            return cached
        model = self.record_type.model_class()
        # all_versions is added by BitemporalMixin (fork >=2.1.2); fall back
        # to objects on the upstream pre-bitemporal package so the property
        # still works during the install transition.
        manager = getattr(model, "all_versions", None) or model.objects
        resolved = manager.filter(entry_id=self.record_entry_id).first()
        # We deliberately allow None to be cached (record was deleted) —
        # template renders empty state, no need to re-query.
        self.__dict__["_resolved_record"] = resolved
        return resolved
