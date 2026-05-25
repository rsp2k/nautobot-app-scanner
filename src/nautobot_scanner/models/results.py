"""Scan result models — what nmap actually found.

`DiscoveredHost` is a PrimaryModel (gets its own page, can be promoted to an
IPAM IPAddress). `DiscoveredPort`, `VulnerabilityFinding`, and
`TraceRouteHop` are BaseModel child records — they only exist in the context
of their parent and don't need standalone UI/API surfaces (they're rendered
nested in the host's detail page).
"""

from django.db import models
from nautobot.apps.constants import CHARFIELD_MAX_LENGTH
from nautobot.apps.models import BaseModel, PrimaryModel
from nautobot.extras.utils import extras_features
from nautobot.ipam.fields import VarbinaryIPField

from nautobot_scanner.choices import HostStateChoices, PortStateChoices, ProtocolChoices, SeverityChoices


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

    class Meta:
        """Meta options."""

        ordering = ("ip_address",)
        verbose_name = "discovered host"
        verbose_name_plural = "discovered hosts"
        unique_together = (("scan", "ip_address"),)
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
        """Count of vulnerability findings across all ports on this host."""
        cached = getattr(self, "_vulnerability_count", None)
        if cached is not None:
            return cached
        # Count VulnerabilityFinding records by walking through ports.
        from nautobot_scanner.models import VulnerabilityFinding

        return VulnerabilityFinding.objects.filter(discovered_port__discovered_host=self).count()


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
    service_name = models.CharField(max_length=64, blank=True)
    banner = models.TextField(blank=True)
    product = models.CharField(max_length=128, blank=True)
    version = models.CharField(max_length=64, blank=True)
    extra_info = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)
    cpe = models.JSONField(
        default=list,
        blank=True,
        help_text="List of CPE strings emitted by nmap -sV (e.g. ['cpe:/a:apache:httpd:2.4.41']).",
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


class VulnerabilityFinding(BaseModel):
    """One vulnerability or interesting NSE-script output for a port.

    Severity is required and defaults to `unknown` (never null) so filter and
    table code never has to branch on missing values. Producer (typically an
    NSE script like `vulners` or `http-headers`) is recorded in `nse_script`.
    """

    discovered_port = models.ForeignKey(
        to="nautobot_scanner.DiscoveredPort",
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    nse_script = models.CharField(
        max_length=128,
        help_text="Name of the NSE script that produced the finding (e.g. 'vulners', 'ssl-cert').",
    )
    output = models.TextField(help_text="Raw script output — may contain CVE IDs, scores, exploit URLs.")
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
        verbose_name = "vulnerability finding"
        verbose_name_plural = "vulnerability findings"

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
