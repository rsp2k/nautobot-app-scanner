"""django-tables2 Table classes for nautobot_scanner list views.

Each PrimaryModel gets a Table with leading ToggleColumn (bulk select),
LinkColumn (navigation), and trailing ButtonsColumn (edit/delete actions).

BaseModel children (DiscoveredPort, VulnerabilityFinding, TraceRouteHop)
get tables too — but those render nested in the parent's detail page,
not as standalone list views.
"""

import django_tables2 as tables
from nautobot.apps.tables import BaseTable, ButtonsColumn, StatusTableMixin, ToggleColumn

from nautobot_scanner import models


class ScannerAgentTable(StatusTableMixin, BaseTable):
    """List-view table for ScannerAgent."""

    pk = ToggleColumn()
    name = tables.LinkColumn()
    agent_type = tables.Column(verbose_name="Type")
    location = tables.Column(linkify=True)
    last_seen = tables.DateTimeColumn(short=False, verbose_name="Last Seen")
    version = tables.Column()
    actions = ButtonsColumn(models.ScannerAgent)

    class Meta(BaseTable.Meta):
        model = models.ScannerAgent
        fields = ("pk", "name", "agent_type", "status", "location", "last_seen", "version", "actions")
        default_columns = ("pk", "name", "agent_type", "status", "location", "last_seen", "actions")


class ScanProfileTable(BaseTable):
    """List-view table for ScanProfile."""

    pk = ToggleColumn()
    name = tables.LinkColumn()
    scan_type = tables.Column(verbose_name="Type")
    timing_template = tables.Column(verbose_name="Timing")
    actions = ButtonsColumn(models.ScanProfile)

    class Meta(BaseTable.Meta):
        model = models.ScanProfile
        fields = ("pk", "name", "scan_type", "timing_template", "nmap_arguments", "description", "actions")
        default_columns = ("pk", "name", "scan_type", "timing_template", "description", "actions")


class ScanTable(BaseTable):
    """List-view table for Scan."""

    pk = ToggleColumn()
    agent = tables.Column(linkify=True)
    profile = tables.Column(linkify=True)
    status = tables.Column()
    started_at = tables.DateTimeColumn(short=False, verbose_name="Started")
    completed_at = tables.DateTimeColumn(short=False, verbose_name="Completed")
    summary = tables.Column(orderable=False, verbose_name="Summary")
    actions = ButtonsColumn(models.Scan)

    class Meta(BaseTable.Meta):
        model = models.Scan
        fields = ("pk", "agent", "profile", "status", "started_at", "completed_at", "summary", "actions")
        default_columns = ("pk", "agent", "profile", "status", "started_at", "completed_at", "actions")


class DiscoveredHostTable(BaseTable):
    """List-view table for DiscoveredHost.

    Renders standalone (full /scanner/discovered-hosts/ list) and nested in
    Scan detail pages (where ``scan`` and ``linked_*`` columns are hidden
    via exclude_columns in the panel declaration).
    """

    pk = ToggleColumn()
    ip_address = tables.LinkColumn()
    hostname = tables.Column()
    host_state = tables.Column(verbose_name="State")
    os_family = tables.Column(verbose_name="OS")
    mac_address = tables.Column(verbose_name="MAC")
    scan = tables.Column(linkify=True)
    linked_ipaddress = tables.Column(linkify=True, verbose_name="IPAM IP")
    linked_device = tables.Column(linkify=True, verbose_name="Device")
    actions = ButtonsColumn(models.DiscoveredHost)

    class Meta(BaseTable.Meta):
        model = models.DiscoveredHost
        fields = (
            "pk", "ip_address", "hostname", "host_state", "os_family", "os_type",
            "mac_address", "os_accuracy", "scan", "linked_ipaddress", "linked_device", "actions",
        )
        default_columns = (
            "pk", "ip_address", "hostname", "host_state", "os_family",
            "mac_address", "scan", "linked_ipaddress", "actions",
        )


class DiscoveredPortTable(BaseTable):
    """Nested-only table for DiscoveredPort, rendered in DiscoveredHost detail."""

    port = tables.Column()
    protocol = tables.Column()
    state = tables.Column()
    service_name = tables.Column(verbose_name="Service")
    product = tables.Column()
    version = tables.Column()
    extra_info = tables.Column(verbose_name="Extra")

    class Meta(BaseTable.Meta):
        model = models.DiscoveredPort
        fields = ("port", "protocol", "state", "service_name", "product", "version", "extra_info")
        default_columns = ("port", "protocol", "state", "service_name", "product", "version")


class VulnerabilityFindingTable(BaseTable):
    """Nested-only table for VulnerabilityFinding, rendered in DiscoveredHost detail."""

    discovered_port = tables.Column(verbose_name="Port")
    nse_script = tables.Column(verbose_name="Script")
    severity = tables.Column()
    output = tables.Column()

    class Meta(BaseTable.Meta):
        model = models.VulnerabilityFinding
        fields = ("discovered_port", "nse_script", "severity", "output")
        default_columns = ("discovered_port", "nse_script", "severity")


class TraceRouteHopTable(BaseTable):
    """Nested-only table for TraceRouteHop, rendered in DiscoveredHost detail."""

    hop_number = tables.Column(verbose_name="#")
    hop_ip = tables.Column(verbose_name="IP")
    hop_hostname = tables.Column(verbose_name="Hostname")
    rtt_ms = tables.Column(verbose_name="RTT (ms)")

    class Meta(BaseTable.Meta):
        model = models.TraceRouteHop
        fields = ("hop_number", "hop_ip", "hop_hostname", "rtt_ms")
        default_columns = ("hop_number", "hop_ip", "hop_hostname", "rtt_ms")
