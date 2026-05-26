"""django-tables2 Table classes for nautobot_scanner list views.

Each PrimaryModel gets a Table with leading ToggleColumn (bulk select),
LinkColumn (navigation), and trailing ButtonsColumn (edit/delete actions).

BaseModel children (DiscoveredPort, NseFinding, TraceRouteHop)
get tables too — but those render nested in the parent's detail page,
not as standalone list views.
"""

import django_tables2 as tables
from django.utils.html import format_html
from nautobot.apps.tables import BaseTable, ButtonsColumn, StatusTableMixin, ToggleColumn

from nautobot_scanner import models


class ScannerAgentTable(StatusTableMixin, BaseTable):
    """List-view table for ScannerAgent."""

    pk = ToggleColumn()
    name = tables.LinkColumn()
    agent_type = tables.Column(verbose_name="Type")
    location = tables.Column(linkify=True)
    last_seen = tables.DateTimeColumn(short=False, verbose_name="Last Seen")
    expected_checkin_interval_seconds = tables.Column(verbose_name="Checkin (s)")
    version = tables.Column()
    actions = ButtonsColumn(models.ScannerAgent)

    class Meta(BaseTable.Meta):
        model = models.ScannerAgent
        fields = (
            "pk", "name", "agent_type", "status", "location",
            "last_seen", "expected_checkin_interval_seconds", "version", "actions",
        )
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
    # Both counts come from the model properties — they read the annotated
    # value when the viewset's queryset annotated it (fast path, no N+1),
    # and fall back to a per-row count query for nested-panel contexts.
    open_port_count = tables.Column(verbose_name="Open Ports", orderable=False)
    vulnerability_count = tables.Column(verbose_name="Vulns", orderable=False)
    os_family = tables.Column(verbose_name="OS")
    mac_address = tables.Column(verbose_name="MAC")
    mac_vendor = tables.Column(verbose_name="Vendor")
    scan = tables.Column(linkify=True)
    linked_ipaddress = tables.Column(linkify=True, verbose_name="IPAM IP")
    linked_device = tables.Column(linkify=True, verbose_name="Device")
    actions = ButtonsColumn(models.DiscoveredHost)

    class Meta(BaseTable.Meta):
        model = models.DiscoveredHost
        fields = (
            "pk", "ip_address", "hostname", "host_state",
            "open_port_count", "vulnerability_count",
            "os_family", "os_type", "mac_address", "mac_vendor", "os_accuracy",
            "scan", "linked_ipaddress", "linked_device", "actions",
        )
        default_columns = (
            "pk", "ip_address", "hostname", "host_state",
            "open_port_count", "vulnerability_count",
            "mac_address", "mac_vendor", "scan", "linked_ipaddress", "actions",
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
    state_reason = tables.Column(verbose_name="Reason")
    tunnel = tables.Column(verbose_name="TLS")

    class Meta(BaseTable.Meta):
        model = models.DiscoveredPort
        fields = (
            "port", "protocol", "state", "service_name",
            "product", "version", "extra_info", "state_reason", "tunnel",
            # Phase F: available-but-not-default columns. Operators that
            # care about whether a service was guessed vs. probed (and how
            # confidently) opt in via the table Configure menu.
            "service_method", "service_conf",
        )
        default_columns = ("port", "protocol", "state", "service_name", "product", "version")


class NseFindingTable(BaseTable):
    """Nested-only table for NseFinding, rendered in DiscoveredHost detail."""

    # linkify on nse_script wires to NseFinding.get_absolute_url() — clicking
    # the script name opens the full-output detail page. The port column has
    # linkify=False explicitly because Nautobot's BaseTable auto-linkifies FK
    # columns and DiscoveredPort has no detail page — without the explicit
    # opt-out the table 500s with "Cannot find a URL for 22/tcp open".
    discovered_port = tables.Column(verbose_name="Port", linkify=False)
    nse_script = tables.Column(verbose_name="Script", linkify=True)
    severity = tables.Column()
    output = tables.Column(verbose_name="Output preview")
    references = tables.Column(verbose_name="Refs", orderable=False)

    def render_output(self, value):
        """Truncated single-line preview with full content in `title=` for hover.

        Raw script output is typically multi-line indented blocks — collapsing
        whitespace into one line gives a useful at-a-glance preview without
        breaking the table layout. The full text is one click (Script column)
        away and one hover (title attribute) for quick peek.
        """
        if not value:
            return "—"
        collapsed = " ".join(value.split())
        preview = collapsed[:140]
        suffix = "…" if len(collapsed) > 140 else ""
        return format_html(
            '<code style="font-size:.85em" title="{}">{}{}</code>',
            value, preview, suffix,
        )

    def render_references(self, value):
        """Show count + first URL as a quick-link; full list lives on detail page."""
        if not value:
            return "—"
        first = value[0]
        more = len(value) - 1
        suffix = format_html(' <span style="opacity:.6">+{}</span>', more) if more else ""
        return format_html(
            '<a href="{}" target="_blank" rel="noopener noreferrer" title="{}">{}{}</a>{}',
            first, first, str(first)[:30], "…" if len(str(first)) > 30 else "", suffix,
        )

    class Meta(BaseTable.Meta):
        model = models.NseFinding
        fields = ("discovered_port", "nse_script", "severity", "output", "references")
        default_columns = ("discovered_port", "nse_script", "severity", "output", "references")


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
