"""UI viewsets for nautobot_scanner.

Each PrimaryModel gets a NautobotUIViewSet that bundles list, detail,
create, edit, delete, and bulk-action views together. Each viewset also
declares `object_detail_content` — the panel layout for the detail page.

BaseModel children (DiscoveredPort, VulnerabilityFinding, TraceRouteHop)
don't get standalone viewsets; they render nested in DiscoveredHost detail
via ObjectsTablePanel.

`serializer_class = None` is a Phase 3 placeholder — Phase 7 will wire up
the API serializers and viewsets in `api/`. Until then list/detail UI
works without REST access.
"""

from nautobot.apps.ui import ObjectDetailContent, ObjectFieldsPanel, ObjectsTablePanel, Panel, SectionChoices
from nautobot.apps.views import NautobotUIViewSet

from nautobot_scanner import filters, forms, models, tables
from nautobot_scanner.api import serializers


class ScanOverviewPanel(Panel):
    """Custom hero panel for Scan detail pages.

    Renders the status pill, big-stat tiles (hosts up/down, ports open,
    vulns, hops), agent/profile/timing metadata, and target chips. Replaces
    the generic ObjectFieldsPanel which can't render M2M relationships
    (the manager's repr leaks through as `ipam.Prefix.None`) and can't
    style the status enum as a colored badge.

    Template: templates/nautobot_scanner/inc/scan_overview.html
    """

    label = "Scan Overview"
    body_content_template_path = "nautobot_scanner/inc/scan_overview.html"


class ScannerAgentUIViewSet(NautobotUIViewSet):
    """CRUD viewset for ScannerAgent."""

    queryset = models.ScannerAgent.objects.all()
    table_class = tables.ScannerAgentTable
    filterset_class = filters.ScannerAgentFilterSet
    filterset_form_class = forms.ScannerAgentFilterForm
    form_class = forms.ScannerAgentForm
    serializer_class = serializers.ScannerAgentSerializer
    lookup_field = "pk"

    object_detail_content = ObjectDetailContent(
        panels=(
            ObjectFieldsPanel(
                section=SectionChoices.LEFT_HALF,
                weight=100,
                fields=[
                    "name", "agent_type", "status", "location", "user",
                    "version", "last_seen", "capabilities", "description",
                ],
            ),
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=100,
                table_class=tables.ScanTable,
                table_filter="agent",
                table_title="Recent Scans",
                exclude_columns=["agent"],
            ),
        ),
    )


class ScanProfileUIViewSet(NautobotUIViewSet):
    """CRUD viewset for ScanProfile."""

    queryset = models.ScanProfile.objects.all()
    table_class = tables.ScanProfileTable
    filterset_class = filters.ScanProfileFilterSet
    filterset_form_class = forms.ScanProfileFilterForm
    form_class = forms.ScanProfileForm
    serializer_class = serializers.ScanProfileSerializer
    lookup_field = "pk"

    object_detail_content = ObjectDetailContent(
        panels=(
            ObjectFieldsPanel(
                section=SectionChoices.LEFT_HALF,
                weight=100,
                fields=[
                    "name", "scan_type", "timing_template",
                    "nmap_arguments", "enabled_scripts", "description",
                ],
            ),
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=100,
                table_class=tables.ScanTable,
                table_filter="profile",
                table_title="Scans using this profile",
                exclude_columns=["profile"],
            ),
        ),
    )


class ScanUIViewSet(NautobotUIViewSet):
    """CRUD viewset for Scan.

    Detail page shows the scan parameters on the left and the discovered
    hosts on the right. Raw XML is exposed as a downloadable artifact (the
    FileField renders as a link in ObjectFieldsPanel) for forensic
    inspection and parser-bug recovery.
    """

    queryset = models.Scan.objects.all()
    table_class = tables.ScanTable
    filterset_class = filters.ScanFilterSet
    filterset_form_class = forms.ScanFilterForm
    form_class = forms.ScanForm
    serializer_class = serializers.ScanSerializer
    lookup_field = "pk"

    object_detail_content = ObjectDetailContent(
        panels=(
            # Hero overview — replaces ObjectFieldsPanel since M2M fields and
            # the status-enum badge both need custom rendering.
            ScanOverviewPanel(
                section=SectionChoices.LEFT_HALF,
                weight=100,
            ),
            # Discovered hosts is the most-interacted-with table, so it gets
            # the full right column.
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=100,
                table_class=tables.DiscoveredHostTable,
                table_filter="scan",
                table_title="Discovered Hosts",
                exclude_columns=["scan"],
            ),
        ),
    )


class DiscoveredHostUIViewSet(NautobotUIViewSet):
    """CRUD viewset for DiscoveredHost.

    Detail page shows host metadata on the left, then the host's open
    ports, vulnerabilities, and traceroute hops on the right. The
    Promote-to-IPAddress action (Phase 9) hangs off this view.
    """

    queryset = models.DiscoveredHost.objects.all()
    table_class = tables.DiscoveredHostTable
    filterset_class = filters.DiscoveredHostFilterSet
    filterset_form_class = forms.DiscoveredHostFilterForm
    form_class = forms.DiscoveredHostForm
    serializer_class = serializers.DiscoveredHostSerializer
    lookup_field = "pk"

    object_detail_content = ObjectDetailContent(
        panels=(
            ObjectFieldsPanel(
                section=SectionChoices.LEFT_HALF,
                weight=100,
                fields=[
                    "scan", "ip_address", "hostname", "mac_address",
                    "host_state", "os_family", "os_type", "os_accuracy",
                    "linked_ipaddress", "linked_device",
                ],
            ),
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=100,
                table_class=tables.DiscoveredPortTable,
                table_filter="discovered_host",
                table_title="Open Ports",
            ),
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=200,
                table_class=tables.TraceRouteHopTable,
                table_filter="discovered_host",
                table_title="Traceroute Hops",
            ),
        ),
    )
