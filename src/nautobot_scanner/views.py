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

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from nautobot.apps.ui import ObjectDetailContent, ObjectFieldsPanel, ObjectsTablePanel, Panel, SectionChoices
from nautobot.apps.views import NautobotUIViewSet
from nautobot.dcim.models import Device, Interface
from nautobot.ipam.models import IPAddress

from nautobot_scanner import filters, forms, models, tables
from nautobot_scanner.api import serializers


class DiscoveredHostPromoteView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """Promote a DiscoveredHost into a real ipam.IPAddress.

    Two permissions are required:
    - `nautobot_scanner.change_discoveredhost` — to update linked_ipaddress
    - `ipam.add_ipaddress` — because we're creating an IPAddress record

    The second one is the security-critical check the Plan agent flagged
    during design: a user with scanner permissions but no IPAM write
    access shouldn't be able to spawn IPAM records via this side door.
    """

    permission_required = ("nautobot_scanner.change_discoveredhost", "ipam.add_ipaddress")

    def get(self, request, pk):
        """Render the prefilled promotion form."""
        host = get_object_or_404(models.DiscoveredHost, pk=pk)
        initial = self._initial_for(host)
        form = forms.PromoteDiscoveredHostForm(initial=initial)
        return render(
            request,
            "nautobot_scanner/discoveredhost_promote.html",
            {"object": host, "form": form},
        )

    def post(self, request, pk):
        """Create the IPAddress, link it back, redirect."""
        host = get_object_or_404(models.DiscoveredHost, pk=pk)
        form = forms.PromoteDiscoveredHostForm(request.POST)

        if not form.is_valid():
            return render(
                request,
                "nautobot_scanner/discoveredhost_promote.html",
                {"object": host, "form": form},
            )

        cleaned = form.cleaned_data
        # Determine the address mask: discovered IPs are bare hosts so we
        # default to /32 (IPv4) or /128 (IPv6). User can edit on the IPAddress
        # detail page afterwards if a different mask is needed.
        ip_str = str(host.ip_address)
        mask = "/128" if ":" in ip_str else "/32"
        address = f"{ip_str}{mask}"

        new_ip = IPAddress.objects.create(
            address=address,
            namespace=cleaned["namespace"],
            status=cleaned["status"],
            dns_name=cleaned.get("dns_name") or host.hostname,
            tenant=cleaned.get("tenant"),
            description=cleaned.get("description")
            or f"Promoted from scanner DiscoveredHost {host.pk} (scan {host.scan.pk})",
        )
        host.linked_ipaddress = new_ip
        host.save(update_fields=["linked_ipaddress"])

        messages.success(
            request,
            f"Created IPAddress {new_ip.address} and linked DiscoveredHost {host.ip_address} to it.",
        )
        return redirect(new_ip.get_absolute_url())

    @staticmethod
    def _initial_for(host) -> dict:
        """Pre-fill values from the discovered host + first-Active defaults."""
        from nautobot.extras.models import Status as _Status
        from nautobot.ipam.models import Namespace as _Namespace

        # Default to "Global" namespace (Nautobot's stock default) and
        # "Active" status. Both are pre-baked into a vanilla install.
        try:
            namespace_initial = _Namespace.objects.get(name="Global").pk
        except _Namespace.DoesNotExist:
            namespace_initial = None
        try:
            status_initial = _Status.objects.get(name="Active").pk
        except _Status.DoesNotExist:
            status_initial = None

        return {
            "namespace": namespace_initial,
            "status": status_initial,
            "dns_name": host.hostname,
            "description": f"Promoted from scanner DiscoveredHost {host.pk} (scan {host.scan.pk})",
        }


class DiscoveredHostPromoteToDeviceView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """Promote a DiscoveredHost into a real dcim.Device + Interface + IPAddress.

    Heavier workflow than the IPAddress promotion — a Device requires
    Location + Role + DeviceType so the form takes more inputs. In one
    atomic transaction we:

    1. Create the Device (with the form's name/location/role/device_type/...)
    2. Create or reuse the IPAddress (reuses if linked_ipaddress already set)
    3. Create an Interface on the Device (with the discovered MAC if any)
    4. Assign the IPAddress to the Interface
    5. Set Device.primary_ip4 = the IPAddress
    6. Set DiscoveredHost.linked_device = the new Device

    Required permissions: nautobot_scanner.change_discoveredhost,
    dcim.add_device, dcim.add_interface, ipam.add_ipaddress.
    """

    permission_required = (
        "nautobot_scanner.change_discoveredhost",
        "dcim.add_device",
        "dcim.add_interface",
        "ipam.add_ipaddress",
    )

    def get(self, request, pk):
        """Render the prefilled form."""
        host = get_object_or_404(models.DiscoveredHost, pk=pk)
        initial = self._initial_for(host)
        form = forms.PromoteDiscoveredHostToDeviceForm(initial=initial)
        return render(
            request,
            "nautobot_scanner/discoveredhost_promote_to_device.html",
            {"object": host, "form": form},
        )

    def post(self, request, pk):
        """Create the Device + Interface + IPAddress in one transaction."""
        host = get_object_or_404(models.DiscoveredHost, pk=pk)
        form = forms.PromoteDiscoveredHostToDeviceForm(request.POST)

        if not form.is_valid():
            return render(
                request,
                "nautobot_scanner/discoveredhost_promote_to_device.html",
                {"object": host, "form": form},
            )

        cleaned = form.cleaned_data

        with transaction.atomic():
            device = Device.objects.create(
                name=cleaned["name"],
                location=cleaned["location"],
                role=cleaned["role"],
                device_type=cleaned["device_type"],
                status=cleaned["status"],
                platform=cleaned.get("platform"),
                tenant=cleaned.get("tenant"),
            )

            # IPAddress resolution — three cases, in priority order:
            #   1. linked_ipaddress already set (explicit promote-to-IP first)
            #   2. IP exists in the chosen namespace (someone else created it)
            #   3. Doesn't exist → create fresh
            # Case 2 matters because IPAddress has a unique constraint on
            # (parent_prefix, host), so naive create() raises IntegrityError
            # when the IP was added via a Scan target setup or manual entry.
            if host.linked_ipaddress:
                ip = host.linked_ipaddress
            else:
                ip_str = str(host.ip_address)
                mask = "/128" if ":" in ip_str else "/32"
                ip = IPAddress.objects.filter(
                    host=ip_str,
                    parent__namespace=cleaned["ipaddress_namespace"],
                ).first()
                if ip is None:
                    ip = IPAddress.objects.create(
                        address=f"{ip_str}{mask}",
                        namespace=cleaned["ipaddress_namespace"],
                        status=cleaned["ipaddress_status"],
                        dns_name=host.hostname or "",
                        description=f"Auto-created with Device {device.name} from scanner DiscoveredHost {host.pk}",
                    )
                host.linked_ipaddress = ip

            interface = Interface.objects.create(
                device=device,
                name=cleaned["interface_name"],
                type="virtual",
                mac_address=host.mac_address or None,
                status=cleaned["status"],
            )
            # Assign the IPAddress to the Interface.
            ip.assigned_object = interface
            ip.save()

            # Primary IP must be set *after* assignment.
            if ":" in str(host.ip_address):
                device.primary_ip6 = ip
            else:
                device.primary_ip4 = ip
            device.save()

            host.linked_device = device
            host.save(update_fields=["linked_ipaddress", "linked_device"])

        messages.success(
            request,
            f"Created Device '{device.name}' with interface '{interface.name}' and primary IP {ip.address}.",
        )
        return redirect(device.get_absolute_url())

    @staticmethod
    def _initial_for(host) -> dict:
        """Pre-fill values from the discovered host."""
        from nautobot.extras.models import Status as _Status
        from nautobot.ipam.models import Namespace as _Namespace

        # Strip the domain from the hostname for a cleaner Device name.
        # `sonos-542a1b19f8b0.example.com` → `sonos-542a1b19f8b0`.
        name = (host.hostname or str(host.ip_address)).split(".", 1)[0]

        try:
            ns = _Namespace.objects.get(name="Global").pk
        except _Namespace.DoesNotExist:
            ns = None
        try:
            active = _Status.objects.get(name="Active").pk
        except _Status.DoesNotExist:
            active = None

        return {
            "name": name,
            "status": active,
            "ipaddress_status": active,
            "ipaddress_namespace": ns,
            "interface_name": "mgmt0",
        }


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


class DiscoveredHostActionsPanel(Panel):
    """Action bar for DiscoveredHost detail pages.

    Shows the Promote button when linked_ipaddress is null, and shows
    the linked IPAddress info when it's set. Cheaper than a full
    ObjectFieldsPanel for this two-state display.
    """

    label = "Actions"
    body_content_template_path = "nautobot_scanner/inc/discoveredhost_actions.html"


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

    # Annotate counts in the queryset so the standalone list view doesn't N+1
    # on the Open Ports / Vulns columns. The DiscoveredHost model properties
    # read these annotations if present, falling back to per-row counts for
    # nested-panel contexts where the standalone queryset doesn't apply.
    from django.db.models import Count, Q

    queryset = models.DiscoveredHost.objects.annotate(
        _open_port_count=Count("ports", filter=Q(ports__state="open"), distinct=True),
        _vulnerability_count=Count("ports__vulnerabilities", distinct=True),
    )
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
            DiscoveredHostActionsPanel(
                section=SectionChoices.LEFT_HALF,
                weight=200,
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
