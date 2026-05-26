"""UI viewsets for nautobot_scanner.

Each PrimaryModel gets a NautobotUIViewSet that bundles list, detail,
create, edit, delete, and bulk-action views together. Each viewset also
declares `object_detail_content` — the panel layout for the detail page.

BaseModel children (DiscoveredPort, NseFinding, TraceRouteHop)
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
from nautobot_scanner.diff import diff_scans, previous_scan_on_agent


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
        """Pre-fill values from the discovered host.

        ``manufacturer`` is auto-selected when the host's mac_vendor (resolved
        from the OUI at ingest) matches an existing dcim.Manufacturer. The
        lookup is tolerant: an OUI registration of "Hewlett Packard" matches
        a Nautobot Manufacturer named "HP" or "Hewlett-Packard" via the
        first significant word + icontains. Saves the operator from re-typing
        what we already know from the layer-2 evidence.
        """
        from nautobot.dcim.models import Manufacturer as _Manufacturer
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

        # OUI-derived manufacturer hint.
        manufacturer_pk = None
        if host.mac_vendor:
            # First-significant-word match is more forgiving than a full string
            # compare: IEEE registers "Hewlett Packard" but Nautobot installs
            # might have "HP", "HPE", "Hewlett-Packard", "Hewlett Packard
            # Enterprise" — all reasonable. We take the first match; if there
            # are multiple, operator can override in the dropdown.
            # Strip trailing punctuation so "Apple," matches "Apple", and
            # bare "Inc"/"Corp" suffixes get peeled off ("Cisco Systems, Inc"
            # → "Cisco" as the fallback term).
            first_word = host.mac_vendor.split()[0].rstrip(",.;:")
            match = (
                _Manufacturer.objects.filter(name__icontains=host.mac_vendor).first()
                or _Manufacturer.objects.filter(name__icontains=first_word).first()
            )
            if match:
                manufacturer_pk = match.pk

        return {
            "name": name,
            "status": active,
            "ipaddress_status": active,
            "ipaddress_namespace": ns,
            "interface_name": "mgmt0",
            "manufacturer": manufacturer_pk,
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
            # Per-port NSE findings for this scan: 3-hop filter
            # NseFinding → DiscoveredPort → DiscoveredHost → Scan.
            # Anyone reading a scan detail wants to see "what did the NSE
            # scripts find?" without drilling into each host individually.
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=200,
                table_class=tables.NseFindingTable,
                table_filter="discovered_port__discovered_host__scan",
                table_title="Port Findings",
            ),
            # Host-scope NSE findings (smb-os-discovery, snmp-info, etc.):
            # 2-hop filter NseFinding → DiscoveredHost → Scan. Separate
            # panel because the port column reads "—" here.
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=250,
                table_class=tables.NseFindingTable,
                table_filter="discovered_host__scan",
                table_title="Host Findings",
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
                    "scan", "ip_address", "hostname", "mac_address", "mac_vendor",
                    "host_state", "os_family", "os_type", "os_accuracy",
                    "tcp_sequence_class", "distance_hops",
                    "uptime_seconds", "last_boot_at",
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
            # Two-hop filter: NseFinding → DiscoveredPort → DiscoveredHost.
            # Per-port NSE findings (vulners, ssl-cert, http-title) live here.
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=150,
                table_class=tables.NseFindingTable,
                table_filter="discovered_port__discovered_host",
                table_title="Port Findings",
            ),
            # Direct filter: NseFinding → DiscoveredHost.
            # Host-scope NSE findings (smb-os-discovery, snmp-info, ssh-hostkey)
            # attach directly to the host with no port. Same NseFinding table
            # class — the underlying rows differ only in which FK is set.
            ObjectsTablePanel(
                section=SectionChoices.RIGHT_HALF,
                weight=175,
                table_class=tables.NseFindingTable,
                table_filter="discovered_host",
                table_title="Host Findings",
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


class ScanDiffView(LoginRequiredMixin, View):
    """Side-by-side diff of two scans on the same agent.

    The "other" scan is determined automatically from the URL — if no
    ``vs`` query param is provided we use ``previous_scan_on_agent`` to
    find the most recent prior completed scan on the same agent. This
    matches the most common operator question: "what changed since last
    time we scanned this network?"

    The diff is bitemporally-anchored at "now" (current beliefs). A
    future ``?as_of=<ISO datetime>`` param could surface the diff as it
    appeared at a prior point in recording-time — deferred for now since
    no UI affordance exists for picking that anchor.
    """

    def get(self, request, pk):
        """Render the diff against the previous (or explicit ``?vs=``) scan."""
        scan = get_object_or_404(models.Scan, pk=pk)

        # Allow ?vs=<scan_pk> to pin the comparison to a specific other scan.
        # Defaults to "previous completed scan on this agent" when absent.
        vs_pk = request.GET.get("vs")
        if vs_pk:
            other = get_object_or_404(models.Scan, pk=vs_pk)
        else:
            other = previous_scan_on_agent(scan)

        if other is None:
            messages.warning(
                request,
                f"No prior completed scan found on agent {scan.agent.name} — "
                f"nothing to diff against.",
            )
            return redirect(scan.get_absolute_url())

        # diff_scans treats (a, b) as (before, after) — order by completed_at.
        if other.completed_at and scan.completed_at and other.completed_at < scan.completed_at:
            before, after = other, scan
        else:
            before, after = scan, other

        diff = diff_scans(before, after)
        return render(
            request,
            "nautobot_scanner/scan_diff.html",
            {"object": scan, "before": before, "after": after, "diff": diff},
        )


class DiscoveredHostRescanView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """POST endpoint that re-dispatches a scan against THIS host's IP only.

    Bitemporal-safe: the new Scan creates fresh DiscoveredHost rows with
    their own ``recorded_during`` window. Prior beliefs stay queryable
    via ``.as_of(<prior_time>)`` and the scan diff view. Nothing gets
    overwritten — every rescan is purely additive to the timeline,
    making this a one-click "is anything different on this host right
    now?" check.

    Scope: the new scan targets EXACTLY one IP — the discovered host's
    ``ip_address`` — via the ``target_raw_ips`` field (added in
    migration 0011 specifically for this case). No IPAM commitment is
    created or required. The fact that linked_ipaddress may or may not
    be set is irrelevant; we always go through the raw-IP path so
    behavior is identical for promoted and unpromoted hosts.

    Agent + profile inherit from the host's parent scan, so the rescan
    exercises the same code path the original did. The diff view from
    the resulting scan back to its parent immediately surfaces what
    changed.
    """

    permission_required = ("nautobot_scanner.change_discoveredhost",)

    def post(self, request, pk):
        """Dispatch a fresh single-host scan; redirect to its detail page."""
        host = get_object_or_404(models.DiscoveredHost, pk=pk)
        parent = host.scan

        new_scan = models.Scan.objects.create(
            agent=parent.agent,
            profile=parent.profile,
            target_raw_ips=[str(host.ip_address)],
        )

        from nautobot_scanner.backends import get_backend

        get_backend(parent.agent).dispatch(new_scan)
        new_scan.refresh_from_db()

        messages.success(
            request,
            f"Dispatched rescan of {host.ip_address} via {parent.agent.name} "
            f"using profile '{parent.profile.name}'. Status: {new_scan.status}.",
        )
        return redirect(new_scan.get_absolute_url())


class NseFindingDetailView(LoginRequiredMixin, View):
    """Per-finding detail page — full output + references + parent context.

    NseFinding is a BaseModel child (not PrimaryModel) so it doesn't get
    a NautobotUIViewSet. The table view only ever shows a 150-char preview
    of `output`; this page renders the full multi-line script output in a
    `<pre>` block. Script dumps like `ssl-cert` and `smb-os-discovery`
    routinely run hundreds of lines and need their own real estate.

    No edit/create — findings are agent-ingested and immutable from the
    operator's point of view. A future delete action could go here once
    we decide whether deleting findings should also vacate the underlying
    bitemporal belief rows.
    """

    def get(self, request, pk):
        """Render the finding's full output with parent breadcrumb."""
        finding = get_object_or_404(models.NseFinding, pk=pk)
        # Parent is "exactly one of port-or-host" by CheckConstraint, so
        # the template can `{% if finding.discovered_port %}` to branch.
        host = finding.discovered_host or (
            finding.discovered_port.discovered_host if finding.discovered_port else None
        )
        return render(
            request,
            "nautobot_scanner/nsefinding.html",
            {"object": finding, "host": host},
        )
