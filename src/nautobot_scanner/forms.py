"""Django forms for nautobot_scanner create/edit views and filter UIs.

Each PrimaryModel gets two forms: a `XForm` (NautobotModelForm) for
create/edit and a `XFilterForm` (NautobotFilterForm) for the list-view
filter sidebar. ChoiceSet-backed fields explicitly declare MultipleChoiceField
in the filter form so users can multi-select states like host_state=up,down.

Also defines `PromoteDiscoveredHostForm` — Phase 9's promote-to-IPAddress
workflow form. Not a ModelForm because the source model (DiscoveredHost)
isn't the target model (IPAddress); we collect just the fields IPAM needs
to materialize a new IPAddress and the view does the cross-model write.
"""

from django import forms
from nautobot.apps.forms import DynamicModelChoiceField, NautobotFilterForm, NautobotModelForm
from nautobot.dcim.models import DeviceType, Location, Manufacturer, Platform
from nautobot.extras.models import Role, Status
from nautobot.ipam.models import Namespace, Prefix
from nautobot.tenancy.models import Tenant

from nautobot_scanner import models
from nautobot_scanner.choices import (
    AgentTypeChoices,
    HostStateChoices,
    PortStateChoices,
    ProtocolChoices,
    ScanStateChoices,
    ScanTypeChoices,
    SeverityChoices,
    TimingTemplateChoices,
)


# -----------------------------------------------------------------------------
# ScannerAgent
# -----------------------------------------------------------------------------
class ScannerAgentForm(NautobotModelForm):
    """Create/edit form for ScannerAgent."""

    class Meta:
        model = models.ScannerAgent
        fields = (
            "name", "agent_type", "status", "location",
            "user", "expected_checkin_interval_seconds",
            "version", "capabilities", "description", "tags",
        )


class ScannerAgentFilterForm(NautobotFilterForm):
    """Filter sidebar form for ScannerAgent list view."""

    model = models.ScannerAgent
    field_order = ("q", "name", "agent_type", "status", "location")

    q = forms.CharField(required=False, label="Search")
    agent_type = forms.MultipleChoiceField(choices=AgentTypeChoices, required=False)


# -----------------------------------------------------------------------------
# ScanProfile
# -----------------------------------------------------------------------------
class ScanProfileForm(NautobotModelForm):
    """Create/edit form for ScanProfile."""

    class Meta:
        model = models.ScanProfile
        fields = (
            "name", "scan_type", "nmap_arguments", "timing_template",
            "enabled_scripts", "description", "tags",
        )


class ScanProfileFilterForm(NautobotFilterForm):
    """Filter sidebar form for ScanProfile list view."""

    model = models.ScanProfile
    field_order = ("q", "name", "scan_type", "timing_template")

    q = forms.CharField(required=False, label="Search")
    scan_type = forms.MultipleChoiceField(choices=ScanTypeChoices, required=False)
    timing_template = forms.MultipleChoiceField(choices=TimingTemplateChoices, required=False)


# -----------------------------------------------------------------------------
# Scan
# -----------------------------------------------------------------------------
class ScanForm(NautobotModelForm):
    """Create/edit form for Scan.

    Scans are typically created by the RunScan Job (Phase 6), but the manual
    create form is useful for admin imports and debugging — operators can
    pre-create a pending Scan row and dispatch it manually.
    """

    agent = DynamicModelChoiceField(queryset=models.ScannerAgent.objects.all())
    profile = DynamicModelChoiceField(queryset=models.ScanProfile.objects.all())

    class Meta:
        model = models.Scan
        fields = (
            "agent", "profile", "target_prefixes", "target_ipaddresses",
            "status", "error_message", "tags",
        )


class ScanFilterForm(NautobotFilterForm):
    """Filter sidebar form for Scan list view."""

    model = models.Scan
    field_order = ("q", "agent", "profile", "status")

    q = forms.CharField(required=False, label="Search")
    agent = DynamicModelChoiceField(queryset=models.ScannerAgent.objects.all(), required=False)
    profile = DynamicModelChoiceField(queryset=models.ScanProfile.objects.all(), required=False)
    status = forms.MultipleChoiceField(choices=ScanStateChoices, required=False)


# -----------------------------------------------------------------------------
# DiscoveredHost
# -----------------------------------------------------------------------------
class DiscoveredHostForm(NautobotModelForm):
    """Edit-only form for DiscoveredHost.

    Hosts are created by parser.persist() during scan ingest, so the form
    is restricted to admin-correctable fields: host_state overrides and
    manual link assignments to existing IPAM / DCIM records. Identity
    fields (scan, ip_address) and nmap-derived metadata (hostname, os_*,
    mac) are intentionally omitted — overwriting them would diverge from
    the underlying scan and create audit ambiguity.
    """

    class Meta:
        model = models.DiscoveredHost
        # ip_address is a VarbinaryIPField (non-editable, stored as bytes) so
        # it cannot appear in a ModelForm directly. scan is identity-locked
        # at ingest time. Both are intentionally excluded.
        fields = (
            "host_state",
            "linked_ipaddress", "linked_device",
            "tags",
        )


class DiscoveredHostFilterForm(NautobotFilterForm):
    """Filter sidebar form for DiscoveredHost list view."""

    model = models.DiscoveredHost
    field_order = ("q", "host_state", "scan", "linked_device", "linked_ipaddress")

    q = forms.CharField(required=False, label="Search")
    host_state = forms.MultipleChoiceField(choices=HostStateChoices, required=False)
    # Re-declare ChoiceSet filters so DiscoveredPort/NseFinding/etc.
    # multi-select work on the standalone host list filter sidebar.
    port_state = forms.MultipleChoiceField(choices=PortStateChoices, required=False)
    protocol = forms.MultipleChoiceField(choices=ProtocolChoices, required=False)
    severity = forms.MultipleChoiceField(choices=SeverityChoices, required=False)


# -----------------------------------------------------------------------------
# DiscoveredHost → IPAddress promotion
# -----------------------------------------------------------------------------
class PromoteDiscoveredHostForm(forms.Form):
    """Form for promoting a DiscoveredHost into a real ipam.IPAddress.

    Pre-populated from the discovered host (IP, hostname → dns_name). The
    view enforces `ipam.add_ipaddress` permission separately — this form
    only validates the payload.
    """

    namespace = DynamicModelChoiceField(
        queryset=Namespace.objects.all(),
        help_text="The IPAM namespace this IPAddress will live in.",
    )
    parent_prefix = DynamicModelChoiceField(
        queryset=Prefix.objects.all(),
        required=False,
        query_params={"namespace_id": "$namespace"},
        help_text=(
            "Optional. The parent prefix is normally inferred automatically; "
            "set this only if the discovered IP fits multiple candidate parents."
        ),
    )
    status = forms.ModelChoiceField(
        queryset=Status.objects.all(),
        help_text="Status of the new IPAddress record (e.g. Active, Reserved).",
    )
    dns_name = forms.CharField(
        required=False,
        max_length=255,
        help_text="DNS / PTR name. Pre-filled from the discovered hostname.",
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        help_text="Optional. Assigning a tenant scopes this address for billing/segmentation.",
    )
    description = forms.CharField(
        required=False,
        max_length=200,
        help_text="Free-form note; pre-filled with the discovering scan reference.",
    )


class PromoteDiscoveredHostToDeviceForm(forms.Form):
    """Promote a DiscoveredHost into a real dcim.Device.

    Heavier than the IPAddress promotion because a Device requires
    Location + Role + DeviceType. Also auto-creates an Interface (with
    MAC if we discovered one) and an IPAddress, then links them so the
    Device picks up the discovered IP as its primary_ip4.

    The view checks `dcim.add_device` permission separately — this form
    only validates the payload.
    """

    name = forms.CharField(
        max_length=64,
        help_text="Device name. Pre-filled from the discovered hostname (domain stripped).",
    )
    location = DynamicModelChoiceField(
        queryset=Location.objects.all(),
        help_text="Where the device physically lives.",
    )
    role = DynamicModelChoiceField(
        queryset=Role.objects.all(),
        query_params={"content_types": "dcim.device"},
        help_text="Functional role (e.g., 'Access Point', 'Server').",
    )
    manufacturer = DynamicModelChoiceField(
        queryset=Manufacturer.objects.all(),
        required=False,
        help_text=(
            "Auto-selected from the discovered MAC's OUI when a matching "
            "Manufacturer already exists in Nautobot. Used to filter the "
            "device_type dropdown — pick or change the manufacturer first."
        ),
    )
    device_type = DynamicModelChoiceField(
        queryset=DeviceType.objects.all(),
        query_params={"manufacturer_id": "$manufacturer"},
        help_text="Model — the dropdown filters by manufacturer above.",
    )
    status = forms.ModelChoiceField(
        queryset=Status.objects.all(),
        help_text="Lifecycle status (e.g., Active).",
    )
    platform = DynamicModelChoiceField(
        queryset=Platform.objects.all(),
        required=False,
        help_text="Optional. OS/firmware platform.",
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        help_text="Optional. Tenant scoping.",
    )
    interface_name = forms.CharField(
        max_length=64,
        initial="mgmt0",
        help_text="Name for the auto-created Interface that holds the discovered IP.",
    )
    ipaddress_namespace = DynamicModelChoiceField(
        queryset=Namespace.objects.all(),
        help_text="Namespace for the new IPAddress (or its parent lookup if reusing).",
    )
    ipaddress_status = forms.ModelChoiceField(
        queryset=Status.objects.all(),
        help_text="Status for the new IPAddress record.",
    )
