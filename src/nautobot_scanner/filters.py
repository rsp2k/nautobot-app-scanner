"""django-filter FilterSet classes for nautobot_scanner list views.

Each FilterSet declares which model fields are URL-queryable. Backed by
NautobotFilterSet which auto-adds tags, custom-field, and search-token (q)
support.
"""

from nautobot.apps.filters import MultiValueCharFilter, NautobotFilterSet

from nautobot_scanner import models


class ScannerAgentFilterSet(NautobotFilterSet):
    """Filter set for ScannerAgent list view."""

    class Meta:
        model = models.ScannerAgent
        fields = ["name", "agent_type", "location", "version"]


class ScanProfileFilterSet(NautobotFilterSet):
    """Filter set for ScanProfile list view."""

    class Meta:
        model = models.ScanProfile
        fields = ["name", "scan_type", "timing_template"]


class ScanFilterSet(NautobotFilterSet):
    """Filter set for Scan list view."""

    class Meta:
        model = models.Scan
        fields = ["agent", "profile", "status", "target_prefixes", "target_ipaddresses"]


class DiscoveredHostFilterSet(NautobotFilterSet):
    """Filter set for DiscoveredHost list view."""

    # VarbinaryIPField has no auto-introspectable filter type — django-filter
    # would raise AssertionError without an explicit declaration. Same pattern
    # firewall-models uses for its IPRange.start_address / end_address.
    ip_address = MultiValueCharFilter(label="IP address")

    class Meta:
        model = models.DiscoveredHost
        fields = [
            "scan", "ip_address", "mac_address", "hostname",
            "os_family", "host_state", "linked_ipaddress", "linked_device",
            # Phase E OS depth: enables ?os_vendor=Apple, ?os_device_type=printer.
            # Both fields are db_indexed so list-view filtering stays fast.
            "os_vendor", "os_device_type",
        ]
