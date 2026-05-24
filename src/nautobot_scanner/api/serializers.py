"""DRF serializers for nautobot_scanner.

`fields = "__all__"` exposes every column. DiscoveredHost.ip_address needs
an explicit declaration because VarbinaryIPField (non-editable, stored as
bytes) can't be auto-introspected by DRF — same pattern firewall-models
uses for its IPRange address fields.
"""

from rest_framework import serializers
from nautobot.apps.api import NautobotModelSerializer

from nautobot_scanner import models


class ScannerAgentSerializer(NautobotModelSerializer):
    class Meta:
        model = models.ScannerAgent
        fields = "__all__"


class ScanProfileSerializer(NautobotModelSerializer):
    class Meta:
        model = models.ScanProfile
        fields = "__all__"


class ScanSerializer(NautobotModelSerializer):
    class Meta:
        model = models.Scan
        fields = "__all__"


class DiscoveredHostSerializer(NautobotModelSerializer):
    """DiscoveredHost API serializer.

    ip_address is exposed as a plain string (CharField), not the underlying
    VarbinaryIPField bytes — that's what API consumers expect, and Django
    auto-coerces the value on write via the VarbinaryIPField.to_python().
    """

    ip_address = serializers.CharField()

    class Meta:
        model = models.DiscoveredHost
        fields = "__all__"


class DiscoveredPortSerializer(NautobotModelSerializer):
    class Meta:
        model = models.DiscoveredPort
        fields = "__all__"


class VulnerabilityFindingSerializer(NautobotModelSerializer):
    class Meta:
        model = models.VulnerabilityFinding
        fields = "__all__"


class TraceRouteHopSerializer(NautobotModelSerializer):
    """TraceRouteHop API serializer (hop_ip is VarbinaryIPField, same fix)."""

    hop_ip = serializers.CharField()

    class Meta:
        model = models.TraceRouteHop
        fields = "__all__"
