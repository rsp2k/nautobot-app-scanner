"""DRF viewsets for nautobot_scanner REST API.

NautobotModelViewSet bundles list/retrieve/create/update/destroy actions
plus filterset support, pagination, and the standard tags/notes/changelog
relations.
"""

from nautobot.apps.api import NautobotModelViewSet

from nautobot_scanner import filters, models
from nautobot_scanner.api import serializers


class ScannerAgentAPIViewSet(NautobotModelViewSet):
    queryset = models.ScannerAgent.objects.all()
    serializer_class = serializers.ScannerAgentSerializer
    filterset_class = filters.ScannerAgentFilterSet


class ScanProfileAPIViewSet(NautobotModelViewSet):
    queryset = models.ScanProfile.objects.all()
    serializer_class = serializers.ScanProfileSerializer
    filterset_class = filters.ScanProfileFilterSet


class ScanAPIViewSet(NautobotModelViewSet):
    queryset = models.Scan.objects.all()
    serializer_class = serializers.ScanSerializer
    filterset_class = filters.ScanFilterSet


class DiscoveredHostAPIViewSet(NautobotModelViewSet):
    queryset = models.DiscoveredHost.objects.all()
    serializer_class = serializers.DiscoveredHostSerializer
    filterset_class = filters.DiscoveredHostFilterSet


# DiscoveredPort / VulnerabilityFinding / TraceRouteHop don't currently
# have FilterSets (BaseModel children, only rendered nested), so they get
# the default no-filter viewset. Phase 7 may add filtersets if the
# Nautobot SDK clients ask for them.
class DiscoveredPortAPIViewSet(NautobotModelViewSet):
    queryset = models.DiscoveredPort.objects.all()
    serializer_class = serializers.DiscoveredPortSerializer


class VulnerabilityFindingAPIViewSet(NautobotModelViewSet):
    queryset = models.VulnerabilityFinding.objects.all()
    serializer_class = serializers.VulnerabilityFindingSerializer


class TraceRouteHopAPIViewSet(NautobotModelViewSet):
    queryset = models.TraceRouteHop.objects.all()
    serializer_class = serializers.TraceRouteHopSerializer
