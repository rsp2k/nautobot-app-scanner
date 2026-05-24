"""REST API URL routes — resolves under /api/plugins/scanner/."""

from nautobot.apps.api import OrderedDefaultRouter

from nautobot_scanner.api import views

router = OrderedDefaultRouter()
router.register("agents", views.ScannerAgentAPIViewSet)
router.register("profiles", views.ScanProfileAPIViewSet)
router.register("scans", views.ScanAPIViewSet)
router.register("discovered-hosts", views.DiscoveredHostAPIViewSet)
router.register("discovered-ports", views.DiscoveredPortAPIViewSet)
router.register("vulnerabilities", views.VulnerabilityFindingAPIViewSet)
router.register("traceroute-hops", views.TraceRouteHopAPIViewSet)

app_name = "nautobot_scanner-api"
urlpatterns = router.urls
