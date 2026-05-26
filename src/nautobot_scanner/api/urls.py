"""REST API URL routes — resolves under /api/plugins/scanner/."""

from django.urls import path
from nautobot.apps.api import OrderedDefaultRouter

from nautobot_scanner.api import views

router = OrderedDefaultRouter()
router.register("agents", views.ScannerAgentAPIViewSet)
router.register("profiles", views.ScanProfileAPIViewSet)
router.register("scans", views.ScanAPIViewSet)
router.register("discovered-hosts", views.DiscoveredHostAPIViewSet)
router.register("discovered-ports", views.DiscoveredPortAPIViewSet)
# `vulnerabilities` endpoint kept for backwards-compatible URL — model
# renamed to NseFinding (covers host-scope + port-scope NSE output).
router.register("vulnerabilities", views.NseFindingAPIViewSet)
router.register("traceroute-hops", views.TraceRouteHopAPIViewSet)

app_name = "nautobot_scanner-api"

# Agent-specific endpoints — token-auth'd, sit OUTSIDE the router so
# they can use a different authentication_classes than CRUD viewsets.
urlpatterns = router.urls + [
    path(
        "agents/<uuid:pk>/pending-scans/",
        views.AgentPendingScansView.as_view(),
        name="agent_pending_scans",
    ),
    path(
        "agents/<uuid:pk>/checkin/",
        views.AgentCheckinView.as_view(),
        name="agent_checkin",
    ),
    path(
        "scans/<uuid:pk>/ingest/",
        views.ScanIngestView.as_view(),
        name="scan_ingest",
    ),
]
