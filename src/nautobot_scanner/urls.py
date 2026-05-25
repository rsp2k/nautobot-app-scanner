"""URL routes for nautobot_scanner.

Plugin URLs auto-mount under /plugins/<base_url>/ — `base_url='scanner'`
in NautobotScannerConfig means routes here resolve under `/plugins/scanner/`.
"""

from django.urls import path
from nautobot.apps.urls import NautobotUIViewSetRouter

from nautobot_scanner import views

app_name = "nautobot_scanner"

router = NautobotUIViewSetRouter()
router.register("agents", views.ScannerAgentUIViewSet)
router.register("profiles", views.ScanProfileUIViewSet)
router.register("scans", views.ScanUIViewSet)
router.register("discovered-hosts", views.DiscoveredHostUIViewSet)

# Custom action URL — sits OUTSIDE the router because it's not a CRUD
# operation. Mounts at /plugins/scanner/discovered-hosts/<uuid>/promote/.
# Order matters: the router's <pk>/ catch-all is fine because Django's
# URL resolver tries longer paths first.
urlpatterns = router.urls + [
    path(
        "discovered-hosts/<uuid:pk>/promote/",
        views.DiscoveredHostPromoteView.as_view(),
        name="discoveredhost_promote",
    ),
    path(
        "discovered-hosts/<uuid:pk>/promote-to-device/",
        views.DiscoveredHostPromoteToDeviceView.as_view(),
        name="discoveredhost_promote_to_device",
    ),
]
