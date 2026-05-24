"""URL routes for nautobot_scanner.

Plugin URLs auto-mount under /plugins/<base_url>/ — `base_url='scanner'`
in NautobotScannerConfig means routes here resolve under `/plugins/scanner/`.
"""

from nautobot.apps.urls import NautobotUIViewSetRouter

from nautobot_scanner import views

app_name = "nautobot_scanner"

router = NautobotUIViewSetRouter()
router.register("agents", views.ScannerAgentUIViewSet)
router.register("profiles", views.ScanProfileUIViewSet)
router.register("scans", views.ScanUIViewSet)
router.register("discovered-hosts", views.DiscoveredHostUIViewSet)

urlpatterns = router.urls
