"""URL routes for nautobot_scanner.

Plugin URLs auto-mount under /plugins/<base_url>/ — `base_url='scanner'`
in NautobotScannerConfig means routes here resolve under `/plugins/scanner/`.
"""

from django.urls import path
from nautobot.apps.urls import NautobotUIViewSetRouter

from nautobot_scanner import views
from nautobot_scanner import views_bulk_promote
from nautobot_scanner import views_reconciliation
from nautobot_scanner import views_scan_tab

app_name = "nautobot_scanner"

router = NautobotUIViewSetRouter()
router.register("agents", views.ScannerAgentUIViewSet)
router.register("profiles", views.ScanProfileUIViewSet)
router.register("scans", views.ScanUIViewSet)
router.register("discovered-hosts", views.DiscoveredHostUIViewSet)

# Custom action URLs — sit OUTSIDE the router because they're not CRUD
# operations. Ordering NOTE: the router generates a `<pk>` pattern that
# accepts any string, so `discovered-hosts/bulk-promote/` would collide
# with `discovered-hosts/<pk>=bulk-promote/` and route to the CRUD
# viewset. Put custom paths FIRST so the resolver matches them before
# falling through to the router.
urlpatterns = [
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
    # POST endpoint — dispatches a fresh single-host scan against this
    # host's IP via target_raw_ips (no IPAM commitment required).
    path(
        "discovered-hosts/<uuid:pk>/rescan/",
        views.DiscoveredHostRescanView.as_view(),
        name="discoveredhost_rescan",
    ),
    # Bitemporal scan diff — `?vs=<scan_pk>` pins to a specific other scan;
    # absent, the view auto-picks the previous completed scan on the same agent.
    path(
        "scans/<uuid:pk>/diff/",
        views.ScanDiffView.as_view(),
        name="scan_diff",
    ),
    # Per-finding detail page — full untruncated output + parent context +
    # references list. Routed outside the router because NseFinding is a
    # BaseModel child without a standalone UIViewSet (no list page).
    path(
        "findings/<uuid:pk>/",
        views.NseFindingDetailView.as_view(),
        name="nsefinding",
    ),
    # IPAM reconciliation report — standalone nav-level surface. Prefix-
    # grouped diff of live DiscoveredHosts against ipam.IPAddress; ranked
    # by discovered_count / prefix_size so sparse-but-real subnets sort
    # above phantom-full blocks. See docs/agent-threads/ipam-
    # reconciliation-report/ for the design contract.
    path(
        "reconciliation/",
        views_reconciliation.ReconciliationView.as_view(),
        name="reconciliation",
    ),
    # Bulk promote — POST-only two-step preview → confirm flow. Batches
    # single-host promotes inside one transaction.atomic(). Defaults
    # created IPAddresses to status=Provisional (see migration 0023).
    path(
        "discovered-hosts/bulk-promote/",
        views_bulk_promote.DiscoveredHostBulkPromoteView.as_view(),
        name="discoveredhost_bulk_promote",
    ),
    # Per-Scan reconciliation view — same engine, scoped to one scan.
    # Linked from the standalone report + optionally surfaced on the
    # Scan detail page.
    path(
        "scans/<uuid:pk>/reconciliation/",
        views_scan_tab.ScanReconciliationTabView.as_view(),
        name="scan_reconciliation_tab",
    ),
] + router.urls
