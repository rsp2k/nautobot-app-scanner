"""Per-Scan reconciliation tab view.

Sits behind the URL name ``plugins:nautobot_scanner:scan_reconciliation_tab``
(mounted at ``scans/<uuid:pk>/reconciliation/`` — the standalone view at
``plugins:nautobot_scanner:reconciliation`` handles the nav-level rollup;
this file is only the tab drill-in for a single scan).

The view is a thin adapter: it loads the Scan, parses the optional
``?as_of=`` bitemporal anchor from the query string, calls
``build_reconciliation(scan=scan, ...)`` and hands the resulting
:class:`ReconciliationReport` to the template. All noise/scope filtering
is deferred to the standalone view — the tab is intentionally the
"what does THIS scan know" pre-scoped answer.

Kept in a separate module from ``views.py`` because:
    1. The main-branch integration commit wires this into the router and
       the ``Tab`` on ``ScanUIViewSet.object_detail_content``.
    2. The tests in ``test_scan_tab_view.py`` can import the class
       without pulling every other viewset into scope.
"""

from __future__ import annotations

from datetime import datetime

from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.shortcuts import get_object_or_404, render
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from django.views import View

from nautobot_scanner import models
from nautobot_scanner.reconciliation import build_reconciliation


def _parse_as_of_param(raw: str | None) -> datetime | None:
    """Parse a ``?as_of=<ISO-8601>`` query parameter.

    Empty or unparseable → ``None`` (engine falls back to current beliefs).
    Naive datetimes are stamped with the current timezone so the
    ``recorded_during`` range lookup doesn't blow up on mixed tz-aware
    vs. tz-naive comparisons.
    """
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


class ScanReconciliationTabView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """Render the reconciliation report pre-scoped to a single Scan.

    Permission: ``nautobot_scanner.view_discoveredhost`` — same gate the
    standalone view uses. Ties the surface to "you can see the underlying
    hosts" so operators without discover-read access don't get a side
    channel into scan contents.

    Bitemporal: ``?as_of=<ISO>`` anchors the report at a historic
    recording-time. Empty defaults to current beliefs (``timezone.now()``
    inside the engine), matching the standalone view's convention.
    """

    permission_required = ("nautobot_scanner.view_discoveredhost",)

    def get(self, request, pk):
        """Load the Scan, run reconciliation restricted to it, render the tab."""
        scan = get_object_or_404(models.Scan, pk=pk)
        as_of = _parse_as_of_param(request.GET.get("as_of"))

        report = build_reconciliation(scan=scan, as_of=as_of)

        # Deep-link to the standalone rollup with a pre-filter to this scan.
        # Reverse is wrapped because the standalone view URL is registered
        # by a follow-up integration commit; falling back to ``None`` keeps
        # this tab renderable in isolation.
        try:
            standalone_url = (
                f"{reverse('plugins:nautobot_scanner:reconciliation')}?scan={scan.pk}"
            )
        except NoReverseMatch:
            standalone_url = None

        return render(
            request,
            "nautobot_scanner/scan_reconciliation_tab.html",
            {
                "object": scan,
                "scan": scan,
                "report": report,
                "as_of": as_of,
                "standalone_url": standalone_url,
            },
        )
