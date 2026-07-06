"""Standalone view for the IPAM reconciliation report.

Lives in its own module so this feature slice (view + form + template +
tests) can land as a clean, self-contained pull request. The maintainer's
integration commit wires the URL + nav entry in ``urls.py`` /
``navigation.py`` in a follow-up, at which point this view will resolve at
``/plugins/scanner/reconciliation/`` under the name
``plugins:nautobot_scanner:reconciliation``.

The view is a thin adapter: parse GET params via the filter form, call
``reconciliation.build_reconciliation(...)``, hand the result to the
template. All the business logic lives in the pure-function engine
already committed in ``reconciliation.py``.

Design notes from
``docs/agent-threads/ipam-reconciliation-report/
20260705T182313Z-scanner-maintainer-recon-proposal.md`` section
"Standalone view":

- ``LoginRequiredMixin + PermissionRequiredMixin`` gate on
  ``nautobot_scanner.view_discoveredhost`` (the report is a read-only
  presentation of the same rows that permission already governs).
- ``?as_of=<ISO-8601>`` is parsed explicitly rather than through the
  form so that a URL bookmark keeps working when the form validation
  layer changes; the form's ``as_of`` field is the interactive UX,
  the URL parameter is the API.
- Bad ``as_of`` values fall back to ``None`` (current beliefs) rather
  than 400-erroring; the goal is a report surface that always renders,
  never a strict validation gate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.shortcuts import render
from django.views import View

from nautobot_scanner import reconciliation
from nautobot_scanner.forms_reconciliation import ReconciliationFilterForm


def _parse_as_of_param(raw: Optional[str]) -> Optional[datetime]:
    """Parse an ``?as_of=`` URL parameter into a datetime, or return None.

    ``datetime.fromisoformat`` handles ``2026-07-05T18:23:13+00:00`` and
    ``2026-07-05T18:23:13Z`` in 3.11+. On anything unparseable we swallow
    the ``ValueError`` and let the caller default to ``timezone.now()`` —
    the report should always render, even from a malformed bookmark.
    """
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


class ReconciliationView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """Render the bidirectional IPAM reconciliation report.

    Same permission gate as the DiscoveredHost list view: if you can
    see the raw discovered rows, you can see this rolled-up view of
    which ones are still undocumented in IPAM.

    The URL wire-up is deferred to the main-branch integration commit;
    the expected reverse name is
    ``plugins:nautobot_scanner:reconciliation``.
    """

    permission_required = ("nautobot_scanner.view_discoveredhost",)

    template_name = "nautobot_scanner/reconciliation.html"

    def get(self, request):
        """Build the report and hand it to the template.

        Form is bound to ``request.GET`` when any GET params are present,
        unbound otherwise — an unbound form renders with the field
        ``initial`` values so a fresh visit lands on the safe defaults
        (``scope=rfc1918``, ``exclude_reserved=True``,
        ``include_stale_ipam=False``, ``as_of`` empty).
        """
        form = ReconciliationFilterForm(request.GET or None)

        # ``as_of`` is parsed straight from the URL for bookmark-stability
        # (see module docstring). If the form's own DateTimeField also
        # cleaned it successfully we could cross-check, but the URL is
        # the source of truth here.
        as_of = _parse_as_of_param(request.GET.get("as_of"))

        # Pull the rest of the filters through the form so field-level
        # validation still applies (e.g. Namespace/VRF PK existence).
        # ``cleaned_data`` is only populated when the form validates;
        # ``form.is_valid()`` short-circuits to False on an unbound form
        # too, so we branch and fall back to the field ``initial`` values.
        if form.is_valid():
            scope = form.cleaned_data.get("scope") or "rfc1918"
            namespaces = form.cleaned_data.get("namespaces") or None
            vrfs = form.cleaned_data.get("vrfs") or None
            exclude_reserved = form.cleaned_data.get("exclude_reserved", True)
            include_stale_ipam = form.cleaned_data.get(
                "include_stale_ipam", False
            )
        else:
            # Unbound (or invalid) form: use the field defaults so the
            # report still renders. Invalid submissions leave the form's
            # error UI in place so the operator can see what to fix.
            scope = "rfc1918"
            namespaces = None
            vrfs = None
            exclude_reserved = True
            include_stale_ipam = False

        report = reconciliation.build_reconciliation(
            as_of=as_of,
            namespaces=namespaces,
            vrfs=vrfs,
            scope=scope,
            exclude_reserved=exclude_reserved,
            include_stale_ipam=include_stale_ipam,
        )

        context = {
            "form": form,
            "report": report,
            "as_of": as_of or report.as_of,
        }
        return render(request, self.template_name, context)
