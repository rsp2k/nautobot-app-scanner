"""Phase M.3: reconciliation-report action-button dispatch views.

The reconciliation report already has a "Bulk Promote" action button
that POSTs selected DiscoveredHost IDs to the promote flow. M.3 adds
two sibling action buttons that dispatch fingerprint probes against
the same selected IPs:

- **HTTP Fingerprint Selected** → dispatches the ``http-probe-rich``
  profile against the selected DHs' IPs. No credential attempts;
  purely observational.
- **SNMP Recon Selected** → dispatches the ``snmp-recon-deep`` profile,
  which tries the default-community wordlist. Loud credential-attempt
  warning; guardrails match the CLI ``snmp_recon_undocumented``
  command.

Both views are POST-only. The HTML uses ``<button formaction="...">``
overrides so one form + one selection produces three possible
actions (Bulk Promote, HTTP Fingerprint, SNMP Recon) without JS.

The IP-list resolution mirrors the bulk-promote view: filter
DiscoveredHost by the posted IDs, extract distinct IP strings, sort
for deterministic dispatch. Empty selection → clean redirect back to
the reconciliation report with a warning message.
"""

from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.http import HttpResponseNotAllowed
from django.shortcuts import redirect
from django.views import View

from nautobot_scanner import models


HTTPX_PROFILE_NAME = "http-probe-rich"
SNMP_PROFILE_NAME = "snmp-recon-deep"


def _resolve_selected_ips(request) -> list[str]:
    """Extract the sorted, deduped IP list from the POSTed discovered_host_id[]."""
    host_ids = request.POST.getlist("discovered_host_id")
    if not host_ids:
        return []
    ips = set(
        models.DiscoveredHost.objects.filter(pk__in=host_ids)
        .values_list("ip_address", flat=True)
    )
    return sorted(str(ip) for ip in ips)


def _dispatch_scan(request, *, profile_name: str, ips: list[str], action_label: str):
    """Shared body: create Scan with target_raw_ips, dispatch through the agent's backend.

    Returns a redirect to the resulting Scan's detail page on success,
    or a redirect back to the reconciliation report on error. Errors
    always land as a Django messages entry so the reconciliation UI's
    top banner surfaces them.
    """
    from nautobot_scanner.backends import get_backend

    try:
        profile = models.ScanProfile.objects.get(name=profile_name)
    except models.ScanProfile.DoesNotExist:
        messages.error(
            request,
            f"Profile {profile_name!r} not found — {action_label} unavailable. "
            f"Run migrations to seed it (migration 0022 for httpx, 0025 for snmp).",
        )
        return redirect("plugins:nautobot_scanner:reconciliation")

    agent = models.ScannerAgent.objects.order_by("name").first()
    if agent is None:
        messages.error(
            request,
            f"{action_label} needs at least one ScannerAgent. Configure "
            f"one in Apps > Scanner > Scanner Agents first.",
        )
        return redirect("plugins:nautobot_scanner:reconciliation")

    scan = models.Scan.objects.create(
        agent=agent,
        profile=profile,
        target_raw_ips=ips,
        was_pentest_mode=bool(profile.is_pentest_mode),
    )
    backend = get_backend(agent)
    backend.dispatch(scan)
    scan.refresh_from_db()

    messages.success(
        request,
        f"{action_label} dispatched: Scan {scan.pk} against {len(ips)} target IP(s) "
        f"via agent {agent.name!r}. Status: {scan.status!r}.",
    )
    return redirect(scan.get_absolute_url())


class DiscoveredHostFingerprintHttpxView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """POST-only: dispatch http-probe-rich against selected DiscoveredHosts.

    Same permission gate as running any other scan through the UI —
    scanner change_discoveredhost. HTTP probing is not a credential
    attempt, so no additional permission required beyond scanner-write.
    """

    permission_required = ("nautobot_scanner.change_discoveredhost",)

    def get(self, request):
        """Reject GET — action-button flow is POST-only."""
        return HttpResponseNotAllowed(["POST"])

    def post(self, request):
        """Resolve selected IPs, dispatch a http-probe-rich Scan."""
        ips = _resolve_selected_ips(request)
        if not ips:
            messages.warning(
                request,
                "No hosts were selected for HTTP fingerprinting. Pick one "
                "or more rows on the reconciliation view and try again.",
            )
            return redirect("plugins:nautobot_scanner:reconciliation")

        return _dispatch_scan(
            request,
            profile_name=HTTPX_PROFILE_NAME,
            ips=ips,
            action_label="HTTP fingerprint (httpx)",
        )


class DiscoveredHostFingerprintSnmpView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """POST-only: dispatch snmp-recon-deep against selected DiscoveredHosts.

    Credential-attempt: this dispatch tries ~25 well-known default
    community strings against every selected IP. All attempts land in
    the target device's SNMP logs. The reconciliation-driven selection
    mitigates the risk (documented devices don't appear in the report),
    but operators should still glance at the selection before clicking.

    Requires the change_discoveredhost permission. When a proper
    ``nautobot_scanner.use_credential_attempt_profiles`` permission
    lands (see Phase M design brief §Credential-attempt gating
    deferred), this view will require that too.
    """

    permission_required = ("nautobot_scanner.change_discoveredhost",)

    def get(self, request):
        """Reject GET — action-button flow is POST-only."""
        return HttpResponseNotAllowed(["POST"])

    def post(self, request):
        """Resolve selected IPs, dispatch a snmp-recon-deep Scan.

        SNMP dispatch is a CREDENTIAL ATTEMPT — every selected IP will
        receive ~25 SNMP auth requests with default community strings.
        The reconciliation-driven selection restricts to undocumented
        hosts only, but the operator sees the selection in the
        preview before this view fires.
        """
        ips = _resolve_selected_ips(request)
        if not ips:
            messages.warning(
                request,
                "No hosts were selected for SNMP fingerprinting. Pick one "
                "or more rows on the reconciliation view and try again.",
            )
            return redirect("plugins:nautobot_scanner:reconciliation")

        return _dispatch_scan(
            request,
            profile_name=SNMP_PROFILE_NAME,
            ips=ips,
            action_label="SNMP recon (credential attempt)",
        )
