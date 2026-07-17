"""Reconciliation-driven target selection for the fingerprint pipeline.

The Phase M fingerprint tools (httpx, and later snmp-recon) run against
the **currently-undocumented** set: DiscoveredHosts where both
``linked_device`` and ``linked_ipaddress`` are NULL. That set is what
the IPAM Reconciliation surface already tracks — but consumed as an
IP list rather than the grouped-by-prefix report the UI renders.

The load-bearing operational constraint (see the Phase M design brief):
never probe an already-documented device. Doing so would generate
SNMP auth-trap floods, HTTP access-log entries, and false SOC alerts
on the operator's own gear. Restricting the target set to
undocumented rows makes the workflow bounded and self-shrinking —
each successful identification + promote removes a host from the
target set on the next run.

This module is pure: no ORM writes, no dispatch. Consumers are the
management commands (``http_fingerprint_undocumented``, later
``snmp_recon_undocumented``) that turn the returned IP list into a
``Scan`` record.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Callable, Optional

from django.utils import timezone


def resolve_undocumented_targets(
    scope_filter: Optional[Callable] = None,
    cooldown_hours: int = 24,
    include_recently_scanned: bool = False,
) -> list[str]:
    """Return the IP list to probe next in the fingerprint pipeline.

    Args:
        scope_filter: Optional queryset transform. Callable receives the
            base ``DiscoveredHost.objects.current()`` queryset (already
            filtered to undocumented rows) and must return a queryset.
            Use this for per-prefix or per-namespace narrowing:

                scope_filter=lambda qs: qs.filter(ip_address__startswith="10.1.3.")

        cooldown_hours: Skip hosts that were touched by an httpx or
            snmp-info NseFinding within the last N hours. Default 24 —
            prevents operator-error re-runs from doubling up SNMP
            auth-log noise on the same target. Set to ``0`` to disable.
        include_recently_scanned: Bypass the cooldown filter entirely.
            Useful for a forced re-scan after a config change.

    Returns:
        List of IP address strings (``["10.24.144.2", "10.1.3.6", ...]``),
        de-duplicated and sorted for deterministic dispatch order.
        Empty list is a valid signal — nothing to probe right now.

    Idempotency & determinism:
        Result depends only on the current DB state and ``timezone.now()``.
        Two calls a millisecond apart may differ if a scan completed in
        between; that's the intended behavior (freshly-scanned hosts
        drop out of the target set immediately).
    """
    # Deferred imports so `--help` on the management command works without
    # Django app-ready. Same pattern as parser.persist().
    from nautobot_scanner.models import DiscoveredHost, NseFinding

    qs = DiscoveredHost.objects.current().filter(
        linked_device__isnull=True,
        linked_ipaddress__isnull=True,
    )

    if scope_filter is not None:
        qs = scope_filter(qs)

    if not include_recently_scanned and cooldown_hours > 0:
        # Exclude hosts touched by fingerprint tools within the cooldown
        # window. Done as a two-step query rather than a
        # `host_findings__scan__completed_at__gte` join because the
        # Django ORM refuses that traversal through the reverse M2O
        # from DiscoveredHost — the "join on the field not permitted"
        # error. Cheap: NseFinding.scan is a straightforward FK; the
        # candidate NseFinding set is bounded by scan volume in the
        # cooldown window (small).
        cutoff = timezone.now() - timedelta(hours=cooldown_hours)
        recent_dh_ids = set(
            NseFinding.objects.filter(
                nse_script__in=["httpx", "snmp-info", "snmp-sysdescr"],
                discovered_host__scan__completed_at__gte=cutoff,
                discovered_host__isnull=False,
            ).values_list("discovered_host_id", flat=True)
        )
        if recent_dh_ids:
            qs = qs.exclude(pk__in=recent_dh_ids)

    ips = sorted({str(host.ip_address) for host in qs.only("ip_address")})
    return ips
