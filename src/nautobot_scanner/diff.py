"""Scan-to-scan diff helpers.

Pure functions that compare two completed Scans and report which hosts
appeared, disappeared, or changed between them. Designed to be called
from a view, a Job, or a notification webhook.

Bitemporality matters here: `as_of=` lets callers ask "what was the
diff *as we believed it on date T*" — useful when a re-parse changes
historical scan data and you want to reproduce the diff a colleague
saw last week in their report.
"""

from __future__ import annotations

import datetime
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Iterable

from django.utils import timezone


@dataclass(frozen=True)
class HostFacts:
    """A flattened snapshot of one DiscoveredHost's interesting fields.

    Used for diff comparison — equality of two HostFacts means "scanner
    saw the same observable properties." Excludes fields that vary
    between scans without representing real change (created/updated
    timestamps, entry_id, the scan FK itself).
    """

    ip_address: str
    host_state: str
    hostname: str
    mac_address: str
    mac_vendor: str
    os_family: str
    os_type: str
    open_ports: frozenset[tuple[int, str]]  # (port, protocol) tuples
    vulnerability_count: int

    @classmethod
    def from_host(cls, host) -> "HostFacts":
        """Build from a DiscoveredHost ORM instance."""
        port_pairs = frozenset(
            host.ports.filter(state="open").values_list("port", "protocol")
        )
        return cls(
            ip_address=str(host.ip_address),
            host_state=host.host_state,
            hostname=host.hostname,
            mac_address=host.mac_address,
            mac_vendor=host.mac_vendor,
            os_family=host.os_family,
            os_type=host.os_type,
            open_ports=port_pairs,
            vulnerability_count=host.vulnerability_count,
        )


@dataclass
class HostChange:
    """A single host present in both scans, with a per-field changeset."""

    ip_address: str
    before: HostFacts
    after: HostFacts
    fields_changed: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.fields_changed)

    @property
    def ports_opened(self) -> frozenset[tuple[int, str]]:
        return self.after.open_ports - self.before.open_ports

    @property
    def ports_closed(self) -> frozenset[tuple[int, str]]:
        return self.before.open_ports - self.after.open_ports


@dataclass
class ScanDiff:
    """Result of comparing two scans."""

    scan_a_id: str
    scan_b_id: str
    added: list[HostFacts]  # in B, not in A
    removed: list[HostFacts]  # in A, not in B
    changed: list[HostChange]  # in both with differences
    unchanged_count: int  # in both, identical

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def _facts_by_ip(hosts: Iterable) -> dict[str, HostFacts]:
    """Index a queryset of DiscoveredHost into {ip_str: HostFacts}."""
    return {str(h.ip_address): HostFacts.from_host(h) for h in hosts}


# Fields whose value-equality defines "this host hasn't changed observably"
# between scans. Open ports are compared as a set so port order doesn't matter.
_COMPARED_FIELDS = (
    "host_state",
    "hostname",
    "mac_address",
    "mac_vendor",
    "os_family",
    "os_type",
    "open_ports",
    "vulnerability_count",
)


def diff_scans(scan_a, scan_b, *, as_of: datetime.datetime | None = None) -> ScanDiff:
    """Compare the host populations of two scans.

    Args:
        scan_a: the "before" scan (Scan instance)
        scan_b: the "after" scan (Scan instance)
        as_of: optional recording-time anchor. Defaults to "now" (current
            beliefs). Pass an earlier datetime to reproduce the diff as
            it appeared at that point in history.

    Returns:
        ScanDiff with `added`/`removed`/`changed`/`unchanged_count` populated.
        `changed` entries carry per-field changeset info via HostChange.
    """
    from nautobot_scanner.models import DiscoveredHost

    anchor = as_of or timezone.now()

    # Bitemporal slice — get the beliefs about each scan that were
    # current at `anchor`. Prefetch ports + vulnerabilities to avoid N+1.
    a_hosts = (
        DiscoveredHost.objects.as_of(anchor)
        .filter(scan=scan_a)
        .prefetch_related("ports", "ports__vulnerabilities")
    )
    b_hosts = (
        DiscoveredHost.objects.as_of(anchor)
        .filter(scan=scan_b)
        .prefetch_related("ports", "ports__vulnerabilities")
    )

    a_by_ip = _facts_by_ip(a_hosts)
    b_by_ip = _facts_by_ip(b_hosts)

    a_ips = set(a_by_ip)
    b_ips = set(b_by_ip)

    added = [b_by_ip[ip] for ip in sorted(b_ips - a_ips)]
    removed = [a_by_ip[ip] for ip in sorted(a_ips - b_ips)]

    changed: list[HostChange] = []
    unchanged_count = 0
    for ip in sorted(a_ips & b_ips):
        before = a_by_ip[ip]
        after = b_by_ip[ip]
        diffs = [f for f in _COMPARED_FIELDS if getattr(before, f) != getattr(after, f)]
        if diffs:
            changed.append(HostChange(ip_address=ip, before=before, after=after, fields_changed=diffs))
        else:
            unchanged_count += 1

    return ScanDiff(
        scan_a_id=str(scan_a.pk),
        scan_b_id=str(scan_b.pk),
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged_count,
    )


def previous_scan_on_agent(scan):
    """Find the most-recent completed scan on the same agent before `scan`.

    Returns None if `scan` is the first completed scan on its agent — the
    UI uses this to gate the "Compare with previous" button (no button when
    there's nothing to compare against).
    """
    from nautobot_scanner.models import Scan

    if not scan.completed_at:
        return None
    return (
        Scan.objects.filter(
            agent=scan.agent,
            status="completed",
            completed_at__lt=scan.completed_at,
        )
        .order_by("-completed_at")
        .first()
    )
