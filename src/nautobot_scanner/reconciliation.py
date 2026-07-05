"""IPAM reconciliation engine.

Answers the questions the scanner exists to answer:
    - Which live-and-discovered hosts have NO matching ``ipam.IPAddress``?
    - Which ``ipam.IPAddress`` records were never observed live?

Both are ORM joins on data the app already stores; there is no new
persistent schema. This module is pure functions plus two dataclasses,
so tests + the view + the CSV Job all consume the same types.

Anti-noise: prefixes get a ``rank_signal = discovered_count /
prefix_size`` ratio. Sparse-but-real subnets (e.g., 12 undocumented out
of a /24 clinical VLAN, 0.047) sort ABOVE phantom-full blocks
(e.g., single 6to4 relay answering for all 254 addresses of
``192.88.99.0/24``, 1.0). That's the exact noise case bingham-ops
flagged in the feature request — one device ARP-answering for a
reserved block shouldn't drown the actionable signal.

Bitemporal: default ``as_of`` is ``timezone.now()`` (current beliefs),
matching the ``diff_scans`` convention in ``diff.py``. Passing an
earlier datetime reproduces the report as it appeared then.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Literal, Optional

from django.utils import timezone


# ---------------------------------------------------------------------------
# Special-use ranges (IANA IPv4 Special-Purpose Address Registry, RFC 5735/6890)
# ---------------------------------------------------------------------------
# `exclude_reserved=True` drops any prefix that's a subnet of one of these.
# Rationale: for reconciliation, a "live host" in these ranges is nearly always
# noise — either a misbehaving device answering for the whole block (the 6to4
# phantom case) or scan-tool artifacts from documentation/benchmark ranges.
_RESERVED_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),         # "this network"
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),    # 6to4 relay anycast (RFC 7526 deprecated)
    ipaddress.ip_network("198.18.0.0/15"),     # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved for future
)

# RFC 1918 private-use IPv4. `scope="rfc1918"` restricts the report to
# subnets that are entirely inside one of these.
_RFC1918_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_rfc1918(net: ipaddress._BaseNetwork) -> bool:
    """True iff ``net`` is entirely inside one of the RFC 1918 ranges."""
    if not isinstance(net, ipaddress.IPv4Network):
        return False
    return any(net.subnet_of(r) for r in _RFC1918_V4)


def _is_reserved(net: ipaddress._BaseNetwork) -> bool:
    """True iff ``net`` is entirely inside an IANA special-use range."""
    if not isinstance(net, ipaddress.IPv4Network):
        return False
    return any(net.subnet_of(r) for r in _RESERVED_V4)


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReconciliationRow:
    """One live-but-undocumented host, ready to render or CSV-export.

    Direction is inferred by the caller: rows from ``groups`` are
    "undocumented" (live discovered, not in IPAM); rows from
    ``stale_groups`` are "stale IPAM" (documented, never observed live).
    """

    ip_address: str
    prefix: str                             # containing ipam.Prefix; "" if none
    prefix_role: str
    prefix_description: str
    hostname: str
    mac_address: str
    mac_vendor: str
    open_ports: tuple[tuple[int, str], ...]  # ((port, protocol), ...)
    services: tuple[str, ...]                # service_name for each open port
    os_family: str
    os_type: str
    seen_in_scan_id: str                     # str(scan.pk)
    seen_at: Optional[datetime]              # scan.completed_at
    discovered_host_id: str                  # str(pk) — for bulk-promote round-trip


@dataclass(frozen=True)
class ReconciliationGroup:
    """One containing prefix + the rows inside it, plus anti-noise ranking."""

    prefix: str                              # e.g. "192.168.42.0/24"
    prefix_role: str
    prefix_description: str
    rows: tuple[ReconciliationRow, ...]
    total_prefix_size: int                   # num_addresses of the prefix (0 if unknown)
    rank_signal: float                       # count / total_prefix_size


@dataclass(frozen=True)
class ReconciliationReport:
    """Bidirectional report bundle. Views + jobs consume this directly."""

    groups: tuple[ReconciliationGroup, ...]        # undocumented — live, not in IPAM
    stale_groups: tuple[ReconciliationGroup, ...]  # opt-in — IPAM, never observed live
    as_of: datetime                                # anchor used
    scope: str                                     # "rfc1918" | "all"
    exclude_reserved: bool
    include_stale_ipam: bool
    total_rows: int
    total_stale_rows: int


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------

def build_reconciliation(
    *,
    as_of: datetime | None = None,
    namespaces: Iterable | None = None,
    vrfs: Iterable | None = None,
    scope: Literal["rfc1918", "all"] = "rfc1918",
    exclude_reserved: bool = True,
    include_stale_ipam: bool = False,
    scan=None,
) -> ReconciliationReport:
    """Compute the bidirectional IPAM reconciliation report.

    Args:
        as_of: Bitemporal recording-time anchor. ``None`` → current
            beliefs (``timezone.now()``). Pass an earlier datetime to
            reproduce the report as it looked then.
        namespaces: Iterable of ``ipam.Namespace`` to scope both the
            discovered-host side and the IPAM side. ``None`` → all
            namespaces.
        vrfs: Iterable of ``ipam.VRF`` to scope IPAM lookups. ``None``
            → all VRFs.
        scope: ``"rfc1918"`` keeps only prefixes entirely inside
            10/8, 172.16/12, or 192.168/16. ``"all"`` includes public
            ranges too (rarely what operators want; provided for
            completeness).
        exclude_reserved: Drop prefixes entirely inside an IANA
            special-use range. Kills the phantom-full-block noise
            case (6to4 relay, TEST-NET, benchmarking, multicast).
        include_stale_ipam: Also compute the inverse — ``IPAddress``
            records that no live ``DiscoveredHost`` has matched at
            ``as_of``. Off by default because it's the less-common
            question and doubles the work.
        scan: Restrict the discovered-host side to a single ``Scan``.
            Used by the per-scan reconciliation tab.

    Returns:
        A ``ReconciliationReport`` with ``groups`` sorted so that
        low ``rank_signal`` prefixes (sparse-but-real subnets) come
        first and high ``rank_signal`` prefixes (phantom-full blocks
        one device is answering for) come last.
    """
    # Deferred imports so this module can be imported without Django
    # app-ready — tests that don't need the ORM run instantly.
    from nautobot.ipam.models import IPAddress, Prefix

    from nautobot_scanner.models import DiscoveredHost

    anchor = as_of or timezone.now()

    # ---- 1. Load discovered-host beliefs at anchor ----
    hosts_qs = (
        DiscoveredHost.objects.as_of(anchor)
        .filter(host_state="up")
        .filter(linked_ipaddress__isnull=True)
        .select_related("scan")
        .prefetch_related("ports")
    )
    if scan is not None:
        hosts_qs = hosts_qs.filter(scan=scan)

    # ---- 2. Load IPAM state (both for exclusion + optional stale side) ----
    ipam_ips_qs = IPAddress.objects.all()
    if namespaces is not None:
        namespaces = list(namespaces)
        ipam_ips_qs = ipam_ips_qs.filter(parent__namespace__in=namespaces)
    if vrfs is not None:
        vrfs = list(vrfs)
        ipam_ips_qs = ipam_ips_qs.filter(vrfs__in=vrfs)

    # str() unifies IPv4/IPv6 comparison — VarbinaryIPField's netaddr
    # objects vs. IPAddress.host (a Nautobot IPFieldValue) both stringify
    # to the same canonical form.
    ipam_ip_strs = {str(ip.host) for ip in ipam_ips_qs.only("host")}

    # ---- 3. Load prefixes ONCE and build an ip → prefix lookup helper ----
    prefix_qs = Prefix.objects.select_related("role")
    if namespaces is not None:
        prefix_qs = prefix_qs.filter(namespace__in=namespaces)
    all_prefixes = list(prefix_qs)

    # Pre-parse each Prefix's CIDR into an ipaddress network object so
    # containment tests are microseconds instead of milliseconds.
    parsed_prefixes: list[tuple[object, ipaddress._BaseNetwork]] = []
    for p in all_prefixes:
        try:
            parsed_prefixes.append((p, ipaddress.ip_network(str(p.prefix))))
        except ValueError:
            # Prefix with invalid CIDR — should be impossible via the ORM
            # but be defensive. Skip; it can't contain anything.
            continue

    # Sort by prefix length descending (most-specific first) so the
    # first containment hit is the smallest containing prefix.
    parsed_prefixes.sort(key=lambda pair: -pair[1].prefixlen)

    def _containing_prefix(ip_str: str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        for p, net in parsed_prefixes:
            if ip.version == net.version and ip in net:
                return p, net
        return None

    def _prefix_passes_scope(net: ipaddress._BaseNetwork) -> bool:
        """True iff the prefix should appear in the report given scope + exclusion filters."""
        if exclude_reserved and _is_reserved(net):
            return False
        if scope == "rfc1918":
            return _is_rfc1918(net)
        return True

    # ---- 4. Undocumented direction: live host, no matching IPAM ----
    groups: dict[str, list[ReconciliationRow]] = {}
    prefix_meta: dict[str, tuple[str, str, int]] = {}  # prefix_str -> (role, desc, size)

    for host in hosts_qs:
        ip_str = str(host.ip_address)
        if ip_str in ipam_ip_strs:
            continue

        hit = _containing_prefix(ip_str)
        if hit is None:
            # No prefix contains this IP. In rfc1918-scope this is
            # off-scope by definition (the IP itself might not even be
            # RFC1918); skip. In "all" scope surface it under a
            # sentinel bucket so operators see it.
            if scope == "rfc1918":
                continue
            prefix_str = "(no matching prefix)"
            role = desc = ""
            prefix_size = 0
        else:
            p, net = hit
            if not _prefix_passes_scope(net):
                continue
            prefix_str = str(p.prefix)
            role = str(p.role) if p.role else ""
            desc = p.description or ""
            prefix_size = net.num_addresses

        open_ports_seq = tuple(
            (port.port, port.protocol)
            for port in host.ports.all()
            if port.state == "open"
        )
        services_seq = tuple(
            port.service_name for port in host.ports.all()
            if port.state == "open" and port.service_name
        )
        row = ReconciliationRow(
            ip_address=ip_str,
            prefix=prefix_str,
            prefix_role=role,
            prefix_description=desc,
            hostname=host.hostname or "",
            mac_address=host.mac_address or "",
            mac_vendor=host.mac_vendor or "",
            open_ports=open_ports_seq,
            services=services_seq,
            os_family=host.os_family or "",
            os_type=host.os_type or "",
            seen_in_scan_id=str(host.scan_id),
            seen_at=host.scan.completed_at if host.scan_id else None,
            discovered_host_id=str(host.pk),
        )
        groups.setdefault(prefix_str, []).append(row)
        prefix_meta.setdefault(prefix_str, (role, desc, prefix_size))

    undocumented_groups = _assemble_groups(groups, prefix_meta)

    # ---- 5. Stale-IPAM direction (opt-in) ----
    stale_groups: tuple[ReconciliationGroup, ...] = ()
    if include_stale_ipam:
        # An IPAddress is "stale" iff no live DiscoveredHost at anchor
        # has this ip_address AND no host has a linked_ipaddress pointing
        # to it. Efficient path: build set of all currently-live IPs.
        live_ip_strs = {
            str(h.ip_address)
            for h in DiscoveredHost.objects.as_of(anchor)
            .filter(host_state="up")
            .only("ip_address")
        }
        stale_dict: dict[str, list[ReconciliationRow]] = {}
        stale_meta: dict[str, tuple[str, str, int]] = {}
        for ip_addr in ipam_ips_qs.select_related("parent__role"):
            ip_str = str(ip_addr.host)
            if ip_str in live_ip_strs:
                continue
            hit = _containing_prefix(ip_str)
            if hit is None:
                prefix_str = "(no matching prefix)"
                role = desc = ""
                prefix_size = 0
            else:
                p, net = hit
                if not _prefix_passes_scope(net):
                    continue
                prefix_str = str(p.prefix)
                role = str(p.role) if p.role else ""
                desc = p.description or ""
                prefix_size = net.num_addresses

            row = ReconciliationRow(
                ip_address=ip_str,
                prefix=prefix_str,
                prefix_role=role,
                prefix_description=desc,
                hostname=ip_addr.dns_name or "",
                mac_address="",
                mac_vendor="",
                open_ports=(),
                services=(),
                os_family="",
                os_type="",
                seen_in_scan_id="",
                seen_at=None,
                discovered_host_id="",  # empty — stale IPAM rows have no host
            )
            stale_dict.setdefault(prefix_str, []).append(row)
            stale_meta.setdefault(prefix_str, (role, desc, prefix_size))
        stale_groups = _assemble_groups(stale_dict, stale_meta)

    total_rows = sum(len(g.rows) for g in undocumented_groups)
    total_stale_rows = sum(len(g.rows) for g in stale_groups)

    return ReconciliationReport(
        groups=undocumented_groups,
        stale_groups=stale_groups,
        as_of=anchor,
        scope=scope,
        exclude_reserved=exclude_reserved,
        include_stale_ipam=include_stale_ipam,
        total_rows=total_rows,
        total_stale_rows=total_stale_rows,
    )


def _assemble_groups(
    row_dict: dict[str, list[ReconciliationRow]],
    prefix_meta: dict[str, tuple[str, str, int]],
) -> tuple[ReconciliationGroup, ...]:
    """Fold a prefix→rows dict into sorted ReconciliationGroup tuples.

    Sort key: ``rank_signal`` ascending. Sparse-but-real subnets
    (low count/size ratio, e.g. 12/254 = 0.047) come first; phantom-
    full blocks (254/254 = 1.0) come last. Ties broken by prefix
    string for stable output.
    """
    groups: list[ReconciliationGroup] = []
    for prefix_str, rows in row_dict.items():
        role, desc, size = prefix_meta[prefix_str]
        rank = (len(rows) / size) if size > 0 else 0.0
        groups.append(ReconciliationGroup(
            prefix=prefix_str,
            prefix_role=role,
            prefix_description=desc,
            rows=tuple(rows),
            total_prefix_size=size,
            rank_signal=rank,
        ))
    groups.sort(key=lambda g: (g.rank_signal, g.prefix))
    return tuple(groups)


# ---------------------------------------------------------------------------
# CSV export — shared between Job artifact + potential UI download button
# ---------------------------------------------------------------------------

def groups_to_csv(report: ReconciliationReport) -> bytes:
    """Serialize the undocumented side of a report to CSV bytes.

    The stale-IPAM side is included as a second sheet-equivalent (two
    header rows separated by a blank line) when ``report.include_stale_ipam``
    is True. CSV keeps operator-side tooling (grep/awk/spreadsheet)
    trivially compatible; the Job's artifact download surface is
    just this string wrapped in a ``.csv`` filename.
    """
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "direction", "prefix", "prefix_role", "prefix_description",
        "rank_signal", "ip_address", "hostname",
        "mac_address", "mac_vendor", "open_ports", "services",
        "os_family", "os_type", "seen_in_scan_id", "seen_at",
        "discovered_host_id",
    ])

    def _emit(direction: str, groups: tuple[ReconciliationGroup, ...]):
        for group in groups:
            for row in group.rows:
                writer.writerow([
                    direction,
                    group.prefix,
                    group.prefix_role,
                    group.prefix_description,
                    f"{group.rank_signal:.4f}",
                    row.ip_address,
                    row.hostname,
                    row.mac_address,
                    row.mac_vendor,
                    ";".join(f"{p}/{proto}" for p, proto in row.open_ports),
                    ";".join(row.services),
                    row.os_family,
                    row.os_type,
                    row.seen_in_scan_id,
                    row.seen_at.isoformat() if row.seen_at else "",
                    row.discovered_host_id,
                ])

    _emit("undocumented", report.groups)
    if report.include_stale_ipam:
        writer.writerow([])
        _emit("stale_ipam", report.stale_groups)

    return buf.getvalue().encode("utf-8")
