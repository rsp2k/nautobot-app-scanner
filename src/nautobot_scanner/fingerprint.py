"""Reconciliation-driven target selection + M.2 fingerprint fusion.

Two logical layers in this module:

**Target selection** (Phase M.0/M.1): the fingerprint tools (httpx and
snmp-recon-deep) run against the **currently-undocumented** set —
DiscoveredHosts where both ``linked_device`` and ``linked_ipaddress``
are NULL. That set is what the IPAM Reconciliation surface already
tracks; ``resolve_undocumented_targets()`` returns it as an IP list.

**Signal fusion** (Phase M.2): once httpx + snmp-recon-deep have run
against undocumented hosts, their outputs land as ``NseFinding`` rows
attached to the DiscoveredHost. ``fuse_signals()`` reads those
findings + the DiscoveredHost's own fields (mac_vendor, hostname,
nmap OS classification), scores each signal against a vendor pattern
table, and returns an ``Identification`` — dominant vendor +
proposed device role + confidence score. The
``auto_promote_identified`` management command consumes those
identifications.

Both layers are pure over the ORM: no writes, no dispatch. Consumers
are the management commands (``http_fingerprint_undocumented``,
``snmp_recon_undocumented``, ``auto_promote_identified``).

Design constraint (from Phase M design brief):
    Never probe an already-documented device. Restricting the target
    set to undocumented rows makes the workflow bounded and
    self-shrinking — each successful identification + promote removes
    a host from the target set on the next run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Iterable, Optional

from django.utils import timezone

from nautobot_scanner.snmp_vendor_oids import vendor_from_oid


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


# ---------------------------------------------------------------------------
# M.2 — Fingerprint fusion
# ---------------------------------------------------------------------------

# Signal weights — total max score for a fully-fingerprinted host is 13.
# Confidence = total_score / MAX_SCORE. The scorer is deliberately lenient
# on missing signals (host might have no HTTP UI or no SNMP daemon); a
# strong signal from ANY source can still push confidence above the
# operator's threshold. See docs/dev/phase-m-fingerprint-design.md
# §Fingerprint fusion.
SIGNAL_WEIGHTS = {
    "snmp_sysobjectid": 3,   # ground-truth vendor via IANA enterprise number
    "httpx_tls_subject": 3,  # TLS cert subject_cn — cryptographically bound
    "httpx_webserver":  2,   # Server: header (can be spoofed by proxies)
    "httpx_title":      2,   # <title> tag — vendor login-page pattern
    "mac_oui":          2,   # OUI-derived vendor (from mac_vendor field)
    "dns_hostname":     2,   # DNS name matches vendor model prefix
    "nmap_sv_product":  1,   # nmap -sV per-port product name (weakest)
}
MAX_SCORE = sum(SIGNAL_WEIGHTS.values())  # 15 with favicon; 13 without it in M.2


# Vendor pattern tables. Case-insensitive matching against extracted
# signal strings. Add a new vendor by appending to VENDOR_PATTERNS and
# writing a test case in tests/test_fusion.py.
#
# The scoring picks the vendor with the highest total score across all
# firing signals. Ties are broken by whichever appears first in this
# table (stable across runs — iteration order is preserved by dict).
VENDOR_PATTERNS: dict[str, dict[str, list[re.Pattern]]] = {
    "Axis": {
        # Axis embeds "AXIS" in the Server: header and in the TLS subject.
        "webserver": [re.compile(r"axis", re.IGNORECASE)],
        "title":     [re.compile(r"axis(\s|-)*(live view|configuration|setup)", re.IGNORECASE),
                       re.compile(r"axis\s+communications", re.IGNORECASE)],
        "tls_subject": [re.compile(r"axis[\s-]*communications", re.IGNORECASE),
                         re.compile(r"cn\s*=\s*axis[-.]", re.IGNORECASE)],
        # DNS name convention: axis-<mac>.example.local
        "dns": [re.compile(r"^axis[-.]", re.IGNORECASE)],
        "mac_vendor": [re.compile(r"axis", re.IGNORECASE)],
        "sv_product": [re.compile(r"axis", re.IGNORECASE)],
    },
    "Uniview": {
        # Uniview embeds via GoAhead-Webs (shared platform, weaker signal
        # alone but strong in combination with DNS/MAC patterns).
        "webserver": [re.compile(r"uniview", re.IGNORECASE)],
        "title":     [re.compile(r"uniview\s+nvr\s+login", re.IGNORECASE),
                       re.compile(r"uniview", re.IGNORECASE)],
        "tls_subject": [re.compile(r"uniview", re.IGNORECASE),
                         re.compile(r"cn\s*=\s*uniview", re.IGNORECASE)],
        # Uniview product-line DNS prefixes: qnv-c8011r-*, xnf-9013rv-*,
        # pnm-c32083rvq-*, ipc-*. Matches the netmon-2 DNS pattern.
        "dns": [re.compile(r"^(qnv|xnf|pnm|ipc)-", re.IGNORECASE)],
        # Uniview MAC OUI prefix: E4:30:22 shows up as their vendor
        "mac_vendor": [re.compile(r"uniview", re.IGNORECASE)],
        "sv_product": [re.compile(r"uniview", re.IGNORECASE)],
    },
    "Hikvision": {
        "webserver": [re.compile(r"app-webs/|hikvision", re.IGNORECASE)],
        "title":     [re.compile(r"hikvision|dvr\s+login", re.IGNORECASE)],
        "tls_subject": [re.compile(r"hikvision", re.IGNORECASE)],
        "dns": [re.compile(r"^(ds|hk)-", re.IGNORECASE)],
        "mac_vendor": [re.compile(r"hikvision|hangzhou", re.IGNORECASE)],
        "sv_product": [re.compile(r"hikvision", re.IGNORECASE)],
    },
    "Bosch": {
        "webserver": [re.compile(r"bosch", re.IGNORECASE)],
        "title":     [re.compile(r"bosch(\s+security|\s+cctv)", re.IGNORECASE)],
        "tls_subject": [re.compile(r"bosch\s+security", re.IGNORECASE)],
        "dns": [re.compile(r"^bosch-", re.IGNORECASE)],
        "mac_vendor": [re.compile(r"bosch", re.IGNORECASE)],
        "sv_product": [re.compile(r"bosch", re.IGNORECASE)],
    },
    "Vivotek": {
        "webserver": [re.compile(r"vivotek", re.IGNORECASE)],
        "title":     [re.compile(r"vivotek", re.IGNORECASE)],
        "tls_subject": [re.compile(r"vivotek", re.IGNORECASE)],
        "dns": [re.compile(r"^vivotek-", re.IGNORECASE)],
        "mac_vendor": [re.compile(r"vivotek", re.IGNORECASE)],
        "sv_product": [re.compile(r"vivotek", re.IGNORECASE)],
    },
    "Cisco": {
        # Cisco is broad — includes phones (SEP*), switches, routers, APs.
        # M.2 aggregates all under "Cisco"; the device_type_hint from the
        # SNMP OID (network-equipment vs wireless-ap) drives role assignment.
        "webserver": [re.compile(r"cisco[- ]", re.IGNORECASE)],
        "title":     [re.compile(r"cisco\s+(ios|nexus|catalyst|systems)", re.IGNORECASE)],
        "tls_subject": [re.compile(r"cisco\s+systems", re.IGNORECASE)],
        "dns": [re.compile(r"^(sep|cisco|cat|nex|ap-)", re.IGNORECASE)],
        "mac_vendor": [re.compile(r"cisco\s+systems", re.IGNORECASE)],
        "sv_product": [re.compile(r"cisco", re.IGNORECASE)],
    },
    "APC": {
        "webserver": [re.compile(r"apc|schneider", re.IGNORECASE)],
        "title":     [re.compile(r"apc\s+management|schneider\s+electric", re.IGNORECASE)],
        "tls_subject": [re.compile(r"schneider\s+electric|american\s+power\s+conversion", re.IGNORECASE)],
        "dns": [re.compile(r"^(apc|ups)-", re.IGNORECASE)],
        "mac_vendor": [re.compile(r"american\s+power|schneider", re.IGNORECASE)],
        "sv_product": [re.compile(r"apc|schneider", re.IGNORECASE)],
    },
}


# Vendor → proposed Nautobot role name. The role must already exist
# in the target Nautobot instance for the auto-promote to succeed;
# if it doesn't, the identification is still surfaced but the
# proposed_role stays None so the operator can pick manually.
VENDOR_TO_ROLE: dict[str, str] = {
    "Axis":      "Camera",
    "Uniview":   "Camera",
    "Hikvision": "Camera",
    "Bosch":     "Camera",
    "Vivotek":   "Camera",
    "Cisco":     "Network Equipment",  # M.2.5 refines to Switch/Router/AP via OID hint
    "APC":       "UPS",
    "Dell":      "Server",
    "HP":        "Server",
    "Juniper":   "Network Equipment",
    "Netgear":   "Network Equipment",
    "Lexmark":   "Printer",
    "Ricoh":     "Printer",
    "Canon":     "Printer",
    "Xerox":     "Printer",
}


@dataclass
class SignalHit:
    """One signal that fired for a vendor.

    Kept as its own dataclass (rather than a bare tuple) so the audit
    trail on ``Identification.signals`` is self-documenting: a reviewer
    inspecting a promoted Device can see exactly which piece of
    evidence contributed which points.
    """

    signal: str          # SIGNAL_WEIGHTS key: "snmp_sysobjectid", "httpx_webserver", ...
    vendor: str          # matched vendor name from VENDOR_PATTERNS
    weight: int          # the weight this signal contributes
    evidence: str        # short string showing WHAT matched (e.g. "AXIS Q6055" or ".1.3.6.1.4.1.368…")


@dataclass
class Identification:
    """Fusion output for a single DiscoveredHost.

    An identification with confidence >= operator threshold is a
    candidate for auto-promote. Below the threshold, the operator
    still sees the record for manual review.

    Attributes:
        discovered_host_id: PK of the DiscoveredHost this identifies.
        ip_address: The host's IP (denormalized for reporting).
        vendor: The dominant vendor across all firing signals, or ""
            if no signals fired.
        device_type_hint: One of the values from snmp_vendor_oids
            (camera / network-equipment / printer / …) or "" if
            unknown.
        proposed_role: Nautobot Role name to assign at promote time,
            or None if VENDOR_TO_ROLE has no mapping.
        confidence: Score / MAX_SCORE, 0.0 - 1.0.
        signals: All SignalHits that fired, in priority order.
        raw_score: The pre-normalized integer score (for debugging).
    """

    discovered_host_id: str
    ip_address: str
    vendor: str
    device_type_hint: str
    proposed_role: Optional[str]
    confidence: float
    signals: list[SignalHit] = field(default_factory=list)
    raw_score: int = 0

    @property
    def has_identification(self) -> bool:
        """True iff at least one signal fired."""
        return bool(self.signals)


# ---------------------------------------------------------------------------
# Signal extractors
# ---------------------------------------------------------------------------

_SYSOBJECTID_RE = re.compile(
    r"sysObjectID(?:.*?)?[:=]\s*\.?([0-9]+(?:\.[0-9]+)+)",
    re.IGNORECASE | re.DOTALL,
)


def _extract_sysobjectid(nse_output: str) -> Optional[str]:
    """Pull the sysObjectID OID string out of nmap's snmp-info text.

    nmap's ``snmp-info`` NSE emits a multi-line text blob like:

        SNMPv2-MIB::sysObjectID.0 = OID: .1.3.6.1.4.1.9.1.1745

    Or in older nmap versions:

        sysObjectID: 1.3.6.1.4.1.9.1.1745

    The regex accepts either shape. Returns the dotted OID string on
    match, or None. Leading dot is normalized off.
    """
    m = _SYSOBJECTID_RE.search(nse_output or "")
    if not m:
        return None
    return m.group(1).lstrip(".")


def _latest_finding(host, script_name: str):
    """Return the most-recent NseFinding for a host matching an NSE script name.

    Bitemporally: the most-recent by the parent scan's completed_at.
    The ordering path goes through the DiscoveredHost's scan FK
    (``discovered_host__scan__completed_at``) because NseFinding has
    no direct scan FK — findings are reached via their host, and the
    host owns the scan.

    If no matching NseFinding exists, returns None.
    """
    return (
        host.host_findings.filter(nse_script=script_name)
        .order_by("-discovered_host__scan__completed_at")
        .first()
    )


def _extract_all_signals(host) -> list[SignalHit]:
    """Extract every firing signal for a DiscoveredHost, across all vendors.

    Called by ``fuse_signals()``. Returns a flat list of every
    ``(signal, vendor, weight, evidence)`` tuple that matched. The
    caller aggregates by vendor and picks the winner.
    """
    hits: list[SignalHit] = []

    # --- SNMP sysObjectID → vendor (highest confidence signal) --------
    snmp_finding = _latest_finding(host, "snmp-info") or _latest_finding(host, "snmp-sysdescr")
    if snmp_finding is not None:
        oid = _extract_sysobjectid(snmp_finding.output or "")
        if oid:
            resolved = vendor_from_oid(oid)
            if resolved is not None:
                vendor, _hint = resolved
                hits.append(SignalHit(
                    signal="snmp_sysobjectid",
                    vendor=vendor,
                    weight=SIGNAL_WEIGHTS["snmp_sysobjectid"],
                    evidence=f"sysObjectID=.{oid}",
                ))

    # --- httpx signals: webserver, title, TLS subject -----------------
    httpx_finding = _latest_finding(host, "httpx")
    if httpx_finding is not None:
        elements = httpx_finding.elements or {}
        webserver = str(elements.get("webserver", "") or "")
        title = str(elements.get("title", "") or "")
        tls = elements.get("tls") or {}
        tls_subject = str(tls.get("subject_cn", "") or "")

        for vendor, patterns in VENDOR_PATTERNS.items():
            if webserver and any(p.search(webserver) for p in patterns.get("webserver", [])):
                hits.append(SignalHit(
                    signal="httpx_webserver",
                    vendor=vendor,
                    weight=SIGNAL_WEIGHTS["httpx_webserver"],
                    evidence=f"webserver={webserver[:60]!r}",
                ))
            if title and any(p.search(title) for p in patterns.get("title", [])):
                hits.append(SignalHit(
                    signal="httpx_title",
                    vendor=vendor,
                    weight=SIGNAL_WEIGHTS["httpx_title"],
                    evidence=f"title={title[:60]!r}",
                ))
            if tls_subject and any(p.search(tls_subject) for p in patterns.get("tls_subject", [])):
                hits.append(SignalHit(
                    signal="httpx_tls_subject",
                    vendor=vendor,
                    weight=SIGNAL_WEIGHTS["httpx_tls_subject"],
                    evidence=f"tls_subject_cn={tls_subject[:60]!r}",
                ))

    # --- DiscoveredHost fields: mac_vendor, hostname, os_vendor -------
    mac_vendor = str(getattr(host, "mac_vendor", "") or "")
    hostname = str(getattr(host, "hostname", "") or "")
    os_vendor = str(getattr(host, "os_vendor", "") or "")

    for vendor, patterns in VENDOR_PATTERNS.items():
        if mac_vendor and any(p.search(mac_vendor) for p in patterns.get("mac_vendor", [])):
            hits.append(SignalHit(
                signal="mac_oui",
                vendor=vendor,
                weight=SIGNAL_WEIGHTS["mac_oui"],
                evidence=f"mac_vendor={mac_vendor[:40]!r}",
            ))
        if hostname and any(p.search(hostname) for p in patterns.get("dns", [])):
            hits.append(SignalHit(
                signal="dns_hostname",
                vendor=vendor,
                weight=SIGNAL_WEIGHTS["dns_hostname"],
                evidence=f"hostname={hostname[:40]!r}",
            ))
        if os_vendor and any(p.search(os_vendor) for p in patterns.get("sv_product", [])):
            hits.append(SignalHit(
                signal="nmap_sv_product",
                vendor=vendor,
                weight=SIGNAL_WEIGHTS["nmap_sv_product"],
                evidence=f"os_vendor={os_vendor[:40]!r}",
            ))

    return hits


def fuse_signals(host) -> Identification:
    """Compute the vendor identification for a DiscoveredHost.

    Aggregates every firing signal by vendor, picks the vendor with
    the highest total score, and returns an ``Identification``. If no
    signals fire, returns an empty Identification (``has_identification
    = False``, ``confidence = 0.0``, ``vendor = ""``).

    The device_type_hint comes from the SNMP OID when present
    (highest-quality signal). When SNMP isn't in the picture, the hint
    is derived from ``VENDOR_TO_ROLE`` — falling back to "unknown" for
    vendors with no role mapping.

    Args:
        host: A DiscoveredHost instance. Should already have any
            available NseFindings attached — this function does not
            dispatch scans.

    Returns:
        An Identification dataclass. Never raises; unmapped vendors,
        missing fields, and empty NseFinding lists all produce a
        reasonable empty result.
    """
    hits = _extract_all_signals(host)
    if not hits:
        return Identification(
            discovered_host_id=str(host.pk),
            ip_address=str(host.ip_address),
            vendor="",
            device_type_hint="",
            proposed_role=None,
            confidence=0.0,
            signals=[],
            raw_score=0,
        )

    # Aggregate score by vendor. Deterministic tie-break: first
    # occurrence of the winning score wins (Python dict insertion order).
    score_by_vendor: dict[str, int] = {}
    for h in hits:
        score_by_vendor[h.vendor] = score_by_vendor.get(h.vendor, 0) + h.weight

    winner_vendor = max(score_by_vendor, key=score_by_vendor.get)
    winner_score = score_by_vendor[winner_vendor]

    # Device type hint: prefer the SNMP OID's hint if the SNMP signal
    # fired for the winning vendor (highest-quality signal). Otherwise
    # fall back to inferring from the role mapping.
    device_type_hint = ""
    for h in hits:
        if h.vendor == winner_vendor and h.signal == "snmp_sysobjectid":
            oid = h.evidence.split("=.", 1)[-1] if "=." in h.evidence else ""
            resolved = vendor_from_oid(oid) if oid else None
            if resolved is not None:
                _v, device_type_hint = resolved
                break
    if not device_type_hint:
        # Fall back to inferring from the role mapping (informal).
        role_hint = VENDOR_TO_ROLE.get(winner_vendor, "")
        if role_hint == "Camera":
            device_type_hint = "camera"
        elif role_hint == "UPS":
            device_type_hint = "ups"
        elif role_hint == "Printer":
            device_type_hint = "printer"
        elif role_hint == "Network Equipment":
            device_type_hint = "network-equipment"
        elif role_hint == "Server":
            device_type_hint = "server"
        else:
            device_type_hint = "unknown"

    proposed_role = VENDOR_TO_ROLE.get(winner_vendor)

    # Sort signals by weight (descending) for readable audit output.
    winner_signals = sorted(
        [h for h in hits if h.vendor == winner_vendor],
        key=lambda h: (-h.weight, h.signal),
    )

    return Identification(
        discovered_host_id=str(host.pk),
        ip_address=str(host.ip_address),
        vendor=winner_vendor,
        device_type_hint=device_type_hint,
        proposed_role=proposed_role,
        confidence=round(winner_score / MAX_SCORE, 3),
        signals=winner_signals,
        raw_score=winner_score,
    )


# ---------------------------------------------------------------------------
# M.2.5 — auto-provision helpers for Device creation
# ---------------------------------------------------------------------------


def resolve_or_create_manufacturer(vendor: str):
    """Return a ``dcim.Manufacturer`` for the fusion-identified vendor.

    Reuses the existing Manufacturer when its name contains the vendor
    string (case-insensitive), so a Nautobot install with "Axis
    Communications AB" doesn't accidentally get a duplicate "Axis"
    manufacturer. Creates a new Manufacturer when no match exists.

    Called by the M.2.5 --create-devices path in
    ``auto_promote_identified``. Returns the Manufacturer instance.
    """
    from nautobot.dcim.models import Manufacturer

    existing = Manufacturer.objects.filter(name__icontains=vendor).first()
    if existing is not None:
        return existing
    return Manufacturer.objects.create(name=vendor)


def resolve_or_create_device_type(vendor: str, device_type_hint: str):
    """Return a ``dcim.DeviceType`` for the vendor + hint combo.

    Model naming convention: ``{Vendor} Auto-identified {hint}``.
    Example: ``Uniview Auto-identified camera``. Once one host of a
    given vendor+hint lands, subsequent hosts reuse the same
    DeviceType — deduping is at the (manufacturer, model) unique key
    Nautobot already enforces.

    Args:
        vendor: Vendor name from fusion output (used for Manufacturer
            resolution + as the DeviceType model prefix).
        device_type_hint: The ``Identification.device_type_hint`` value
            ("camera", "network-equipment", etc.).

    Returns:
        DeviceType instance, either pre-existing or freshly created.
    """
    from nautobot.dcim.models import DeviceType

    mfg = resolve_or_create_manufacturer(vendor)
    model = f"{vendor} Auto-identified {device_type_hint or 'device'}"
    return DeviceType.objects.get_or_create(
        manufacturer=mfg,
        model=model,
    )[0]


def resolve_or_create_role(role_name: str):
    """Return a ``extras.Role`` for the given name.

    Ensures the ``dcim.device`` content type is attached (a Role has
    to be attached to a content type before it can be assigned to
    Devices — Nautobot 3.x requirement).

    Args:
        role_name: Role name from ``Identification.proposed_role`` or
            ``VENDOR_TO_ROLE``.

    Returns:
        Role instance, with dcim.device content type attached.
    """
    from django.contrib.contenttypes.models import ContentType
    from nautobot.extras.models import Role

    role, created = Role.objects.get_or_create(name=role_name)
    device_ct = ContentType.objects.get(app_label="dcim", model="device")
    if not role.content_types.filter(pk=device_ct.pk).exists():
        role.content_types.add(device_ct)
    return role


def match_existing_device(host):
    """Return an existing Device that likely matches this DiscoveredHost, or None.

    Matches on any of:
        1. Device.primary_ip4.host == host.ip_address
        2. Any Interface on any Device with mac_address == host.mac_address
           (skipped when mac_address is empty)

    Used by the M.2.5 auto-promote path to distinguish "existing device
    that scanner previously mis-created with a MAC name — rename it"
    from "new device — create fresh". Handles the netmon-2 auto-
    generated Axis pair (MAC-named Devices from 2026-07-05) that need
    renaming rather than duplication once fusion identifies them.
    """
    from nautobot.dcim.models import Device, Interface

    ip_str = str(host.ip_address)

    # Try primary IP match first.
    dev = Device.objects.filter(primary_ip4__host=ip_str).first()
    if dev is not None:
        return dev

    # Fall back to MAC on any interface.
    if host.mac_address:
        iface = Interface.objects.filter(mac_address=host.mac_address).first()
        if iface is not None:
            return iface.device

    return None


# ---------------------------------------------------------------------------
# M.2 — bulk fusion (used by auto_promote_identified command)
# ---------------------------------------------------------------------------


def fuse_all_undocumented(min_confidence: float = 0.0) -> Iterable[Identification]:
    """Yield an Identification for every currently-undocumented DiscoveredHost.

    Skips hosts with confidence below the threshold — useful for the
    management-command preview where the operator only cares about
    hosts likely to survive an auto-promote at their chosen threshold.

    Args:
        min_confidence: Skip identifications below this confidence.
            Default 0.0 yields every attempt including empty ones.

    Yields:
        Identification instances, one per DiscoveredHost that clears
        the threshold, in insertion order (undefined stable ordering —
        callers that need a specific sort should collect + sort).
    """
    from nautobot_scanner.models import DiscoveredHost

    qs = DiscoveredHost.objects.current().filter(
        linked_device__isnull=True,
        linked_ipaddress__isnull=True,
    ).prefetch_related("host_findings")

    for host in qs:
        ident = fuse_signals(host)
        if ident.confidence >= min_confidence:
            yield ident
