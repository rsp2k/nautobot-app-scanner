"""Pure-function nmap XML parser + ORM persistence.

Design rationale: split into two layers with NO ORM coupling in the parser.

- `parse_xml(raw)` returns a list of `ParsedHost` dataclasses. It can run in
  a unit test without a database, and — critically — can be re-run against
  the gzipped XML stored on the Scan record to backfill new fields after
  a parser bugfix, without re-executing the original scan.

- `persist(scan, parsed)` takes those dataclasses and writes ORM records.
  This is the only place that touches the database.

Library choice: `python-libnmap` (the de facto Python wrapper for nmap XML)
with `defusedxml` to neutralize XXE attacks — scan output is attacker-
controllable (a scanned host can put hostile content in its banner / TLS
cert subject / NSE script output), and libnmap's own docs flag this CVE
class explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import defusedxml.ElementTree  # noqa: F401 — imported for its side-effect of patching ElementTree

from nautobot_scanner.choices import (
    HostStateChoices,
    PortStateChoices,
    ProtocolChoices,
    SeverityChoices,
)

if TYPE_CHECKING:
    from nautobot_scanner.models import Scan


# ----------------------------------------------------------------------------
# Plain dataclasses — no ORM, no Django, no nmap dependency leaked here.
# ----------------------------------------------------------------------------


@dataclass
class ParsedVulnerability:
    """One NSE-script finding (typically from `vulners` or similar)."""

    nse_script: str
    output: str
    severity: str = SeverityChoices.UNKNOWN
    references: list[str] = field(default_factory=list)
    # Structured key-value data emitted by the NSE script alongside the text
    # output. Empty dict for scripts that emit text only (fingerprint-strings,
    # banner). Nested dict for scripts like ssl-cert (cert.validity.notAfter),
    # smb-os-discovery (os.fqdn), http-headers (each header as a key).
    elements: dict = field(default_factory=dict)


@dataclass
class ParsedPort:
    """One open/closed/filtered port on a host."""

    port: int
    protocol: str
    state: str
    service_name: str = ""
    banner: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: list[str] = field(default_factory=list)
    vulnerabilities: list[ParsedVulnerability] = field(default_factory=list)
    # Richer per-port data nmap exposes alongside state:
    state_reason: str = ""               # "syn-ack", "no-response", "port-unreach", "tcp-rst"
    state_reason_ttl: int | None = None  # TTL of the responding packet
    state_reason_ip: str | None = None   # IP that responded (often a firewall); None when missing
    tunnel: str = ""                     # "ssl" for TLS-wrapped services, empty otherwise
    service_fp: str = ""                 # raw nmap service fingerprint string


@dataclass
class ParsedHop:
    """One traceroute hop."""

    hop_number: int
    hop_ip: str
    hop_hostname: str = ""
    rtt_ms: float | None = None


@dataclass
class ParsedHost:
    """One host's worth of nmap output."""

    ip_address: str
    host_state: str
    hostname: str = ""
    mac_address: str = ""
    mac_vendor: str = ""
    os_family: str = ""
    os_type: str = ""
    os_accuracy: int | None = None
    ports: list[ParsedPort] = field(default_factory=list)
    traceroute_hops: list[ParsedHop] = field(default_factory=list)
    # Host-scope NSE findings (smb-os-discovery, snmp-info, ssh-hostkey).
    # Separate from ParsedPort.vulnerabilities because these have no port.
    host_findings: list[ParsedVulnerability] = field(default_factory=list)
    # Topology + uptime hints that nmap surfaces on every host:
    distance_hops: int | None = None       # network distance (hops to target)
    uptime_seconds: int | None = None      # boot inference from TCP timestamps (-O runs)
    last_boot_at: object = None            # datetime, derived from uptime; populated in persist()
    tcp_sequence_class: str = ""           # ISN class, e.g. "random positive increments"
    # OS classification depth — nmap exposes more than the top match's name
    # and family. vendor + device_type + CPE strings are the bridge to CVE
    # correlation and "show me all printers" filters.
    os_vendor: str = ""                        # Microsoft, Apple, Linux, Cisco, ...
    os_device_type: str = ""                   # 'general purpose', 'router', 'printer', 'firewall', ...
    os_gen: str = ""                           # '10', '7', '2.4.X', ...
    os_cpe: list[str] = field(default_factory=list)  # CPE strings for the top OS match
    os_alternative_matches: list[dict] = field(default_factory=list)  # [{'name': str, 'accuracy': int}, ...]


@dataclass
class ParsedReport:
    """Scan-level metadata pulled from the NmapReport top-level fields.

    Captured at parse time so persist() can stamp the Scan row with the
    actual command nmap ran, the binary version that produced the XML, the
    XML schema version, and how many ports were scanned per host. All four
    answer "what did nmap actually do?" without unpacking the XML by hand.
    """

    nmap_command: str = ""
    nmap_version: str = ""
    xml_version: str = ""
    ports_scanned: int | None = None


# ----------------------------------------------------------------------------
# MAC OUI → vendor resolver. Pure function — uses the IEEE registry bundled
# with netaddr (no network calls, no extra dependencies). Returns empty
# string for any input that doesn't resolve, never raises.
# ----------------------------------------------------------------------------


def resolve_mac_vendor(mac: str) -> str:
    """Return the IEEE-registered vendor for a MAC's OUI, or empty on miss.

    Handles all common MAC formatting (`AA:BB:CC:DD:EE:FF`, `AA-BB-CC-...`,
    bare hex). Empty input returns empty string. OUIs not in the registry —
    typically locally-administered MACs from VMs/containers — also return
    empty string rather than raising.
    """
    if not mac:
        return ""
    try:
        import netaddr

        eui = netaddr.EUI(mac)
        return eui.oui.registration().org or ""
    except (netaddr.AddrFormatError, netaddr.NotRegisteredError, ValueError):
        return ""


# ----------------------------------------------------------------------------
# Parser — pure function, no I/O.
# ----------------------------------------------------------------------------


def parse_xml(raw: str) -> list[ParsedHost]:
    """Parse raw nmap XML into a list of `ParsedHost` dataclasses.

    Back-compat shim — most call sites (tests, older code) only care about
    hosts. New ingest paths should call `parse_xml_with_report()` to also
    capture the report-level provenance (command, version, ports-scanned).

    Args:
        raw: nmap XML output (the contents of a `-oX -` dump). May be empty.

    Returns:
        List of `ParsedHost`. Empty if XML has no hosts or is empty/blank.

    Raises:
        ValueError: if XML is malformed or libnmap rejects it.
    """
    _, hosts = parse_xml_with_report(raw)
    return hosts


def parse_xml_with_report(raw: str) -> tuple[ParsedReport, list[ParsedHost]]:
    """Parse raw nmap XML into report metadata + host list.

    Returns a tuple — the report half stamps Scan provenance fields
    (command-line, nmap version, ports-scanned), the host half feeds
    the per-host persistence loop.

    Empty/blank input returns an empty `ParsedReport` and `[]`.
    """
    if not raw or not raw.strip():
        return ParsedReport(), []

    # Import inside the function so the module loads even if libnmap is
    # somehow unavailable at app-config time (e.g., during introspection).
    from libnmap.parser import NmapParser, NmapParserException

    try:
        report = NmapParser.parse(raw)
    except NmapParserException as exc:
        raise ValueError(f"Invalid nmap XML: {exc}") from exc

    # Report-level metadata — defensive getattr/conversion because older
    # nmap XML may not include every field, and libnmap returns sentinel
    # values like -1 / "" when a field is absent.
    ports_scanned: int | None = None
    try:
        ns = getattr(report, "numservices", -1)
        if isinstance(ns, int) and ns > 0:
            ports_scanned = ns
        elif isinstance(ns, str) and ns.isdigit():
            ports_scanned = int(ns)
    except (AttributeError, TypeError, ValueError):
        pass

    parsed_report = ParsedReport(
        nmap_command=getattr(report, "commandline", "") or "",
        nmap_version=str(getattr(report, "version", "") or "")[:32],
        xml_version=str(getattr(report, "xmlversion", "") or "")[:16],
        ports_scanned=ports_scanned,
    )

    return parsed_report, [_convert_host(h) for h in report.hosts]


def _convert_host(nmap_host) -> ParsedHost:
    """Convert a libnmap `NmapHost` to our `ParsedHost` dataclass."""
    state_map = {
        "up": HostStateChoices.UP,
        "down": HostStateChoices.DOWN,
        "unknown": HostStateChoices.UNKNOWN,
        "skipped": HostStateChoices.SKIPPED,
    }
    state = state_map.get(nmap_host.status, HostStateChoices.UNKNOWN)

    # nmap exposes hostname() as a single string (first hostname in the report).
    # hostnames is a list when there are multiple PTRs.
    hostname = nmap_host.hostnames[0] if nmap_host.hostnames else ""

    # OS detection: libnmap exposes os_match_probabilities() returning a list
    # of NmapOSMatch objects sorted by accuracy. We take the top guess for
    # the headline fields, then walk osclasses[0] for vendor/type/gen/CPE
    # (Phase E depth) and osmatches[1:] for alternatives.
    os_family = ""
    os_type = ""
    os_accuracy: int | None = None
    os_vendor = ""
    os_device_type = ""
    os_gen = ""
    os_cpe: list[str] = []
    os_alternative_matches: list[dict] = []
    if nmap_host.os_fingerprinted and nmap_host.os_match_probabilities():
        matches = nmap_host.os_match_probabilities()
        top = matches[0]
        os_type = top.name
        os_accuracy = int(top.accuracy)
        # osclasses[0] carries vendor/family/type/osgen/cpelist for the top
        # match. Defensive: not every match has an osclass attached.
        if top.osclasses:
            cls = top.osclasses[0]
            os_family = cls.osfamily or ""
            os_vendor = getattr(cls, "vendor", "") or ""
            os_device_type = getattr(cls, "type", "") or ""
            os_gen = getattr(cls, "osgen", "") or ""
            # cpelist contains CPE objects; coerce to strings for JSON storage.
            try:
                os_cpe = [str(c) for c in (getattr(cls, "cpelist", None) or [])]
            except (TypeError, AttributeError):
                os_cpe = []
        # Alternative matches beyond the top. Capped at top 4 alternatives
        # because the long tail (5%-accuracy guesses) is rarely useful and
        # bloats the row.
        for alt in matches[1:5]:
            os_alternative_matches.append({
                "name": alt.name,
                "accuracy": int(alt.accuracy),
            })

    ports = [_convert_port(s, nmap_host) for s in nmap_host.services]
    hops = _extract_traceroute(nmap_host)

    mac = nmap_host.mac or ""

    # Topology / uptime hints. All of these come from runs we already do —
    # `distance` is set whenever traceroute or even ping runs, `uptime` and
    # `tcpsequence` get populated when -O ran. Pull them best-effort; the
    # attribute access can return None or empty dicts depending on libnmap
    # version, so we guard each lookup.
    distance_hops: int | None = None
    try:
        distance_hops = int(nmap_host.distance) if nmap_host.distance else None
    except (AttributeError, TypeError, ValueError):
        pass

    uptime_seconds: int | None = None
    try:
        # libnmap exposes uptime as a dict {"seconds": int, "lastboot": str}.
        # The "seconds" field is what we want; lastboot is nmap's human
        # rendering of when the host booted, which we'll re-derive ourselves
        # at persist time from the scan's completion time minus uptime.
        up = nmap_host.uptime
        if isinstance(up, dict) and up.get("seconds"):
            uptime_seconds = int(up["seconds"])
    except (AttributeError, TypeError, ValueError):
        pass

    tcp_sequence_class = ""
    try:
        # tcpsequence is {"class": str, "values": str, "difficulty": str}
        seq = nmap_host.tcpsequence
        if isinstance(seq, dict):
            tcp_sequence_class = seq.get("class", "") or ""
    except (AttributeError, TypeError):
        pass

    # Host-scope NSE script results. libnmap exposes these via
    # `nmap_host.scripts_results` as a list of dicts shaped like
    # `{"id": str, "output": str, ...}` — identical shape to per-port
    # script results, so we can reuse `_convert_script` directly.
    host_findings = [
        _convert_script(sr) for sr in (getattr(nmap_host, "scripts_results", None) or [])
    ]

    return ParsedHost(
        ip_address=nmap_host.address,
        host_state=state,
        hostname=hostname,
        mac_address=mac,
        mac_vendor=resolve_mac_vendor(mac),
        os_family=os_family,
        os_type=os_type,
        os_accuracy=os_accuracy,
        os_vendor=os_vendor,
        os_device_type=os_device_type,
        os_gen=os_gen,
        os_cpe=os_cpe,
        os_alternative_matches=os_alternative_matches,
        ports=ports,
        traceroute_hops=hops,
        host_findings=host_findings,
        distance_hops=distance_hops,
        uptime_seconds=uptime_seconds,
        tcp_sequence_class=tcp_sequence_class,
        # last_boot_at left as None at parse time; persist() derives it
        # from scan.completed_at - uptime_seconds so the displayed time
        # matches when the *scan ran*, not when parse-time happens to be.
    )


def _convert_port(nmap_service, nmap_host) -> ParsedPort:
    """Convert a libnmap `NmapService` to our `ParsedPort`."""
    protocol_map = {
        "tcp": ProtocolChoices.TCP,
        "udp": ProtocolChoices.UDP,
        "sctp": ProtocolChoices.SCTP,
    }
    state_map = {
        "open": PortStateChoices.OPEN,
        "closed": PortStateChoices.CLOSED,
        "filtered": PortStateChoices.FILTERED,
        "unfiltered": PortStateChoices.UNFILTERED,
        "open|filtered": PortStateChoices.OPEN_FILTERED,
        "closed|filtered": PortStateChoices.CLOSED_FILTERED,
    }

    service_dict = nmap_service.service_dict or {}
    cpe_list = [str(c) for c in (nmap_service.cpelist or [])]

    vulns = []
    # NSE script output is keyed by script name. We treat *every* script
    # output as a finding — the severity stays "unknown" unless the output
    # parses to something more specific (vulners format is heuristically
    # parsed below).
    for script in nmap_service.scripts_results or []:
        vulns.append(_convert_script(script))

    # Richer state-reason data. libnmap exposes these as attributes when the
    # XML has them; older nmap output (or some scan types) may not populate
    # all three, so we guard each access. The `reason` field is universal —
    # every port report includes one.
    state_reason = getattr(nmap_service, "reason", "") or ""
    state_reason_ttl: int | None = None
    try:
        ttl = getattr(nmap_service, "reason_ttl", None)
        if ttl:
            state_reason_ttl = int(ttl)
    except (TypeError, ValueError):
        pass
    # state_reason_ip is VarbinaryIPField (null=True) — coerce empty/missing to
    # None, not "". Empty string is not a valid IP and the field rejects it.
    _raw_reason_ip = getattr(nmap_service, "reason_ip", None)
    state_reason_ip: str | None = _raw_reason_ip if _raw_reason_ip else None
    tunnel = service_dict.get("tunnel", "") or ""
    service_fp = getattr(nmap_service, "servicefp", "") or ""

    return ParsedPort(
        port=nmap_service.port,
        protocol=protocol_map.get(nmap_service.protocol, ProtocolChoices.TCP),
        state=state_map.get(nmap_service.state, PortStateChoices.OPEN),
        service_name=nmap_service.service or "",
        banner=nmap_service.banner or "",
        product=service_dict.get("product", ""),
        version=service_dict.get("version", ""),
        extra_info=service_dict.get("extrainfo", ""),
        cpe=cpe_list,
        vulnerabilities=vulns,
        state_reason=state_reason,
        state_reason_ttl=state_reason_ttl,
        state_reason_ip=state_reason_ip,
        tunnel=tunnel,
        service_fp=service_fp,
    )


def _convert_script(script_result: dict) -> ParsedVulnerability:
    """Convert a libnmap script result dict to a `ParsedVulnerability`.

    libnmap returns NSE script output as a `{"id": str, "output": str, ...}`
    dict. We use the script ID as `nse_script`. Severity guessing is
    deliberately conservative — only the `vulners` format gives us anything
    machine-readable.
    """
    name = script_result.get("id", "")
    output = script_result.get("output", "")
    severity = _guess_severity(name, output)
    references = _extract_references(output)
    # `elements` is libnmap's parse of <elem>/<table> children. Most scripts
    # emit some — ssl-cert is the canonical example with subject/issuer/cert
    # nested dicts. We store it as-is; downstream queries can do JSON path
    # lookups like elements__cert__validity__notAfter__lt=<date>.
    elements = script_result.get("elements") or {}
    return ParsedVulnerability(
        nse_script=name,
        output=output,
        severity=severity,
        references=references,
        elements=elements,
    )


def _guess_severity(script_name: str, output: str) -> str:
    """Heuristic severity from script name + output text.

    `vulners` and `vuln*` script families produce CVSS scores in their
    output — we parse the highest score we see. Other scripts default to
    `info` (informational) or `unknown` for ambiguous cases.
    """
    if script_name == "vulners" or script_name.startswith("vuln"):
        # Look for a CVSS-style number: "CVE-2024-1234   7.5    https://..."
        # Naive but works for the standard vulners output format.
        max_score = 0.0
        for token in output.split():
            try:
                val = float(token)
            except ValueError:
                continue
            if 0.0 <= val <= 10.0 and val > max_score:
                max_score = val
        if max_score >= 9.0:
            return SeverityChoices.CRITICAL
        if max_score >= 7.0:
            return SeverityChoices.HIGH
        if max_score >= 4.0:
            return SeverityChoices.MEDIUM
        if max_score > 0:
            return SeverityChoices.LOW
        return SeverityChoices.UNKNOWN
    if script_name.startswith(("http-", "ssl-", "ssh-", "smb-")):
        return SeverityChoices.INFO
    return SeverityChoices.UNKNOWN


def _extract_references(output: str) -> list[str]:
    """Pull http(s):// URLs out of script output for the references list."""
    refs = []
    for token in output.split():
        if token.startswith(("http://", "https://")):
            # Strip trailing punctuation that often follows URLs in prose
            cleaned = token.rstrip(".,;:)\"'")
            if cleaned not in refs:
                refs.append(cleaned)
    return refs


def _extract_traceroute(nmap_host) -> list[ParsedHop]:
    """Pull traceroute hops out of an `NmapHost`.

    libnmap exposes `_NmapHost__trace` as the raw dict from the XML
    <trace> element. Defensive — many scan profiles don't enable
    --traceroute and the attribute is absent.
    """
    raw_trace = getattr(nmap_host, "_NmapHost__trace", None) or {}
    hops_raw = raw_trace.get("hops") or []
    out: list[ParsedHop] = []
    for h in hops_raw:
        try:
            hop_no = int(h.get("ttl", 0))
        except (TypeError, ValueError):
            continue
        rtt_raw = h.get("rtt")
        rtt: float | None
        try:
            rtt = float(rtt_raw) if rtt_raw not in (None, "") else None
        except (TypeError, ValueError):
            rtt = None
        out.append(
            ParsedHop(
                hop_number=hop_no,
                hop_ip=h.get("ipaddr", "") or "",
                hop_hostname=h.get("host", "") or "",
                rtt_ms=rtt,
            )
        )
    return out


# ----------------------------------------------------------------------------
# Persistence — only place that talks to the ORM.
# ----------------------------------------------------------------------------


def persist(scan: Scan, parsed: list[ParsedHost], report: ParsedReport | None = None) -> dict:
    """Write parsed hosts/ports/etc to the ORM, attached to `scan`.

    Auto-resolves `linked_device` by matching each discovered IP against
    `Device.primary_ip4/6`. Does NOT touch `linked_ipaddress` — that's
    only set by the Promote-to-IPAddress action.

    When `report` is provided, the Scan row is stamped with the report-level
    provenance (nmap_command / nmap_version / xml_version / ports_scanned).
    Optional for back-compat — older code paths pass hosts only.

    Returns a summary dict suitable for `Scan.summary`:
        {"hosts_up": N, "hosts_down": N, "ports_open": N,
         "vulnerabilities": N, "traceroute_hops": N}
    """
    # Imports inside the function to avoid Django-app-loading-order issues
    # when this module is imported at app-config time.
    from nautobot.dcim.models import Device

    from psycopg2.extras import DateTimeTZRange

    from nautobot_scanner.models import (
        DiscoveredHost,
        DiscoveredPort,
        TraceRouteHop,
        NseFinding,
    )

    summary = {
        "hosts_up": 0,
        "hosts_down": 0,
        "ports_open": 0,
        "vulnerabilities": 0,
        "traceroute_hops": 0,
    }

    # Bitemporal wire-time window for every host this scan observed.
    # If completed_at hasn't landed yet (e.g., agent still uploading),
    # leave the upper bound open — it'll be closed by Scan.completed_at
    # being set later, but the host row's valid_during stays "as-of-now"
    # for diff/audit queries that need a moment-in-time anchor.
    valid_during = DateTimeTZRange(
        lower=scan.started_at,
        upper=scan.completed_at,  # may be None — that's fine, range stays open-ended
        bounds="[)",
    )

    # Derive a stable "as of" moment for last_boot_at calculations: prefer
    # the scan's completion time, fall back to its start time, last resort
    # is "now". This anchors uptime → boot-time deterministically based on
    # WHEN the scan ran, not when the parser happens to run.
    import datetime as _dt
    boot_anchor = scan.completed_at or scan.started_at or _dt.datetime.now(_dt.timezone.utc)

    for ph in parsed:
        # Auto-resolve linked Device by primary IP match.
        # We look at primary_ip4 OR primary_ip6 since the discovered host
        # could be either. Falls back to None if no match.
        linked_device = (
            Device.objects.filter(primary_ip4__host=ph.ip_address).first()
            or Device.objects.filter(primary_ip6__host=ph.ip_address).first()
        )

        # Derive last_boot_at if we got uptime info. Storing the absolute
        # boot time means filters/sorts work in the DB ("hosts booted in
        # the last hour") without needing to subtract uptime at query time.
        last_boot_at = (
            boot_anchor - _dt.timedelta(seconds=ph.uptime_seconds)
            if ph.uptime_seconds
            else None
        )

        host = DiscoveredHost.objects.create(
            scan=scan,
            ip_address=ph.ip_address,
            mac_address=ph.mac_address,
            mac_vendor=ph.mac_vendor,
            hostname=ph.hostname,
            os_family=ph.os_family,
            os_type=ph.os_type,
            os_accuracy=ph.os_accuracy,
            os_vendor=ph.os_vendor,
            os_device_type=ph.os_device_type,
            os_gen=ph.os_gen,
            os_cpe=ph.os_cpe,
            os_alternative_matches=ph.os_alternative_matches,
            host_state=ph.host_state,
            linked_device=linked_device,
            distance_hops=ph.distance_hops,
            uptime_seconds=ph.uptime_seconds,
            last_boot_at=last_boot_at,
            tcp_sequence_class=ph.tcp_sequence_class,
            valid_during=valid_during,
            # recorded_during defaults to [now(), None) via the model default
            # entry_id defaults to a fresh uuid4 via the model default
        )

        if ph.host_state == HostStateChoices.UP:
            summary["hosts_up"] += 1
        elif ph.host_state == HostStateChoices.DOWN:
            summary["hosts_down"] += 1

        for pp in ph.ports:
            port = DiscoveredPort.objects.create(
                discovered_host=host,
                port=pp.port,
                protocol=pp.protocol,
                state=pp.state,
                service_name=pp.service_name,
                banner=pp.banner,
                product=pp.product,
                version=pp.version,
                extra_info=pp.extra_info,
                cpe=pp.cpe,
                state_reason=pp.state_reason,
                state_reason_ttl=pp.state_reason_ttl,
                state_reason_ip=pp.state_reason_ip,
                tunnel=pp.tunnel,
                service_fp=pp.service_fp,
            )
            if pp.state == PortStateChoices.OPEN:
                summary["ports_open"] += 1

            for pv in pp.vulnerabilities:
                NseFinding.objects.create(
                    discovered_port=port,
                    nse_script=pv.nse_script,
                    output=pv.output,
                    severity=pv.severity,
                    references=pv.references,
                    elements=pv.elements,
                )
                summary["vulnerabilities"] += 1

        # Host-scope NSE findings (smb-os-discovery, snmp-info, ssh-hostkey, ...).
        # No port FK on these — the CheckConstraint requires exactly one parent.
        for hf in ph.host_findings:
            NseFinding.objects.create(
                discovered_host=host,
                nse_script=hf.nse_script,
                output=hf.output,
                severity=hf.severity,
                references=hf.references,
                elements=hf.elements,
            )
            summary["vulnerabilities"] += 1

        for hop in ph.traceroute_hops:
            TraceRouteHop.objects.create(
                discovered_host=host,
                hop_number=hop.hop_number,
                hop_ip=hop.hop_ip,
                hop_hostname=hop.hop_hostname,
                rtt_ms=hop.rtt_ms,
            )
            summary["traceroute_hops"] += 1

    # Stamp report-level provenance on the Scan row, if the caller provided
    # it. The ingest path (api/views.py:ScanIngestView) flips status +
    # completed_at + summary + ingestion_token=None in its own save() call,
    # so we use a separate update() here to avoid clobbering those fields.
    if report is not None:
        updates = {}
        if report.nmap_command:
            updates["nmap_command"] = report.nmap_command
        if report.nmap_version:
            updates["nmap_version"] = report.nmap_version
        if report.xml_version:
            updates["xml_version"] = report.xml_version
        if report.ports_scanned is not None:
            updates["ports_scanned"] = report.ports_scanned
        if updates:
            from nautobot_scanner.models import Scan as _Scan
            _Scan.objects.filter(pk=scan.pk).update(**updates)

    return summary
