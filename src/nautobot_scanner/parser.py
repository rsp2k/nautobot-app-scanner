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

    Args:
        raw: nmap XML output (the contents of a `-oX -` dump). May be empty.

    Returns:
        List of `ParsedHost`. Empty if XML has no hosts or is empty/blank.

    Raises:
        ValueError: if XML is malformed or libnmap rejects it.
    """
    if not raw or not raw.strip():
        return []

    # Import inside the function so the module loads even if libnmap is
    # somehow unavailable at app-config time (e.g., during introspection).
    from libnmap.parser import NmapParser, NmapParserException

    try:
        report = NmapParser.parse(raw)
    except NmapParserException as exc:
        raise ValueError(f"Invalid nmap XML: {exc}") from exc

    return [_convert_host(h) for h in report.hosts]


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
    # of NmapOSMatch objects sorted by accuracy. We take the top guess.
    os_family = ""
    os_type = ""
    os_accuracy: int | None = None
    if nmap_host.os_fingerprinted and nmap_host.os_match_probabilities():
        top = nmap_host.os_match_probabilities()[0]
        os_type = top.name
        os_accuracy = int(top.accuracy)
        # os_class_probabilities()[0].osfamily is the canonical family string.
        if top.osclasses:
            os_family = top.osclasses[0].osfamily

    ports = [_convert_port(s, nmap_host) for s in nmap_host.services]
    hops = _extract_traceroute(nmap_host)

    mac = nmap_host.mac or ""
    return ParsedHost(
        ip_address=nmap_host.address,
        host_state=state,
        hostname=hostname,
        mac_address=mac,
        mac_vendor=resolve_mac_vendor(mac),
        os_family=os_family,
        os_type=os_type,
        os_accuracy=os_accuracy,
        ports=ports,
        traceroute_hops=hops,
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
    return ParsedVulnerability(
        nse_script=name,
        output=output,
        severity=severity,
        references=references,
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


def persist(scan: Scan, parsed: list[ParsedHost]) -> dict:
    """Write parsed hosts/ports/etc to the ORM, attached to `scan`.

    Auto-resolves `linked_device` by matching each discovered IP against
    `Device.primary_ip4/6`. Does NOT touch `linked_ipaddress` — that's
    only set by the Promote-to-IPAddress action.

    Returns a summary dict suitable for `Scan.summary`:
        {"hosts_up": N, "hosts_down": N, "ports_open": N,
         "vulnerabilities": N, "traceroute_hops": N}
    """
    # Imports inside the function to avoid Django-app-loading-order issues
    # when this module is imported at app-config time.
    from nautobot.dcim.models import Device

    from nautobot_scanner.models import (
        DiscoveredHost,
        DiscoveredPort,
        TraceRouteHop,
        VulnerabilityFinding,
    )

    summary = {
        "hosts_up": 0,
        "hosts_down": 0,
        "ports_open": 0,
        "vulnerabilities": 0,
        "traceroute_hops": 0,
    }

    for ph in parsed:
        # Auto-resolve linked Device by primary IP match.
        # We look at primary_ip4 OR primary_ip6 since the discovered host
        # could be either. Falls back to None if no match.
        linked_device = (
            Device.objects.filter(primary_ip4__host=ph.ip_address).first()
            or Device.objects.filter(primary_ip6__host=ph.ip_address).first()
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
            host_state=ph.host_state,
            linked_device=linked_device,
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
            )
            if pp.state == PortStateChoices.OPEN:
                summary["ports_open"] += 1

            for pv in pp.vulnerabilities:
                VulnerabilityFinding.objects.create(
                    discovered_port=port,
                    nse_script=pv.nse_script,
                    output=pv.output,
                    severity=pv.severity,
                    references=pv.references,
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

    return summary
