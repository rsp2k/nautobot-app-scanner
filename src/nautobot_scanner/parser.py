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
    # Phase F: how + how-confidently nmap identified the service
    service_method: str = ""             # "table" (port-number lookup) vs "probed" (-sV)
    service_conf: int | None = None      # 1..10 confidence score


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
    # Phase F completeness sweep:
    hostnames: list[str] = field(default_factory=list)  # full PTR list; `hostname` denormalized first
    ip_sequence_class: str = ""                         # OS-fingerprint companion to TCP seq class
    extraports: dict = field(default_factory=dict)      # {state, count, reasons:[{reason,count}]}


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


# ----------------------------------------------------------------------------
# Phase G — pluggable parser dispatch + dig parser
# ----------------------------------------------------------------------------


def _parse_dns_answer_records(body: str) -> list[dict]:
    """Extract `name TTL IN TYPE value` records from dig/drill text output.

    Both tools format answer-section lines identically:
        example.com.    3600    IN  A   93.184.216.34
    Lines starting with ``;`` (drill section headers, dig comments) and
    blank lines are skipped. Returns the records as plain dicts ready
    to land in an NseFinding.elements JSONField.
    """
    records: list[dict] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) == 5 and parts[2] == "IN":
            records.append({
                "name": parts[0],
                "ttl": parts[1],
                "type": parts[3],
                "value": parts[4],
            })
    return records


def parse_dig_text(raw: str, targets: list[str]) -> tuple[ParsedReport, list[ParsedHost]]:
    """Minimal dig parser — one ParsedHost per target, dig text as a finding.

    dig's text output (``+noall +answer``) is line-oriented and hard to
    split per target when multiple are queried in one run. For Phase G
    we punt: every target becomes a ParsedHost with state=up, and the
    full dig output is attached as a single host-scope finding. The
    existing UI (host detail → Host Findings panel, finding detail
    page with structured-data block) renders it cleanly.

    A future "smart" dig parser could split the answer section by the
    question that produced each record group and emit one finding per
    record (with `elements={'type': 'A', 'ttl': 300, 'value': ...}`),
    but that's a tightening, not a foundation requirement.
    """
    out: list[ParsedHost] = []
    body = (raw or "").strip()

    records = _parse_dns_answer_records(body)
    finding_elements = {"records": records, "record_count": len(records)}
    has_answers = bool(records)

    for tgt in targets:
        ph = ParsedHost(
            ip_address=tgt,
            host_state=HostStateChoices.UP if has_answers else HostStateChoices.UNKNOWN,
            host_findings=[
                ParsedVulnerability(
                    nse_script="dig-answer",
                    output=body or "(no output)",
                    severity=SeverityChoices.INFO,
                    elements=finding_elements,
                ),
            ],
        )
        out.append(ph)

    return ParsedReport(), out


def parse_drill_text(raw: str, targets: list[str]) -> tuple[ParsedReport, list[ParsedHost]]:
    """drill parser — like dig, plus DNSSEC validation status from flags.

    drill emits the same ``name TTL IN TYPE value`` answer-section lines
    that dig does (so we reuse ``_parse_dns_answer_records``), but it
    ALSO includes a ``flags:`` header where ``ad`` (Authenticated Data)
    means the DNSSEC chain validated all the way to a trust anchor.
    That bit is the whole reason to prefer drill over dig for a DNSSEC
    audit, so we surface it as a top-level element on the finding:

        elements = {
            "records": [...],
            "record_count": N,
            "dnssec_authenticated": True | False | None,
            "rcode": "NOERROR" | "NXDOMAIN" | ...,
        }

    The severity escalates to ``MEDIUM`` when the operator asked for
    DNSSEC chain validation (``-D`` or ``-DT`` in tool_arguments) and
    the chain did NOT validate — that's the actionable signal worth
    flagging visibly on the finding list.
    """
    out: list[ParsedHost] = []
    body = (raw or "").strip()

    records = _parse_dns_answer_records(body)

    # Scan for the flags line — only present once per response.
    # Format: ";; flags: qr rd ra ad ; QUERY: 1, ANSWER: 3, ..."
    dnssec_authenticated: bool | None = None
    rcode: str = ""
    for line in body.splitlines():
        line = line.strip()
        if line.startswith(";; flags:"):
            # Tokenize between "flags:" and the trailing ";"
            after_flags = line.split("flags:", 1)[1].split(";", 1)[0].strip()
            flag_set = set(after_flags.split())
            dnssec_authenticated = "ad" in flag_set
        elif line.startswith(";; ->>HEADER<<-"):
            # Format: ";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 35349"
            for part in line.split(","):
                part = part.strip()
                if part.startswith("rcode:"):
                    rcode = part.split(":", 1)[1].strip()

    finding_elements: dict = {
        "records": records,
        "record_count": len(records),
        "dnssec_authenticated": dnssec_authenticated,
        "rcode": rcode,
    }
    has_answers = bool(records)

    # Severity heuristic: if the operator asked for DNSSEC validation
    # (the dnssec_authenticated bit got set either True or False) and
    # it came back False, that's worth flagging as MEDIUM. Otherwise
    # informational.
    severity = (
        SeverityChoices.MEDIUM
        if dnssec_authenticated is False
        else SeverityChoices.INFO
    )

    for tgt in targets:
        ph = ParsedHost(
            ip_address=tgt,
            host_state=HostStateChoices.UP if has_answers else HostStateChoices.UNKNOWN,
            host_findings=[
                ParsedVulnerability(
                    nse_script="drill-answer",
                    output=body or "(no output)",
                    severity=severity,
                    elements=finding_elements,
                ),
            ],
        )
        out.append(ph)

    return ParsedReport(), out


# ----------------------------------------------------------------------------
# Phase J — curl / mtr / masscan / openssl-s_client parsers
# ----------------------------------------------------------------------------


def parse_curl_text(raw: str, targets: list[str]) -> tuple[ParsedReport, list[ParsedHost]]:
    """Parse curl headers + summary line into structured elements.

    Wire format from ``build_curl_argv``: response headers (one per
    line, ``Key: Value``), a blank line marking HTTP boundary, then a
    summary line:
        ``---CURL-SUMMARY--- STATUS=200 SIZE=528 TIME=0.075 REDIRECTS=0 URL=https://...``

    With multiple targets, curl writes the full headers+summary block
    per URL in sequence — we split on the ``---CURL-SUMMARY---`` token
    so each chunk contains exactly one URL's headers + its summary.

    Severity heuristic:
      - status >= 500: medium (server error)
      - status >= 400: info (client error — often expected from probes)
      - num_redirects > 0 and final URL off-original-domain: medium
        (open-redirect surface; flagged so it's visible in lists)
      - otherwise: info
    """
    body = (raw or "").strip()
    out: list[ParsedHost] = []
    if not body or not targets:
        return ParsedReport(), out

    # Split into per-URL chunks. Every chunk contains a headers block
    # and a single summary line. First chunk has no leading marker;
    # split() yields it as the prefix.
    chunks = body.split("---CURL-SUMMARY---")
    # Drop the trailing empty string if the output ended with a summary.
    summaries = chunks[1:]
    headers_blocks = chunks[:-1] if len(chunks) > 1 else chunks

    # Pair (headers_block, summary_line) per target. If counts don't
    # line up (rare — curl glitched), zip stops at the shorter.
    for i, tgt in enumerate(targets):
        headers_block = headers_blocks[i] if i < len(headers_blocks) else ""
        summary_line = summaries[i].strip() if i < len(summaries) else ""

        # Parse summary line: tokens like STATUS=200 SIZE=528 ...
        summary: dict = {}
        for token in summary_line.split():
            if "=" in token:
                k, v = token.split("=", 1)
                summary[k] = v

        # Parse headers — first line is the status line (HTTP/1.1 200 OK),
        # subsequent are Key: Value pairs. Take the LAST status line in
        # the block (chases redirects).
        headers: dict = {}
        status_line = ""
        for line in headers_block.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("HTTP/"):
                status_line = line
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        try:
            status_code = int(summary.get("STATUS", "0"))
        except (TypeError, ValueError):
            status_code = 0
        try:
            num_redirects = int(summary.get("REDIRECTS", "0"))
        except (TypeError, ValueError):
            num_redirects = 0
        try:
            time_total_s = float(summary.get("TIME", "0"))
            time_total_ms = round(time_total_s * 1000, 2)
        except (TypeError, ValueError):
            time_total_ms = 0.0

        elements = {
            "status_code": status_code,
            "status_line": status_line,
            "response_size": int(summary.get("SIZE", "0") or "0"),
            "time_total_ms": time_total_ms,
            "num_redirects": num_redirects,
            "url_effective": summary.get("URL", ""),
            "server": headers.get("server", "") or headers.get("Server", ""),
            "content_type": headers.get("content-type", "") or headers.get("Content-Type", ""),
            "headers": headers,
        }

        if status_code >= 500:
            severity = SeverityChoices.MEDIUM
        elif num_redirects > 0:
            # Detect off-domain redirect (open-redirect surface).
            # Crude check: if the URL host differs from the target host
            # by more than the obvious "added port" / "lowercased" cases.
            url = elements["url_effective"]
            tgt_host = tgt.split(":", 1)[0].lower() if tgt else ""
            redirected_off_domain = bool(
                tgt_host and url and tgt_host not in url.lower(),
            )
            severity = SeverityChoices.MEDIUM if redirected_off_domain else SeverityChoices.INFO
        else:
            severity = SeverityChoices.INFO

        out.append(ParsedHost(
            ip_address=tgt.split(":", 1)[0] or tgt,  # host part for the model
            host_state=HostStateChoices.UP if status_code else HostStateChoices.UNKNOWN,
            host_findings=[ParsedVulnerability(
                nse_script="curl-probe",
                output=f"{status_line}\n{headers_block}\n{summary_line}",
                severity=severity,
                elements=elements,
            )],
        ))
    return ParsedReport(), out


def parse_mtr_json(raw: str, targets: list[str]) -> tuple[ParsedReport, list[ParsedHost]]:
    """Parse mtr -j JSON output into per-hop path/latency findings.

    JSON shape (one report per invocation; mtr emits one report at a
    time so the file IS the report):
        {"report": {"mtr": {src, dst, ...},
                    "hubs": [{count, host, "Loss%", Snt, Last, Avg,
                              Best, Wrst, StDev}, ...]}}

    Severity:
      - target hop Loss% > 50: high (target unreachable / >half loss)
      - any-hop Loss% > 10: medium (intermittent path issue)
      - otherwise: info (clean baseline)

    Drift detection (avg-RTT change > 50ms from previous scan) is
    server-side bitemporal-diff territory — not part of the parser.
    """
    import json as _json
    out: list[ParsedHost] = []
    body = (raw or "").strip()
    if not body or not targets:
        return ParsedReport(), out

    try:
        data = _json.loads(body)
    except _json.JSONDecodeError as exc:
        raise ValueError(f"Invalid mtr JSON: {exc}") from exc

    report = data.get("report", {}) if isinstance(data, dict) else {}
    raw_hubs = report.get("hubs", []) if isinstance(report, dict) else []
    dst = (report.get("mtr") or {}).get("dst", "") if isinstance(report, dict) else ""

    hops: list[dict] = []
    max_loss_any = 0.0
    target_loss = 0.0
    for hub in raw_hubs:
        if not isinstance(hub, dict):
            continue
        try:
            loss = float(hub.get("Loss%", 0))
        except (TypeError, ValueError):
            loss = 0.0
        hops.append({
            "ttl": hub.get("count"),
            "host": hub.get("host", ""),
            "loss_pct": loss,
            "sent": hub.get("Snt"),
            "last_ms": hub.get("Last"),
            "avg_ms": hub.get("Avg"),
            "best_ms": hub.get("Best"),
            "worst_ms": hub.get("Wrst"),
            "jitter_ms": hub.get("StDev"),
        })
        if loss > max_loss_any:
            max_loss_any = loss
    if hops:
        target_loss = hops[-1]["loss_pct"]

    # Severity heuristic
    if target_loss > 50.0:
        severity = SeverityChoices.HIGH
    elif max_loss_any > 10.0:
        severity = SeverityChoices.MEDIUM
    else:
        severity = SeverityChoices.INFO

    target_reached = bool(hops) and target_loss < 100.0
    elements = {
        "target": dst,
        "hops": hops,
        "target_reached": target_reached,
        "max_hops_seen": len(hops),
        "max_loss_pct_any_hop": max_loss_any,
        "target_loss_pct": target_loss,
    }

    # One ParsedHost per target. mtr only takes one target per
    # invocation in practice, but we follow the multi-target contract
    # — same report attaches to each target.
    for tgt in targets:
        out.append(ParsedHost(
            ip_address=tgt,
            host_state=HostStateChoices.UP if target_reached else HostStateChoices.DOWN,
            host_findings=[ParsedVulnerability(
                nse_script="mtr-report",
                output=body,
                severity=severity,
                elements=elements,
            )],
        ))
    return ParsedReport(), out


def parse_masscan_json(raw: str, targets: list[str]) -> tuple[ParsedReport, list[ParsedHost]]:
    """Parse masscan -oJ JSON into ParsedHost + ParsedPort rows.

    Output is a JSON ARRAY of records (one per IP+timestamp), each:
        {"ip": "1.2.3.4", "timestamp": "...",
         "ports": [{"port": 80, "proto": "tcp", "status": "open",
                    "reason": "syn-ack", "ttl": 64,
                    "service": {"name": "...", "banner": "..."}}, ...]}

    Unlike dig/drill/curl/mtr which create host-scope FINDINGS, masscan
    output maps directly to the same shape nmap produces: hosts with
    ports. We bypass the host-findings path and emit ParsedHost rows
    with populated `ports` instead — the existing persist() loop turns
    them into DiscoveredPort records exactly like nmap output would.

    The ``targets`` arg is unused — masscan tells us which IPs it
    found open ports on, and that's authoritative.
    """
    import json as _json
    out: list[ParsedHost] = []
    body = (raw or "").strip()
    if not body:
        return ParsedReport(), out

    # masscan can emit either a JSON array (-oJ) or NDJSON if the
    # output is interrupted; handle both.
    try:
        # Try the array form first.
        records = _json.loads(body)
        if not isinstance(records, list):
            records = [records]
    except _json.JSONDecodeError:
        # Fall back to one-record-per-line; tolerate trailing commas
        # masscan sometimes leaves on partial output.
        records = []
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                records.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue

    # Aggregate ports per IP. masscan can emit multiple records for
    # the same IP (different timestamps as ports are discovered).
    state_map = {
        "open": PortStateChoices.OPEN,
        "closed": PortStateChoices.CLOSED,
        "filtered": PortStateChoices.FILTERED,
    }
    protocol_map = {
        "tcp": ProtocolChoices.TCP,
        "udp": ProtocolChoices.UDP,
        "sctp": ProtocolChoices.SCTP,
    }
    hosts_by_ip: dict[str, ParsedHost] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        ip = rec.get("ip", "")
        if not ip:
            continue
        if ip not in hosts_by_ip:
            hosts_by_ip[ip] = ParsedHost(ip_address=ip, host_state=HostStateChoices.UP)
        host = hosts_by_ip[ip]
        for port_entry in rec.get("ports", []):
            if not isinstance(port_entry, dict):
                continue
            try:
                port_num = int(port_entry.get("port", 0))
            except (TypeError, ValueError):
                continue
            if not port_num:
                continue
            proto = protocol_map.get(port_entry.get("proto", "tcp"), ProtocolChoices.TCP)
            state = state_map.get(port_entry.get("status", "open"), PortStateChoices.OPEN)
            svc = port_entry.get("service") if isinstance(port_entry.get("service"), dict) else {}
            host.ports.append(ParsedPort(
                port=port_num,
                protocol=proto,
                state=state,
                service_name=svc.get("name", "") if svc else "",
                banner=svc.get("banner", "") if svc else "",
                state_reason=port_entry.get("reason", "") or "",
                state_reason_ttl=port_entry.get("ttl"),
            ))

    out.extend(hosts_by_ip.values())
    return ParsedReport(), out


def parse_openssl_sclient_text(raw: str, targets: list[str]) -> tuple[ParsedReport, list[ParsedHost]]:
    """Parse openssl s_client output into per-target TLS findings.

    Wire format from ``build_openssl_sclient_argv``: per-target chunks
    delimited by ``===TARGET=<addr>===``. Each chunk includes the
    handshake transcript, certificate dump, and "Verify return code"
    line.

    We text-scrape rather than re-parse the PEM cert (would require
    cryptography lib) — gets us subject, issuer, notBefore, notAfter,
    verify result, cipher, protocol. SAN extraction would need a
    second openssl invocation (``openssl x509 -text -noout``); not
    worth the round-trip in v1 — operators who need SANs can read the
    raw output.

    Severity:
      - cert expires in < 7 days: high
      - cert expires in < 30 days: medium
      - Verify return code != 0 (anything but ok): medium
      - else: info
    """
    import datetime as _dt
    import re as _re
    out: list[ParsedHost] = []
    body = (raw or "").strip()
    if not body or not targets:
        return ParsedReport(), out

    # Split into per-target chunks. The first split-result is empty
    # (text starts with the sentinel) so we skip it.
    sentinel_re = _re.compile(r"===TARGET=([^=]+?)===")
    chunks = sentinel_re.split(body)
    # chunks layout: ["", target1, body1, target2, body2, ...]
    chunk_pairs: list[tuple[str, str]] = []
    for i in range(1, len(chunks), 2):
        tgt = chunks[i].strip()
        bod = chunks[i + 1] if i + 1 < len(chunks) else ""
        chunk_pairs.append((tgt, bod))

    # If the sentinel isn't present (single-target / wrapper skipped),
    # fall back to treating the whole body as one target's output.
    if not chunk_pairs and targets:
        chunk_pairs = [(targets[0], body)]

    now = _dt.datetime.now(_dt.timezone.utc)

    for tgt, chunk in chunk_pairs:
        # Extract fields. All are best-effort; missing values become "".
        subject = _first_match(r"^subject=(.+)$", chunk)
        issuer = _first_match(r"^issuer=(.+)$", chunk)
        # openssl 3.x emits cipher in the "New, TLSv1.3, Cipher is X" line.
        # openssl 1.1.x has a separate "Cipher    : X" line. Try both.
        cipher = _first_match(r"^\s*Cipher\s+:\s*(\S+)$", chunk) or \
                 _first_match(r"^New,\s+\S+,\s+Cipher is\s+(\S+)", chunk)
        # Protocol: again two forms across openssl versions.
        protocol = _first_match(r"^\s*Protocol\s*:\s*(\S+)$", chunk) or \
                   _first_match(r"^New,\s+(\S+),\s+Cipher", chunk)
        verify_msg = _first_match(r"^\s*Verify return code:\s*(.+)$", chunk)
        # Validity dates: openssl 3.x's cert-chain dump puts them on
        # ONE line: "   v:NotBefore: Apr  2 21:18:57 2026 GMT; NotAfter: Jul  1 21:24:46 2026 GMT"
        # Older form had separate "Not Before:" / "Not After:" lines.
        # Try the combined form first, fall back to the standalone form.
        validity_combined = _first_match(
            r"v:NotBefore:\s*(.+?GMT);\s*NotAfter:\s*(.+?GMT)", chunk,
        )
        if validity_combined:
            # _first_match returns only group 1; re-match to grab both.
            import re as _re
            m = _re.search(
                r"v:NotBefore:\s*(.+?GMT);\s*NotAfter:\s*(.+?GMT)", chunk,
            )
            not_before_s = m.group(1).strip() if m else ""
            not_after_s = m.group(2).strip() if m else ""
        else:
            not_before_s = _first_match(r"\s+Not Before\s*:\s*(.+)", chunk)
            not_after_s = _first_match(r"\s+Not After\s*:\s*(.+)", chunk)

        # Parse openssl date format: "May 27 19:45:00 2026 GMT"
        def _parse_openssl_dt(s: str) -> _dt.datetime | None:
            if not s:
                return None
            try:
                return _dt.datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=_dt.timezone.utc,
                )
            except ValueError:
                return None

        not_before = _parse_openssl_dt(not_before_s)
        not_after = _parse_openssl_dt(not_after_s)

        days_until_expiry: int | None = None
        if not_after is not None:
            days_until_expiry = (not_after - now).days

        verify_ok = bool(verify_msg and verify_msg.strip().startswith("0 (ok)"))

        # Severity
        if days_until_expiry is not None and days_until_expiry < 7:
            severity = SeverityChoices.HIGH
        elif days_until_expiry is not None and days_until_expiry < 30:
            severity = SeverityChoices.MEDIUM
        elif verify_msg and not verify_ok:
            severity = SeverityChoices.MEDIUM
        else:
            severity = SeverityChoices.INFO

        elements = {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat() if not_before else "",
            "not_after": not_after.isoformat() if not_after else "",
            "days_until_expiry": days_until_expiry,
            "cipher": cipher,
            "protocol": protocol,
            "verify_ok": verify_ok,
            "verify_message": verify_msg,
        }

        # Target may be host:port — store host part in ip_address.
        ip_part = tgt.split(":", 1)[0]
        out.append(ParsedHost(
            ip_address=ip_part or tgt,
            host_state=HostStateChoices.UP if verify_msg else HostStateChoices.UNKNOWN,
            host_findings=[ParsedVulnerability(
                nse_script="openssl-s_client",
                output=chunk.strip()[:4000],  # cap raw at 4KB — full chain is huge
                severity=severity,
                elements=elements,
            )],
        ))
    return ParsedReport(), out


def _first_match(pattern: str, text: str) -> str:
    """Return the first regex capture group's match in `text`, or ''."""
    import re as _re
    m = _re.search(pattern, text, _re.MULTILINE)
    return m.group(1).strip() if m else ""


# Map ToolChoices values → parser function. The dispatch picks one
# at ingest based on the agent's X-Tool header (or the scan's profile).
# Adding a new tool: write a parse_<tool>_<format>() returning the same
# (ParsedReport, list[ParsedHost]) tuple, then register it here.
#
# Signatures differ slightly: nmap doesn't need targets (the XML names
# its own hosts); others do. dispatch_parser() normalizes the call.
PARSERS: dict[str, object] = {
    "nmap": parse_xml_with_report,
    "dig": parse_dig_text,
    "drill": parse_drill_text,
    "curl": parse_curl_text,
    "mtr": parse_mtr_json,
    "masscan": parse_masscan_json,
    "openssl-s_client": parse_openssl_sclient_text,
}


def dispatch_parser(
    tool: str,
    raw: str,
    targets: list[str] | None = None,
) -> tuple[ParsedReport, list[ParsedHost]]:
    """Route raw tool output to its parser. Default to nmap for back-compat."""
    parser_fn = PARSERS.get(tool or "nmap")
    if parser_fn is None:
        raise ValueError(f"No parser registered for tool: {tool!r}")
    # nmap's signature is (raw,) — others take targets too.
    if tool == "nmap" or tool == "":
        return parser_fn(raw)  # type: ignore[no-any-return,operator]
    return parser_fn(raw, targets or [])  # type: ignore[no-any-return,operator]


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
    # Phase F: keep the full list too. Some hosts have user-supplied + PTR
    # + secondary PTRs; the denormalized single one stays in `hostname` for
    # table cells, the rest go into `hostnames` for full-text search.
    hostnames = list(nmap_host.hostnames or [])

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

    # Phase F: companion IP ID sequence class (libnmap exposes it as a
    # plain string OR dict depending on version — handle both).
    ip_sequence_class = ""
    try:
        ipseq = getattr(nmap_host, "ipsequence", None)
        if isinstance(ipseq, dict):
            ip_sequence_class = ipseq.get("class", "") or ""
        elif isinstance(ipseq, str):
            ip_sequence_class = ipseq
    except (AttributeError, TypeError):
        pass

    # Phase F: extraports summary ("997 filtered ports (no-response)").
    # libnmap exposes `extraports_state` as a NESTED dict — keys "state"
    # AND "count" both point to the SAME inner dict shape
    # {'state': str, 'count': str}. Quirk of libnmap; we unwrap once.
    # `extraports_reasons` is a list of {reason, count, proto, ports} dicts.
    extraports: dict = {}
    try:
        ep_state = getattr(nmap_host, "extraports_state", None)
        ep_reasons = getattr(nmap_host, "extraports_reasons", None) or []
        # Walk one level in if the value is itself a dict (libnmap quirk).
        inner = ep_state
        if isinstance(inner, dict) and isinstance(inner.get("state"), dict):
            inner = inner["state"]
        if isinstance(inner, dict) and inner.get("count"):
            extraports = {
                "state": inner.get("state", "") or "",
                "count": int(inner.get("count", 0)),
                "reasons": [
                    {"reason": r.get("reason", ""), "count": int(r.get("count", 0))}
                    for r in ep_reasons
                    if isinstance(r, dict)
                ],
            }
    except (AttributeError, TypeError, ValueError):
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
        hostnames=hostnames,
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
        ip_sequence_class=ip_sequence_class,
        extraports=extraports,
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
    # Phase F: how nmap identified this service + confidence (1..10).
    # "method" lives in service_dict — values are "table" (just looked up
    # the port in nmap-services) or "probed" (actually fingerprinted with
    # -sV). "conf" is libnmap's confidence score.
    service_method = service_dict.get("method", "") or ""
    service_conf: int | None = None
    try:
        c = service_dict.get("conf")
        if c is not None and str(c) != "":
            service_conf = int(c)
    except (TypeError, ValueError):
        pass

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
        service_method=service_method,
        service_conf=service_conf,
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
            hostnames=ph.hostnames,
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
            ip_sequence_class=ph.ip_sequence_class,
            extraports=ph.extraports,
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
                service_method=pp.service_method,
                service_conf=pp.service_conf,
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
