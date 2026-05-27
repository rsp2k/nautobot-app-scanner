# Extending

Common extension points.

## Two extension axes: backends vs tools

These often get confused — they're orthogonal:

| Axis | What it controls | How you extend |
|---|---|---|
| **Backend** (`ScannerBackend` ABC) | *Where* a scan executes — in-worker (Local), remote agent (Remote), or some hypothetical third model (SSH-out-and-run, AWS Inspector wrapper) | One subclass per backend, register in `get_backend()` factory |
| **Tool** (`PARSERS` + `TOOL_REGISTRY` dicts) | *What binary* the backend invokes — `nmap`, `dig`, `drill`, `curl`, `mtr`, `masscan`, `openssl-s_client` | One entry per tool in each dict, plus a `ToolChoices` value |

Adding a new probe tool (`whois`, `nuclei`, `httpx`, etc.) is the
**tool axis**, not the backend axis — see the next section.

## Adding a custom tool

The dispatch is the simplest extension point in the codebase — three
small additions and a migration, no class hierarchy:

1. Add the value to `ToolChoices` in `choices.py`
2. Write `parse_<tool>_<format>(raw, targets) -> (ParsedReport, list[ParsedHost])`
   in `parser.py` and register it in `PARSERS`
3. Write `build_<tool>_argv(scan) -> list[str]` in `agent/agent.py`
   and register it in `TOOL_REGISTRY` with the right content-type
4. Add a migration seeding at least one example profile

See [ADR-013](architecture.md#adr-013-pluggable-parser-dispatch-multi-tool-agent-foundation)
for the design rationale and the regression-test reminder that
`set(ToolChoices) == set(PARSERS) == set(TOOL_REGISTRY)`.

## Adding a custom backend

The `ScannerBackend` abstract base class (`src/nautobot_scanner/backends/base.py`)
has one required method:

```python
class ScannerBackend(ABC):
    @abstractmethod
    def dispatch(self, scan: Scan) -> None:
        """Execute the scan however the backend likes. Persist results
        via parser.persist() (or directly via the ORM)."""
```

To add a new backend (e.g., an out-of-process worker, an SSH-jump
backend, a third-party scanner SaaS wrapper):

1. Create `src/nautobot_scanner/backends/mybackend.py`
2. Subclass `ScannerBackend` and implement `dispatch()`
3. Register in the `get_backend()` factory (`src/nautobot_scanner/backends/__init__.py`)
   keyed off some discriminator (a new `agent_type` choice, or an
   `agent.capabilities` flag, etc.)
4. If you're adding a new `agent_type`, also add the choice value to
   `AgentTypeChoices` in `choices.py` and write a migration

Re-use `parser.dispatch_parser()` to route raw output to the right
parser regardless of which tool the backend invoked.

## Adding a custom scan-result model

If you need richer scan output (e.g. SNMP data, packet captures, SSL
cert details parsed deeper than nmap reports), the right pattern is a
new `BaseModel` child off `DiscoveredHost` or `DiscoveredPort`:

```python
class SSLCertDetail(BaseModel):
    discovered_port = models.OneToOneField(
        to="nautobot_scanner.DiscoveredPort",
        on_delete=models.CASCADE,
        related_name="ssl_cert",
    )
    subject = models.CharField(max_length=512)
    issuer = models.CharField(max_length=512)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    sha256_fingerprint = models.CharField(max_length=64)
```

Then:

1. Add a migration
2. Add an `ObjectsTablePanel` to `DiscoveredPortUIViewSet.object_detail_content`
   (or wherever you want it surfaced)
3. Extend the parser to populate it if applicable

## Adding a template-content panel to another Nautobot model

Want scanner data to show up on, say, `circuits.Circuit` detail pages?

```python
# template_content.py
class CircuitScans(TemplateExtension):
    model = "circuits.circuit"

    def right_page(self):
        return self.render(
            "nautobot_scanner/inc/circuit_scans.html",
            extra_context={
                # build context from self.context["object"] (the Circuit)
                # e.g. by following Circuit -> termination -> IPAddress -> DiscoveredHost
            },
        )

template_extensions = [
    DeviceScans, IPAddressScans, PrefixScans,
    CircuitScans,  # add to the list
]
```

Then drop a template at `templates/nautobot_scanner/inc/circuit_scans.html`.

## Hooking into the DNS-record promotion path (Phase K)

For `tool in DNS_PRODUCING_TOOLS` (`{"dig", "drill"}`), the
`ScanIngestView` runs `dns_promote.promote_finding(finding)` against
every `NseFinding` produced by the scan. Each parsed answer record
gets dispatched through `dns_promote.PROMOTERS` (one entry per DNS
record type) into the right typed `nautobot-dns-models` row.

To add a new DNS record type (e.g., `CAA`, `DNSKEY`, `TLSA`):

1. Add a `_promote_caa(rec, finding, zone)` function in
   `dns_promote.py`. It receives the parsed wire-record dict, the
   source `NseFinding`, and the resolved `DNSZone` object; it should
   call `_upsert_with_amend(CAARecord, natural_key=..., wire_fields=...)`
   to handle the bitemporal-aware insert-or-amend, then call
   `_write_provenance(...)` to record the join row.
2. Register it in the `PROMOTERS` dispatch dict on the same module.
3. Add a test class to `tests/test_dns_promote.py` exercising the
   happy path plus the bitemporal-amend (changed wire data → second
   save rotates `entry_id`).

To add a new **DNS-producing tool** (e.g., a `host` or `nslookup`
parser), expand `DNS_PRODUCING_TOOLS` to include it. The parser must
populate `NseFinding.elements` with a key whose value is a
list-of-dicts shaped like dig/drill's `records: [{name, ttl, type,
value}, ...]`. The promoter is parser-tolerant on the exact shape but
requires those four keys per record.

See [`DnsRecordProvenance`](../models/dnsrecordprovenance.md) for the
sidecar model that captures each promotion and
[ADR-015](architecture.md#adr-015-promote-dig-and-drill-into-typed-dns-models)
for the design rationale (entry_id-via-composite-key, best-effort
promotion, A/AAAA IPAM-coupling gate).

## Hooking into the Promote workflow

The `DiscoveredHostPromoteView` (Phase 9) creates an `ipam.IPAddress`.
If you want side effects when a host is promoted (notify Slack, write
a custom field, etc.), register a `post_save` signal on `IPAddress`
that checks for a `DiscoveredHost` whose `linked_ipaddress` was just
set to this row.

```python
from django.db.models.signals import post_save
from django.dispatch import receiver
from nautobot.ipam.models import IPAddress

@receiver(post_save, sender=IPAddress)
def maybe_handle_promoted_ip(sender, instance, created, **kwargs):
    if not created:
        return
    promoted_from = instance.discovered_hosts.first()
    if promoted_from:
        # your side effect
        notify_slack(f"Promoted {instance} from scan {promoted_from.scan_id}")
```

Wire the receiver up in `signals.py` (`register_signals()` runs at
app-ready time).

## Adding a Nautobot Job that uses scanner data

Standard Nautobot pattern — see `nautobot.extras.jobs.Job` docs. To
operate on the most recent scan for each IPAddress:

```python
from nautobot.extras.jobs import Job
from nautobot_scanner.models import DiscoveredHost

class FlagHostsWithOpenSMB(Job):
    class Meta:
        name = "Flag hosts with open SMB"

    def run(self):
        for host in DiscoveredHost.objects.filter(
            ports__port=445, ports__protocol="tcp", ports__state="open",
            linked_device__isnull=False,
        ).distinct():
            self.logger.warning(f"{host.linked_device}: SMB open at {host.ip_address}")
```

## What's intentionally hard to extend

- **Adding fields to `DiscoveredHost` / `DiscoveredPort` directly** —
  these are derived from nmap output. New fields belong in either
  a `BaseModel` child or in `_custom_field_data` (which the
  `@extras_features("custom_fields")` decorator enables out of the box)
- **Replacing the agent auth model** — User + Token is intentional
  (see ADR-002). Custom auth is possible but requires writing a DRF
  authentication class and is not supported.
- **Mutating scan results post-ingest** — by design, `DiscoveredPort`
  / `NseFinding` / `TraceRouteHop` are immutable scan
  output. If you need to annotate them, use a `_custom_field_data`
  custom field on `DiscoveredHost`.
