# Extending

Common extension points.

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

To add a new backend (e.g., masscan, naabu, an out-of-process worker):

1. Create `src/nautobot_scanner/backends/mybackend.py`
2. Subclass `ScannerBackend` and implement `dispatch()`
3. Register in the `get_backend()` factory (`src/nautobot_scanner/backends/__init__.py`)
   keyed off some discriminator (a new `agent_type` choice, or an
   `agent.capabilities` flag, etc.)
4. If you're adding a new `agent_type`, also add the choice value to
   `AgentTypeChoices` in `choices.py` and write a migration

Re-use `parser.persist()` if your backend produces nmap-compatible XML;
write a tool-specific persistence function if not.

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
  / `VulnerabilityFinding` / `TraceRouteHop` are immutable scan
  output. If you need to annotate them, use a `_custom_field_data`
  custom field on `DiscoveredHost`.
