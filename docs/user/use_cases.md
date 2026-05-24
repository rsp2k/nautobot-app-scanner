# Use Cases

Practical operational queries the app makes easy. Most of these are
GraphQL- or ORM-shaped — copy them into nbshell or the GraphQL UI.

## "What hosts in this prefix have I never scanned?"

```python
from nautobot.ipam.models import Prefix, IPAddress
from nautobot_scanner.models import DiscoveredHost

prefix = Prefix.objects.get(prefix="10.50.0.0/24")
known_ips = set(ip.host for ip in IPAddress.objects.filter(parent=prefix))
scanned_ips = set(
    str(dh.ip_address)
    for dh in DiscoveredHost.objects.filter(scan__target_prefixes=prefix)
)
unscanned = known_ips - scanned_ips
```

## "Which devices have SMB (port 445) open right now?"

```python
from nautobot_scanner.models import DiscoveredPort

DiscoveredPort.objects.filter(
    port=445,
    protocol="tcp",
    state="open",
    discovered_host__linked_device__isnull=False,
).select_related("discovered_host__linked_device").values_list(
    "discovered_host__linked_device__name", "discovered_host__ip_address"
)
```

## "What CVEs did vulners flag against this VLAN's web servers?"

```python
from nautobot_scanner.models import VulnerabilityFinding

VulnerabilityFinding.objects.filter(
    severity__in=["high", "critical"],
    discovered_port__discovered_host__scan__target_prefixes__prefix="10.20.0.0/24",
    discovered_port__service_name__icontains="http",
).select_related("discovered_port__discovered_host").order_by("-severity")
```

## "Which discovered hosts in last night's scan don't have a matching IPAddress?"

```python
from datetime import timedelta
from django.utils import timezone
from nautobot_scanner.models import DiscoveredHost

since = timezone.now() - timedelta(hours=24)
DiscoveredHost.objects.filter(
    scan__completed_at__gte=since,
    host_state="up",
    linked_ipaddress__isnull=True,
)
```

These are candidates for the **Promote to IPAddress** action.

## "Which agents haven't checked in recently?"

```python
from datetime import timedelta
from django.utils import timezone
from nautobot_scanner.models import ScannerAgent

threshold = timezone.now() - timedelta(minutes=10)
stale = ScannerAgent.objects.filter(
    agent_type="remote",
    last_seen__lt=threshold,
)
```

The `MarkStaleAgents` Job (Phase 11) automates flipping these to
`status=offline`, but you can query them directly anytime.

## "Show me a host's full port history across all scans"

```python
from nautobot_scanner.models import DiscoveredHost

DiscoveredHost.objects.filter(
    ip_address="10.50.0.42",
).order_by("-scan__started_at").prefetch_related(
    "ports", "ports__vulnerabilities"
)
```

Each `DiscoveredHost` row is per-scan, so you get one row per scan
that touched that IP — perfect for "did this port open up sometime
in the last week?" analysis.

## "Which prefixes have NEVER been scanned?"

```python
from nautobot.ipam.models import Prefix

Prefix.objects.filter(scans__isnull=True)  # the related_name from Scan.target_prefixes
```

(Add `, status__name="Active"` if you want to limit to active prefixes.)
