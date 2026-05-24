# Data Models

The app defines 7 models grouped into three concerns. Click into any
model for field-level reference.

## Identity

| Model | Base | Purpose |
|-------|------|---------|
| [`ScannerAgent`](scanneragent.md) | `PrimaryModel` | Who runs scans (local vs remote) |
| [`ScanProfile`](scanprofile.md) | `PrimaryModel` | Reusable nmap argument template |

## Execution

| Model | Base | Purpose |
|-------|------|---------|
| [`Scan`](scan.md) | `PrimaryModel` | One scan execution + lifecycle + raw XML |

## Results

| Model | Base | Purpose |
|-------|------|---------|
| [`DiscoveredHost`](discoveredhost.md) | `PrimaryModel` | One host nmap reported |
| [`DiscoveredPort`](discoveredport.md) | `BaseModel` | One port on a discovered host |
| [`VulnerabilityFinding`](vulnerabilityfinding.md) | `BaseModel` | One NSE finding on a port |
| [`TraceRouteHop`](traceroutehop.md) | `BaseModel` | One hop in a host's traceroute path |

## Relationship diagram

```
ScannerAgent ──┐
               │
               ├──FK──→ Scan ──FK──→ DiscoveredHost ──FK──→ DiscoveredPort ──FK──→ VulnerabilityFinding
               │         │             │                              
ScanProfile ───┘         │             └──FK──→ TraceRouteHop
                         │
            ┌────────────┤
            │            │
    M2M to ipam.Prefix   M2M to ipam.IPAddress
    (target_prefixes)    (target_ipaddresses)
```

Plus the links discovered hosts get back into Nautobot's IPAM and DCIM:

```
DiscoveredHost ──FK──→ ipam.IPAddress (linked_ipaddress, set by Promote action)
DiscoveredHost ──FK──→ dcim.Device    (linked_device, auto-resolved at ingest)
```

And the user binding for remote agents:

```
ScannerAgent ──OneToOne──→ auth.User (settings.AUTH_USER_MODEL — Nautobot's users.User)
```

## Base class choices

| Concern | Choice | Reason |
|---------|--------|--------|
| Anything that gets its own UI page | `PrimaryModel` | Status, tags, change-log, custom fields, GraphQL |
| Child records rendered nested in parent | `BaseModel` | Lightweight (UUID PK only); not bloated with status/tags |

See [Architecture Decisions](../dev/architecture.md) for the
reasoning behind these choices.
