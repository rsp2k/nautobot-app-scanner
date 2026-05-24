# App Overview

<figure markdown>
![Scan detail page showing 4 hosts discovered](../images/scan-detail-completed.png)
<figcaption>A completed scan's detail page — stat cards summarize results, the right panel lists each `DiscoveredHost`.</figcaption>
</figure>

## What gets stored

The app turns nmap XML output into Nautobot ORM records. Each `Scan`
produces zero-or-more `DiscoveredHost` rows; each host can have ports,
vulnerability findings, and traceroute hops attached.

```
ScannerAgent ──┐
               ├──→ Scan ──→ DiscoveredHost ──┬──→ DiscoveredPort ──→ VulnerabilityFinding
ScanProfile ───┘             (linked_ipaddress, └──→ TraceRouteHop
                              linked_device)
```

| Layer | Models | Purpose |
|-------|--------|---------|
| **Identity** | `ScannerAgent`, `ScanProfile` | Who runs scans, with what nmap config |
| **Execution** | `Scan` | One scan run — agent + profile + IPAM targets + lifecycle state + raw XML |
| **Results** | `DiscoveredHost`, `DiscoveredPort`, `VulnerabilityFinding`, `TraceRouteHop` | What nmap actually found |

See the [Data Models reference](../models/index.md) for field-by-field
details.

## Where it integrates with the rest of Nautobot

| Nautobot model | Relationship | What it enables |
|----------------|-------------|-----------------|
| `ipam.Prefix` | `Scan.target_prefixes` (M2M) | Scan a whole prefix in one job |
| `ipam.IPAddress` | `Scan.target_ipaddresses` (M2M), `DiscoveredHost.linked_ipaddress` (FK) | Scan specific IPs; link discovered hosts back to known IPAM records |
| `dcim.Device` | `DiscoveredHost.linked_device` (FK) | Auto-resolved at ingest by matching scan IPs against `Device.primary_ip4/6` |
| `dcim.Location` | `ScannerAgent.location` (FK) | Annotate where each agent is deployed |
| `extras.JobResult` | `Scan.job_result` (FK) | Trace any Scan back to the Nautobot Job run that started it |
| `auth.User` (Nautobot's swapped `users.User`) | `ScannerAgent.user` (OneToOne) | DRF Token on this user authenticates remote agents |

## Scan lifecycle

```
                      LocalBackend                  RemoteBackend
                      (synchronous)                 (asynchronous)
                          │                              │
   RunScan Job  ──→  Scan(status=running)  ──→  Scan(status=pending,
                          │                            ingestion_token=<uuid>)
                          │                              │
                   nmap subprocess                Agent polls /pending-scans/,
                   parser.parse_xml               runs nmap,
                   parser.persist                 POSTs results to /ingest/
                          │                              │
                  Scan(status=completed)         Scan(status=completed,
                                                       ingestion_token=null)
```

Lifecycle states (`pending`, `running`, `completed`, `failed`,
`cancelled`) are first-class enum values — see
[`ScanStateChoices`](../models/scan.md).

## Read-only enrichment, with a promotion escape hatch

The app stores scan output in **separate models** from IPAM/DCIM. It
never silently creates an `ipam.IPAddress` from scan data — a transient
NAT, a misconfigured DHCP server, or a one-shot test container could
otherwise pollute your source-of-truth.

When a `DiscoveredHost` should become a real IPAddress, an authorized
user (with `ipam.add_ipaddress` permission) clicks **Promote to
IPAddress** on the host page. The form is pre-filled from the host's IP
and hostname; the user picks namespace/parent_prefix/status/tenant. See
[Promote to IPAddress](promotion.md) for the full flow.

## What's NOT in the app

To keep scope tight, the following were considered and explicitly
omitted:

- **Auto-sync IPAM from scans** — too risky (false positives become
  real IPAM records). Use the Promote action instead.
- **`ARPBinding` model** — `DiscoveredHost.mac_address` already
  captures ARP-resolved MACs; a separate model invited duplicate-truth
  bugs.
- **Custom cron scheduler** — Nautobot's built-in Job scheduler does
  this; we add a Job (`RunScan`) and let operators schedule it.
- **`ServiceFingerprint` model** — fingerprint fields (`product`,
  `version`, `extra_info`, `cpe`) live directly on `DiscoveredPort` —
  nmap's `-sV` pass produces them with the `service_name` anyway,
  so splitting them costs an extra join with zero benefit.
