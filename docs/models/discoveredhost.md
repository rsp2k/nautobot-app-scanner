# DiscoveredHost

One host nmap reported during a scan. Identity is `(scan, ip_address)`
— the same IP discovered across multiple scans yields multiple rows so
historical per-scan state is preserved.

<figure markdown>
![DiscoveredHost detail with nested Open Ports, Vulnerabilities, and Traceroute Hops tables](../images/discoveredhost-detail.png)
<figcaption>DiscoveredHost detail after a `vuln` profile scan. Left column: host fields + the **Actions** panel with Promote-to-IPAddress / Promote-to-Device buttons. Right column: nested tables for Open Ports (6 services), Vulnerabilities (3 Critical `vulners` + 3 Informational `http-server-header`), and Traceroute Hops. IP and hostname are sanitized to RFC-5737 / `.example.com` placeholders.</figcaption>
</figure>

| Field | Description |
|-------|-------------|
| `scan` | FK to `Scan` (CASCADE) |
| `ip_address` | `VarbinaryIPField` (db_indexed) — IPv4 or IPv6 as reported by nmap |
| `mac_address` | CharField(17) — L2 MAC if nmap resolved it (ARP for v4, NDP for v6) |
| `hostname` | CharField |
| `os_family` | CharField — high-level OS guess (Linux, Windows, BSD) from `-O` |
| `os_type` | CharField — specific OS string (e.g. `Linux 5.x`, `Windows Server 2019`) |
| `os_accuracy` | PositiveSmallIntegerField (0-100) — nmap's `accuracy` attribute |
| `host_state` | CharField (choices=`HostStateChoices`, db_indexed) — `up` / `down` / `unknown` / `skipped` |
| `linked_ipaddress` | FK to `ipam.IPAddress` (SET_NULL, db_indexed) — populated by the **Promote to IPAddress** action |
| `linked_device` | FK to `dcim.Device` (SET_NULL, db_indexed) — auto-resolved at ingest by matching IP against `Device.primary_ip4/6` |

**Base class:** `PrimaryModel`.

**`@extras_features`:** custom_fields, custom_links, custom_validators,
export_templates, graphql, relationships, webhooks.

## Unique constraint

`(scan, ip_address)` — one host per scan.

## Indexes

- `(ip_address, host_state)` — fast "what's up at this IP across history"

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| FK out | `scan` | `Scan` |
| FK out | `linked_ipaddress` | `ipam.IPAddress` (set by Promote action) |
| FK out | `linked_device` | `dcim.Device` (auto-resolved at ingest) |
| Reverse FK | `ports` | `DiscoveredPort` |
| Reverse FK | `traceroute_hops` | `TraceRouteHop` |
| Reverse two-hop | `ports.vulnerabilities` | `VulnerabilityFinding` (rendered as a panel on the host detail page via `discovered_port__discovered_host` table filter) |

## Computed properties

| Property | Returns |
|---|---|
| `open_port_count` | Number of `DiscoveredPort` rows on this host where `state="open"`. Reads from `_open_port_count` if the queryset was annotated (the list view does this to avoid N+1), otherwise falls back to a per-row count query. |
| `vulnerability_count` | Total `VulnerabilityFinding` rows across all ports on this host. Same annotation-or-fallback pattern. |

Both properties power the badges on the scanner panels embedded in
Device / IPAddress / Prefix detail pages — using `_count` annotations
keeps those panels fast even when a Device has many associated
DiscoveredHosts.

## Promote actions

A DiscoveredHost can be promoted to a real `ipam.IPAddress` (lightweight,
permission: `ipam.add_ipaddress`) or to a full `dcim.Device` + Interface
+ IPAddress (heavier, requires `dcim.add_device` + `dcim.add_interface`
+ `ipam.add_ipaddress`). See [Promote a Discovered Host](../user/promotion.md)
for both flows.

## See also

- [App Overview](../user/app_overview.md)
- [Promote to IPAddress](../user/promotion.md)

::: nautobot_scanner.models.DiscoveredHost
    options:
      show_root_heading: false
