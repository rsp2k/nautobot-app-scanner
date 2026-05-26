# DiscoveredPort

One port nmap reported on a `DiscoveredHost`. Fingerprint fields
(`product`, `version`, `extra_info`, `cpe`) live here directly rather
than on a separate `ServiceFingerprint` model — see
[ADR-008](../dev/architecture.md#adr-008-os_type-on-host-fingerprint-fields-on-port).

| Field | Description |
|-------|-------------|
| `discovered_host` | FK to `DiscoveredHost` (CASCADE) |
| `port` | PositiveIntegerField (1-65535) |
| `protocol` | CharField (choices=`ProtocolChoices`) — `tcp` / `udp` / `sctp` |
| `state` | CharField (choices=`PortStateChoices`) — `open` / `closed` / `filtered` / `unfiltered` / `open\|filtered` / `closed\|filtered` |
| `service_name` | CharField — nmap's identification (e.g. `http`, `ssh`, `microsoft-ds`) |
| `banner` | TextField — service banner if captured |
| `product` | CharField — vendor product string from `-sV` (e.g. `Apache httpd`) |
| `version` | CharField — version string from `-sV` (e.g. `2.4.41`) |
| `extra_info` | CharField — extra info from `-sV` (e.g. `(Ubuntu)`) |
| `cpe` | JSONField (list) — CPE strings from `-sV` (e.g. `["cpe:/a:apache:httpd:2.4.41"]`) |

**Base class:** `BaseModel` (lightweight — no status/tags/change-log).

## Unique constraint

`(discovered_host, port, protocol)` — one row per port per protocol per
host per scan.

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| FK out | `discovered_host` | `DiscoveredHost` |
| Reverse FK | `vulnerabilities` | `NseFinding` |

::: nautobot_scanner.models.DiscoveredPort
    options:
      show_root_heading: false
