# TraceRouteHop

One hop in the path nmap traced to a `DiscoveredHost`. Anchored to the
host (not the scan) because the host's FK transitively gives us the
scan — dual FKs would invite drift between the two.

| Field | Description |
|-------|-------------|
| `discovered_host` | FK to `DiscoveredHost` (CASCADE) — the trace target |
| `hop_number` | PositiveSmallIntegerField — 1 = first hop, etc. |
| `hop_ip` | `VarbinaryIPField` (db_indexed) — IP of the hop |
| `hop_hostname` | CharField — PTR result if nmap resolved it |
| `rtt_ms` | FloatField (nullable) — round-trip time in ms; null if hop didn't respond |

**Base class:** `BaseModel` (lightweight — no status/tags/change-log).

## Unique constraint

`(discovered_host, hop_number)` — one row per hop per traced host.

## When this is populated

Only when the scan profile's `nmap_arguments` includes `--traceroute`.
Otherwise the rows simply don't exist for that host.

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| FK out | `discovered_host` | `DiscoveredHost` |

::: nautobot_scanner.models.TraceRouteHop
    options:
      show_root_heading: false
