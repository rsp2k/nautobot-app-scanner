# ScanProfile

A reusable nmap argument template. Operators pick a profile by name
when dispatching a scan; the backend uses the profile's
`nmap_arguments` directly (plus the targets appended at dispatch
time).

| Field | Description |
|-------|-------------|
| `name` | Unique identifier (operator-chosen, e.g. `discovery-fast`, `tcp-vuln-vulners`) |
| `scan_type` | Coarse classification — `discovery` / `port` / `version` / `vuln` / `topology`. Used for table filtering and panel decisions; `nmap_arguments` is the actual source of truth |
| `nmap_arguments` | TextField — raw nmap flags (e.g. `-sS -sV --top-ports 1000`). DO NOT include target spec or `-oX` |
| `timing_template` | `T0`..`T5` — paranoid through insane |
| `enabled_scripts` | JSONField list of NSE script names — informational; you still have to include `--script <name>` in `nmap_arguments` to actually run them |
| `description` | Free-text |

**Natural key:** `name`.

**Base class:** `PrimaryModel`.

**`@extras_features`:** custom_fields, custom_links, custom_validators,
export_templates, graphql, relationships, webhooks.

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| Reverse FK | `scans` | `Scan` (one profile is used by many scans) |

## See also

- [Scan Profiles user guide](../user/scan_profiles.md) — common recipes

::: nautobot_scanner.models.ScanProfile
    options:
      show_root_heading: false
