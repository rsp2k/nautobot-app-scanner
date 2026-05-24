# Scan

One scan execution. Named `Scan` rather than `ScanJob` to avoid
colliding with Nautobot's `extras.jobs.Job` namespace.

| Field | Description |
|-------|-------------|
| `agent` | FK to `ScannerAgent` (PROTECT) — which agent ran / will run the scan |
| `profile` | FK to `ScanProfile` (PROTECT) — what nmap args |
| `target_prefixes` | M2M to `ipam.Prefix` — scan whole prefixes |
| `target_ipaddresses` | M2M to `ipam.IPAddress` — scan individual IPs |
| `status` | CharField (choices=`ScanStateChoices`, db_indexed) — `pending` / `running` / `completed` / `failed` / `cancelled` |
| `cancel_requested` | BooleanField — remote agents poll between hosts |
| `started_at` | DateTime, nullable |
| `completed_at` | DateTime, nullable |
| `summary` | JSONField — counts populated at ingest (hosts, ports, vulns) |
| `ingestion_token` | UUID (unique, nullable) — one-shot; required on POST `/ingest/`. Cleared after ingest |
| `raw_xml` | FileField — gzipped nmap XML stored under `media/scanner/xml/YYYY/MM/` |
| `raw_xml_size` | PositiveIntegerField — uncompressed XML size in bytes |
| `job_result` | FK to `extras.JobResult` (SET_NULL) — back-link to dispatching Job run |
| `error_message` | TextField — populated when `status=failed` |

**Base class:** `PrimaryModel`.

**`@extras_features`:** custom_fields, custom_links, custom_validators,
export_templates, graphql, relationships, webhooks.

## Indexes

- `(agent, status)` — fast lookup of "what's running on agent X"
- `(status, started_at)` — fast lookup of "what's been running recently"

## Lifecycle

```
pending  ──[local backend or pending-scans/ pull]──→  running  ──→  completed
   │                                                    │
   │                                                    ├── failed
   │                                                    └── cancelled
   ▼
cancelled (before ever running)
```

The `ingestion_token` is generated at Scan creation (via the
field's `default=uuid.uuid4`) and cleared at the end of a successful
`POST /ingest/`. It is `unique=True` with `null=True`, which works in
Postgres because `NULL != NULL` for uniqueness — multiple completed
scans can all have null tokens.

## Race protection

Ingest is guarded by:

1. `select_for_update()` on the Scan row
2. `status="running"` filter — POST against a completed/cancelled scan
   gets 409
3. `ingestion_token=<posted>` filter — POST with wrong/expired token
   gets 409

See [ADR-005](../dev/architecture.md#adr-005-ingest-race-protection-one-shot-token-select_for_update).

## Computed properties

| Property | Returns |
|----------|---------|
| `duration_seconds` | Float — wall-clock duration of the scan, or `None` if not finished |

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| FK out | `agent` | `ScannerAgent` |
| FK out | `profile` | `ScanProfile` |
| M2M out | `target_prefixes` | `ipam.Prefix` |
| M2M out | `target_ipaddresses` | `ipam.IPAddress` |
| FK out | `job_result` | `extras.JobResult` |
| Reverse FK | `hosts` | `DiscoveredHost` |

## See also

- [Running Scans user guide](../user/running_scans.md)

::: nautobot_scanner.models.Scan
    options:
      show_root_heading: false
