# ScannerAgent

A scan executor — either in-process inside the Nautobot worker
(`agent_type=local`) or a registered remote process authenticated by
DRF Token.

| Field | Description |
|-------|-------------|
| `name` | Unique identifier (operator-chosen, e.g. `dc1-local`, `branch-fra-agent01`) |
| `agent_type` | `local` (in worker) or `remote` (standalone agent) — see [`AgentTypeChoices`](../user/agents.md) |
| `status` | StatusField — `Active` / `Offline` / `Maintenance` (admin-extensible) |
| `location` | FK to `dcim.Location` (nullable) — where the agent is physically deployed |
| `user` | OneToOne to `settings.AUTH_USER_MODEL` (nullable) — auto-created for remote agents; the DRF Token on this user authenticates the agent |
| `last_seen` | DateTime, db_indexed — updated at every checkin |
| `version` | Agent software version reported at checkin |
| `capabilities` | JSONField — free-form dict (nmap version, NSE scripts available, platform) reported at checkin |
| `description` | Free-text |

**Natural key:** `name`.

**Base class:** `PrimaryModel`.

**`@extras_features`:** custom_fields, custom_links, custom_validators,
export_templates, graphql, relationships, statuses, webhooks.

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| FK out | `location` | `dcim.Location` |
| OneToOne out | `user` | Nautobot's swapped User model |
| Reverse FK | `scans` | `Scan` (one agent runs many scans) |

## Auto-User creation for remote agents

When a `ScannerAgent` is created with `agent_type=remote` and `user`
is left null, a signal in `signals.py` creates a dedicated `auth.User`
named `scanner-agent-<name>` and a DRF Token on that user. The token is
displayed once in the admin UI and never shown again — rotation is
manual via the user's admin page.

Local agents leave `user` null; they don't authenticate to anything.

## See also

- [Scanner Agents user guide](../user/agents.md)
- [Architecture: ADR-002 on auth choice](../dev/architecture.md#adr-002-agent-auth-via-user-drf-token-not-extrassecret)

::: nautobot_scanner.models.ScannerAgent
    options:
      show_root_heading: false
