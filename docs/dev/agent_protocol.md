# Agent Protocol

The REST contract a remote agent must implement to participate in
scanner. This page is the source of truth — the reference agent at
`examples/reference_agent.py` is one implementation of it.

!!! note "API surface comes in Phase 7"
    These endpoints are designed and documented but not yet shipped.
    Build against this spec; once Phase 7 lands the implementation
    must match what's here.

## Base URL

```
https://<nautobot-host>/api/plugins/scanner/
```

## Authentication

Every request includes a DRF Token in the Authorization header:

```
Authorization: Token <token-value>
```

The token belongs to the `auth.User` that's bound to the
`ScannerAgent` (1:1). The custom auth class on the agent endpoints
validates that the token's user matches the `<agent_id>` in the URL —
agents can only act as themselves.

The token is shown **once** at agent creation. Lost tokens are rotated
via the user's admin page.

## Endpoints

### `GET /agents/<id>/pending-scans/`

Return all scans currently assigned to this agent in `pending` status.

**Response 200:**

```json
{
  "scans": [
    {
      "id": "0fcaf26c-...",
      "ingestion_token": "57ab2090-...",
      "profile": {
        "id": "e08f1d76-...",
        "nmap_arguments": "-sS -sV --top-ports 1000",
        "timing_template": "T4",
        "enabled_scripts": ["vulners"]
      },
      "targets": ["10.50.0.0/24", "192.168.1.42/32"],
      "cancel_requested": false
    }
  ]
}
```

**Response 401:** invalid / missing token, or token's user doesn't
match the `<agent_id>` in the URL.

The `targets` array is a list of nmap-syntax target strings —
prefixes are emitted in CIDR form, individual IPs in `/32` or `/128`
form. Just pass them straight to nmap.

### `POST /scans/<id>/ingest/`

Submit raw nmap XML for parsing and persistence. **The scan must be
in `running` state** (transition: PendingScansView flips it to running
when an agent fetches it; the agent then POSTs ingest).

**Request headers:**

```
Authorization: Token <token>
X-Ingestion-Token: <ingestion_token from pending-scans/>
Content-Type: application/xml
```

**Request body:** raw nmap XML output (the contents of `nmap ... -oX -`).

**Response 200:**

```json
{
  "scan_id": "0fcaf26c-...",
  "status": "completed",
  "hosts_persisted": 42,
  "ports_persisted": 318,
  "vulnerabilities_persisted": 5
}
```

**Response 409:** the ingest token doesn't match, OR the scan is no
longer in `running` state. Retrying with the same token will keep
hitting 409. **Do not retry.**

**Response 400:** XML was un-parseable. The scan transitions to
`failed`; the agent should log and move on.

### `POST /agents/<id>/checkin/`

Heartbeat. Updates `last_seen`, `version`, `capabilities`.

**Request body:**

```json
{
  "version": "1.0.0",
  "capabilities": {
    "nmap_version": "7.94",
    "nse_scripts": ["vulners", "http-title", "ssl-cert"],
    "platform": "Linux 5.15 amd64"
  }
}
```

**Response 200:** empty body.

Agents should check in at least every `agent_checkin_interval_seconds`
(default: 60). The `MarkStaleAgents` job flips agents to `offline`
when `last_seen < now - 3 * interval`.

## Recommended agent loop

```python
while True:
    checkin()
    for scan in pending_scans():
        if scan.cancel_requested:
            continue
        xml = nmap_run(scan.profile, scan.targets)
        try:
            ingest(scan.id, scan.ingestion_token, xml)
        except Conflict409:
            pass  # don't retry
        except BadRequest400:
            log("nmap output rejected: ", xml[:500])
    sleep(CHECKIN_INTERVAL)
```

## What an agent should NOT do

- Don't parse the XML on the agent side — server is the single source
  of truth for what fields exist. Send the raw XML.
- Don't retry 409 ingests — the token is one-shot.
- Don't create scans yourself — only `RunScan` (server-side) creates
  scans. Agents only consume them.
- Don't modify the `Scan` record except via the documented endpoints.
- Don't checkin with bogus capabilities — they're surfaced in the UI
  and operators rely on them.

## Versioning

The contract is **stable from v1.0 onward**. Pre-1.0 (the `2026.x.x`
calver releases) may break it; in that case the change is announced
in the release notes and the reference agent updated in lockstep.

Future versions of the contract will be advertised via a
`scanner-protocol-version` HTTP header on responses. Agents should
log warnings if the server reports a newer protocol than they were
built against.
