# Scanner Agent Protocol

The wire contract between `nautobot-app-scanner` and a remote agent. If
you can speak HTTP and run `nmap`, you can write a conforming agent in
any language — see [`agent/agent.py`](../agent/agent.py) for the
reference Python implementation (~250 lines, standard library only).

## Lifecycle

```
   Operator                Nautobot                Remote Agent
   ────────                ────────                ────────────
       │                       │                         │
       │ Runs the "Run Scan"   │                         │
       │ Job, picks a remote   │                         │
       │ agent                 │                         │
       ├───────────────────────▶                         │
       │                       │                         │
       │           Scan(status=pending,                  │
       │           ingestion_token=<uuid>)               │
       │                       │                         │
       │                       │       GET /pending-scans/
       │                       ◀─────────────────────────┤
       │                       │                         │
       │           ① atomically flips                    │
       │              status=running                     │
       │           ② returns scan list                   │
       │                       ├────────────────────────▶│
       │                       │                         │
       │                       │              ③ runs nmap
       │                       │                 with given
       │                       │                 args + targets
       │                       │                         │
       │                       │  POST /scans/<id>/ingest/
       │                       │  X-Ingestion-Token: <uuid>
       │                       │  body: raw nmap XML
       │                       ◀─────────────────────────┤
       │                       │                         │
       │           ④ select_for_update                   │
       │              + token check                      │
       │           ⑤ parse XML, persist                  │
       │           ⑥ status=completed                    │
       │              ingestion_token=None               │
       │                       │                         │
       │   Sees results        │                         │
       │   on the Scan         │                         │
       │   detail page         │                         │
       ◀───────────────────────┤                         │
```

## Authentication

All three endpoints require an HTTP `Authorization: Token <key>` header.
The token must belong to a `User` that is bound (via `OneToOneField`)
to a `ScannerAgent` with `agent_type=remote`. Plain Nautobot user
tokens won't work — they'll return `401`.

Tokens are auto-issued when a remote agent is created via Nautobot's
admin UI:

1. Scanner → Agents → Add → fill in name, set `Agent Type = Remote`, Save.
2. The signal handler auto-creates a User named `scanner-agent-<slug>`.
3. Visit the User detail page (linked from the agent) and create a Token.

## Endpoints

Base URL: `{nautobot_base}/api/plugins/scanner/`

---

### `GET /agents/<uuid>/pending-scans/`

Polls for scans assigned to this agent that are waiting to be picked up.

**Atomic side effect**: every scan returned is transitioned
`pending → running` *inside the same transaction* that selects them, so
two pollers (or two pollers from the same agent racing each other)
can't both pick up the same scan. `SELECT ... FOR UPDATE SKIP LOCKED`
handles the concurrent case.

**Request**

```http
GET /api/plugins/scanner/agents/12c69f09-ea56-4fff-8c55-13bd6d53c065/pending-scans/
Authorization: Token <key>
```

**Response 200**

```json
[
  {
    "id": "f89f3738-7394-4eba-bd7f-be216ee18d40",
    "ingestion_token": "a4c8b1d2-e9f4-4a5b-9c7d-3e2f1a8b5c6d",
    "profile": {
      "name": "version-scan",
      "scan_type": "version",
      "nmap_arguments": "-sV --top-ports 100",
      "timing_template": "T4",
      "enabled_scripts": []
    },
    "targets": {
      "prefixes": ["10.128.144.0/24"],
      "ipaddresses": []
    }
  }
]
```

Empty array means "no work". Poll again later.

**Errors**

| Status | Cause |
|---|---|
| `401` | Token missing or invalid |
| `403` | Token belongs to a different agent than the one in the URL |
| `404` | Agent UUID doesn't exist (or isn't `agent_type=remote`) |

---

### `POST /scans/<uuid>/ingest/`

Uploads nmap XML for a previously-picked-up scan. The server parses the
XML, materializes `DiscoveredHost` / `DiscoveredPort` / `VulnerabilityFinding`
/ `TraceRouteHop` records, gzips the raw XML to storage, and transitions
the scan to `completed`.

**Critical**: the `X-Ingestion-Token` header must match the
`ingestion_token` you received from `/pending-scans/`. The server clears
the token on successful ingest, so a second POST with the same token
gets `403`. This is the retry-after-504 defense — a network blip
between you and Nautobot won't cause double-insertion of host records.

**Request**

```http
POST /api/plugins/scanner/scans/f89f3738-7394-4eba-bd7f-be216ee18d40/ingest/
Authorization: Token <key>
Content-Type: application/xml
X-Ingestion-Token: a4c8b1d2-e9f4-4a5b-9c7d-3e2f1a8b5c6d

<?xml version="1.0" encoding="UTF-8"?>
<nmaprun ...>
  ...
</nmaprun>
```

**Response 200**

```json
{
  "scan_id": "f89f3738-7394-4eba-bd7f-be216ee18d40",
  "status": "completed",
  "summary": {
    "hosts_up": 256,
    "hosts_down": 0,
    "ports_open": 11,
    "vulnerabilities": 0,
    "traceroute_hops": 0
  }
}
```

**Errors**

| Status | Cause |
|---|---|
| `400` | Missing/malformed `X-Ingestion-Token`, or unparseable nmap XML |
| `401` | Token missing or invalid |
| `403` | Token-agent doesn't own this scan; OR token has already been consumed (replay) |
| `404` | Scan UUID doesn't exist |
| `409` | Scan is in a state that can't accept ingest (e.g. `cancelled`) |

---

### `POST /agents/<uuid>/checkin/`

Heartbeat. Updates `last_seen` (mandatory) and optionally `version` and
`capabilities` if the agent wants to publish them.

**Request**

```http
POST /api/plugins/scanner/agents/12c69f09-ea56-4fff-8c55-13bd6d53c065/checkin/
Authorization: Token <key>
Content-Type: application/json

{
  "version": "reference-agent/1.0",
  "capabilities": {
    "nmap_version": "Nmap version 7.94 ( https://nmap.org )",
    "hostname": "dmz-jumpbox"
  }
}
```

Both `version` and `capabilities` are optional. A bare empty `{}` is
valid and just bumps `last_seen`.

**Response 200**

```json
{
  "agent_id": "12c69f09-ea56-4fff-8c55-13bd6d53c065",
  "last_seen": "2026-05-24T23:59:01.123456Z",
  "version": "reference-agent/1.0",
  "capabilities": {...}
}
```

Recommended cadence: every 60 seconds. The server-side `Mark Stale
Agents Offline` Job flips agents to status `Offline` when `last_seen >
3 × CHECKIN_INTERVAL_SECONDS` ago (default threshold: 180 seconds).

## Building your own agent

Minimal pseudocode:

```python
while True:
    scans = http_get(f"{base}/agents/{agent_id}/pending-scans/", token)
    for scan in scans:
        argv = ["nmap", "-oX", "-"] + scan["profile"]["nmap_arguments"].split() \
             + [f"-{scan['profile']['timing_template']}"] \
             + scan["targets"]["prefixes"] + scan["targets"]["ipaddresses"]
        xml = subprocess.run(argv, capture_output=True, text=True).stdout
        http_post(
            f"{base}/scans/{scan['id']}/ingest/",
            body=xml,
            headers={"X-Ingestion-Token": scan["ingestion_token"]},
            token=token,
        )
    sleep(POLL_INTERVAL)
```

Background thread does `POST /checkin/` every `CHECKIN_INTERVAL`. That's
the whole protocol. The reference agent is ~250 lines because it adds
TLS opts, error handling, signal traps, capability probing, and
configuration loading — none of which are protocol requirements.
