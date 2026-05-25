# Reference Scanner Agent

A containerized scanner agent that talks to a `nautobot-app-scanner`
install. Drop it in wherever you need scanning visibility — DMZ, branch
office, an isolated OT VLAN, or right alongside Nautobot itself.

Same image, two deployment modes:

| Mode | Use it when | Compose file |
|---|---|---|
| **Host network** | Scanning the LAN the host is on, physical interfaces, SPAN ports | `docker-compose.host-mode.yml` |
| **Bridge / attached** | Inventorying services inside docker overlays (caddy, app stacks) | `docker-compose.bridge-mode.yml` |

## Quick start

1. **Register the agent in Nautobot.** Scanner → Agents → Add. Pick
   `agent_type=remote`. After save, click the auto-created `User` link
   on the agent detail page, then create a Token. Copy the token —
   you'll only see it once.
2. **Configure the agent.**
   ```bash
   cd agent/
   cp .env.example .env
   # Edit .env: NAUTOBOT_URL, AGENT_ID (from the agent's URL), AGENT_TOKEN.
   ```
3. **Start the container.**
   ```bash
   # Host network (recommended for scanning external networks)
   docker compose -f docker-compose.host-mode.yml --env-file .env up -d

   # OR bridge mode (recommended for scanning docker overlays)
   docker compose -f docker-compose.bridge-mode.yml --env-file .env up -d
   ```
4. **Verify.** The agent's `last_seen` field in Nautobot updates within
   `CHECKIN_INTERVAL_SECONDS` (default 60). After that, dispatch a scan
   via Jobs → `Scanner: Run Scan` picking your remote agent.

## How it works

Three HTTP calls, all token-authenticated:

```
                    ┌────────────────────────────────┐
                    │            Nautobot            │
                    └────────────────────────────────┘
                       ▲              ▲           ▲
   1. POST /checkin/   │              │           │  3. POST /scans/<id>/ingest/
      every 60s        │              │           │     X-Ingestion-Token: <uuid>
                       │              │           │     body: raw nmap XML
                       │              │           │
                       │   2. GET /agents/<id>/   │
                       │      pending-scans/      │
                       │      every 30s           │
                       │              │           │
                    ┌────────────────────────────────┐
                    │       Scanner Agent            │
                    │      (this container)          │
                    └────────────────────────────────┘
                                 │
                                 │ subprocess.run(nmap)
                                 ▼
                          Network targets
```

Race protection is handled server-side: scans are atomically transitioned
from `pending` to `running` on first GET so two pollers can't grab the
same one, and the ingestion token is single-use so retried POSTs after a
504 don't double-insert.

## Production notes

- **CAP_NET_RAW** is granted in both compose files. Without it, nmap
  falls back to TCP `connect()` scans — slower, noisier, but functional.
- **TLS verification** is on by default. Self-signed dev certs: set
  `VERIFY_TLS=false` in `.env`.
- **Resource use** is tiny when idle (~10 MB RSS). During scans it spikes
  with nmap's memory footprint — typically 50-200 MB for /24 ranges.
- **Logs** stream to stdout in plain-text format suitable for any docker
  log aggregator (Loki, Splunk Forwarder, syslog driver, etc.).

## Protocol reference

See [`../docs/agent-protocol.md`](../docs/agent-protocol.md) for the full
HTTP contract — payload schemas, status codes, error semantics. The
agent.py source is also short (~250 lines, standard library only) and
makes a fine reference implementation if you'd rather write your own
agent in a different language.
