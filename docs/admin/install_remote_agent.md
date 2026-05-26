# Install a Remote Scanner Agent

The repo ships a containerized reference agent under
[`agent/`](https://github.com/rsp2k/nautobot-app-scanner/tree/main/agent).
It's a single Python file plus a Dockerfile — same image, three compose
variants for different network-reach scenarios. This page is the
operational deploy walkthrough.

For the *protocol* (if you're writing a custom agent), see
[Agent Protocol](../dev/agent_protocol.md).
For *when* to use a remote agent vs the local backend, see
[Scanner Agents](../user/agents.md).

## Deployment modes

| Mode | Use it when | Compose file |
|---|---|---|
| **Host network** | Scanning the LAN the host sits on, physical interfaces, SPAN ports, DMZ / OT / branch segments | `agent/docker-compose.host-mode.yml` |
| **Bridge / attached** | Inventorying services inside a docker overlay (caddy stack, app cluster, etc.) | `agent/docker-compose.bridge-mode.yml` |
| **Dev-bridge** | Local development — joins `nautobot-scanner-dev_internal` to scan and reverse-look-up Nautobot's own dev containers via docker DNS | `agent/docker-compose.dev-bridge.yml` |

All three run the same `agent.py` script, same Dockerfile, same env vars
— only the network topology differs.

## Bootstrap walkthrough

### 1. Register the agent in Nautobot

**Apps > Scanner > Scanner Agents > Add**:

| Field | Value |
|---|---|
| Name | something distinctive — e.g. `dmz-agent-01`, `scanhost-01-agent` |
| Agent type | **Remote (standalone agent)** |
| Status | `Active` |
| Location | (optional, but useful for grouping) |

Saving with `agent_type=remote` triggers a signal that auto-creates a
matching `auth.User` named `scanner-agent-<name>`. The User shows up on
the agent detail page as a clickable link.

### 2. Mint a Token for the User

Open the auto-created User's admin page and create a Token. **Copy the
token immediately** — Nautobot only shows it once. Lost tokens are
rotated by deleting and re-issuing, not retrieved.

### 3. Get the agent's UUID

From the agent's detail page URL:

```
/plugins/scanner/agents/0fcaf26c-1234-5678-90ab-cdef12345678/
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                          this is AGENT_ID
```

### 4. Configure the agent container

```bash
cd agent/
cp .env.example .env
$EDITOR .env
```

Required env vars:

| Variable | Value |
|---|---|
| `NAUTOBOT_URL` | Full URL including scheme: `https://nautobot.example.com` |
| `AGENT_ID` | UUID from step 3 |
| `AGENT_TOKEN` | DRF Token from step 2 |
| `VERIFY_TLS` | `true` in production, `false` for self-signed dev certs |

Optional:

| Variable | Default | Notes |
|---|---|---|
| `CHECKIN_INTERVAL_SECONDS` | `60` | Heartbeat cadence on the **agent** side. Match this to the agent's `expected_checkin_interval_seconds` on the server side (or leave both blank to use the plugin default). |
| `POLL_INTERVAL_SECONDS` | `30` | How often the agent checks for new pending scans. |
| `SCAN_TIMEOUT_SECONDS` | `3600` | Max wall time for one nmap subprocess. |
| `NMAP_BIN` | `/usr/bin/nmap` | Override if you ship a custom nmap. |

!!! tip "Slower checkin for flaky links"
    For an agent on a high-latency or intermittent link (satellite,
    cellular, restricted firewall), bump the agent's
    `CHECKIN_INTERVAL_SECONDS` (e.g. `300` = 5 min) **and** set
    `expected_checkin_interval_seconds = 300` on the matching
    `ScannerAgent` in Nautobot. Otherwise `MarkStaleAgents` will flip
    the agent to `Offline` every time the checkin runs late.

### 5. Start the container

Pick the right compose file for your topology:

```bash
# Host-network mode (most common — scans whatever LAN the host can reach)
docker compose -f docker-compose.host-mode.yml --env-file .env up -d

# Bridge mode — scans the docker overlay you attach to
docker compose -f docker-compose.bridge-mode.yml --env-file .env up -d

# Dev-bridge — joins the Nautobot dev stack's internal network
docker compose -f docker-compose.dev-bridge.yml --env-file .env up -d
```

### 6. Verify

Within `CHECKIN_INTERVAL_SECONDS`, the agent's **Last Seen** field on
the agent detail page updates to "a few seconds ago." If it doesn't:

- Tail the agent's logs: `docker compose -f docker-compose.host-mode.yml logs -f`
- Look for HTTP errors (401 = wrong token, 404 = wrong agent ID, 5xx =
  TLS / connectivity)
- From the agent container: `curl -H "Authorization: Token $AGENT_TOKEN"
  https://$NAUTOBOT_URL/api/plugins/scanner/agents/$AGENT_ID/`

Once the agent is online, dispatch a scan via **Jobs > Scanner: Run Scan**
picking the new agent as the executor.

## Operational notes

### Base image: `nicolaka/netshoot` (Phase G)

The agent image extends `nicolaka/netshoot:v0.13` rather than a minimal
Alpine+nmap base. netshoot bundles ~50 networking tools (dig, masscan,
hping3, openssl, mtr, curl, scapy, …) — all reachable by the agent
when a `ScanProfile` selects them via the `tool` field. The Dockerfile
additionally `apk add`s `masscan` and `hping3` (not in netshoot stock),
and runs `setcap` on `nmap` / `masscan` / `hping3` so each can use raw
sockets without `--privileged`.

**Image size tradeoff.** netshoot is ~600 MB vs ~30 MB for a minimal
nmap-only build. For agents on flaky / metered links (satellite,
cellular, branch with thin pipes), the larger initial pull is real
cost. The benefit: a single image supports every probe tool the app
dispatches (`tool=nmap` / `dig` / `masscan` / `curl` / `mtr` /
`openssl-s_client`) so you don't have to manage one image per tool.

**Per-tool capability probe.** On startup, the agent inspects each
tool's version and posts the inventory in its `/checkin/` capabilities
payload — Nautobot sees which tools the agent actually has and can
dispatch accordingly. A profile that asks for a tool the agent doesn't
have results in a scan that immediately moves to `status=failed` with
the missing-tool name in `error_message`.

### CAP_NET_RAW for ARP discovery

nmap's `-PR` (ARP ping) and OS-fingerprint (`-O`) need raw sockets. Both
shipping compose files grant the container `CAP_NET_RAW` and run
`setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip
/usr/bin/nmap` in the image build. Without these, nmap falls back to TCP
`connect()` discovery — slower, noisier, but functional. The visible
symptom is empty `mac_address` on every `DiscoveredHost` — nmap can't
ARP-resolve without raw sockets.

### TLS

`VERIFY_TLS=true` (the default) enforces certificate validation against
the system trust store. For dev environments with self-signed certs,
set `VERIFY_TLS=false`. For production, install your CA bundle into
the image (build with `--build-arg CA_BUNDLE=...`) rather than
disabling verification.

### Resource use

Idle agent: ~10 MB RSS. During a scan: nmap dominates the footprint —
typically 50-200 MB for /24 ranges, more for `-A` aggressive scans or
NSE-heavy profiles. The agent itself is single-threaded; the docker
container won't peg multiple cores.

### Logs

Plain-text logs on stdout, suitable for any docker log driver
(json-file, syslog, gelf, fluentd, loki). The agent doesn't write
anywhere on disk other than nmap's temp output, which gets read and
discarded immediately.

### Reverse SSH tunnel pattern (no public Nautobot)

If your Nautobot is on a private network and the agent host is somewhere
that can SSH out to your bastion, you can avoid exposing Nautobot
publicly with a reverse tunnel:

```bash
# From your workstation (where Nautobot dev stack is running on 8087)
ssh -N -f -R 8087:127.0.0.1:8087 rpm@scanhost-01.example.net
```

Then on the agent host set `NAUTOBOT_URL=http://127.0.0.1:8087`. The
tunnel forwards the agent's outbound HTTP calls back to your Nautobot
without any inbound firewall rule. Cleanup: `pkill -f 'ssh.*-R 8087'`
on the workstation.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Last Seen never updates | Wrong token | Re-issue token, update `.env`, restart container |
| Last Seen never updates | Wrong AGENT_ID | Check the URL in step 3 — UUID right after `/agents/` |
| 401 in agent logs | Token belongs to a different user | The token must be on the user *bound to this agent* — check ScannerAgent.user FK |
| 409 on POST /ingest/ | Ingestion token already used / scan already completed | Don't retry, it's working as designed (race protection) |
| Empty MAC addresses | CAP_NET_RAW missing | Verify compose file grants it; image must include the setcap line |
| Scans hang at `running` | Agent crashed mid-scan | Tail logs; restart the agent; the scan will eventually time out and move to `failed` |
| Slow scans | T-template too conservative | Bump from T3 → T4 on the profile, or `-PR` + ARP requires raw sockets (see above) |

## Multi-agent deployments

There's no limit on how many `ScannerAgent` records you can register.
Common patterns:

- **One per network segment** — `dmz-agent`, `mgmt-agent`, `branch-fra`,
  `branch-nyc`. Each polls independently; pick the right one when
  dispatching a scan based on which segment the targets are in.
- **One per environment** — `prod-agent`, `staging-agent`. Same hosts,
  different agents, so scan history can be filtered by environment.
- **HA pair on the same network** — Two agents in the same segment will
  both poll the same `pending` scans, but the server's
  `select_for_update` race protection means exactly one wins per scan.
  Useful if you want failover but accept that "load balancing" is
  whichever agent polls first.
