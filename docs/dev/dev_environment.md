# Development Environment

The repo ships a complete Docker-Compose dev stack under `development/`:
Postgres + Redis + Nautobot web + Nautobot worker, with the app source
bind-mounted for hot reload.

## One-time setup

```bash
git clone https://github.com/rsp2k/nautobot-app-scanner
cd nautobot-app-scanner

# Generate .env with random dev secrets
cp development/.env.example development/.env
# (then edit development/.env — at minimum set DOMAIN and rotate the
# changeme- placeholders for the four passwords)
```

The dev stack expects a Docker external network named `caddy` for
reverse-proxy integration. If you don't have one yet:

```bash
docker network create caddy
```

If you don't have caddy-docker-proxy running, just hit the loopback
port at `http://127.0.0.1:8087/` instead (the compose maps it for
direct host access).

## Build the image

```bash
make build
```

First build pulls `ghcr.io/nautobot/nautobot:3.1-py3.12` (~2GB
compressed). Subsequent builds reuse cached layers, ~10s.

## Start the stack

```bash
make up
```

Wait ~60s for first-boot migrations and superuser creation. Tail logs:

```bash
make logs-web
```

## Working with the code

The `src/nautobot_scanner/` directory is bind-mounted into the
container at `/opt/plugin/src/`. Most code changes take effect after a
container restart:

```bash
make restart
```

Model / settings changes that require a migration:

```bash
make makemigrations    # generates 0002_*.py
make migrate           # applies it
```

Note: `makemigrations` runs the container as root and chowns the
generated file back to the host UID — bypasses the container's
nautobot user (UID 999) vs host user (UID 1000) bind-mount mismatch.

## Run the tests

```bash
make test
```

This invokes `nautobot-server test nautobot_scanner --keepdb` which
keeps the test DB around between runs for speed. To force a fresh
DB:

```bash
docker compose exec nautobot-web nautobot-server test nautobot_scanner
```

## Lint

```bash
make ruff
```

Runs `ruff check` + `ruff format --check` on `src/`.

## Useful shells

```bash
make shell    # bash on the web container
make nbshell  # nautobot-server shell_plus (Django shell + auto-imports)
```

## Tearing down

```bash
make down      # stop containers, keep volumes
make clean     # DESTRUCTIVE — drop all volumes (wipes DB)
```

## Build the docs locally

```bash
pip install -r docs/requirements.txt
mkdocs serve
```

Visit `http://127.0.0.1:8001/`. See [Publishing Docs](../admin/install_docs_site.md)
for the production deploy flow.

## Host-networked scanner-agent (for LAN scans with MAC discovery)

The dev compose includes a dedicated `scanner-agent` container that
runs the [reference remote agent](agent_protocol.md) with
`network_mode: host`. Without this — i.e., with only the bridge-
networked `nautobot-worker` doing LocalBackend dispatches — scans of
the host's LAN (`192.168.x.y`, `10.x.y.z` etc.) work but `nmap` can't
see ARP replies because:

1. The worker container's packets get SNAT'd through the docker
   bridge — by the time they reach the LAN, the source IP is the
   host's IP, not the container's.
2. ARP responses come back to the host, not the container.
3. nmap inside the container never observes the ARP reply, so
   `DiscoveredHost.mac_address` stays `null` for every host.

Symptom: the **MAC** and **Vendor** columns on Discovered Hosts and
the scan-detail page render `—` for every row, even though the
manual `nmap` from the host (outside the container) populates them.

The host-networked scanner-agent fixes this by sharing the host's
network namespace — it has L2 visibility to whatever LAN the host
is on, so nmap's ARP probes actually see replies and
`mac_vendor` gets OUI-resolved from nmap's bundled database. The
end-to-end effect on a typical home LAN:

| | Bridge-networked worker | Host-networked agent |
|---|---|---|
| Hosts up (`-sn` discovery) | 22 | 33 |
| MAC populated | 0 / 22 | 32 / 33 |
| Vendor populated | 0 / 22 | 31 / 32 |

The 11-host delta is devices that respond to ARP but not to TCP
discovery (e.g. mDNS-only HomeKit accessories, older IoT, the
gateway itself). The single MAC-without-vendor outlier is typically
a randomized OUI (privacy MAC) on a modern phone.

### Provisioning the agent

The `scanner_agent_token` management command makes this a one-liner:

```bash
# First time: create the agent + mint the token
make shell  # or `docker compose -f development/docker-compose.yml exec nautobot-web nautobot-server shell`

# Inside the container:
nautobot-server scanner_agent_token dev-host-agent --create
```

Output is the UUID + token + ready-to-paste `.env` stanza:

```
Created agent 'dev-host-agent'

  UUID:     8a4e7cd5-ced2-4a24-9a31-fb38a3acb423
  Token:    ad260cd29d4faffdc56f81950bea9f42bac1d91f
  Location: Home
  User:     scanner-agent-dev-host-agent

Add to your agent's .env:

    SCANNER_AGENT_ID=8a4e7cd5-ced2-4a24-9a31-fb38a3acb423
    SCANNER_AGENT_TOKEN=ad260cd29d4faffdc56f81950bea9f42bac1d91f
```

Append those two lines to `development/.env`, then `docker compose
up -d scanner-agent` — the agent picks up the token, checks in to
Nautobot, and starts polling for assigned scans every 10s.

### Other command modes

```bash
# Read-only (default) — print existing UUID + token for an agent that already exists
nautobot-server scanner_agent_token dev-host-agent

# Machine-friendly (for `>> .env` redirection — suppresses header text)
nautobot-server scanner_agent_token dev-host-agent --env-stanza >> development/.env

# Token rotation — delete the existing token and mint a fresh one
# Use after a suspected leak, or as part of routine credential hygiene
nautobot-server scanner_agent_token dev-host-agent --rotate

# Create at a specific Location (otherwise picks the first Location in the DB)
nautobot-server scanner_agent_token new-agent --create --location "Idaho Office"
```

The default invocation is idempotent and read-only — safe to run in CI
as a "does this agent exist + what's its current token" check.

### Verifying the agent is actually scanning the LAN

After dispatching a discovery scan via the host-agent:

```python
# In nautobot-server shell:
from nautobot_scanner.models import Scan
scan = Scan.objects.filter(agent__name='dev-host-agent').latest('completed_at')
print(f'hosts={scan.hosts.count()}')
print(f'MACs populated: {sum(1 for h in scan.hosts.all() if h.mac_address)}/{scan.hosts.count()}')
```

If MAC count is `0/N`, the agent is most likely running but going
through the bridge anyway — check `docker inspect <agent-container>
--format '{{.HostConfig.NetworkMode}}'` and confirm it returns
`host` (not `bridge` or a custom network name).

If the count is non-zero, the agent path is working — point any scan
profile at the host-agent (in the Run Scan job's **Agent** dropdown)
and MACs will populate.

## Gotchas

This project has accumulated a few rediscover-the-hard-way lessons
worth recording once instead of N times:

- **`nmap -sS` as non-root needs both `cap_net_raw` AND `--privileged`.**
  Linux file capabilities grant the kernel-level permission, but
  nmap's own pre-flight check ignores them. Set the cap AND pass
  `--privileged` in `nmap_arguments` for the profile, or run as root.
- **`{# %}` Django comments are single-line only.** Multi-line
  `{# ... #}` blocks render their body as visible HTML text. Always
  use `{% comment %}...{% endcomment %}` for multi-line blocks.
- **`testssl --jsonfile /dev/stdout` interleaves progress text.**
  testssl writes its progress narration to stdout regardless of the
  `--jsonfile` flag, so `/dev/stdout` produces invalid JSON. Use a
  real temp file + cat (the LocalBackend argv builder does this).
- **`ssh-audit` exits non-zero to signal severity** (0=clean,
  2=warn, 3=info, 4=fail). The LocalBackend has a
  `_TOLERATE_NONZERO_EXIT` allowlist for this; the agent wraps the
  shell with `|| true` for the same reason.
- **Docker `no_new_privs` blocks file capabilities for non-root
  exec.** Disable via `security_opt: [no-new-privileges:false]` on
  any container that needs raw-socket scans (in dev, the
  `nautobot-common` anchor sets this globally; in prod, set it
  per-service for the worker/agent only).
- **The `rest_framework.authtoken.models.Token` vs
  `nautobot.users.models.Token` distinction.** Nautobot uses its own
  Token model (with description + expiration support); DRF's parallel
  Token is a different model with overlapping fields and zero
  cross-reference. Always import from `nautobot.users.models` for
  agent tokens.
