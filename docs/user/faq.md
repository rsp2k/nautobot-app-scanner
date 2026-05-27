# FAQ

## Does this app scan from inside the Nautobot host?

It can. The **Local backend** does exactly that — the probe tool
selected by the profile (nmap / dig / drill / curl / mtr / masscan /
openssl-s_client) runs inside the Nautobot Celery worker container.
For network segments the Nautobot host can't reach, use a **Remote
agent**. See [Scanner Agents](agents.md).

## Will it auto-populate IPAM from scan results?

No. By design. Scan output goes into the app's own `DiscoveredHost`
model. To turn a discovered host into an `ipam.IPAddress`, an
authorized user explicitly clicks **Promote to IPAddress**. See
[Promote to IPAddress](promotion.md) for the reasoning.

## How are remote agents authenticated?

DRF Token bound to a per-agent `auth.User`. The User is auto-created
via a signal when you create a `ScannerAgent` with `agent_type=remote`.
The token is shown once at agent creation and never again — rotate via
the user's admin page.

## Why not `extras.Secret` for agent credentials?

`extras.Secret` is for Nautobot fetching credentials **outward** (to
vault / env / file). Agent auth is **inbound** — the agent presents a
credential, Nautobot validates it. Wrong direction of trust for the
`Secret` model. See [Architecture Decisions](../dev/architecture.md#adr-002-agent-auth-via-user-drf-token-not-extrassecret).

## Can two scans run against the same prefix at the same time?

By default no — the `RunScan` job rejects overlap to prevent racing
updates. Check **Allow overlap** in the job form if you know what you're
doing (e.g., a fast discovery scan can safely run alongside a slow
vuln scan).

## What happens to historical scans when I rescan?

Nothing — `DiscoveredHost` rows are keyed by `(scan, ip_address)`. The
same IP discovered across multiple scans yields multiple rows so you
have a full history. The `IPAddress` detail panel (in Phase 8) shows
all scans that touched that IP, newest first.

## Where is the raw scan output stored?

Two FileFields on `Scan`, mutually exclusive:

- **nmap scans** → `Scan.raw_xml` (gzipped under
  `media/scanner/xml/YYYY/MM/`)
- **everything else** (dig / drill / curl / mtr / masscan /
  openssl-s_client) → `Scan.raw_output` (gzipped under
  `media/scanner/output/YYYY/MM/`)

Both go to your Nautobot media storage backend (filesystem by default,
S3-compatible if you've configured one). NOT in Postgres — output for
a single scan of a /22 can be many megabytes, which would bloat the DB
and kill `pg_dump`. The `tool_used` field tells you which file to
look at.

You can re-parse stored output if you fix a parser bug — see
[Architecture Decisions](../dev/architecture.md#adr-003-pure-function-parser-separate-from-orm-persistence).

## Can I write my own backend?

Yes. Implement the `ScannerBackend` ABC (`dispatch(scan)`) and wire it
into the `get_backend()` factory. See [Extending](../dev/extending.md).

## Can I write my own remote agent?

Yes. The REST contract is documented at
[Agent Protocol](../dev/agent_protocol.md). The reference agent at
`examples/reference_agent.py` is a working implementation in ~150 lines
of Python.

## Why is `os_type` on the host, not on each port?

nmap's OS detection (`-O`) is per-host, not per-port. Putting `os_type`
on `DiscoveredPort` would mean N copies of the same value per host.

## Are scan results subject to Nautobot change-logging?

Yes — `Scan`, `DiscoveredHost`, `ScannerAgent`, and `ScanProfile` are
all `PrimaryModel` with `@extras_features(... "webhooks" ...)`. Edits
appear in the object's history tab. Child records (`DiscoveredPort`,
`NseFinding`, `TraceRouteHop`) are `BaseModel` and don't get
their own change log — they're considered immutable scan output once
persisted.
