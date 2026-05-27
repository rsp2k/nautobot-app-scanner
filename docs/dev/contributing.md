# Contributing

Thanks for considering a contribution. This is a small project; the
contribution flow is intentionally lightweight.

## Before you start coding

1. **Check the issue tracker** for an existing discussion. If your
   change is non-trivial, open an issue first to confirm direction
   before writing code.
2. **Read [Architecture Decisions](architecture.md)** — those choices
   are load-bearing. Proposals to revisit them are welcome but need to
   address the original "why."
3. **Read the [Plan file](https://github.com/rsp2k/nautobot-app-scanner/blob/main/docs/dev/architecture.md)**
   to understand what's currently mid-flight vs. shipped.

## Set up the dev environment

See [Development Environment](dev_environment.md) for the full walkthrough.
Short version:

```bash
git clone https://github.com/rsp2k/nautobot-app-scanner
cd nautobot-app-scanner
cp development/.env.example development/.env
# edit development/.env to set DOMAIN and rotate the changeme- secrets
make build
make up
make migrate
```

Then attach to nbshell or http://127.0.0.1:8087/ (loopback port — see
`development/docker-compose.yml`).

## Coding standards

- **Python**: ruff for lint + format. The pyproject.toml has the
  full config — line length 120, pydocstyle "google" convention,
  enables E/W/F/I/B/UP/D rules.
- **Models**: every PrimaryModel must declare the full
  `@extras_features(...)` set unless there's a documented reason not
  to. See [`models/agents.py`](https://github.com/rsp2k/nautobot-app-scanner/blob/main/src/nautobot_scanner/models/agents.py)
  for the canonical example.
- **Migrations**: generate via `make makemigrations` (which handles
  the host UID / container UID 999 bind-mount mismatch); commit the
  generated migration file in the same commit as the model change.
- **Tests**: every new model needs a test in `tests/test_models.py`;
  every new parser change needs a fixture XML + parser test.

## Commit messages

- No Claude / AI-attribution noise in the commit body (per repo
  convention)
- Subject line: short, imperative, ≤72 chars
- Body: explain the _why_, not the _what_ (the diff already shows the what)

## Pull requests

1. Branch off `main`
2. Push to your fork
3. Open a **draft PR** to start — `gh pr create --draft` is the
   convention here
4. Once tests pass and you're confident, request review

CI runs `make test` and `make ruff` on every push.

## What kinds of contributions are welcome

- New nmap parser features (so far we cover `-sn`, `-sS`, `-sU`,
  `-sV`, `-O`, `--script`, `--traceroute`)
- New probe tools added to the multi-tool dispatch — see
  [ADR-013](architecture.md#adr-013-pluggable-parser-dispatch-multi-tool-agent-foundation).
  The current set is `nmap` / `dig` / `drill` / `curl` / `mtr` /
  `masscan` / `openssl-s_client`. Open candidates: `whois`,
  `httpx`/`subfinder` (ProjectDiscovery suite), `nuclei` (templated
  CVE detection), `testssl.sh` (deeper TLS audit than `openssl
  s_client`), `tcpdump`/`tshark` (with care — PCAP shape is large).
- Additional scan profile recipes worth documenting
- New `ScannerBackend` implementations (in-process vs remote vs
  some future SSH-out-and-run model — backends are orthogonal to
  the per-tool dispatch)
- Template-content panels for additional Nautobot models
- Doc improvements (broken links, typos, clarifications)

## What's out of scope

- Auto-syncing IPAM from scan results (deliberate; see
  [Architecture Decisions](architecture.md))
- Replacing the Nautobot Job scheduler with a custom one
- Heavy authentication providers beyond Nautobot's built-in
  (LDAP/SAML/etc. work — they're Nautobot-level, not app-level)
