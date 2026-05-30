# Installation

## Requirements

| Component | Version |
|-----------|---------|
| Nautobot | 3.0+ (tested 3.1.x) |
| Python | 3.10–3.13 |
| python-libnmap | 0.7+ |
| defusedxml | 0.7+ |
| nautobot-dns-models-bitemporal | `2.2.1` (git URL pin to the renamed fork dist until its PyPI publish flips — see note below) |
| Probe tool binaries | only required on the host that runs scans — see per-tool versions in the [Compatibility Matrix](compatibility_matrix.md#probe-tool-versions) |

See [Compatibility Matrix](compatibility_matrix.md) for full support
details.

## Install via pip

```bash
pip install nautobot-app-scanner
```

The package pulls in `python-libnmap` (XML parser), `defusedxml`
(XML-bomb protection), and `nautobot-dns-models-bitemporal` (typed
DNS records that dig/drill scan answers promote into — see
[ADR-015](../dev/architecture.md#adr-015-promote-dig-and-drill-into-typed-dns-models)).
It does NOT install any probe tool binaries — you need to install
those separately on whichever host actually runs scans (the Nautobot
worker for `local` agents, or each remote-agent host).

!!! note "nautobot-dns-models-bitemporal is pinned to a git URL @ tag"
    Phase K (the dig/drill → typed-DNS promotion) depends on the
    `BitemporalMixin` and explicit `obj.amend()` API added in the
    bitemporal fork of `nautobot-app-dns-models`, published as the
    `nautobot-dns-models-bitemporal` distribution (the rename signals
    the API divergence — upstream's `nautobot-dns-models` doesn't
    have `amend()` and would `AttributeError` during promotion).
    The fork's PyPI publish remains deferred per its own audit
    discipline, so `pyproject.toml` pins it via git URL:
    `nautobot-dns-models-bitemporal @ git+https://github.com/rsp2k/nautobot-app-dns-models@v2.2.1`.
    `pip install nautobot-app-scanner` resolves and fetches the fork
    automatically; no manual step needed. The import path stays
    `nautobot_dns_models` — no code-side change. When the publish
    flips, a one-line follow-up bumps the pin to a plain version
    specifier. See `docs/agent-threads/bitemporal-dns-integration/`
    for the full coordination history (24 messages, 13 bugs caught
    across the integration arc).

### Installing the probe tool binaries

The scanner dispatches one of seven tools per profile. Install only
the tools you'll actually use; a profile that asks for a missing tool
fails cleanly with the tool name in `Scan.error_message`.

| OS | nmap-only | Full multi-tool set (Phase G + J) |
|----|---|---|
| Debian / Ubuntu | `apt-get install nmap` | `apt-get install nmap masscan mtr-tiny ldnsutils dnsutils curl openssl` |
| RHEL / Rocky / Fedora | `dnf install nmap` | `dnf install nmap masscan mtr ldns-utils bind-utils curl openssl` |
| Arch | `pacman -S nmap` | `pacman -S nmap masscan mtr ldns bind-tools curl openssl` |
| Alpine (containers) | `apk add nmap` | `apk add nmap masscan mtr ldns-utils bind-tools curl openssl` |
| macOS (dev only) | `brew install nmap` | `brew install nmap masscan mtr ldns bind curl openssl` |

(`drill` ships in the `ldns-utils` / `ldns` package on most distros;
`dig` in `bind-utils` / `bind-tools` / `dnsutils`.)

For container deploys see the dev `Dockerfile` in `development/` — it
extends `nicolaka/netshoot` which bundles all seven tools out of the
box (plus ~40 more) so a single image supports every profile the app
dispatches.

## Configure

Add to `nautobot_config.py`:

```python
PLUGINS = [
    "nautobot_scanner",
    "nautobot_dns_models",   # required — Phase K promotes dig/drill into this
]

PLUGINS_CONFIG = {
    "nautobot_scanner": {
        # Optional overrides — defaults shown
        "agent_checkin_interval_seconds": 60,
        "local_scan_timeout_seconds": 3600,
        "prefix_coverage_cache_ttl_seconds": 300,
    },
    "nautobot_dns_models": {},
}
```

Both plugins must be listed — `nautobot_scanner` writes typed DNS
records into the `nautobot_dns_models` tables on every dig/drill
ingest, so the second plugin's models need to be installed and
migrated for scan ingest to succeed.

All settings are optional — the defaults from
`NautobotScannerConfig.default_settings` will be used otherwise.

## Apply migrations

```bash
nautobot-server migrate
nautobot-server collectstatic --noinput
```

Restart the Nautobot web and worker processes. The **Scanner** nav menu
appears immediately; the **Scanner: Run Scan** and **Scanner: Scan
Prefix** jobs become available under **Jobs**.

## First-time setup

1. Visit **Apps > Scanner > Scanner Agents** and create a `local` agent
   for your Nautobot worker host.
2. Visit **Apps > Scanner > Scan Profiles** and create at least one
   profile (`-sn` host-discovery is a safe first profile).
3. Run a scan against a small test prefix (see
   [Getting Started](../user/app_getting_started.md)).

## Permissions

The app honors Nautobot's standard model-permission system. Typical
role grants:

| Role | Recommended permissions |
|------|------------------------|
| Operator (scan + view results) | `nautobot_scanner.add_scan`, `nautobot_scanner.view_*` |
| Admin (manage agents/profiles) | `nautobot_scanner.*` |
| Promoter (turn discoveries into IPAM) | the above + `ipam.add_ipaddress` |

The **Promote to IPAddress** view specifically requires
`ipam.add_ipaddress` — scanner permissions alone are not enough.
