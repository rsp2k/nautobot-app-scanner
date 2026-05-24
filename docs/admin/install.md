# Installation

## Requirements

| Component | Version |
|-----------|---------|
| Nautobot | 3.0+ (tested 3.1.x) |
| Python | 3.10–3.13 |
| python-libnmap | 0.7+ |
| defusedxml | 0.7+ |
| nmap binary | 7.x+ (only required for the LocalBackend host) |

See [Compatibility Matrix](compatibility_matrix.md) for full support
details.

## Install via pip

```bash
pip install nautobot-app-scanner
```

The package's only Python deps are `python-libnmap` (XML parser) and
`defusedxml` (XML-bomb protection). It does NOT pull in nmap itself —
you need to install that separately on whichever host actually runs
scans (the Nautobot worker for `local` agents, or each remote-agent
host).

### Installing nmap

| OS | Command |
|----|---------|
| Debian / Ubuntu | `apt-get install nmap` |
| RHEL / Rocky / Fedora | `dnf install nmap` |
| Arch | `pacman -S nmap` |
| Alpine (containers) | `apk add nmap` |
| macOS (dev only) | `brew install nmap` |

For container deploys see the dev `Dockerfile` in `development/` — it
bakes nmap into the Nautobot worker image.

## Configure

Add to `nautobot_config.py`:

```python
PLUGINS = [
    "nautobot_scanner",
]

PLUGINS_CONFIG = {
    "nautobot_scanner": {
        # Optional overrides — defaults shown
        "agent_checkin_interval_seconds": 60,
        "local_scan_timeout_seconds": 3600,
        "prefix_coverage_cache_ttl_seconds": 300,
    },
}
```

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
