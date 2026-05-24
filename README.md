# nautobot-app-scanner

nmap-based network scanning for Nautobot — discovers hosts, ports, services,
and vulnerabilities against IPAM-defined targets, then surfaces results on
the existing Device, IPAddress, and Prefix pages.

## What it does

- **Two scan backends**: a local backend that runs `nmap` inside the Nautobot
  Celery worker, and a remote-agent backend for scanning isolated network
  segments (DMZ, OT, branch offices) where the Nautobot host can't reach.
- **First-class models** for scans, discovered hosts, open ports, service
  fingerprints, vulnerability findings (NSE), and traceroute hops.
- **Read-only enrichment by default** — never auto-creates IPAM/DCIM records.
  An explicit "Promote to IPAddress" action lets users convert a discovered
  host into an `ipam.IPAddress`.
- **Template panels** inject scan summaries on `dcim.device`, `ipam.ipaddress`,
  and `ipam.prefix` detail pages.

## Quick start

```bash
cp .env.example .env
# edit .env: set DOMAIN and rotate the changeme- secrets
make build
make up
make migrate
```

Browse to `https://${DOMAIN}/` (Caddy reverse-proxy handles TLS) and log in
with the superuser credentials from `.env`.

## Status

Pre-alpha — scaffold only. See [plan](../../../.claude/plans/yo-i-d-like-to-serialized-lantern.md)
for the implementation roadmap.

## License

Apache-2.0
