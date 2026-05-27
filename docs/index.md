# Nautobot Scanner

A Nautobot app that dispatches one of seven network probe tools
(`nmap` / `dig` / `drill` / `curl` / `mtr` / `masscan` /
`openssl-s_client`) against IPAM-defined targets and stores discovered
hosts, open ports, service fingerprints, vulnerability findings, DNS
records, HTTP responses, TLS handshakes, traceroute hops, and DNSSEC
validation status as first-class queryable models — then surfaces the
results on existing Device, IPAddress, and Prefix detail pages.

!!! warning "Pre-alpha"
    Under active development. Backwards-incompatible changes possible until v1.
    Use the calendar-versioned releases (`YYYY.MM.DD`) to pin a known-good
    snapshot in production.

<figure markdown>
![Completed scan detail with stat cards and discovered-host table](images/scan-detail-completed.png)
<figcaption>Scan detail view — agent + profile + targets + lifecycle + raw XML + per-host results, all on one page. Click to zoom.</figcaption>
</figure>

## Why this app

Network teams already have an IPAM (Nautobot) and probe tools (nmap,
dig, curl, masscan…). The gap is that **scan results live in XML files,
JSON blobs, and one-shot terminal output, not in the IPAM**, so the
operational questions you actually need answers to are awkward:

- "Which hosts in 10.50.0.0/24 weren't there last month?"
- "Show me every device with SMB exposed to the data-center VLAN."
- "Which IPAddresses in the IPAM don't have a recent successful scan?"
- "What CVEs did `vulners` report against this segment's web servers?"

This app stores scan output **next to** your IPAM, with full referential
integrity. A `DiscoveredPort` is a real foreign key target — you can
filter, join, GraphQL-query, and template-extend it like any other
Nautobot model.

## Two scan backends

| Backend | Where the probe tool runs | When to use |
|---------|--------------------------|-------------|
| **Local** | Inside the Nautobot Celery worker | Single-site deploys, scanning networks the Nautobot host can reach |
| **Remote** | Standalone Python agent process | Scanning isolated segments (DMZ, OT, branch offices, remote sites) where the Nautobot host has no L3 reachability |

Both backends share the same data model and the same parser-dispatch
table — the only difference is where the probe subprocess executes.

## Enrichment, not replacement

The app **never auto-creates IPAM/DCIM records**. Scan results live in
their own `DiscoveredHost` model. To convert a discovered host into a
real `ipam.IPAddress`, a user explicitly clicks **Promote to IPAddress**
on the host detail page — with full permission checks against
`ipam.add_ipaddress`. See [Promote to IPAddress](user/promotion.md).

## Documentation

- **[User Guide](user/app_overview.md)** — what scans are, how to run them,
  how to read the results, how to integrate with the rest of Nautobot
- **[Data Models](models/index.md)** — schema reference, field-by-field
- **[Administrator Guide](admin/install.md)** — installation, configuration,
  upgrade, compatibility matrix
- **[Developer Guide](dev/contributing.md)** — architecture decisions,
  agent protocol, writing a custom backend

## Quick links

- **Source**: [github.com/rsp2k/nautobot-app-scanner](https://github.com/rsp2k/nautobot-app-scanner)
- **Issue tracker**: same repo
- **Author**: Ryan Malloy &lt;ryan@supported.systems&gt;
- **License**: Apache 2.0
