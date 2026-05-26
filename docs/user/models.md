# Models Overview

The app defines 7 Django models split across three concerns. This page
is a one-screen mental map; for field-level reference visit the
individual model pages under [Data Models](../models/index.md).

## Identity

- **[`ScannerAgent`](../models/scanneragent.md)** — who runs scans.
  `agent_type` selects between in-worker (`local`) and standalone
  (`remote`) execution. Remote agents are bound to a Nautobot user
  whose DRF Token is the agent's bearer credential.
- **[`ScanProfile`](../models/scanprofile.md)** — reusable nmap
  argument template. One profile per "kind of scan" you want
  operators to be able to run.

## Execution

- **[`Scan`](../models/scan.md)** — one scan execution. Ties an agent
  to a profile to a set of IPAM targets. Holds the lifecycle state,
  the one-shot `ingestion_token`, the raw nmap XML, and a back-link
  to the dispatching `extras.JobResult`.

## Results

- **[`DiscoveredHost`](../models/discoveredhost.md)** — one host nmap
  reported (per scan). Owns its own `linked_ipaddress` and
  `linked_device` FKs back to Nautobot IPAM/DCIM.
- **[`DiscoveredPort`](../models/discoveredport.md)** — one port on a
  discovered host. Fingerprint fields (`product`, `version`,
  `extra_info`, `cpe`) live here directly — no separate
  `ServiceFingerprint` model.
- **[`NseFinding`](../models/nsefinding.md)** —
  one NSE-script finding on a port. `severity` defaults to `unknown`
  (never null).
- **[`TraceRouteHop`](../models/traceroutehop.md)** — one hop in
  nmap's `--traceroute` path to a discovered host.

## Base classes at a glance

| Model | Base | Why |
|-------|------|-----|
| `ScannerAgent` | `PrimaryModel` | Gets its own UI/API, status, tags, custom fields |
| `ScanProfile` | `PrimaryModel` | Same — operators want to manage profiles like first-class records |
| `Scan` | `PrimaryModel` | Same — auditability, custom fields, GraphQL |
| `DiscoveredHost` | `PrimaryModel` | Has its own page, gets the **Promote** action |
| `DiscoveredPort` | `BaseModel` | Only exists in context of its host; rendered nested |
| `NseFinding` | `BaseModel` | Same — rendered nested on the port |
| `TraceRouteHop` | `BaseModel` | Same — rendered nested on the host |

All `PrimaryModel`s have the standard `@extras_features(...)` set —
custom fields, statuses, webhooks, GraphQL, relationships, custom
validators, custom links, export templates.

## What was deliberately NOT modeled

| Considered | Decision | Reason |
|-----------|----------|--------|
| `ARPBinding` | Dropped | `DiscoveredHost.mac_address` covers it; separate model invites duplicate-truth |
| `ServiceFingerprint` (OneToOne with DiscoveredPort) | Folded into `DiscoveredPort` | Fields always arrive together from `-sV`; split costs a join with no benefit |
| `ScanSchedule` with cron | Dropped | Nautobot's job scheduler handles this; one less concept to learn |
| `os_type` per port | Moved to `DiscoveredHost` | OS detection is per-host, not per-port |
