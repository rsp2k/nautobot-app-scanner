# Use Cases

Operational questions the app answers, and which UI surface answers each
one. Every flow on this page is point-and-click — no shell required.

## "Which IPs in this prefix have I never scanned?"

**Where**: IPAM → **Prefixes** → click your prefix → the **Scan Coverage**
panel on the right.

The [Scanner Coverage panel](app_overview.md) (injected by the app via
a `TemplateExtension`) renders coverage stats directly on every
`ipam.Prefix` detail page:

- Percent of in-prefix IPs that have at least one scan
- Hosts up / hosts down across all scans against this prefix
- Recent scan history with click-through to each `Scan` detail page

For a `/24` the coverage figure is computed live; for `/16` and larger
it's cached for 5 minutes so the page load stays fast.

**Closing the gap**: dispatch a `discovery` profile scan against the
prefix — **Jobs → Run Scan → pick prefix → submit**. Re-open the
Prefix detail; coverage % climbs.

---

## "Which hosts are running SMB / SSH / TLS?"

**Where**: dispatch the matching service-recon profile, then read the
findings on the resulting Scan detail page.

The shipped [service-focused NSE profiles](scan_profiles.md#service-focused-nse-recon-5-profiles)
exist precisely for this — each one narrows nmap to one service category
and fires the NSE scripts that surface relevant data:

| Question | Profile to run |
|---|---|
| Who's exposing SMB (and which SMB protocols)? | `smb-recon` |
| Who's exposing SSH (and which auth methods)? | `ssh-recon` |
| Who's exposing TLS (with what certs)? | `tls-audit` |
| Who's exposing HTTP (with what `Server:` header)? | `web-recon` |
| Who's exposing SNMP? | `snmp-recon` |

After the scan completes, the Scan detail page rolls up every
`NseFinding` from every host into one panel. Filter by `severity` or
`nse_script` to narrow further.

---

## "What CVEs did the latest vuln scan turn up?"

**Where**: open the most recent `vuln` profile scan from **Scanner →
Scans** → the **NSE findings** panel on the Scan detail page.

The `vuln` profile runs nmap's `vulners` NSE script, which attaches
`severity=high` or `severity=critical` `NseFinding` rows to discovered
ports with CPE matches in the vulners DB. Click any finding row to
open its detail page — `output` carries CVE IDs and CVSS scores;
`references` carries vendor advisory + exploit-DB URLs;
[`elements`](../models/nsefinding.md) carries structured key-value
data like `cvss.score` and `cvss.vector`.

Per-host view: drill into any `DiscoveredHost` from the scan; the
**Port Findings** panel lists per-port `vulners` output for that host.

---

## "Which discovered hosts aren't yet in IPAM?"

**Where**: **Scanner → Discovered Hosts** → filter **Linked IP
Address** is empty.

The list view's **Linked IP Address** column is a click-through to the
matching `ipam.IPAddress`, populated by the
[Promote to IPAddress](promotion.md) action. Rows where the column
shows `—` haven't been promoted yet.

For each candidate row, hit **Promote to IPAddress** (or **Promote to
Device** if it's real network equipment) — the form pre-fills from the
discovered host's IP and hostname; you supply namespace / status / parent
prefix and submit.

---

## "Which remote agents have stopped checking in?"

**Where**: **Scanner → Scanner Agents** → look at the **Status** column.

Remote agents check in via `POST /api/plugins/scanner/agents/<id>/checkin/`
on a configurable cadence (default 60s). The
[`MarkStaleAgents` Job](running_scans.md) (scheduled every 5 minutes
out of the box) flips `status=Offline` on any remote agent whose
`last_seen` is older than `3 × expected_interval`.

The agent list view groups by status — `Offline` agents bubble visually
(yellow badge against the green `Active`). Click into one to see when
it last checked in and its capabilities snapshot.

---

## "What changed on this host since the last scan?"

**Where**: open the host's most recent `DiscoveredHost` detail page →
**Rescan this host** button → on the resulting scan, **Compare with
previous scan**.

Two coupled features make this a one-click flow:

1. [**Rescan this host**](../models/discoveredhost.md#rescan-this-host)
   dispatches a fresh single-host scan inheriting agent + profile from
   the host's parent scan. Bitemporally additive — old beliefs stay
   queryable.
2. The resulting scan's detail page has a **Compare with previous scan
   on \<agent\>** button that opens the [scan diff view](scan_diff.md) —
   showing per-field deltas, opened/closed port deltas, and
   vulnerability-count drift between the two scans of the same host.

For the broader "what changed on every host in this segment?" question,
use the same Compare button on a full-prefix scan instead of a
single-host rescan.

---

## "Show me everything Apple / Microsoft / Cisco on this network"

**Where**: **Scanner → Discovered Hosts** → filter by **OS Vendor**.

The `os_vendor` field on `DiscoveredHost` is populated from nmap's
osclass data when an `-O` profile runs (`os-detect`, `full-tcp`). The
list view filter is `?os_vendor=Apple` (or Cisco, Fortinet, Linux,
Microsoft …) and the column is db-indexed for fast filtering.

Combine with **OS Device Type** (`?os_device_type=printer` /
`router` / `firewall` / `switch` / `webcam` / …) to slice further —
"all Apple iOS smartphones" or "all Cisco switches" turn into URL
parameters, not custom queries.

---

## "Show me one host's full scan history"

**Where**: **Scanner → Discovered Hosts** → filter **Ip Address** to
the host's IP.

`DiscoveredHost` rows are keyed by `(scan, ip_address)` — one row per
scan that touched that IP — so filtering by IP gives you one row per
scan, sorted newest-first. Each row links to the per-scan host detail
where you can compare port lists, vendor info, OS classification, and
NSE findings as of that scan.

Bitemporal bonus: even if a scan was re-parsed later (parser bugfix),
the [`DiscoveredHost` model preserves prior beliefs](../models/discoveredhost.md#bitemporality).
The list view shows current beliefs by default; programmatic access
via `.as_of(<datetime>)` is available for audit replay.

---

## "Which DNS names resolve to this discovered host?"

**Where**: any `DiscoveredHost` detail page → the **DNS Records
(pointing here)** panel on the right.

Once Phase K is enabled (any dig or drill scan has run and its records
have been promoted), the panel queries
`DiscoveredHost.dns_records_pointing_here` — which walks IPAM
(`IPAddress` keyed by host IP) → `nautobot-dns-models` (`ARecord` /
`AAAARecord` filtered by that IPAddress FK). The cross-reference
surfaces the cross-layer answer in one place:

- *Scanner layer* says: "we saw an open port on `198.51.100.42`."
- *DNS layer* says: "`mail.example.com`, `mta-01.example.com`, and
  `legacy-relay.example.com` all resolve to `198.51.100.42`."

The panel renders only typed records — the IP has to exist in IPAM
first. A discovered host whose IP is not (yet) promoted to IPAM shows
the panel empty, with an explanatory message: "promote the IP to IPAM
and re-run dig/drill to populate this." That's the same
[best-effort IPAM-coupling gate](../models/dnsrecordprovenance.md#a-and-aaaa-records-and-the-ipam-coupling-gate)
the promoter uses on write — symmetric on read.

---

## "Which scans saw an A record for example.com?"

**Where**: Nautobot REST or GraphQL against `nautobot_dns_models.ARecord`,
then follow `arecord.dns_promotions` (the reverse relation from
[`DnsRecordProvenance`](../models/dnsrecordprovenance.md)) to the
source `NseFinding`, then to the parent `Scan`.

This is the question Phase K's promotion path exists to answer.
Before Phase K, DNS records lived as JSON on `NseFinding.elements` —
browsable but not filterable. After Phase K, the same data lives in
typed `nautobot-dns-models` tables with proper indexes, FK joins to
IPAM, and full REST + GraphQL exposure.

The provenance row also preserves the **wire** TTL and value (which
upstream `nautobot-dns-models` clips: TTL ≥ 300s, TXT ≤ 256 chars), so
audit queries that need the un-clipped data still have it.

---

## "What did nmap actually run for this scan?"

**Where**: any Scan detail page → the **Provenance** card.

The Scan model captures four fields from the nmap XML at ingest:

- `nmap_command` — the literal command-line nmap executed (including
  any flags the dispatcher merged in beyond `profile.nmap_arguments`)
- `nmap_version` — the nmap binary version, e.g. `7.94`
- `xml_version` — XML schema version (forensic value when parsers
  drift between nmap releases)
- `ports_scanned` — denominator for the **Open ports** stat card
  ("found 10 open out of 100 scanned" vs "out of 65535")

Reproducibility one query away instead of one shell pivot into the
gzipped raw XML.

---

## Gaps — known operational questions without a great UI answer

A few common questions don't have a clean point-and-click answer yet.
Listed here so you know to use GraphQL, the REST API, or `nbshell`
for these — or to file a feature request.

| Question | Workaround |
|---|---|
| "Which prefixes have **never** been scanned?" | IPAM Prefix list (Nautobot core), then cross-reference Scan list. GraphQL is the cleanest cross-model query. |
| "Find every port=445 host across all scans" | No standalone DiscoveredPort list view — `DiscoveredPort` is nested under host. Workaround: run `smb-recon` and read the resulting Scan detail. |
| "Cross-scan NSE finding search" | NseFinding has only a detail view, no list view. Per-Scan / per-Host rollup panels cover most use cases; a global list view is a candidate feature. |

All scanner models declare `@extras_features("graphql")` so the
[Nautobot GraphQL endpoint](https://docs.nautobot.com/projects/core/en/stable/user-guide/feature-guides/graphql/)
exposes them with the standard relations — useful for the gap cases
above.
