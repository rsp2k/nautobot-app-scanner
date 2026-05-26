# Architecture Decisions

Brief log of design choices made during pre-1.0. Knowing **why** helps
future contributors avoid re-litigating settled questions.

## ADR-001: Pluggable scan backends (local + remote)

There are two ways to run a scan: in-process inside the Nautobot
worker, or in a separate agent process talking back over REST. We
support both via a `ScannerBackend` ABC with a `dispatch(scan)`
method.

**Why both:**

- **Local-only** is too limiting — networks Nautobot can't reach (DMZ,
  OT, partner segments, branches) need scanning too
- **Remote-only** is over-engineered for the common single-site case
  where the Nautobot host can reach everything that matters
- The ABC makes adding a third backend (e.g. SSH-out-and-run, AWS
  Inspector wrapper) a contained change

**Tradeoff:** every Scan dispatches through one indirection layer.
Worth it for the optionality.

## ADR-002: Agent auth via User + DRF Token, not `extras.Secret`

Each remote `ScannerAgent` is bound to a dedicated `auth.User`
(auto-created via a signal). The DRF Token on that user is the agent's
bearer credential.

**Why not `extras.Secret`:**

- `Secret` is for Nautobot fetching credentials **outward** (vault,
  env var, file)
- Agent auth is **inbound** — the agent presents a credential,
  Nautobot validates it
- Wrong direction of trust for the `Secret` model

**Why User + Token:**

- Free audit trail (`created_by` / `last_updated_by` populate
  correctly across the app)
- Standard DRF `TokenAuthentication` — no custom auth class to maintain
- Permission scoping via Django groups
- Token rotation works via standard `/users/<user>/edit-token/` flow

**Tradeoff:** auto-creating an `auth.User` per agent is unusual
(normally users are humans). The signal does it transparently — the
operator just sees "scanner agent created."

## ADR-003: Pure-function parser separate from ORM persistence

The parser splits into two functions:

```python
def parse_xml(raw: str) -> list[ParsedHost]:
    """No DB. Returns plain dataclasses."""

def persist(scan: Scan, parsed: list[ParsedHost]) -> None:
    """Writes to ORM."""
```

**Why split:**

1. Parser unit tests run without a DB — just `parse_xml(fixture_xml)`
   and assert on the dataclasses. Fast, no Django setup tax.
2. When you fix a parser bug six months later, you can re-run
   `persist()` on a `Scan`'s stored `raw_xml` to backfill the
   corrected fields **without re-running the scan**. Major
   operational win.
3. The same parser can serve both backends without each backend
   re-implementing XML handling.

**Tradeoff:** one more function in the call chain, plus the dataclass
type. Worth it.

## ADR-004: Store raw nmap XML as FileField, not TextField

`Scan.raw_xml` is a `FileField` writing under `media/scanner/xml/`,
gzipped.

**Why not TextField:**

- A `/22` scan can produce many MB of XML
- Postgres TOAST handles big rows but `pg_dump` slows dramatically,
  and `Scan.objects.all()` without `.defer("raw_xml")` is dangerous
- Backup / restore flows want big blobs in object storage, not the DB

**Why gzipped:** nmap XML compresses ~10–20×.

**Tradeoff:** an extra file roundtrip on parse/re-parse. Negligible
compared to the actual scan time.

## ADR-005: Ingest race protection — one-shot token + select_for_update

The agent-side `POST /ingest/` flow looks like:

```python
with transaction.atomic():
    scan = Scan.objects.select_for_update().get(
        id=scan_id, status="running", ingestion_token=posted_token,
    )
    parser.persist(scan, parser.parse_xml(raw))
    scan.status = "completed"
    scan.ingestion_token = None  # clear — one-shot
    scan.save()
```

**Why both `select_for_update()` and a token:**

- Two simultaneous agent POSTs to the same scan race without the row
  lock; the second one's `persist()` would create duplicate
  DiscoveredHost rows (which then fail the unique_together but only
  after some writes have happened)
- A token alone protects against scan-ID guessing but not against
  retry-after-504 (the agent retries the same token; without the lock,
  both succeed)
- Together: any retry with a stale token or post-completion status
  gets a clean 409

## ADR-006: Read-only enrichment, with explicit Promote action

Discovered hosts live in `DiscoveredHost`, not in IPAM. There is no
auto-sync from scans to `ipam.IPAddress`. An authorized user
explicitly clicks **Promote to IPAddress** on a discovered host to
create the IPAddress.

<figure markdown>
![Scanner panel on a Prefix detail page](../images/prefix-scanner-panel.png)
<figcaption>Enrichment in action: scan data surfaces on the IPAM Prefix detail page via a `TemplateExtension`. The underlying IPAM record is untouched — the panel is a read-only join, not an inline edit.</figcaption>
</figure>

**Why:**

- A transient NAT or container that responded once shouldn't become a
  permanent IPAM row
- A misconfigured DHCP server bursting through address space shouldn't
  pollute the source-of-truth
- A spoofing attacker shouldn't decide what shows up in IPAM

**The Promote view requires `ipam.add_ipaddress` permission** — not
just scanner permissions. Scanner is enrichment; IPAM mutation is an
IPAM-level decision.

## ADR-007: No custom `ScanSchedule` model

Nautobot's Job scheduler handles cron-like recurring jobs out of the
box. We add a `RunScan` Job; operators schedule it via the standard
Nautobot UI.

**Why not a first-class ScanSchedule:**

- One less concept to learn, one less data model to maintain
- Nautobot's scheduler already has retry policy, history, log
  streaming, manual-trigger fallback
- A custom scheduler would have to re-build all of that

**Tradeoff:** the link from "this scan happened" to "this schedule
configuration" goes through `Scan.job_result` rather than a direct
FK to a schedule. Acceptable — the JobResult has the inputs anyway.

## ADR-008: `os_type` on host, fingerprint fields on port

- `DiscoveredHost.os_family` / `os_type` / `os_accuracy` — host-level
  (nmap `-O` reports per host)
- `DiscoveredPort.product` / `version` / `extra_info` / `cpe` —
  port-level (nmap `-sV` reports per port/service)

**Why not a separate `ServiceFingerprint` OneToOne with DiscoveredPort:**

- `-sV` always produces these alongside `service_name`/`banner` — they
  always arrive together
- A OneToOne would cost a join on every port render with no benefit
- The fields don't represent a distinct concept; they're just more
  detail about the same service

## ADR-009: No `ARPBinding` model

`DiscoveredHost.mac_address` already captures the MAC nmap resolves via
ARP (for IPv4) or NDP (for IPv6). A separate `ARPBinding` model would
duplicate that.

**Why we considered it anyway:** ARP-binding history per IP could be
useful for rogue-host detection. But the right place for that is a
dedicated time-series table or external SIEM — not first-class in this
schema.

## ADR-010: Bitemporal `DiscoveredHost` (valid time + recorded time)

Each `DiscoveredHost` row carries two independent time dimensions —
`valid_during` (wire time: when nmap observed the host) and
`recorded_during` (belief time: when scanner-app believed this row was
the current state of `(scan, ip)`). This is the "tier-4" bitemporal
pattern, ported from `l2trace.warehack.ing`.

**The single-temporal alternative:** keep one row per `(scan, ip)`,
overwrite on re-parse. Simpler schema, simpler queries, no `entry_id`
field, no partial-unique index, no `current()` / `as_of()` methods.

**Why we pay the cost anyway:** the operational scenarios that
single-temporal can't handle are real and recurring.

- **Re-parsing without rewriting history.** Parser bugs ship. When you
  fix one and re-process the stored XML, single-temporal silently
  changes what every prior report would have said. Bitemporal closes
  the old belief's `recorded_during` window and inserts a new row —
  the old answer remains queryable for anyone who needs to reproduce a
  report against last week's belief.
- **Diff reproducibility.** [Comparing Scans](../user/scan_diff.md)
  accepts `as_of=<datetime>` to anchor the diff at a recorded-time
  other than `now()`. A colleague's "Tuesday saw X" claim stays
  verifiable on Friday even after a re-parse.
- **Audit trail without a separate model.** Single-temporal would need
  an `AuditLog` table to capture "what did this row look like before
  the re-parse." Bitemporal makes the same answer a queryset method.

**Constraint change.** The original `unique_together = (("scan",
"ip_address"))` would reject the second-belief row at insert. Replaced
with a **partial unique index** that only enforces uniqueness on rows
where `recorded_during__upper IS NULL` (current belief). Historical
beliefs distinguished by `entry_id`.

**Why partial unique over PostgreSQL `ExclusionConstraint`:** simpler,
and catches the only failure mode that actually arises (two CURRENT
beliefs colliding on insert). Amendment paths always close the prior
belief atomically — overlapping belief windows would only arise from
buggy amendments, which the partial unique catches at insert time.

**Default manager contract.** `objects.all()` deliberately returns
*all* beliefs (current + historical). This matches Django's
"manager.all() returns all rows" expectation, which Nautobot internals
(admin, serializers, list viewsets) rely on. Callers that want
"current beliefs only" use `.current()`; the user-facing list viewset
applies this scoping in its `get_queryset()` so the UI defaults to
current-only.

## ADR-011: Resolve MAC OUI → vendor at ingest time, not on render

`DiscoveredHost.mac_vendor` is populated by the parser via
`netaddr`'s bundled IEEE OUI registry, at ingest time. Empty string for
locally-administered MACs and unknown OUIs.

**The lazy alternative:** compute the vendor on every render via a
template tag or model property. No `mac_vendor` field, no migration,
the lookup table is bundled with `netaddr` anyway so the work is local.

**Why we materialize:** three properties of how the vendor gets used.

- **Filterable.** With a stored field, the DiscoveredHost list view
  can offer "Filter by Vendor" without scanning every row at query
  time. The `db_index=True` makes this O(log n).
- **Diff-comparable.** [Comparing Scans](../user/scan_diff.md) treats
  `mac_vendor` as one of the `_COMPARED_FIELDS` that defines "host
  has observably changed." Lazy computation makes the diff slow
  (re-resolve every MAC on both sides) and means a vendor-DB update
  silently retroactively-changes historical diffs.
- **Auto-fill at Promote.** When a discovered host is promoted to a
  full `dcim.Device`, the form pre-selects a Nautobot
  `Manufacturer` matching `mac_vendor` if one exists. Computing
  this from scratch in the form view would require a join the
  filter-by-vendor query already has cached.

**Why `netaddr`, not an external API.** Two reasons: no network
round-trip cost at ingest (the registry is bundled with `netaddr`'s
wheel), and no dependency on a third-party service that could
rate-limit or disappear. Quarterly `pip install -U netaddr` picks up
the latest IEEE registry — no app-side work needed.
