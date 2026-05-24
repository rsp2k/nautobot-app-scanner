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
