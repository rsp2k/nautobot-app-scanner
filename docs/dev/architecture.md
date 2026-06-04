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

## ADR-012: Generalize Finding model from port-scope-only to port-OR-host scope

The original `VulnerabilityFinding` model required a `DiscoveredPort`
FK — every finding had to attach to a specific port. Migration `0009`
generalizes this: the model is renamed to `NseFinding`,
`discovered_port` becomes nullable, a new `discovered_host` nullable
FK is added, and a `CheckConstraint` enforces that exactly one of the
two is set per row.

**The strictly-port-scoped alternative:** keep `discovered_port`
required. Simpler schema, no XOR check, no two-panel UI on the host
detail page.

**Why we generalize:** the strict-port shape silently dropped real data.

- **Host-scope NSE scripts produce real findings.** `smb-os-discovery`,
  `snmp-info`, `snmp-sysdescr`, `ssh-hostkey`, `ssh-auth-methods` all
  fire once per host, not per port. Pre-`0009`, the parser had no
  ingest path for `nmap_host.scripts_results` — those findings hit
  the floor. After: 5 host-scope `NseFinding` rows on a typical
  `smb-recon` run; SMBv1 dialect annotations on Win XP machines
  surface as drift.
- **The rename matches what's actually stored.** `vulners` IS NSE, but
  so is `http-title` and `ssl-cert` — informational scripts without
  CVEs. The `severity` field (`info` / `low` / ... / `critical`)
  already distinguishes vulnerability findings from informational
  ones; the old `VulnerabilityFinding` name implied the model
  rejected the informational case, which it never did.
- **Two parallel models would have been worse.** The alternative —
  add a separate `HostScopeFinding` model — would duplicate the
  `nse_script` / `output` / `severity` / `references` schema and
  force every consumer (serializers, tables, summary rollups) to
  union across two models. A single model with two nullable parent
  FKs is one query, one serializer, one table.

**Why a CheckConstraint, not just `clean()` validation.**
Schema-level constraints fail closed. `bulk_create`, raw SQL, ORM
patches that bypass `full_clean()`, and buggy future parser changes
all get caught at insert time rather than producing orphan or
double-parent rows that pollute downstream rollups (the
`vulnerability_count` aggregation, for example, double-counts a
finding that somehow had both parents set).

**Knock-on changes.** The host detail page now renders **two**
finding panels — `host_findings` (direct FK) and `ports.vulnerabilities`
(two-hop). The `DiscoveredHost.vulnerability_count` property sums
across both scopes. The `_vulnerability_count` annotation in the
list view's `get_queryset()` combines them too so the **Vulns**
column stays accurate without a per-row fallback. Existing
`vulners`-only deployments behave identically — host-scope findings
simply remain empty if you never run a host-scope-script profile.

## ADR-013: Pluggable parser dispatch (multi-tool agent foundation)

Until Phase G, every code path assumed "the tool is nmap" — the
parser was libnmap-only, the agent's `build_argv()` hardcoded
`[nmap, -oX, -, …]`, the ingest endpoint accepted only XML. This
locked out everything the agent's host machine could do beyond nmap.

The fix: a **dispatch dict** mapping tool name to parser callable
(`parser.PARSERS = {"nmap": parse_nmap, "dig": parse_dig, …}`) with
a `dispatch_parser(tool_name) → callable` helper. ScanProfile gains
a `tool` field; the agent's `TOOL_REGISTRY` maps tool name to
`(argv_builder, content_type)`; the ingest endpoint reads the
`X-Tool` request header to pick which parser runs.

**The polymorphic-class alternative considered:** a `ToolBackend`
abstract base class with `build_argv() / parse_output()` methods,
one subclass per tool. Cleaner inheritance, more Java-shaped.

**Why dispatch dict instead:**

- **Parsers are pure functions.** They take raw bytes, return a
  list of `ParsedHost` dataclasses. No state, no setup, no teardown.
  A class adds zero behavior over a top-level `def`.
- **Adding a tool is 3 changes, not 3 files.** Append to `PARSERS`,
  append to `TOOL_REGISTRY` on the agent, add a `choices` value.
  A polymorphic hierarchy would require a new module per subclass
  plus registration glue.
- **Dispatch is `O(1)` dict lookup.** `isinstance()` chains in a
  registry walker would be `O(n)` and a future maintainer would
  reasonably wonder why we chose them.
- **Field validation lives where the data lives.** `tool_arguments`
  validation happens in the per-tool `argv_builder` function on the
  agent — no need to push validation up into the model when the
  agent is going to revalidate anyway.

**Back-compat.** `ScanProfile.tool` defaults to `nmap`. Every
pre-Phase-G seeded profile (migrations 0002, 0005, 0010) creates
nmap-shaped profiles that simply inherit the default and keep
working. Pre-Phase-G agents that don't send `X-Tool` get treated
as nmap submissions.

**Raw output storage.** `Scan.raw_xml` stays as the nmap field;
`Scan.raw_output` is the parallel for non-XML tools (gzipped to
`media/scanner/output/YYYY/MM/`). Mutually exclusive — exactly one
is populated per scan, indicated by `tool_used`. Could have been
collapsed into a single field with file-extension discrimination,
but separate fields make "give me every nmap scan's XML" a clean
queryset filter instead of a path-suffix string match.

**Phase G' + J + L postscript — closing the "dropdown lies" gap.**
Phase G shipped the dispatch foundation but only `nmap` + `dig`
parsers; `ToolChoices` was a superset of `PARSERS` + `TOOL_REGISTRY`,
so a user picking `curl` / `mtr` / `masscan` / `openssl-s_client`
from the profile dropdown got a 400 at ingest. Phase G' added
`drill` (DNSSEC validation alongside dig); Phase J added the
remaining four to bring all three sets to parity; **Phase L added
`testssl` and `ssh-audit`** as the deep-audit pair (compliance-grade
TLS + SSH audits with native ordinal severity). The dispatch contract
didn't change — only the registry filled out. The
`TestToolRegistriesInParity` regression test that landed in Phase L
asserts `set(ToolChoices.values()) == set(PARSERS.keys())` at the
server side; the agent's `TOOL_REGISTRY` is kept in sync by its own
CI. The "dropdown lies" gap is now locked closed by that test;
adding tool #10 must keep all three registries in lockstep.

## ADR-014: Pentest mode permission gating + immutable audit flag

Phase I adds five pentest-class fields to `ScanProfile`
(`decoy_addresses` / `fragment_packets` / `mtu` / `source_port` /
`idle_scan_zombie`). Each maps to one nmap evasion flag. Phase J
widened the trigger to also include `tool in PENTEST_TOOLS`
(currently `{"masscan"}`) — masscan at the seeded 50k pps rate is
unmistakable to any IDS regardless of evasion flags, so tool-identity
gating is correct. Setting any one evasion field, or selecting any
tool in `PENTEST_TOOLS`, flips the profile into "pentest mode," and:

1. **Dispatch is gated by a new permission**
   (`nautobot_scanner.use_pentest_profiles`). Without it, dispatch
   raises `PermissionDenied` with the legal-authorization notice
   in the message. Editing or viewing pentest profiles is *not*
   gated — only dispatch.
2. **`Scan.was_pentest_mode` is stamped True at dispatch** and
   never updated afterward.

**The derived-at-render alternative considered:** compute
"is_pentest" by reading the linked profile's flags whenever the UI
renders a scan. Simpler schema (no extra column), no migration.

**Why stamp instead:**

- **Profiles get edited.** An operator could dispatch with three
  pentest flags set, then later edit the profile to clean
  configuration. The historical answer to "was THIS scan dispatched
  in pentest mode?" must stay correct forever — for audit, for
  compliance review, for incident response — regardless of
  subsequent profile edits. Derived-at-render returns whatever
  the profile *currently* says.
- **Filterability.** With a stored, db-indexed Boolean, the question
  "show me every pentest scan from the last quarter" is a
  one-clause queryset filter. Derived from the profile, it would
  require joining and walking five nullable fields in WHERE.
- **Audit trail without webhook gymnastics.** The stamped value
  flows through change-log, GraphQL, exports, and webhooks without
  any custom serializer code.

**Why permission gating in `utils.check_pentest_permission()`, not
per-view.** Three dispatch sites exist: `jobs.RunScan`,
`jobs.ScanPrefix`, `views.DiscoveredHostRescanView`. Inlining the
permission check in each would mean three places to forget to
update when adding a fourth dispatch site. The centralized helper
also returns the `is_pentest` flag, so the caller can stamp
`was_pentest_mode` in one call:

```python
was_pentest = check_pentest_permission(request.user, scan.profile)
scan.was_pentest_mode = was_pentest
scan.save()
```

**Form-side legal-warning banner.** The pentest fields render under
a yellow legal-authorization banner on the `ScanProfile` add/edit
form (operators can't claim they didn't know). The
[Pentest Mode user docs](../user/pentest_mode.md) carry the
detailed permission-setup walkthrough so this banner doesn't need
to explain everything inline.

## ADR-015: Promote dig and drill into typed dns-models

Phase G + G' shipped dig and drill as scanner tools — but their
output landed on `NseFinding.elements` as JSON. "Which scans saw an
`A` record for `example.com`?" was browsable but not queryable; no
joins to IPAM, no filters in the REST API, no GraphQL edges. Phase K
hooks the dig/drill ingest path into the typed-DNS layer provided by
[`nautobot-app-dns-models`](https://github.com/rsp2k/nautobot-app-dns-models),
so each parsed answer record becomes a row in the right typed table
(`ARecord`, `MXRecord`, `NSRecord`, `TXTRecord`, etc.) **plus** a
sidecar `DnsRecordProvenance` row joining the typed record back to
the scanner finding.

**Three structural decisions** that took the most negotiation, with
the failed alternatives recorded so they don't get re-litigated:

### 1. The fork, not upstream

We pin **`nautobot-dns-models-bitemporal @ v2.2.1`** (git URL @ tag,
fork of upstream `nautobot/nautobot-app-dns-models`) rather than
upstream itself.

- **Why the fork.** DNS data is the canonical "what's true *now*"
  store, but operators routinely ask "what did `mail.example.com`
  resolve to last Tuesday?" — the same shape question that
  [ADR-010 bitemporal `DiscoveredHost`](#adr-010-bitemporal-discoveredhost-valid-time-recorded-time)
  answers for hosts. The fork adds `BitemporalMixin` to `DNSZone` /
  `DNSRegistration` / every DNS record class — the same
  `valid_during` / `recorded_during` / `entry_id` triple — so
  re-scans rotate the belief window through `manager.as_of(dt)`
  instead of needing a sidecar history table.
- **Why the renamed distribution.** The fork's `v2.2.0a1` tag
  renamed the published dist from `nautobot-dns-models` to
  `nautobot-dns-models-bitemporal` because the `save()` / `amend()`
  API split (see decision #4 below) is a behavioral contract break
  versus upstream. Anyone `pip install`-ing `nautobot-dns-models`
  expecting upstream semantics would silently get the fork's
  semantics — the rename forces an explicit opt-in. The import path
  stays `nautobot_dns_models` so no scanner code changes.
- **Why pin to git URL, not PyPI.** The fork's PyPI publish remains
  deferred per its own audit discipline. Pinning through
  `nautobot-dns-models-bitemporal @ git+https://.../@v2.2.1` is the
  canonical install path until publish flips; swap to a plain
  `nautobot-dns-models-bitemporal == 2.2.1` in a follow-up.

### 2. `entry_id`-via-composite-key, not `GenericForeignKey(record_type, pk)`

`DnsRecordProvenance` references the typed record via
`(record_type ContentType, record_entry_id UUID)` and resolves it
through a manual `model.all_versions.filter(entry_id=...)` lookup —
**not** through Django's standard `GenericForeignKey`.

- **Why not GFK.** GFK is hardcoded to use the target's `pk`. The
  bitemporal mixin's sequenced-amend pattern rebinds `pk` on every
  belief change — a `(record_type, pk)` GFK would silently follow
  the successor after one amend, losing the "we observed this
  **specific** belief at scan time" identity. Discovered during the
  K' refactor; the schema fix shipped as migration `0020` (column
  rename only, since 0019 had only just landed and the table was
  empty).
- **The resolver uses `all_versions`, not `objects`.** The default
  manager filters to current beliefs; a provenance row pointing at
  a superseded belief — the whole point of `entry_id` — would
  resolve to `None` against `objects`. The fork's `all_versions`
  manager queries the full history. Graceful fallback to `objects`
  keeps the property working if anyone installs upstream `2.1.1`
  over the top.

### 3. Best-effort promotion, never blocks ingest

The promoter is invoked from `ScanIngestView` for `tool in
DNS_PRODUCING_TOOLS` (`{"dig", "drill"}`) after the scan has fully
persisted. Each per-record promotion is wrapped in `try/except
Exception` — the broad catch is **deliberate**:

- A bug in `nautobot-dns-models 2.1.x` (we've found and reported
  several) must not break scan ingest. The raw data still lives
  on `NseFinding.elements` either way, so a failed promotion
  loses no information; only the queryability degrades.
- The agent has already POSTed and moved on. Failing ingest after
  the agent's one-shot ingestion token has been consumed would
  strand the scan in `running` forever.

Same principle as [ADR-011's MAC OUI resolution](#adr-011-resolve-mac-oui-vendor-at-ingest-time-not-on-render):
enrichment that *can* fail must *fail soft* relative to the
critical-path "did the scan complete" question.

**Counts dict, not exceptions, for partial success.** The
promoter returns
`{"promoted": Counter, "created": Counter, "amended": Counter,
"unchanged": Counter, "skipped": int}` so callers can bucket
outcomes (and the test suite can lock them in) without
relying on stringly-typed exceptions.

### 4. `obj.amend()` for sequenced rotation, with one-retry `ConcurrentAmendError` handling

The bitemporal fork's `v2.2.0` API split made the rotation contract
explicit: `obj.save()` is now framework-standard pk-stable UPDATE,
and `obj.amend(**field_changes)` is the entry point that closes the
prior belief window and inserts the successor row.

- **Why the split exists upstream.** Before the split, `save()`
  implicitly rotated the belief whenever a tracked field changed —
  which broke ~30 Nautobot framework tests that assume pk stability
  across edits (edit-view round-trips, REST `PATCH`/`PUT`, list-view
  ordering). The implicit-rotation contract was simpler but brittle
  against the framework; the explicit `amend()` API is the cleaner
  answer.
- **Why we use it.** `_upsert_with_amend` detects drift between the
  freshly-parsed wire fields and the current belief, calls
  `obj.amend(**drift)` once, and writes the provenance row **after**
  the call (so `obj.entry_id` captures the freshly-rotated belief,
  not the prior one). No-drift case: `unchanged` outcome, no DB
  write, no provenance row.
- **`ConcurrentAmendError` retry-once.** Two scans posting findings
  against the same target simultaneously can race — both detect the
  same drift, both call `amend()`, only one wins the row-level lock
  the fork added in `v2.2.0a2`. The loser catches
  `ConcurrentAmendError`, re-reads the row, recomputes drift against
  the now-current state, and either returns `unchanged` (the other
  writer landed our exact data) or amends again with the *remaining*
  drift. Both branches are regression-tested. The exception import
  is wrapped in `try/except ImportError` so anyone running upstream
  or a future fork version that drops the exception type doesn't
  `NameError` — the except clause just becomes dead code.

### A and AAAA records need IPAM, others don't

`ARecord` / `AAAARecord` in `nautobot-dns-models` carry a `ForeignKey`
to `ipam.IPAddress` — not a raw IP string. Nautobot 3.x `IPAddress`
requires a parent `Prefix` in the same `Namespace`, so we can't
synthesize an IPAddress for an arbitrary public IP without also
synthesizing the covering prefix (which would pollute IPAM).

**v1 behavior:** look up `IPAddress.objects.filter(host=ip_str)`; if
found, write the typed A/AAAA record; if not, log + skip but **always
write the provenance row** with the raw value. Once the operator
creates the covering prefix and re-scans, the next promotion fills in
the typed record; the earlier provenance row stays as historical
context — bitemporally additive, same shape as every other scanner
record.

Non-A/AAAA records (`CNAME`, `MX`, `NS`, `TXT`, `PTR`, `SRV`) have no
IPAM coupling and always promote.

### The decision trail

The full negotiation between this repo and the dns-models maintainer
during Phase K is committed at `docs/agent-threads/bitemporal-dns-integration/`
— 24 messages, captured via the agent-thread protocol, surfaced
**13 bugs** across the integration arc (5 from scanner-side
integration testing, 2 from the fork's own full-test-suite runs, 6
from a separate Margaret-Hamilton-style reliability review on the
fork side). The thread documents two upstream migration bug
discoveries (`name[]` vs `text[]` cast, non-idempotent `EXCLUDE`
constraint creation), the `save()`/`amend()` API split rationale,
and the structural back-and-forth that produced the
`_upsert_with_amend` helper at the center of the promoter. Worth
keeping for the same reason the ADRs are: a commit message captures
the resolved decision; the thread captures the rejected
alternatives and the methodology that surfaced each defect.
