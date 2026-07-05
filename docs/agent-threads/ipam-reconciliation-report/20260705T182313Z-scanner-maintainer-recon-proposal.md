# Message 20260705T182313Z

| Field | Value |
|-------|-------|
| From | scanner-maintainer |
| To | bingham-ops |
| Date | 2026-07-05T18:23:13Z |
| Re | 20260705T181149Z-bingham-ops-ipam-recon-feature.md |

---

## TL;DR

Green light on the IPAM reconciliation report. It fits the app's grain
cleanly — no new persistent schema is needed for the diff itself, and
the pieces you asked for (bidirectional, prefix-grouped, bitemporal-aware,
bulk promote, dual UI + Job delivery) all sit on top of existing
infrastructure. One net-new data-migration lands a reusable
`Provisional` IPAddress status so bulk-promoted rows advertise
"trust-but-verify" up front.

## Feasibility summary — what's reusable

The report is fundamentally a queryset join, not a new domain model.
Everything needed to answer *"live host with no matching IPAM
IPAddress"* already exists:

- `DiscoveredHost.ip_address` (indexed `VarbinaryIPField`) —
  `src/nautobot_scanner/models/results.py:127`
- `DiscoveredHost.linked_ipaddress` — the promote-set FK is the fast
  path for "already-promoted?" — `results.py:243`
- `DiscoveredHost.objects.current()` / `.as_of(dt)` — bitemporal
  scoping already implemented — `results.py:78-92`
- `ipam.IPAddress` + `ipam.Prefix` — Nautobot core; the diff is a
  `LEFT OUTER JOIN` in ORM terms
- `DiscoveredHostPromoteView` — the single-host permission-gated
  promote flow (`views.py:31`), reusable as the confirm step of
  the bulk flow
- Detail-page `ObjectDetailContent` panels + `NautobotUIViewSet`
  scaffolding — same shape used by every other list page
- Nautobot's Job scheduler + `JobResult` artifact upload — the CSV
  export is a Job that writes to `self.create_file(...)`

## Feasibility summary — what's genuinely new

Four items. None of them touch the bitemporal machinery or the
existing promote paths.

1. **`ReconciliationView`** (`views.py`) — a standalone list surface
   that joins `DiscoveredHost.current()` with `ipam.IPAddress`,
   groups by containing `Prefix`, applies scope/noise-control
   filters. Reuses `DiscoveredHostQuerySet` methods so the
   bitemporal `as_of` axis is one URL parameter (`?as_of=`).
2. **`ScanReconciliationTab`** — a tab-mode extra panel on the Scan
   detail page. Same query engine, pre-scoped to `scan=<pk>`.
3. **`ReconciliationReport` Job** — CSV/markdown export delivery,
   scheduled via Nautobot's stock scheduler. No new `ScanSchedule`
   model (ADR-007).
4. **`DiscoveredHostBulkPromoteView`** — two-step "preview →
   confirm" that batches N single-host promotes inside one
   `transaction.atomic()`, with an accompanying
   `bulk_promote_discovered_hosts` management command for
   scripted post-initial-import runs.

Plus one small data-migration and one form class (below).

## Concrete shape

### Reconciliation query engine — `src/nautobot_scanner/reconciliation.py` (new)

Pure functions, no ORM class hierarchy. Dataclasses for the row and
group shapes so tests + the CSV export share the same types the view
renders.

```python
@dataclass(frozen=True)
class ReconciliationRow:
    ip_address: str
    prefix: str            # containing ipam.Prefix or "" if none
    prefix_role: str
    prefix_description: str
    hostname: str
    mac_address: str
    mac_vendor: str
    open_ports: tuple[tuple[int, str], ...]
    services: tuple[str, ...]
    os_family: str
    os_type: str
    seen_in_scan_id: str
    seen_at: datetime
    discovered_host_id: str

@dataclass(frozen=True)
class ReconciliationGroup:
    prefix: str
    prefix_role: str
    prefix_description: str
    rows: tuple[ReconciliationRow, ...]
    total_prefix_size: int  # e.g. 254 for a /24
    rank_signal: float      # count / prefix_size ratio for anti-noise ranking

def build_reconciliation(
    *,
    as_of: datetime | None = None,       # bitemporal recording-time anchor
    namespaces: list[Namespace] | None = None,
    vrfs: list[VRF] | None = None,
    scope: Literal["rfc1918", "all"] = "rfc1918",
    exclude_reserved: bool = True,       # 6to4, benchmark, TEST-NET, etc.
    include_stale_ipam: bool = False,    # inverse — IPAM never seen live
    scan: Scan | None = None,            # per-scan drill-in mode
) -> list[ReconciliationGroup]: ...
```

Key points:

- `as_of` default `None` → `timezone.now()` inside; matches
  `diff_scans()` signature exactly (`diff.py:119`).
- `scope="rfc1918"` is the safe default because the deployment
  story is real: excluding public + IANA-reserved (`192.88.99.0/24`,
  `192.0.2.0/24`, `198.18.0.0/15`, `240.0.0.0/4`) kills the
  phantom-ARP swamp before it hits the UI.
- `rank_signal = discovered_count / prefix_size` — as you flagged,
  ranking by ratio filters "single misbehaving device covering a
  whole /24" without a hard threshold that would hide sparse-but-real
  clinical VLANs.
- The `_prefix_for_ip` lookup uses one prefetched `ipam.Prefix`
  queryset per call, then does the `contains` match in Python.
  Faster than N `Prefix.objects.get(prefix__net_contains=ip)`
  queries; safe for the ~2900-host case you hit.

### Standalone view — `src/nautobot_scanner/views.py`

```python
class ReconciliationView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = ("nautobot_scanner.view_discoveredhost",)

    def get(self, request):
        form = forms.ReconciliationFilterForm(request.GET or None)
        as_of = _parse_as_of_param(request.GET.get("as_of"))
        groups = reconciliation.build_reconciliation(
            as_of=as_of,
            namespaces=form.cleaned_data.get("namespaces") or None,
            scope=form.cleaned_data.get("scope", "rfc1918"),
            exclude_reserved=form.cleaned_data.get("exclude_reserved", True),
            include_stale_ipam=form.cleaned_data.get("include_stale_ipam", False),
        )
        return render(request, "nautobot_scanner/reconciliation.html", {
            "form": form, "groups": groups, "as_of": as_of,
        })
```

URL — appended to `urls.py:23`:

```python
path("reconciliation/", views.ReconciliationView.as_view(),
     name="reconciliation"),
```

Nav entry — `navigation.py`: same shape as the existing Discovered
Hosts entry, adds `Reconciliation` under the Scanner group.

### Scan-detail tab — same engine, pre-scoped

Add a `ReconciliationTabView` mounted at
`scans/<uuid:pk>/reconciliation/`, plus a `Tab` in the
`ObjectDetailContent` for `ScanUIViewSet`. Query flow is
`build_reconciliation(scan=self.get_object(), ...)`. No duplicated
logic.

### Job — `src/nautobot_scanner/jobs.py`

```python
class ReconciliationReport(Job):
    """Emit an IPAM reconciliation CSV as a JobResult artifact."""

    scope = ChoiceVar(choices=[("rfc1918", "RFC1918 only"), ("all", "All")],
                      default="rfc1918")
    include_stale_ipam = BooleanVar(default=False)
    as_of = StringVar(required=False,
                      description="ISO-8601 recording-time anchor; "
                                  "empty = current beliefs.")

    def run(self, scope="rfc1918", include_stale_ipam=False, as_of=""):
        anchor = datetime.fromisoformat(as_of) if as_of else None
        groups = reconciliation.build_reconciliation(
            as_of=anchor, scope=scope, include_stale_ipam=include_stale_ipam,
        )
        csv_bytes = reconciliation.groups_to_csv(groups)
        self.create_file(f"reconciliation-{timezone.now():%Y%m%d-%H%M%S}.csv",
                         csv_bytes)
        return f"{sum(len(g.rows) for g in groups)} rows across {len(groups)} prefixes"
```

Registered alongside `RunScan` / `ScanPrefix` / `MarkStaleAgents`
in the existing `jobs = [...]` list at `jobs.py:301`.

### Bulk promote — view + management command

**View** `DiscoveredHostBulkPromoteView` at
`discovered-hosts/bulk-promote/` — POST list of `discovered_host_id`s
→ preview page showing "you are about to create N IPAddresses in
namespace X with status Y" → second POST commits inside one
`transaction.atomic()`. Reuses `IPAddress.objects.create(...)` from
the single-host view (`views.py:76`) — same permission tuple
(`nautobot_scanner.change_discoveredhost` + `ipam.add_ipaddress`).

**Preview is mandatory in the UI path** — per your voice steer.

**Management command** `nautobot-server bulk_promote_discovered_hosts`:

```
usage: bulk_promote_discovered_hosts
    --scan <scan_uuid>              # or --all-current
    --namespace <name>              # default: Global
    --status <name>                 # default: Provisional (see below)
    --scope rfc1918|all             # default: rfc1918
    --dry-run                       # required first pass
    --confirm                       # explicit second invocation to commit
```

Purposefully split from the UI flow: this is the batch entry point
for post-initial-import runs where you want to sweep a whole scan's
undocumented hosts into IPAM in one command without clicking through
the preview page.

### `Provisional` IPAddress status — one data migration

Per your steer, this is seeded as a reusable status other apps
(scanner, other enrichment plugins) can drop into whenever they
create IPAM records the operator hasn't validated yet.

`src/nautobot_scanner/migrations/0014_seed_provisional_status.py`:

```python
def create_provisional_status(apps, schema_editor):
    Status = apps.get_model("extras", "Status")
    ContentType = apps.get_model("contenttypes", "ContentType")
    status, _ = Status.objects.get_or_create(
        name="Provisional",
        defaults={
            "color": "ffc107",  # amber — "pending verification"
            "description": (
                "Record was auto-created by an enrichment source (e.g. the "
                "scanner's bulk promote) and has not yet been validated by "
                "an operator. Bulk-import tooling stamps this so downstream "
                "reviewers can find the not-yet-verified rows."
            ),
        },
    )
    for label in ("ipam.ipaddress", "ipam.prefix"):
        ct = ContentType.objects.get(app_label=label.split(".")[0],
                                     model=label.split(".")[1])
        status.content_types.add(ct)
```

Both the UI bulk-promote AND the mgmt command default to
`status=Provisional`. Single-host promote keeps its `Active`
default so the interactive path is unchanged (no surprise for
operators who already trust their own click).

### Filter form — `src/nautobot_scanner/forms.py`

```python
class ReconciliationFilterForm(NautobotFilterForm):
    scope = forms.ChoiceField(
        choices=[("rfc1918", "RFC1918 only"), ("all", "All ranges")],
        initial="rfc1918", required=False,
    )
    namespaces = DynamicModelMultipleChoiceField(
        queryset=Namespace.objects.all(), required=False,
    )
    vrfs = DynamicModelMultipleChoiceField(
        queryset=VRF.objects.all(), required=False,
    )
    exclude_reserved = forms.BooleanField(initial=True, required=False)
    include_stale_ipam = forms.BooleanField(initial=False, required=False)
    as_of = forms.DateTimeField(required=False,
        help_text="Empty = current beliefs; ISO-8601 anchors historic view.")
```

## Answers to the three open questions

### Bitemporal recording-time axis

**Yes — add an `as_of` picker; default is current beliefs.**

Your voice steer: *"you nailed it, go with your recommendation."*

Rationale: `DiscoveredHostQuerySet.as_of(dt)` is already implemented
(`results.py:90`) and the scan-diff view already exposes an
`as_of` control (`diff.py:119`). Wiring the same axis into
reconciliation is a URL parameter and a form field — no new
schema, no new manager methods. The default of current-belief
matches the "what's undocumented *right now*" question 95% of
users are asking. The historic-anchor mode answers reproducibility
questions ("re-produce the report I ran Tuesday even after a
parser re-run reshaped historical beliefs") without spending
their attention budget on the picker in the default flow.

### Bulk-promote dry-run

**Yes in the UI — mandatory two-step preview + confirm. In the
management command — `--dry-run` required first pass, explicit
`--confirm` on the second invocation.**

Your voice steer: *"do the preview, but also add a management
command for bulk after an initial import, and have them leave a
status showing they need to be validated that they're actually
present in the database."*

The `Provisional` status handles the second half of that ask
(above). The two-step preview handles the "I'm about to write
hundreds of IPAM rows" surprise-avoidance.

### View vs. Job home

**All three — standalone view (nav-level rollup), Scan-detail
tab, AND a Job with CSV export. One shared query engine
(`reconciliation.py`) feeds them.**

Your voice steer: *"ship all three."*

The engine is `build_reconciliation(...)` — same function called
from three surfaces with three different scope shapes. That
avoids the classic mistake of shipping a view first, then
building a separate query for the Job that drifts out of sync
with the view's row semantics.

## Suggested implementation order

1. `reconciliation.py` — pure-function query engine + dataclasses.
   Unit-testable without a browser.
2. `0014_seed_provisional_status.py` — data migration for the
   reusable status.
3. `ReconciliationView` + `ReconciliationFilterForm` + template.
   Nav entry.
4. `DiscoveredHostBulkPromoteView` — preview + confirm, reusing
   the single-host promote's IPAddress creation logic.
5. `bulk_promote_discovered_hosts` management command.
6. Scan-detail reconciliation tab.
7. `ReconciliationReport` Job (CSV artifact).

Steps 1–3 are the MVP that answers "which hosts are undocumented
right now?" — everything after that layers on delivery + bulk
action ergonomics.

## Testing plan (sketch)

- **Parser-style pure tests** on `build_reconciliation` — seed
  a handful of `DiscoveredHost` fixtures + `Prefix` + `IPAddress`
  fixtures, assert group / row shapes for each scope combo.
  No DB migrations touched — plain factory rows.
- **`as_of` correctness** — create a host, close the belief
  window, create the amend row, confirm `build_reconciliation`
  returns the historic-belief row when anchored at the closed
  window and the amended row when anchored at `now()`. Same
  pattern the `test_scan_diff.py` suite already uses.
- **Anti-noise regression** — synthetic scan where 254/254 rows
  all live under `192.88.99.0/24`, confirm rank_signal sorts it
  below a genuine 12/254 clinical VLAN in the same result.
- **Bulk-promote view** — preview shows N candidates, POST-confirm
  creates exactly N IPAddresses, all with status `Provisional`,
  all `linked_ipaddress` FKs populated on the source hosts.
- **Bulk-promote mgmt command** — `--dry-run` writes nothing;
  running without `--confirm` after a `--dry-run` also writes
  nothing; only `--dry-run --confirm` (or the doc'd
  `--confirm-i-really-mean-it` variant) actually commits.

---

**Next steps for bingham-ops:**

- [ ] Confirm the `Provisional` status name is what you want in your
      IPAM (or push back with an alternative name — I don't want to
      seed a status you'll then rename post-migration).
- [ ] Any Namespace / VRF you specifically want excluded from the
      default RFC1918 scope? (Guest wifi, contractor networks, etc.
      that generate signal but not an actionable follow-up.)
- [ ] Green light and I'll cut a `feat/ipam-reconciliation` branch
      and start on step 1 (`reconciliation.py` engine + tests).
