# DnsRecordProvenance

One row per dig/drill answer record promoted into
[`nautobot-app-dns-models`](https://github.com/rsp2k/nautobot-app-dns-models)
during scan ingest. Joins a scanner `NseFinding` to the typed DNS-models
record it produced, preserves the wire values that get clipped by
upstream constraints, and survives the bitemporal-amend cycle that
rebinds the canonical record's primary key.

Introduced in migration `0019` and re-targeted from `record_id` to
`record_entry_id` in `0020` — see [the rationale below](#why-record_entry_id-not-record_id).

| Field | Description |
|-------|-------------|
| `record_type` | FK to `contenttypes.ContentType` (`+`, CASCADE) — which typed DNS record this row points at (`ARecord`, `MXRecord`, `TXTRecord`, etc.). Together with `record_entry_id` forms the composite reference. |
| `record_entry_id` | UUIDField (db_indexed) — the **bitemporal `entry_id`** of the specific belief row this promotion observed. Stable for one belief's lifetime; survives sequenced-amend saves that rotate the record's `pk`. |
| `finding` | FK to `NseFinding` (CASCADE) — the dig/drill scan finding whose `elements` carried this record on the wire. |
| `observed_at` | DateTimeField (db_indexed, default `now`) — when the parser dispatched this answer into dns-models. |
| `record_type_label` | CharField(16) — DNS record type as it appeared on the wire (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `PTR`, `SRV`). Carries the wire string even when the typed model's class name differs. |
| `raw_value` | CharField(512) — the value field exactly as the parser saw it on the wire, **before** upstream truncation. The canonical record may have lossily clipped this (`TXTRecord.text` caps at 256); the provenance row keeps the full string. |
| `raw_ttl` | PositiveIntegerField (nullable) — the TTL exactly as the parser saw it on the wire, **before** upstream clipping (dns-models enforces a 300s floor). `null` when the source tool didn't emit a TTL. |

**Base class:** `BaseModel` (lightweight — no status/tags/change-log).

**Default ordering:** `-observed_at` (most-recent observation first).

**Lookup index:** `(record_type, record_entry_id, -observed_at)` named
`dnsprov_record_recent_idx` — supports the "show me the recurrence
history of this belief" query in one index scan.

## Why `record_entry_id`, not `record_id`

The bitemporal fork of `nautobot-app-dns-models` (>= 2.1.2) attaches a
`BitemporalMixin` to every DNS record class. The mixin's sequenced-amend
pattern **rebinds the record's `pk` on every belief change**: closing
the old belief's `recorded_during` window and inserting a successor row
gives the successor a fresh primary key.

Django's `GenericForeignKey` is hardcoded to use the target's `pk`. If
we'd stored `(record_type, record.pk)` and the underlying record then
amended, the GFK would silently follow the successor — losing the "this
is the **specific** belief we observed at scan time" identity that
provenance exists to capture.

The fork's `entry_id` field is stable for one belief row's lifetime,
which is exactly what provenance needs. The trade-off: we resolve
through the typed model's manager manually (see [the `record`
property](#the-record-property)) instead of letting Django's contenttype
machinery do it. Worth it.

The original design used `record_id` (a plain UUID matching the
record's pk) and was caught during the Phase K' refactor before any
data hit production — migration `0020` is the column rename.

## The `record` property

Read-side resolution lives on `DnsRecordProvenance.record`:

```python
@property
def record(self):
    model = self.record_type.model_class()
    manager = getattr(model, "all_versions", None) or model.objects
    return manager.filter(entry_id=self.record_entry_id).first()
```

Two design beats:

- **`all_versions` over `objects`.** The default `objects` manager
  returns only current beliefs (`upper(recorded_during) IS NULL`). A
  provenance row that points at a *superseded* belief — the entire
  reason `entry_id` exists — would resolve to `None` against `objects`.
  `all_versions` is the bitemporal-fork-added manager that queries the
  full history; that's what provenance needs.
- **Graceful fallback.** If someone installs upstream `2.1.1` (no
  bitemporal mixin, no `all_versions`) over the top, the resolver
  falls back to `objects` so the property keeps working — current
  beliefs only, but no exception.

Cached per-instance via `__dict__["_resolved_record"]` so template
loops calling `{{ p.record }}` repeatedly don't hammer the DB. `None`
is a valid cached value (record was hard-deleted upstream); the
template renders an empty state in that case.

## Why `raw_ttl` and `raw_value` exist

Upstream `nautobot-dns-models` enforces two write-time constraints
that don't match wire reality:

| Constraint | Wire reality | Provenance escape hatch |
|---|---|---|
| `_ttl >= 300` (5-minute floor) | Cloudflare commonly serves TTL=60 | `raw_ttl` keeps the wire value; the canonical record stores `max(300, raw_ttl)` |
| `TXTRecord.text` max_length 256 | Modern DKIM keys routinely 512+ chars | `raw_value` keeps the wire string; the canonical record stores `raw_value[:256]` |

Both lifts are queued for `nautobot-dns-models 2.2.0`. Once that
release ships, the two `raw_*` fields become redundant and can be
dropped via a follow-up migration. The `record_type_label` field also
becomes redundant if upstream adopts a polymorphic `DNSRecord`
superclass — it's currently load-bearing because the typed-table-per-
record-type design makes a generic "what type was this?" lookup
require crawling content types.

## A and AAAA records and the IPAM coupling gate

`ARecord` and `AAAARecord` in `nautobot-dns-models` carry a foreign key
to `ipam.IPAddress` — they're not stored as raw IP strings. Nautobot
3.x requires every `IPAddress` to live inside a `Prefix` within the
same `Namespace`, so the promoter can't safely auto-create an
`IPAddress` for an arbitrary public IP without also synthesizing the
covering prefix (which would pollute IPAM with `0.0.0.0/0`-class
parents).

Phase K's v1 behavior is **best-effort skip**:

1. Look up `IPAddress.objects.filter(host=record_value)`.
2. If it exists, write the typed A/AAAA record with the FK.
3. If it doesn't, log and skip — but **always write the provenance
   row**, so the operator can see "we saw this A record on the wire,
   here's the raw value, no IPAM linkage yet."

Once the operator creates the covering prefix and re-runs the scan,
the next promotion finds the IPAddress and writes the typed record.
The provenance row from the earlier scan stays as historical
context — bitemporally additive, the way every other scanner record
behaves.

Non-A/AAAA records (`CNAME`, `MX`, `NS`, `TXT`, `PTR`, `SRV`) have no
IPAM coupling, so they always promote.

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| FK out | `record_type` | `contenttypes.ContentType` (resolved + cached via `.record`) |
| FK out | `finding` | `NseFinding` |
| Reverse FK | `dns_promotions` | one `NseFinding` accumulates one row per re-scan that observed the answer |

The `finding.dns_promotions.all()` reverse relation powers the
"DNS Records" panel on the `NseFinding` detail page — every row
shows `record_type_label`, the resolved record link, and a
wire-TTL → stored-TTL comparison flagging the clip.

## See also

- [ADR-015](../dev/architecture.md#adr-015-promote-dig-and-drill-into-typed-dns-models) — design rationale
- [NseFinding](nsefinding.md) — the source of every provenance row
- [DiscoveredHost.dns_records_pointing_here](discoveredhost.md) — the
  cross-reference property surfaced as a panel on the host detail page
- `docs/agent-threads/bitemporal-dns-integration/` — full decision
  trail captured during the dns-models integration

::: nautobot_scanner.models.DnsRecordProvenance
    options:
      show_root_heading: false
