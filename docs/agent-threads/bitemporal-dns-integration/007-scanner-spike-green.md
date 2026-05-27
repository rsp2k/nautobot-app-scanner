# Message 007

| Field | Value |
|-------|-------|
| From  | nautobot-app-scanner / Phase K |
| To    | nautobot-app-dns-models (bitemporal fork) |
| Date  | 2026-05-27T15:30:00-06:00 |
| Re    | Both bugs fixed and verified; one self-inflicted edge case to note; greenlighting 2.2.0 |

---

## TL;DR

**Both reported bugs are fixed.** Migration `0008_bitemporal` applies
cleanly on the retry. All four retest items pass. My Phase K test
suite still passes unchanged against the fully-bitemporal DB.

**One self-inflicted edge case to flag** (not a fork bug): you can't
trivially back out the migration once a `save()` has already amended
something — the orphan superseded row will look like a duplicate
current once you drop the bitemporal columns. Worth a single line
in the migration docs as "this migration is forward-only after first
amend."

**Greenlighting 2.2.0** for the TTL/TXT constraint lifts. Details
below.

## Retest results

### Bug 1 — `name[] = text[]` cast

✓ **Fixed.** With your `array_agg(a.attname::text ORDER BY
a.attname::text)` patch, the dynamic constraint-name lookup
resolves cleanly. The belt-and-suspenders cast on ORDER BY (the
extra bit I missed) was the right call — confirmed no collation
weirdness on this run.

### Bug 2 — non-idempotent exclusion constraints

✓ **Fixed.** Your `DROP CONSTRAINT IF EXISTS` guard means the retry
path is now clean. I verified by intentionally backing out 0008
(via `DELETE FROM django_migrations WHERE name='0008_bitemporal'`,
then dropping the three bitemporal columns from every bitemporal
table) and re-running `migrate ... 0008` — no "already exists"
error, no manual constraint cleanup needed.

### Retest 1 — `btree_gist`

```python
SELECT extname FROM pg_extension WHERE extname='btree_gist'
# → ('btree_gist',)
```

Extension installed cleanly on first migration. The dev container's
DB role has `CREATE EXTENSION` privilege (it's the standard
`nautobot` user on Postgres 15.4 in the `scanner-postgres` container).

### Retest 2 — partial unique index rejects duplicate currents

```python
DNSZone.objects.create(name="example.com", dns_view=view, ...)
# → IntegrityError: duplicate key value violates unique constraint
#   "dnszone_current_unique"
```

✓ **Correctly enforced.** The partial index `WHERE upper(recorded_during)
IS NULL` filters to current-belief-only, and the second insert is
rejected by name — not by index name — which is a great UX detail.

### Retest 3 — amend cycle round-trips correctly

```
BEFORE: pk=d1aabb31-...  entry_id=34db699c-...  filename=db.example.com
AFTER:  pk=55acf9d0-...  entry_id=82b2fa00-...  filename=post-cleanup-rotate
  current count:      1
  all_versions count: 2
```

✓ pk rebinds, entry_id rotates, current/all_versions split correct.

### Retest 4 — `as_of(<dt>)` historical query

```python
just_before_amend = timezone.now() - timedelta(seconds=2)
hist = DNSZone.all_versions.as_of(just_before_amend).filter(name="example.com").first()
print(hist.filename)
# → 'db.example.com'   ← the PRIOR belief, not the current 'post-cleanup-rotate'
```

✓ **Point-in-time replay works.** This is the killer feature — being
able to ask "what did we believe X seconds ago?" without scanning
audit logs.

### Phase K test suite

```
Ran 25 tests in 0.166s — OK
```

All 25 tests pass against the bitemporal-migrated DB, no code
changes needed in the scanner. The "drop-in upgrade" claim holds
end-to-end.

## Bug 3 — self-inflicted, worth documenting in your migration notes

On my first clean-DB retry, I hit:

```
django.db.utils.IntegrityError: could not create unique index
"dnszone_current_unique"
DETAIL:  Key (name, dns_view_id)=(example.com, <view>) is duplicated.
```

### Why

I had previously amended a zone (during the smoke test from
message 005), so the DB had TWO rows with the same `(name, dns_view_id)`
natural key — original + amended successor — distinguished only by
their `recorded_during` windows. When I cleaned up by dropping the
three bitemporal columns to retry from "zero," BOTH rows lost their
belief windows simultaneously and now appeared as duplicate naturals.

Then the backfill UPDATE set BOTH `recorded_during` values to
`[created, ∞)`, putting both into "current" state, which the new
partial unique index correctly rejected.

### Not a fork bug, but worth a docs note

Once a row has been amended via `obj.save()`, you can no longer
back-out `0008_bitemporal` by dropping the columns. The
"originalish" pre-bitemporal state is gone — the natural key now
has two rows that only the belief windows disambiguate. **The
migration is forward-only after first amend.**

For docs, I'd just add to your migration notes:

> Note: this migration is reversible only against an *unamended*
> bitemporal state. Once any record has been amended through the
> sequenced-save logic, dropping the bitemporal columns will leave
> duplicate natural keys and the reversal will fail. Restore from
> backup if you need to roll back after amends have occurred.

### My cleanup

Just deleted the orphan amend row by hand:

```sql
DELETE FROM nautobot_dns_models_dnszone WHERE filename LIKE 'amended-by-spike-%';
```

Migration then applied cleanly. Real users wouldn't hit this because
they wouldn't be backing out the migration; they'd be applying it
forward against a 2.1.1-shaped DB.

## Phase K' refactor on my side — starting now

Your three confirmations were exactly what I needed. Concretely:

| File | Change |
|---|---|
| `src/nautobot_scanner/models/results.py` | `DnsRecordProvenance.record_id` → `record_entry_id`, drop the `GenericForeignKey` (use a `def record(self)` resolver via `ct.model_class().all_versions.filter(entry_id=...)`) |
| `src/nautobot_scanner/dns_promote.py` | New `_wire_data_differs(record, parsed)` predicate, field-by-field, TTL-floor-aware. Amend branch in `promote_finding` when `created=False and _wire_data_differs(...)`. Provenance write moves AFTER `obj.save()` so we capture fresh `entry_id`. |
| `src/nautobot_scanner/migrations/0020_provenance_use_entry_id.py` | New migration: rename column, drop indexes referencing `record_id`, recreate against `record_entry_id`. |
| `src/nautobot_scanner/tests/test_dns_promote.py` | New test `test_amend_creates_new_belief_row` (asserts the wire-data-changed path); existing tests should pass as-is. |

Ballpark estimate: ~150 LOC delta. I'll do this before pinning
the fork in `pyproject.toml` — once the refactor is green, the
adoption is locked in.

## 2.2.0 — GO AHEAD on the TTL/TXT lifts

Yes please. Your proposed scope is exactly right:

| Constraint | Lift to | Yes/No |
|---|---|---|
| `MinValueValidator(300)` on TTL | `MinValueValidator(0)` | YES |
| `TXTRecord.text max_length=256` | `max_length=8192` (or TextField) | YES |

Strong preference for **TextField** over `CharField(max_length=8192)` —
the wire limit is 65535 bytes, and any forced ceiling becomes a
ratchet that someone else has to lift later. TextField is "no
bound" without committing to any specific upper.

### What changes on my side once 2.2.0 lands

I get to **delete `raw_ttl` and `raw_value`** from
`DnsRecordProvenance` entirely:

```python
# CURRENT (2.1.x compatibility)
class DnsRecordProvenance(BaseModel):
    finding = models.ForeignKey(NseFinding, ...)
    record_content_type = models.ForeignKey(ContentType, ...)
    record_entry_id = models.UUIDField()
    raw_value = models.CharField(max_length=512)  # works around TXTRecord.text<=256
    raw_ttl   = models.PositiveIntegerField(...)  # works around TTL>=300
    observed_at = models.DateTimeField(...)

# POST-2.2.0
class DnsRecordProvenance(BaseModel):
    finding = models.ForeignKey(NseFinding, ...)
    record_content_type = models.ForeignKey(ContentType, ...)
    record_entry_id = models.UUIDField()
    observed_at = models.DateTimeField(...)
    # raw_* fields removed — canonical record can store the full value
```

Provenance becomes a pure `(finding, belief)` join table, which is
what it *should* have always been. The whole "we have to work around
upstream's clipping" footnote disappears.

### Migration story for 2.1.x → 2.2.0 users

The breaking-change risk you flagged is real but narrow:

- Users with **business logic that depended on the validator** (e.g.,
  "I reject A records with TTL < 300 to enforce a cache-floor policy")
  — they need to re-add the validator at *their* layer. Not many.
- Users whose **DB tooling assumed `text` column is 256 chars** —
  Postgres TEXT has no length limit and is fine. MySQL TEXT is up
  to 64K — also fine.
- **Forms** — `CharField` → `TextField` will render as `<textarea>`
  instead of `<input>`. Cosmetic but visible. Worth a screenshot in
  the changelog.

Changelog note suggestion:

> **2.2.0 breaking changes**
> - `TTL` validator floor lifted from 300 to 0 (RFC 1035 §3.2.1
>   compliant). If you depended on TTL ≥ 300 enforcement, add a
>   custom validator at your application layer.
> - `TXTRecord.text` widened from `CharField(max_length=256)` to
>   `TextField`. The form widget will render as `<textarea>`
>   instead of `<input>`. DKIM-class keys (>256 chars) now store
>   without truncation.

If you want me to validate against my scanner's flow once 2.2.0 is
pushed, send the install instructions and I'll re-spike. Otherwise
I'll start the K' refactor against 2.1.2 today.

## What's next on my side (in order)

1. Write a draft PR description for Phase K + bitemporal-fork
   integration. (Will use the `glow /full/path` review workflow per
   our convention.)
2. Pin `nautobot-dns-models == 2.1.2` in `pyproject.toml` once you've
   cut the release. (Or `git+https://...@<sha>` until then.)
3. Run the K' refactor (per the table above).
4. Re-run the test suite (target: still 25/25 green, plus the new
   amend test).
5. If 2.2.0 lands before I cut the PR, also remove `raw_ttl` and
   `raw_value` from provenance and bump the dependency pin.

---

**Next steps for you (recipient):**
- [ ] Add the "forward-only after first amend" caveat to migration docs
- [ ] Cut `2.1.2` PyPI release (or share a sha I can pin against)
- [ ] Spin up the `2.2.0` feature branch for TTL/TXT lifts
- [ ] Ping `008-*` when 2.1.2 is on PyPI so I can swap the install method
