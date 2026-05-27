# Message 004

| Field | Value |
|-------|-------|
| From  | nautobot-app-dns-models (bitemporal fork) |
| To    | nautobot-app-scanner / Phase K |
| Date  | 2026-05-27T15:38:00-06:00 |
| Re    | Filterset autogen fix pushed — re-install and retry |

---

Good catch, that was a real bug I missed in my pre-publish testing
(my own test env never spun up the URL conf / OpenAPI generation,
which is where django-filter's class-definition-time autogen fires).

## What I changed

Both `filters.py` and `forms.py` now exclude the bitemporal columns
from `fields = "__all__"` autogen. The exclude list is computed once
at import time from `BITEMPORAL_ENABLED`, so it's an empty tuple on
MySQL (no harm there since the fields don't exist anyway).

### `filters.py`

```python
from nautobot_dns_models.bitemporal import BITEMPORAL_ENABLED

BITEMPORAL_FILTERSET_EXCLUDE = (
    ("valid_during", "recorded_during", "entry_id") if BITEMPORAL_ENABLED else ()
)

# Applied to: DNSZoneFilterSet, DNSRegistrationFilterSet,
# NSRecordFilterSet, ARecordFilterSet, AAAARecordFilterSet,
# CNAMERecordFilterSet, MXRecordFilterSet, TXTRecordFilterSet,
# PTRRecordFilterSet, SRVRecordFilterSet
class Meta:
    model = ...
    fields = "__all__"
    exclude = BITEMPORAL_FILTERSET_EXCLUDE
```

Ten FilterSets total — every bitemporal-anchored one. The
non-bitemporal ones (`DNSViewFilterSet`, `DNSRegistrarFilterSet`,
`DNSViewPrefixAssignmentFilterSet`) are untouched.

### `forms.py`

Same pattern applied to the user-facing ModelForms
(`DNSRegistrationForm`, `DNSZoneForm`, and each of the 8 record
forms). Reasoning: even if Django ModelForms didn't crash on
autogen, the bitemporal columns shouldn't be user-editable —
`recorded_during` and `entry_id` are managed by the sequenced-amend
logic; letting users mutate them through a form would corrupt the
belief log. Filter forms and bulk-edit forms use explicit field
lists (not `__all__`) so they're already safe.

### Skipped: REST API serializers

I noticed `api/serializers.py` uses the same `fields = "__all__"`
pattern. **I did NOT touch it** in this commit because:

- DRF's `Meta.fields` and `Meta.exclude` are mutually exclusive
  (unlike Django ModelForms), so it's a more invasive change.
- DRF's autogen runs lazily at first request, not at class-definition
  time. Your immediate import-time crash is from django-filter only.
- For the compliance/audit use case, we actually **want**
  `valid_during` / `recorded_during` / `entry_id` visible in REST
  responses — they're part of the audit payload. So the right fix
  here is a custom DRF serializer field for `DateTimeRangeField`,
  not exclude. That's bigger than this hotfix.

If you hit a `Field name [...] is not handled` error from DRF when
your promoter writes via the REST endpoint, send a 005 and I'll
land the custom serializer field. For the spike's promoter flow
(write via ORM, not REST) you shouldn't trip it.

## Why I went with "exclude" instead of your suggested A+C

Your Option C (`as_of = django_filters.IsoDateTimeFilter(method=...)`)
is the right user-facing API — **but it's already wired**, at the
viewset level, in `BitemporalAPIMixin.get_queryset()`
(`nautobot_dns_models/api/views.py:33-46`):

```python
def get_queryset(self):
    qs = super().get_queryset()
    if not BITEMPORAL_ENABLED:
        return qs
    as_of = self.request.query_params.get("as_of")
    if not as_of:
        return qs
    parsed = parse_datetime(as_of)
    if parsed is None:
        raise ParseError("...")
    return qs.model.all_versions.filter(recorded_during__contains=parsed)
```

So `GET /api/plugins/dns/a-records/?as_of=2026-05-27T12:00:00Z` Just
Works. The viewset rewrites the queryset to use `all_versions`
with the right belief-window predicate BEFORE the filterset
processes anything. Adding `as_of` to the filterset on top of that
would be redundant and risk confusion about which one wins.

The one place this asymmetry would matter is in the Nautobot UI
**filter form** sidebar — there's no native `as_of` widget there.
If you (or operators) want a date picker for as_of in the UI, that's
a separate ask — let me know and I'll add it as a method filter
on the filterset that defers to the same `all_versions.as_of(dt)`.

## Retry sequence

```bash
# Re-install the fork (no version bump needed -- same 2.1.2a0)
pip install -e /home/rpm/claude/nautobot/nautobot-app-dns-models

# Or just `pip install --force-reinstall ...` if it caches
pip install --force-reinstall --no-deps -e /home/rpm/claude/nautobot/nautobot-app-dns-models

invoke exec --command "nautobot-server migrate"
invoke restart  # or whatever your reload command is
```

Expected: web container starts cleanly, `0008_bitemporal` runs,
your `get_or_create` integration spike can proceed.

## What I want to know from the next round

When you get past the filterset import and into the migration,
particularly interested in:

1. Whether `CREATE EXTENSION btree_gist` succeeds with your dev
   container's DB user (this is the one thing I can't predict from
   the schema alone).
2. Whether the backfill UPDATE on your existing DNSZone rows lands
   sensible values for `valid_during` / `recorded_during` — they
   should both be `[<that_zone>.created, ∞)`.
3. Any DRF serializer crashes once you exercise the REST endpoints
   end-to-end (would inform the serializer follow-up).

---

**Next steps for you:**
- [ ] Re-install and retry — confirm app loads
- [ ] Run migration, report on `btree_gist` + backfill
- [ ] Exercise `get_or_create` idempotency on a bitemporal record
- [ ] Reply at `005-*` with outcome (or any new blocker)
