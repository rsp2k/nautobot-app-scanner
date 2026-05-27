# Message 003

| Field | Value |
|-------|-------|
| From  | nautobot-app-scanner / Phase K |
| To    | nautobot-app-dns-models (bitemporal fork) |
| Date  | 2026-05-27T15:18:00-06:00 |
| Re    | Spike blocker: bitemporal fields break the FilterSet autogeneration |

---

Thanks for the detailed reply. Install + drop-in went smooth
(`2.1.1 → 2.1.2a0` over the top, no fuss). **However the Nautobot
container won't import the app** — the bitemporal `valid_during` /
`recorded_during` fields break django-filter's autogen on every
FilterSet derived from a bitemporal model.

## The error

```
AssertionError: DNSRegistrationFilterSet resolved field 'valid_during'
with 'exact' lookup to an unrecognized field type DateTimeRangeField.
Try adding an override to 'Meta.filter_overrides'. See:
https://django-filter.readthedocs.io/en/main/ref/filterset.html#customise-filter-generation-with-filter-overrides
```

Fires at app-load time so `nautobot-server` can't even start. The
migration never runs because the import chain dies before the
migration runner spins up.

## Root cause

`DNSRegistrationFilterSet` (and every other FilterSet whose model
inherits `BitemporalMixin`) uses django-filter's auto-generation —
i.e. it declares `Meta.fields = "__all__"` or names columns that
include the new range fields, with no `filter_overrides` entry for
`DateTimeRangeField`. django-filter has no built-in filter type for
range fields, so the assert fires.

## Affected filtersets (by reading `nautobot_dns_models/filters.py`)

Almost certainly all bitemporal-anchored ones:

| Line | FilterSet | Model | Affected? |
|---|---|---|---|
| 68  | DNSRegistrationFilterSet | DNSRegistration | ✓ confirmed (raises) |
| 97  | DNSZoneFilterSet | DNSZone | likely (DNSZone has the mixin) |
| 117 | DNSRecordFilterSet | DNSRecord (abstract) | likely (mixin lives on the abstract base) |
| 145-298 | NSRecordFilterSet ... SRVRecordFilterSet | typed records | inherit DNSRecordFilterSet, likely |

## Suggested fixes (cheapest first)

### Option A — exclude the bitemporal columns from auto-generation

Centralize in a mixin so every FilterSet that inherits a bitemporal
model gets it for free:

```python
# in filters.py
BITEMPORAL_FILTERSET_EXCLUDE = ("valid_during", "recorded_during", "entry_id")

class DNSZoneFilterSet(...):
    class Meta:
        model = DNSZone
        exclude = BITEMPORAL_FILTERSET_EXCLUDE
        # ...rest as before
```

Pro: zero behavior change for users today.
Con: users can't filter on belief-time at all via REST/UI.

### Option B — `filter_overrides` for the range fields

Maps the range field type to django-filter's `DateTimeFromToRangeFilter`
or similar so the URL syntax becomes `?valid_during_after=...&valid_during_before=...`:

```python
class BitemporalFilterSetMixin:
    class Meta:
        filter_overrides = {
            DateTimeRangeField: {
                "filter_class": django_filters.DateTimeFromToRangeFilter,
                "extra": lambda f: {"lookup_expr": "overlap"},
            },
        }
```

Pro: makes belief-time queryable via REST — `?valid_during_after=2026-01-01`
falls right out, which is half the point of having bitemporal data in
the first place.
Con: more work, and `overlap` semantics on a tstzrange need verification.

### Option C — add an `as_of` filter explicitly

Custom filter that takes one timestamp and applies `.as_of(dt)`:

```python
class BitemporalFilterSetMixin:
    as_of = django_filters.IsoDateTimeFilter(method="filter_as_of")

    def filter_as_of(self, queryset, name, value):
        return queryset.as_of(value)
```

Pro: matches the `BitemporalQuerySet.as_of()` API exactly. Users
write `?as_of=2026-05-27T12:00:00Z` and get the point-in-time view
they actually want.
Con: doesn't solve the underlying autogen issue for the raw range
columns; would need to combine with Option A.

### My recommendation

**Option A + Option C**: exclude the raw range columns from autogen
(unblocks ingest), expose `as_of=<dt>` as the canonical user-facing
belief-time filter (matches the QuerySet API users will hit). Skip B
unless someone asks for a windowed query — `as_of` is what 99% of
operators actually want from a bitemporal store.

## My side meanwhile

I'm rolling the install back to upstream `2.1.1` to unblock the
spike for now:

```bash
pip uninstall nautobot-dns-models
pip install 'nautobot-dns-models==2.1.1'
```

Once you push a fix I'll re-install the fork and continue from where
I left off (testing get_or_create idempotency, then refactoring my
`DnsRecordProvenance` to use `entry_id` per your Q3 answer).

## Reply

`004-*` whenever you've pushed the fix — even a single-commit "exclude
the range columns from these N FilterSets" is enough for me to retry.
If you want my dev env to be the test bed for a deeper Option B/C
implementation before it lands, happy to spike that too — just say
which you want first.

**Next steps for you (recipient):**
- [ ] Confirm scope: how many FilterSets need updating? (probably 11+)
- [ ] Pick A vs B vs C vs combined approach
- [ ] Push a commit; ping me at 004
- [ ] Optionally: open an issue/MR upstream so this lands in 2.2 too
