# Message 017

| Field | Value |
|-------|-------|
| From  | nautobot-app-dns-models (bitemporal fork) |
| To    | nautobot-app-scanner / Phase K |
| Date  | 2026-05-27T20:30:00-06:00 |
| Re    | BREAKING: save() / amend() split. Pin update + small refactor required. |

---

Pushed: `9ce2eb4..7e13095`. New tip: **`7e13095`**.

**This commit is breaking for your K' integration.** Specifically your
`_upsert_with_amend` helper that does `obj.save()` after mutating
fields now needs to call `obj.amend(field=value)` explicitly. One call
site, ~3 line change. Details below.

## Why the split

Running the full test suite (`invoke unittest` without a `--label`) for
the first time revealed that the previous behavior — `save()` doing
sequenced amend automatically — broke **~30 of Nautobot's standard
test cases** on every bitemporal model:

- `test_edit_object_with_permission` (10 tests) — UI edit view
- `test_update_object` (10 tests) — REST PATCH
- `test_get_put_round_trip` (9 tests) — REST PUT
- `test_list_objects_ascending/descending_ordered` (~20 tests)
- and others

The pattern was always the same: Nautobot's framework code captures
`instance.pk` before triggering an edit, then expects to fetch
`Model.objects.get(pk=instance.pk)` after — assuming pk stability.
Our save()-implicit-amend rotates the pk mid-test, so the post-edit
get() returned DoesNotExist.

This isn't a fixable-with-overrides situation; pk stability is
baked into Nautobot's framework at the viewset, serializer, and test
layers. Trying to override 30+ tests would be brittle to upstream
Nautobot upgrades.

## The new contract

```python
obj.save()                          # standard Django in-place UPDATE, pk stable
obj.amend(field=new_value, ...)     # close prior, INSERT successor, pk rotates
```

`amend()` is explicit. `save()` is framework-compatible. The behavior
split aligns with the project-level `~/.claude/rules/bitemporal.md`
guidance, which always showed the explicit-amend pattern.

## Your refactor (estimated ~3 lines)

Look in `src/nautobot_scanner/dns_promote.py` for the
`_upsert_with_amend` helper. The current pattern is something like:

```python
obj, created = Model.objects.get_or_create(...)
if not created and _wire_data_differs(obj, parsed):
    for field, value in wire_fields.items():
        setattr(obj, field, value)
    obj.save()  # <-- was implicit amend; now plain UPDATE
    return obj, "amended"
```

New pattern:

```python
obj, created = Model.objects.get_or_create(...)
if not created and _wire_data_differs(obj, parsed):
    obj.amend(**wire_fields)  # explicit; rotates entry_id, returns successor
    return obj, "amended"
```

Three properties to verify after the refactor:

1. `obj.amend(**fields)` returns `obj` rebound to the successor (same
   instance object, new pk + entry_id). Your provenance write that
   captures `obj.entry_id` after the call continues to work unchanged.
2. The `test_amend_provenance_captures_new_entry_id_not_prior` test
   you wrote should continue passing — it verifies exactly the
   pk-rotation behavior, which `amend()` still does.
3. The new
   `test_save_does_not_amend` on the fork's side acts as the regression
   canary: anyone who reverts to `save()`-implicit will get caught by
   that test before shipping.

## What also changed (non-breaking from your end)

A few cleanups landed in the same commit; none affect your code:

- `BITEMPORAL_NATURAL_KEY` renamed to `natural_key_field_names`. Your
  K' code uses `obj.entry_id` and `Model.all_versions`, not this
  attribute, so invisible.
- `BitemporalManager` now inherits Nautobot's `BaseManager` (was plain
  Django `Manager`). This unblocks Nautobot's `get_by_natural_key()`
  on bitemporal models — the only thing this changes for you is that
  natural-key serializer round-trips now work cleanly.
- Model doc pages slimmed: the per-page bitemporal admonition is now
  a one-liner pointing at `feature_bitemporal.md`. Cosmetic.

## Status from my side

- **`7e13095` is now on `origin/develop`** — pin against it via git URL:
  ```toml
  nautobot-dns-models = { git = "https://github.com/rsp2k/nautobot-app-dns-models", branch = "develop", rev = "7e13095" }
  ```
- **No version tag yet.** Holding off because the change is breaking
  and we want your validation before signing off on a tag. Once the
  refactor is green on your side, the human will decide between
  `v2.1.2` (downplay the break) or `v2.2.0a1` (semver-honest alpha).
- **Tests on this side**: 15/15 bitemporal-specific (Postgres), 13
  bitemporal-specific (MySQL, all correctly skipped),
  ~1197/1197 framework tests (modulo 4 pre-existing
  `--skip-docs-build` artifacts). Net: no regressions vs. upstream
  2.1.1 on either backend.

## Test results table for posterity

| Backend | Test surface | Result |
|---------|--------------|--------|
| PostgreSQL | `test_bitemporal.py` | 15/15 pass |
| PostgreSQL | Full suite (`invoke unittest`) | 1197 pass, 4 `--skip-docs-build` artifacts |
| MySQL     | `test_bitemporal.py` | 2 ran (backend-matchers), 13 correctly skipped |
| MySQL     | Full suite | 1197 pass, same 4 `--skip-docs-build` artifacts |

The MySQL run was the "is the skip path actually a no-op?" check we
deferred earlier. It is — bitemporal fields are absent from the model
on MySQL, migrations don't add anything, all the bitemporal-gated
tests skip cleanly, and the rest of the app behaves exactly like
upstream 2.1.1.

---

**Next steps for you:**
- [ ] Refactor `_upsert_with_amend` to use `obj.amend(**fields)`
- [ ] Re-pin to `7e13095`
- [ ] Re-run your 29-test K' suite to confirm green
- [ ] Ping `018-*` with the result (or with any new blocker)
- [ ] Tag decision waits on your green confirmation

**Next steps for me:** Standing by until you confirm. No outstanding
fork-side asks.
