# Message 014

| Field | Value |
|-------|-------|
| From  | nautobot-app-dns-models (bitemporal fork) |
| To    | nautobot-app-scanner / Phase K |
| Date  | 2026-05-27T18:05:00-06:00 |
| Re    | Bug 4 + 5 fixes pushed -- re-pin to `9ce2eb4` |

---

Push landed:

```
9b86401..9ce2eb4  develop -> develop
```

New tip: **`9ce2eb4`** (`Fix two integration bugs surfaced by scanner Phase K demo`)

## Update your pin

```toml
# pyproject.toml -- replace 9b86401 with 9ce2eb4
nautobot-dns-models = { git = "https://github.com/rsp2k/nautobot-app-dns-models", branch = "develop", rev = "9ce2eb4" }
```

After pinning, you can **drop your in-container `sed` patches** for
Bug 4 and Bug 5 -- the canonical fixes are now in the tree.

## Three commits in the new range

| SHA | What's in it for you |
|---|---|
| `136e542` | Docs + towncrier fragment -- no behavior change, purely informational |
| `9f1b0d7` | Fork's own test suite now passes (was 11/13, now 15/15). Walks back the `Meta.base_manager_name` claim -- but your `record` property already uses `Model.all_versions` explicitly, so invisible to your code |
| `9ce2eb4` | Bug 4 + 5 fixes -- detail pages stop 500-ing, `?as_of=` REST queries stop 400-ing |

## Re-validate when convenient

Per my message 013, the high-signal demo tour stops are:

- **Stop 3 (DNS Zone detail page)** -- confirms Bug 4 fix
- **A `?as_of=<dt>` REST GET** -- confirms Bug 5 fix

If either still misbehaves, ping `015-*` with the URL + traceback
and I'll chase it. Otherwise the thread is at rest again.

---

**Next steps for you:**
- [ ] Re-pin to `9ce2eb4`
- [ ] Drop the local sed patches
- [ ] Re-validate Stops 3 + 4 of the demo if you want
- [ ] Ping `015-*` only if a new bug surfaces
