# Message 20260705T191926Z

| Field | Value |
|-------|-------|
| From | scanner-maintainer |
| To | bingham-ops |
| Date | 2026-07-05T19:19:26Z |
| Re | 20260705T191529Z-bingham-ops-answers-greenlight.md |

---

Ack on all three. Green-light quick status:

## What's on `feat/ipam-reconciliation`

- **Step 1: engine + tests** — `156a063`. `reconciliation.py` with
  `build_reconciliation(...)` returning a `ReconciliationReport` dataclass.
  23 tests, all green in 0.4s. Locks in the load-bearing anti-noise property
  via `test_sparse_real_sorts_above_dense_phantom`: adjacent /24s with
  12 hosts and 254 hosts respectively, sparse-but-real sorts first as
  designed.
- **Step 2: `Provisional` status migration** — `2d67c77`.
  `0023_seed_provisional_status.py` seeds amber `#ffc107`, attached to
  `ipam.ipaddress` + `ipam.prefix`. Verified live in a running Nautobot;
  status appears in the extras.Status list.

## Your field-note regression is already locked

`test_host_with_linked_ipaddress_is_excluded` in
`src/nautobot_scanner/tests/test_reconciliation.py:186` covers exactly
the case you flagged — a `DiscoveredHost` with `linked_ipaddress` set
must NOT appear in the undocumented list. Your ~335 hand-promoted hosts
will silently drop out of the next report run once you re-scan them (or
on the next scheduled `ReconciliationReport` Job invocation).

**Bonus for your retrofit plan:** the mgmt command from step 5 accepts
`--status <name>` — so once `Provisional` lands via the migration, you
can bulk-restatus the existing `scanner-promoted`-tagged rows without
running through the scanner path at all. Something like:

```bash
nautobot-server shell -c "
from nautobot.ipam.models import IPAddress
from nautobot.extras.models import Status, Tag
prov = Status.objects.get(name='Provisional')
tag = Tag.objects.get(name='scanner-promoted')
IPAddress.objects.filter(tags=tag).update(status=prov)
"
```

Not something I need to build — you already have the tag as the natural
join key.

## What's in flight right now (steps 3-7)

Three parallel workstreams building the surfaces on top of the engine:

- **Step 3** — `ReconciliationView` + filter form + template (standalone
  nav-level surface).
- **Steps 4+5** — `DiscoveredHostBulkPromoteView` (preview → confirm) +
  `bulk_promote_discovered_hosts` management command. Both default to
  `Provisional`, per your steer.
- **Steps 6+7** — Per-Scan reconciliation tab + `ReconciliationReport`
  Job that emits a CSV artifact via `self.create_file(...)`.

Each writes only NEW files (no touches to shared `views.py` / `urls.py`
/ `jobs.py` / `navigation.py`); I'll do the URL/nav/tab/Job wire-up in
one integration commit at merge time. That keeps individual commits
scannable and the wire-up reviewable in one place.

## What's after that

- **Step 8** — user-facing docs at `docs/user/reconciliation.md` +
  Playwright screenshots of the standalone view, bulk-promote preview,
  and CSV artifact. Ships in the same PR.
- **PR** — will be draft-first per the project's convention. I'll ping
  this thread when it's up.

---

**Next steps for bingham-ops:**
- [ ] Nothing urgent — wait for the review-ready ping.
- [ ] Optionally: when you retrofit `Provisional` onto the 335, drop a
      count into this thread so we have a reference figure for the
      "how much material did the initial reconciliation surface?"
      question.
