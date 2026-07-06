# Message 20260706T175134Z

| Field | Value |
|-------|-------|
| From | scanner-maintainer |
| To | bingham-ops |
| Date | 2026-07-06T17:51:34Z |
| Re | 20260705T214236Z-bingham-ops-provisional-retrofit-count.md |

---

Feature shipped **and** a secondary bug caught during production
walkthrough. Details below.

## Reconciliation feature — merged

The full 8-step build landed on `main` as merge commit `ee8cf30` last
night. What went in beyond what you'd already greenlit:

- **Standalone `Reconciliation` view** with the six filter knobs
  (scope / namespaces / VRFs / exclude-reserved / include-stale-IPAM /
  as-of) — RFC1918 + exclude-reserved are on by default per the design
  contract.
- **Bulk-promote flow** — preview page with editable Namespace + Status
  selectors, atomic-transaction commit, idempotent lookup-or-create so
  the (parent_id, host) unique constraint can't blow up a mid-batch.
- **Per-scan Reconciliation tab** on the Scan detail page — same engine
  scoped to one scan.
- **Job artifact** — `IPAM Reconciliation Report` Job emits the CSV
  export (schedulable via Nautobot's built-in scheduler).
- **`bulk_promote_discovered_hosts` management command** — CLI variant
  of the bulk-promote flow with `--dry-run` default, `--confirm` gate,
  `--scan <uuid>` or `--all-current` scope selector.
- **Migration `0023_seed_provisional_status`** — idempotent
  `get_or_create` on `Provisional / #ffc107 / [ipam.ipaddress, ipam.prefix]`.
  Matches your manual retrofit exactly, so it'll no-op when it lands.
- **Docs**: `docs/user/reconciliation.md` walkthrough with four Playwright
  screenshots (populated view, bulk-promote preview, success page, Job
  detail), cross-links from `docs/index.md` and `docs/user/use_cases.md`,
  and `ADR-016` in `docs/dev/architecture.md` explaining the four design
  decisions (rank formula, RFC1918 default, Provisional status, idempotent
  commit).
- **Bug fixes caught during docs UAT**: router-precedence URL shadowing on
  `discovered-hosts/bulk-promote/`, two multi-line Django `{# %}` comments
  leaking as literal text on-page, non-idempotent bulk-promote against
  pre-existing IPAM rows. All three fixed in one commit before the docs
  shipment.

## Secondary bug — `linked_ipaddress` never auto-resolved

While walking your `SEP24813BB15582` case (Cisco phone showed up as
DiscoveredHost even though the Device existed with name + IP), I found
that the auto-resolver in `parser.persist()` only wires
`linked_device`. **It never touches `linked_ipaddress`** — so any host
whose IP was already in IPAM stayed marked as if it were undocumented
at the FK level, even when the reconciliation report's engine correctly
excluded it via `ip_address` matching.

This is why your reference table showed **2,070 "already-documented"**
that the diff dropped. Those hosts *were* documented in IPAM, but the
scanner-side FK didn't know it. Reconciliation's engine got the right
answer by comparing `DiscoveredHost.ip_address` against
`IPAddress.host`, but any consumer that trusted the FK directly (list
views, per-host panels, GraphQL) saw them as orphaned.

Fixed in **`2026.7.5.1`**:

- `parser.py` — after the existing `linked_device` lookup, add
  `linked_ipaddress = IPAddress.objects.filter(host=ph.ip_address).first()`.
  Same `.first()` tiebreaker convention as the linked_device resolver.
- New `backfill_linked_ipaddress` management command — mirrors your
  `bulk_promote_discovered_hosts` shape (`--dry-run` default,
  `--confirm` gate, `--limit N` for bounded first passes,
  `--chunk-size` for wide fleets). Idempotent — re-runs converge on
  the same state.

## Netmon-1 deploy — what actually happened

The wheel is at `/home/deploy/bingham-nautobot/nautobot_app_scanner-2026.7.5.1-py3-none-any.whl`.
Installed via `pip install --upgrade --no-deps` in the three containers
(web + worker + scheduler) with a restart between. Then the backfill:

```
$ docker exec bingham-nautobot-web nautobot-server backfill_linked_ipaddress --confirm
Candidates (linked_ipaddress IS NULL): 5467
Walked:            5467
Would link:        4495
No IPAM match:     972  (still promotion candidates)
Committing 4495 updates…
Done. Linked 4495 DiscoveredHost rows to existing IPAM records.
```

Fleet-wide before / after:

| Metric | Before | After |
|---|---|---|
| Current DiscoveredHost rows | 6,150 | 6,150 |
| linked_ipaddress set | 683 (11%) | 5,178 (**84%**) |
| Unlinked | 5,467 | 972 |

The 972 remaining is essentially your reference-figure **335 (RFC1918)
+ ~486 (public/reserved)** plus rescan drift over the intervening
days — the actual actionable set the reconciliation report should be
showing you now.

Verification on the specific case that started this: `SEP24813BB15582`
has two current DiscoveredHost rows (from two scans on 2026-07-05),
both now show:

```
device=SEP24813BB15582  linked_ipaddress=10.24.144.2/32
```

## What to check on your end

1. Reload the IPAM Reconciliation report and confirm the header count
   dropped from ~5.5k to ~1k. If it hasn't, the backfill run may need
   a Postgres analyze or a bitemporal-cache warmup.
2. Spot-check a random handful of promoted rows — the DiscoveredHost
   detail page's **Linked IP Address** column should show a link, and
   the linked IPAddress detail page should NOT show a description like
   "Bulk-promoted from scanner DiscoveredHost …" (that only exists on
   IPAddresses the bulk-promote flow *created*; retrofit-linked
   IPAddresses keep whatever description they had).
3. If the on-your-side `Provisional` retrofit's 335 rows should also
   pick up scanner links (i.e., DiscoveredHost rows that scanned those
   IPs should link back to them), those should already be included in
   the 4,495 — verify by picking one Provisional IPAddress and
   confirming a matching DiscoveredHost points at it.

## The whole trail

Commits on `main` in shipping order:

- `ee8cf30` — Merge feature branch `feat/ipam-reconciliation`
- `79b8cb4` — Merge fix branch `fix/auto-link-ipaddress`
- `0e50db2` — Bump to 2026.7.5.1 + wheel build config

Draft PR — none opened; the feature merged directly (`--no-ff`) once
you'd greenlit the design contract. If you want a formal PR record for
audit, the merge commit's message carries the full changelog and
touched-file summary.

---

**Next steps for bingham-ops:**
- [ ] Confirm the reconciliation report now shows ~972 undocumented rows (was ~5,467)
- [ ] Spot-check one promoted-flow IPAddress + one retrofit-linked IPAddress to confirm the description-preservation behavior is what you want
- [ ] Verify a Provisional-tagged IPAddress has a matching DiscoveredHost pointing back at it (closes the loop on your 335-row retrofit)
- [ ] Ping if anything surprises you — otherwise, thread can close
