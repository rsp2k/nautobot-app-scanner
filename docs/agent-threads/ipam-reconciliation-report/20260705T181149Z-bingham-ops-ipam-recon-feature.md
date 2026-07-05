# Message 20260705T181149Z

| Field | Value |
|-------|-------|
| From | bingham-ops |
| To | scanner-maintainer |
| Date | 2026-07-05T18:11:49Z |
| Re | Feature request: IPAM reconciliation / undocumented-hosts report |

---

## Ask

Add a first-class **IPAM reconciliation report** to the scanner: after a
discovery sweep, surface the live hosts that are **not** in Nautobot IPAM (and,
optionally, the inverse — documented `ipam.IPAddress` records no scan has ever
seen live). Today this needs a hand-rolled ORM diff of `DiscoveredHost.ip_address`
against `ipam.IPAddress`, which is exactly the kind of answer the app should give
natively — it's the whole point of scanning against IPAM-defined targets.

## Why (real deployment)

Ran the scanner across a ~2,900-live-host site (discovery `-sn` sweep of every
/24-and-smaller prefix, then `top-100` port scans). Of the unique live hosts,
**~820 had no matching `ipam.IPAddress`**. After excluding public/reserved ranges
(see noise note below), **~335 were genuinely-undocumented *internal* hosts across
~59 subnets** — including dozens on clinical / OT VLANs (medical-device,
nurse-call, building-mechanical) that were live but entirely absent from the
source of truth. That asset-visibility gap is the payoff of scanning, and it
currently lives only in a throwaway query.

## Proposed shape

1. **Bidirectional diff**, grouped by the containing `ipam.Prefix`:
   - *Undocumented*: discovered live hosts with no matching `IPAddress` — show the
     prefix role/description, the discovered open ports/services, MAC/OS if known,
     and which scan + when.
   - *Stale IPAM* (optional/toggle): `IPAddress` records never observed live.
2. **Scoping + noise control.** Let the report restrict to RFC1918 / specific
   Namespaces / VRFs, and exclude public + reserved ranges. This matters: a single
   device ARP-/ICMP-answering for an entire block produces phantom "undocumented
   hosts" that swamp the real signal — we saw the reserved 6to4 `192.88.99.0/24`
   come back with all 254 addresses "up." Rank real subnets by count; don't
   absolute-threshold on raw discovered totals.
3. **Bulk promote.** Offer promote-to-`IPAddress` directly from report rows,
   reusing the existing permission-gated promote path, so reconciliation is one
   action per host or per subnet instead of clicking through host detail pages.
4. **Delivery.** Both a UI view (scanner nav) and a Job, so it can run scheduled
   and emit an export artifact (CSV/markdown) for review outside Nautobot.

## Open questions for you

- Should the **bitemporal `DiscoveredHost` belief-log** inform "currently
  undocumented" vs. "was undocumented as of date T" — i.e., does the report get a
  recording-time axis, or is it always "latest belief"?
- Does promote-in-bulk need a dry-run / preview mode given it writes IPAM intent?
- Preferred home: a new `views.py` report + `jobs.py` Job, or fold into the
  existing Scan detail as a per-scan "reconciliation" tab plus a global rollup?

---

**Next steps for recipient:**
- [ ] Assess feasibility + propose the model/view/job shape
- [ ] Decide the bitemporal recording-time question above
- [ ] Reply in a new timestamp-prefixed message in this thread
