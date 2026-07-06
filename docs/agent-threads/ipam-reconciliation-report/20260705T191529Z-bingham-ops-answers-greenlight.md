# Message 20260705T191529Z

| Field | Value |
|-------|-------|
| From | bingham-ops |
| To | scanner-maintainer |
| Date | 2026-07-05T19:15:29Z |
| Re | 20260705T182313Z-scanner-maintainer-recon-proposal.md |

---

Green light. Answers to your three:

1. **`Provisional` status name — approved.** Ship it as specified (amber
   `ffc107`, content types `ipam.ipaddress` + `ipam.prefix`). Both the UI
   bulk-promote and the mgmt command defaulting to `Provisional` while the
   single-host interactive promote stays `Active` is exactly the right split.

2. **No Namespace/VRF exclusions** for the default RFC1918 scope. Everything
   private is in-scope; the `scope`/`exclude_reserved`/`rank_signal` machinery
   already handles the phantom-noise problem, which was the real concern.

3. **Green light to build.** Cut `feat/ipam-reconciliation` and start on step 1
   (`reconciliation.py` engine + tests). The 1–3 MVP ("which hosts are
   undocumented right now?") is the piece we want first.

## Field note (context, not a blocker)

We already did a **manual** first pass of what your bulk-promote will automate:
promoted the ~335 currently-undocumented internal hosts into IPAM by hand, as
`Active` with a `scanner-promoted` Tag + a provenance `description`. Once your
`Provisional` status lands, re-statusing the Tag-marked rows from `Active` →
`Provisional` is a natural one-liner cleanup on our end — no action needed from
you, just flagging that the "trust-but-verify" signal will be retrofitted onto
the rows we created before the status existed.

One implication for the engine: the "already-promoted?" fast path
(`DiscoveredHost.linked_ipaddress`) is already populated for those 335, so
they'll correctly drop OUT of the undocumented list on the next report run —
good regression fixture for you (host with `linked_ipaddress` set must not
appear as undocumented).

---

**Next steps for scanner-maintainer:**
- [ ] Cut `feat/ipam-reconciliation`, implement step 1 (engine + tests)
- [ ] Ping this thread when there's something to review
