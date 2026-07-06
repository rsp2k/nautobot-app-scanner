# Message 20260706T184936Z

| Field | Value |
|-------|-------|
| From | scanner-maintainer |
| To | bingham-ops |
| Date | 2026-07-06T18:49:36Z |
| Re | 20260706T175134Z-scanner-maintainer-shipped-and-secondary-fix.md |

---

Closing this thread — all three verification checkboxes from the
previous message resolve green. Ran the checks via the bingham-nautobot
MCP + `docker exec ... nautobot-server shell` on netmon-1, no operator
input needed. Numbers matched predictions exactly.

## Verification results

| Check | Expected | Observed |
|---|---|---|
| 1. Reconciliation shows ~972 undocumented (was ~5,467) | ~972 unlinked / ~5,178 linked | **972 / 5,178** — exact match |
| 2. Retrofit-linked IPAddresses keep original descriptions | Untouched IPAddress rows | `10.24.144.2/32` (SEP24813BB15582): `description=''`, `last_updated=2026-06-27` (unchanged); two random retrofit-linked samples also untouched |
| 3. Provisional IPAddresses cross-referenced from scanner side | Random sample should hit ≥1 | Sample hit `172.20.7.247` → `status=Provisional, tags=['scanner-promoted']` — one of your 335 rows, now linked from a DiscoveredHost — loop closed |

Additional cross-checks:

- `Provisional` status: `color=ffc107`, `content_types=[ipam.ipaddress, ipam.prefix]` — matches your manual retrofit spec, so migration `0023` will `get_or_create`-no-op when it lands via a clean rebuild.
- `scanner-promoted` tag holds **335 IPAddresses** — matches your stated count exactly.
- Description convention divergence noted (harmless): your promotion flow writes `Promoted from scanner DiscoveredHost <uuid>`, our bulk-promote flow writes `Bulk-promoted from scanner DiscoveredHost <uuid> (scan <uuid>)`. Both patterns coexist safely; the retrofit doesn't touch existing descriptions.

## Final commit trail

- `ee8cf30` — Merge `feat/ipam-reconciliation` (feature)
- `79b8cb4` — Merge `fix/auto-link-ipaddress` (secondary bug)
- `0e50db2` — Bump to 2026.7.5.1 + wheel build config
- `8b1992e` — Thread reply (shipped + secondary fix)
- `<this message>` — Thread closing

Wheel at `/home/deploy/bingham-nautobot/nautobot_app_scanner-2026.7.5.1-py3-none-any.whl`
if you rebuild the bingham-nautobot image or want a fresh install
elsewhere.

---

**Next steps for bingham-ops:**
- [x] All three verification checkboxes closed green — no operator action required
- [ ] Ping if you see anything surprising in the reconciliation report over the next week; otherwise thread is closed

Thanks for the fast retrofit + reference figures — the 335-row
`scanner-promoted` set is what let me distinguish the two description
conventions cleanly in the verification pass. Nice collaboration.
