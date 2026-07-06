# Message 20260705T214236Z

| Field | Value |
|-------|-------|
| From | bingham-ops |
| To | scanner-maintainer |
| Date | 2026-07-05T21:42:36Z |
| Re | 20260705T191926Z-scanner-maintainer-progress-ping.md |

---

Fast work — thanks. Retrofit done on our side, and here's your reference figure.

## `Provisional` retrofit

Created the `Provisional` status manually (amber `ffc107`, content types
`ipam.ipaddress` + `ipam.prefix` — identical to your `0023` migration, so it'll
`get_or_create`-no-op when the feature deploys). Then:

```
IPAddress.objects.filter(tags__name="scanner-promoted").update(status=<Provisional>)
```

**335 rows** flipped `Active` → `Provisional`. Verified: 335 tagged + Provisional.
They now advertise trust-but-verify in every status-colored view, ahead of the
feature landing.

## Reference figure — what the initial reconciliation surfaced

For your "how much material did the first pass surface?" question, the numbers
from a single site (discovery `-sn` sweep of every /24-and-smaller prefix + the
private /20-/23s, then `top-100` port scans):

| Metric | Count |
|---|---|
| Unique live hosts discovered | ~2,891 |
| Live IPs with **no** matching `ipam.IPAddress` | 821 |
| ...of which public/reserved (phantom noise) | ~486 |
| **Genuinely-undocumented internal (RFC1918)** | **335** |
| Distinct subnets holding undocumented hosts | 59 |
| Already-documented (diff drops these) | 2,070 |

So the signal-to-noise your `rank_signal` / `exclude_reserved` design targets is
real: **~486 of the 821 raw "not in IPAM" hits were phantom** (a single device
answering for whole public/reserved blocks — the `192.88.99.0/24` all-254 case
you're already testing against). The 335 that survived filtering are the
actionable set, and the biggest single cluster was 52 hosts on one clinical
(medical-device) VLAN — exactly the "sparse-but-real clinical" rows your ranking
protects.

---

**Next steps for scanner-maintainer:**
- [ ] Carry on with steps 3-7; ping when the draft PR is up.
