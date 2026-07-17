# Phase M — httpx + snmp-recon: reconciliation-driven device fingerprinting

**Status:** M.0 + M.1 + M.2 landed (2026-07-16), M.3 + M.2.5 pending.
Feature branch: `feat/httpx-snmp-fingerprint`.

**Shipped-state check performed 2026-07-16** revealed that the httpx
tool integration originally sketched in this doc's Phase M.0 section
was **already shipped as Phase L+1a**:

- `ToolChoices.HTTPX = "httpx"` present since choices.py rev at Phase L+1a
- `parse_httpx_jsonl` implemented at `parser.py:1156`, wired into
  `PARSERS` dict
- `build_httpx_argv` implemented at `agent/agent.py:450`
- Dockerfile installs httpx binary from GitHub Releases (lines 34-39)
- Migration `0022_seed_phase_lp1a_httpx_profile.py` seeds the
  `http-probe-rich` scan profile

M.0 as actually shipped was a much narrower two-file addition on top:
the reconciliation-driven target resolver and the management command
that dispatches the existing `http-probe-rich` profile against the
undocumented set. See §Files touched below for what actually landed
in the branch.

## Context

The IPAM Reconciliation surface (shipped in `2026.7.5.x`) leaves the
operator with a list of undocumented hosts — after backfill on
netmon-1, ~972 rows that have neither `linked_device` nor
`linked_ipaddress` set. To close the loop, we need to answer "what
kind of device is this?" for each row automatically, then hand the
operator (or the auto-promote path) a confidence-scored identity so
the promote step can assign the right Device role.

Two independent signal sources feed the identity:

- **httpx** — modern HTTP/HTTPS probe, JSONL output, follows
  redirects, extracts headers + title + body hash + favicon MMH3 +
  full TLS cert + tech-detect. Reveals camera admin UIs,
  vendor Server headers (GoAhead-Webs / lighttpd-with-Uniview-mods),
  and web-page title strings (`Axis - Live view`,
  `Uniview NVR Login`).
- **snmp-recon** — nmap NSE bundle (`snmp-info`, `snmp-sysdescr`,
  `snmp-brute`) driven against default community strings.
  `sysObjectID` gives ground-truth vendor identity even when the
  device doesn't expose an HTTP UI.

Fused with existing signals already captured (`mac_vendor`,
`DiscoveredHost.hostname` DNS pattern, nmap `-sV` port fingerprints),
the two new tools close the identification gap for the classes of
device most-often left undocumented: IP cameras, printers,
environmental sensors, older switches.

The load-bearing operational constraint (surfaced during design):
**both tools only run against currently-undocumented hosts.** Probing
a device that's already in IPAM would generate SNMP auth-trap logs and
HTTP access-log entries on the operator's own infrastructure — the
scanner would trip the operator's SOC on every run. Restricting the
target set to the reconciliation output makes the workflow bounded
and self-shrinking: each successful identification + promote removes
a host from the target set for the next run. The pipeline converges
toward zero.

## Goals

1. **Identify undocumented hosts by vendor + device type** with two
   signal sources (HTTP fingerprint + SNMP OID) that can each stand
   alone or fuse for higher confidence.
2. **Auto-promote high-confidence identifications** into
   `ipam.IPAddress` + optionally `dcim.Device` with the correct role
   (`Camera` / `Switch` / `Printer` / `AccessPoint` / `Sensor`), so
   the operator's undocumented list actually shrinks.
3. **Never leak the operator's real credentials.** SNMP community
   strings used at scan time come from a static image-baked wordlist.
   The operator's real communities (in `extras.Secret`) are never
   readable by the scanner code path.
4. **Never probe already-documented devices.** Bounded target set =
   the current reconciliation output (`linked_device IS NULL AND
   linked_ipaddress IS NULL`). Each recon run has an audit trail of
   what it touched.

## Non-goals

- **Full SNMP inventory sync** (interfaces, ARP tables, MAC-address
  learning). Out of scope — this is *identification*, not
  data-plane telemetry. The existing `nautobot_ssot_l2trace` app
  covers ongoing SNMP-based sync separately.
- **Web-app vulnerability scanning** (nuclei templates). Also out of
  scope; queued as Phase L+1 continuation.
- **Rewriting `web-recon`** — the nmap NSE-based `web-recon` profile
  keeps its role for prefix-wide fleet inventory. httpx complements
  it for per-host fingerprint depth, not replaces it.
- **Auto-creating Device rows without an operator confirmation
  threshold.** High-confidence identifications propose the promote,
  operator confirms. Manual override always available.

## Tool integration — the ADR-013 pattern

Per [ADR-013 pluggable parser dispatch](architecture.md#adr-013-pluggable-parser-dispatch-multi-tool-agent-foundation),
each new tool is a five-piece change plus a seed migration plus docs.
Same shape both tools follow.

### httpx (Tier C, ProjectDiscovery suite) — **ALREADY SHIPPED as Phase L+1a**

The five-piece ADR-013 integration for httpx landed before this
design brief was written. What's in the codebase today:

| Piece | Path | Actual state |
|---|---|---|
| Enum | `src/nautobot_scanner/choices.py` — `ToolChoices` | ✅ `HTTPX = "httpx"` present, comment reads "Phase L+1a: httpx (ProjectDiscovery suite, first tool)" |
| Argv builder | `agent/agent.py:450` — `TOOL_REGISTRY` | ✅ `build_httpx_argv(scan)` implemented, reads targets from stdin (cleaner than CLI), content-type `application/jsonl` |
| Parser | `src/nautobot_scanner/parser.py:1156` — `PARSERS` | ✅ `parse_httpx_jsonl(raw, targets)` implemented, wired at `PARSERS["httpx"]` |
| Image | `agent/Dockerfile:34-39` | ✅ Pre-built binary from `github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/…` — curl+unzip → `/usr/local/bin/httpx` |
| Profile | `src/nautobot_scanner/migrations/0022_seed_phase_lp1a_httpx_profile.py` | ✅ Seeds `http-probe-rich` — `tool_arguments="-tls-grab -tech-detect -title -server -web-server -content-length -ip -response-time -status-code -timeout 15"` |
| Docs | `docs/user/scan_profiles.md` | ✅ Documented as Phase L+1a's http-probe-rich profile |

The `http-probe-rich` profile name is what M.0 dispatches by default
(the management command's `--profile` flag). No new profile / new
migration needed for M.0 — the reconciliation-driven dispatch layer
uses the shipped profile as-is.

Output `elements` shape per target:

```json
{
  "status_code": 200,
  "content_length": 1234,
  "content_type": "text/html; charset=UTF-8",
  "server": "GoAhead-Webs",
  "title": "Uniview NVR Login",
  "tech": ["GoAhead-Webs", "Bootstrap:3.3.7", "jQuery:1.11.3"],
  "favicon_mmh3": "-247588896",
  "body_sha256": "e3b0c442...",
  "redirect_chain": ["http://10.1.3.6/", "http://10.1.3.6/login.html"],
  "tls_cert": {
    "issuer": "CN=Axis Communications AB",
    "subject": "CN=axis-b8a44f00abcd.local",
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2029-12-31T23:59:59Z",
    "sans": ["axis-b8a44f00abcd.local"]
  }
}
```

### snmp-recon (Tier B, nmap NSE bundle)

Rides existing nmap tool — no new binary. Uses NSE scripts
`snmp-info`, `snmp-sysdescr`, `snmp-brute` with a bundled wordlist.

| Piece | Path | Content |
|---|---|---|
| Community wordlist | `agent/snmp-defaults.txt` (new) | Well-known default community strings only. Baked into image `chmod 444`. |
| Argv builder | `agent/agent.py` — `TOOL_REGISTRY` `nmap` handler already exists; new profile just points nmap at the NSE bundle | `nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-brute --script-args snmpcommunity.wordlist=/etc/scanner/snmp-defaults.txt <ip>` |
| Vendor OID table | `src/nautobot_scanner/snmp_vendor_oids.py` (new) | Static dict: OID-prefix → vendor + device_type_hint |
| Parser handling | `src/nautobot_scanner/parser.py` | Extend the nmap NSE parser to recognize `snmp-info` / `snmp-sysdescr` output, extract sysObjectID, match against `snmp_vendor_oids`, emit `NseFinding` with vendor identification in `elements` |
| Profile | `src/nautobot_scanner/migrations/0025_seed_phase_m_profiles.py` | New profile `snmp-recon`, `tool="nmap"`, `is_pentest_mode=True` |
| Docs | as above | Note credential-isolation architecture explicitly |

Vendor OID table (starter — extend as we find more in the field):

```python
SNMP_VENDOR_OIDS = {
    "1.3.6.1.4.1.9":     ("Cisco",     "network-equipment"),
    "1.3.6.1.4.1.368":   ("Axis",      "camera"),
    "1.3.6.1.4.1.31460": ("Uniview",   "camera"),
    "1.3.6.1.4.1.11048": ("Hikvision", "camera"),
    "1.3.6.1.4.1.36849": ("Bosch",     "camera"),
    "1.3.6.1.4.1.11":    ("HP",        "server-or-printer"),
    "1.3.6.1.4.1.318":   ("APC",       "ups"),
    "1.3.6.1.4.1.674":   ("Dell",      "server"),
    "1.3.6.1.4.1.2636":  ("Juniper",   "network-equipment"),
    "1.3.6.1.4.1.4526":  ("Netgear",   "network-equipment"),
    "1.3.6.1.4.1.6027":  ("Force10",   "network-equipment"),
}
```

Match by longest-prefix-first so `.1.3.6.1.4.1.9.1.<sub>` still lands
on Cisco.

Community wordlist (baseline draws from onesixtyone + vendor docs):

```
public
private
community
snmp
admin
manager
read-only
router
switch
cisco
apc
axis
ups
public@0
private@0
```

**Wordlist size cap**: 25 entries. Larger = more auth-log noise
per-target. This baseline hits the well-known set without brute-force
territory.

## Target selection — reconciliation-driven, always

Both tools consume the same target-IP list at dispatch time:

```python
from nautobot_scanner.models import DiscoveredHost

targets = list(
    DiscoveredHost.objects.current()
    .filter(linked_device__isnull=True, linked_ipaddress__isnull=True)
    .values_list("ip_address", flat=True)
    .distinct()
)
```

Wrapped in a helper `resolve_undocumented_targets(scope_filter=None)`
that lives in `src/nautobot_scanner/fingerprint.py` (new module).
`scope_filter` accepts an optional callable to narrow by prefix,
namespace, VRF — enables the phased-rollout use case ("start with the
CAMERAS_NEW /24, then widen").

**Extra guardrail — 24h recon-cooldown filter:**

```python
targets = targets.exclude(
    host_findings__nse_script__in=["snmp-info", "httpx"],
    host_findings__scan__completed_at__gte=timezone.now() - timedelta(hours=24),
)
```

Operator-error re-runs won't double up auth-log volume on the same
target within 24h. Configurable via a `--cooldown-hours N` flag on
the management command.

## Credential isolation — hard architectural rule

**Rule:** the scanner code path can never read the operator's real
SNMP communities. Not policy — code-level impossibility.

Implementation:

1. Real communities live in `extras.Secret` records. Nothing in
   `src/nautobot_scanner/` imports `extras.Secret` or reads the
   secret store.
2. Scan-time community wordlist source is
   `/etc/scanner/snmp-defaults.txt` inside the agent image. Path is
   hardcoded in the argv builder — no config override, no PLUGIN_CONFIG
   pulldown, no template variable substitution.
3. Wordlist file is baked read-only (`chmod 444`) at Dockerfile
   build time. Any accidental future refactor that tries to write
   there fails at container startup.
4. Test asserts the wordlist file exists, is readable, is not
   world-writable, and contains only ASCII-printable single-token
   entries (no shell metacharacters, no whitespace, no operator
   secrets accidentally-committed).

ADR-worthy decision: separation of source of truth. Real operational
communities have their own management surface (Secret rotation via
whatever secret-mgmt tool bingham uses); scanner wordlist has its
own, static, and *deliberately public* (checked in, versioned in git,
publicly greppable — precisely so a leak review sees the exact same
file the scanner uses).

## Fingerprint fusion + confidence score

Once both httpx and snmp-recon land, the fusion module computes a
per-host identity score. Lives in
`src/nautobot_scanner/fingerprint.py` alongside the target resolver.

Signal weights (proposed — tunable in code, no config surface):

| Signal | Weight | Source |
|---|---|---|
| SNMP sysObjectID matches vendor OID prefix | 3 | snmp-recon |
| httpx `Server` header matches vendor pattern | 2 | httpx |
| httpx `title` matches vendor login-page pattern | 2 | httpx |
| httpx favicon MMH3 matches vendor favicon | 3 | httpx |
| MAC OUI resolves to vendor | 2 | existing `mac_vendor` |
| DNS name matches vendor model prefix (Uniview `qnv-*`, Axis `axis-*`) | 2 | existing `hostname` |
| nmap `-sV` product string matches vendor | 1 | existing |

Threshold: ≥4 points and a single dominant vendor → high-confidence
identification. Score of 2-3 → medium (surface in reconciliation UI
for operator to confirm). Below 2 → don't propose auto-promote.

The confidence value is a **single tunable number**, defaulting to
`0.7` at M.2 launch. Per-vendor thresholds (weaker `GoAhead-Webs` at
`0.85`, distinctive `Axis` at `0.55`) are a possible follow-up
refinement once we have real-world false-positive/false-negative
data — see Resolved Decisions §2.

Fusion output:

```python
@dataclass
class Identification:
    discovered_host_id: str
    vendor: str                     # "Uniview"
    device_type_hint: str           # "camera"
    proposed_role: str              # "Camera"
    confidence: float               # 0.0 - 1.0 (score/max_score)
    signals: list[dict]             # audit trail of what fired
```

## Auto-promote with role assignment

Extend the existing `DiscoveredHostBulkPromoteView` and its
management-command cousin to accept an `Identification` list. When
provided, the promote target gets:

- `ipam.IPAddress` created (existing flow)
- `dcim.Device` created with `role=<proposed_role>`,
  `manufacturer=<vendor>`, `status=Provisional`
- Interface created and IP assigned
- Device tagged `scanner-auto-identified` for downstream review filter

New management command:

```bash
nautobot-server auto_promote_identified --confidence 0.7 --dry-run
nautobot-server auto_promote_identified --confidence 0.7 --confirm
```

Default confidence threshold `0.7`. Lower value → more auto-promotes,
lower quality. Higher → conservative.

## Files touched (summary)

### M.0 — landed 2026-07-16

Only **two new source files** were actually needed once we accounted
for the Phase L+1a already-shipped state:

```
src/nautobot_scanner/fingerprint.py                          new,  ~80 lines
src/nautobot_scanner/management/commands/http_fingerprint_undocumented.py  new, ~200 lines
src/nautobot_scanner/tests/test_fingerprint.py               new, ~290 lines (15 test cases)
```

M.0 total: ~570 LOC, no new migration, no Dockerfile change, no
choices.py touch, no new profiles. 15/15 tests pass in 0.17s.

### M.1 — landed 2026-07-16

```
agent/Dockerfile                                             +10 lines (mkdir + COPY + chmod)
agent/snmp-defaults.txt                                       new,  25 lines
src/nautobot_scanner/snmp_vendor_oids.py                      new, ~130 lines (27 vendors, longest-prefix-match)
src/nautobot_scanner/migrations/0025_seed_snmp_recon_deep_profile.py  new, ~105 lines
src/nautobot_scanner/management/commands/snmp_recon_undocumented.py   new, ~240 lines
src/nautobot_scanner/tests/test_snmp_vendor_oids.py           new, ~170 lines (16 test cases)
docs/user/scan_profiles.md                                     +2 lines (new profile row)
```

M.1 actual: ~680 LOC, 1 migration, 1 test module (16 tests), no
new fixture (deferred — real snmp-info XML captured in M.2).

Note: **existing `snmp-recon` profile is preserved for back-compat**.
`snmp-recon-deep` (this migration) is the credential-attempt variant
with the wordlist. Also **no parser changes**: nmap's snmp-info NSE
output already gets stored as host-scope NseFinding by the existing
Phase G parser handling. The vendor-OID matching (via
`snmp_vendor_oids.vendor_from_oid`) is invoked by the M.2 fusion
module, not at parse time.

**Credential-attempt gating deferred.** `ScanProfile.is_pentest_mode`
computes from `tool in PENTEST_TOOLS` (masscan only) or specific
nmap flag fields (decoys/fragments/MTU/source-port). None cleanly
represent "SNMP wordlist attempt against remote systems." Proper
gating requires a new `is_credential_attempt` schema field on
ScanProfile — deferred to a follow-up refactor. In the meantime the
sibling management command's restricted targeting (undocumented set
only) and the profile description's loud `*** CREDENTIAL ATTEMPT ***`
prefix carry the guardrail.

### M.2 — landed 2026-07-16 (lean cut)

```
src/nautobot_scanner/fingerprint.py                          +~400 lines (VENDOR_PATTERNS + Identification + fuse_signals)
src/nautobot_scanner/management/commands/auto_promote_identified.py   new, ~250 lines
src/nautobot_scanner/tests/test_fingerprint.py               +~200 lines (11 new fusion tests)
```

M.2 actual: ~850 LOC, 11 new tests (26/26 pass overall). No new
migration, no Dockerfile change.

**Scope decision (M.2 lean cut):** the shipped M.2 promotes identified
hosts into `ipam.IPAddress` records with fusion metadata in the
description. Full `dcim.Device` auto-creation is **deferred to M.2.5**
because it requires Location + DeviceType inputs that the fingerprint
pipeline can't invent — the operator supplies those, then M.2.5 wires
them into the auto-promote flow. In the meantime, the preview surface
(`auto_promote_identified --dry-run`) is the primary M.2 value:
operators see the fusion output, review confidence scores, and
manually promote via the existing UI flow.

**M.2 signal weights actually shipped** (favicon deferred — the current
`http-probe-rich` profile doesn't enable `-favicon`):

| Signal | Weight | Source |
|---|---|---|
| SNMP sysObjectID matches vendor OID prefix | 3 | snmp-recon-deep |
| httpx TLS cert `subject_cn` matches vendor pattern | 3 | http-probe-rich (upgraded from 2 — cert is cryptographically bound) |
| httpx `webserver` header matches vendor | 2 | http-probe-rich |
| httpx `title` matches vendor login-page pattern | 2 | http-probe-rich |
| MAC OUI resolves to vendor | 2 | existing `mac_vendor` field |
| DNS name matches vendor model prefix | 2 | existing `hostname` field |
| nmap `-sV` product string matches vendor | 1 | existing `os_vendor` field |

MAX_SCORE = 15. Confidence = raw_score / MAX_SCORE.

**7 initial vendors** with patterns: Axis, Uniview, Hikvision, Bosch,
Vivotek, Cisco, APC. Extension is easy — add a `VENDOR_PATTERNS`
entry + a test case.

### Adjusted grand total

M.0 + M.1 + M.2 shipped as of 2026-07-16:
- M.0: ~570 LOC (fingerprint.py target resolver + http_fingerprint
  command + 15 tests)
- M.1: ~680 LOC (SNMP wordlist + vendor OIDs + snmp-recon-deep
  migration + snmp_recon command + 16 vendor-OID tests)
- M.2: ~850 LOC (fingerprint.py fusion extension + auto_promote
  command + 11 fusion tests)

**Total shipped: ~2,100 LOC across 9 new files, 1 migration, 42
tests all passing.** Higher than the original ~1,300 estimate
because the M.0 + M.1 discovery revealed httpx + snmp-recon tool
integration was already shipped — the shipped LOC is almost entirely
new pipeline logic, not tool wiring, plus the test coverage that
wasn't in the original plan.

M.2.5 + M.3 remain pending.

## Verification plan

### Local dev-stack E2E

1. `docker compose up -d` — dev stack with the new image (agent
   variant with httpx + snmp-defaults.txt baked in).
2. Manually create one DiscoveredHost with `linked_device` set and
   one with both FKs null. `resolve_undocumented_targets()` returns
   only the second.
3. Run `nautobot-server http_fingerprint_undocumented --dry-run` —
   confirms the target list matches.
4. Run against `example.com` (safe external target — Cloudflare
   response). httpx JSONL should parse cleanly, produce
   `NseFinding` with 200 status + `Server` header populated.
5. Same for `snmp_recon_undocumented --dry-run --limit 1` against a
   local SNMP-enabled test container.
6. `auto_promote_identified --dry-run` shows the proposed
   Device+role for the identified host.

### Prod dry-run on netmon-2 (via docker exec into swarm task)

**With operator checkpoint before running.**

1. `docker exec <swarm-web> nautobot-server http_fingerprint_undocumented --dry-run --prefix 10.1.3.0/24`
   — should show ~30 Uniview cameras in the CAMERAS_NEW /24 as
   candidate targets. Operator confirms the target list looks right.
2. `docker exec <swarm-web> nautobot-server http_fingerprint_undocumented --confirm --prefix 10.1.3.0/24`
   — dispatches an actual `Scan` against those IPs. Wait for completion,
   inspect the resulting `NseFinding` rows to confirm httpx output
   captured correctly.
3. `docker exec <swarm-web> nautobot-server auto_promote_identified --dry-run --confidence 0.7`
   — proposes Uniview cameras for auto-promote with Camera role.
   Operator reviews.
4. If review clean: `--confirm` to actually create the Device rows.
5. Reconciliation report re-loaded shows ~30 fewer undocumented rows;
   `Camera` role now has 30 devices.

## Rollout phases

Even inside "one PR bundle," ship in a strict order:

1. **Phase M.0** — **landed 2026-07-16.** Reconciliation-driven
   dispatch layer over the pre-existing (Phase L+1a) httpx tool
   integration. Two new files: `fingerprint.py` (target resolver) and
   `http_fingerprint_undocumented` (management command). Operator now
   gets structured httpx JSONL on `NseFinding` for the
   reconciliation-undocumented set. Zero credential-attempt risk.
   Both-null filter enforced; 24h cooldown default; per-prefix scope
   available via `--prefix`. 15/15 tests pass.
2. **Phase M.1** — **landed 2026-07-16.** SNMP wordlist file baked
   into agent image (`chmod 444`), `snmp-recon-deep` profile
   (migration 0025), vendor OID table (27 vendors,
   longest-prefix-match), `snmp_recon_undocumented` management
   command with credential-attempt banner. Still no fusion, no
   auto-promote — the extra signal source lands on `NseFinding` via
   the existing Phase G parser handling. Pentest-mode gating
   deferred (see M.1 Files touched section for the schema-refactor
   note).
3. **Phase M.2** — **landed 2026-07-16.** Fusion module +
   `Identification` dataclass + `SignalHit` audit-trail + 7-signal
   weighted scorer + `VENDOR_PATTERNS` for 7 vendors +
   `auto_promote_identified` management command with default
   confidence threshold `0.7`. Preview surface shows above-threshold
   candidates AND a sub-threshold peek so operators can see where
   fusion is landing. `--confirm` creates IPAddress records with
   fusion metadata in description; Device auto-create deferred to
   M.2.5 (needs operator-supplied Location + DeviceType). The
   **one-shot Axis-rows cleanup** on netmon-2 (rename by DNS,
   re-role to Camera) also moves to M.2.5 with the Device flow.
4. **Phase M.3** — retune the confidence threshold once operator
   trust is established (possibly per-vendor). Add the "SNMP-probe
   undocumented" and "HTTP-fingerprint undocumented" action buttons
   to the reconciliation report UI.

Each phase is independently shippable. Any halt in a middle phase
leaves the operator with the earlier phases' value intact.

## Resolved decisions

Four open questions from the initial draft, resolved 2026-07-16:

### §1. httpx binary distribution — pre-built COPY, version-pinned

Use the pre-built binary from
`github.com/projectdiscovery/httpx/releases/latest`, COPY'd into the
agent image with an inline `# httpx vX.Y.Z — bump manually` comment
above the URL. Smaller build layer (no Go toolchain in the image
graph), reproducible version-pin, one-line bump when we want a newer
httpx. Rejected: `go install` in-image (adds ~150 MB build stage even
with multi-stage discard, and floats the version at every build).

### §2. Confidence threshold shape — single number for M.2

M.2 ships with a single `--confidence 0.7` flag on
`auto_promote_identified`. Per-vendor thresholds (`Axis 0.55`,
`GoAhead-Webs 0.85`) are a follow-up refinement once we have
real-world false-positive/false-negative data from the first few
production dry-runs. The `Identification.signals` audit list already
carries the per-signal detail needed to tune this — no schema change
required to add per-vendor gating later.

### §3. Two auto-created Axis rows on netmon-2 — one-shot cleanup in M.2

The pair created 2026-07-05 (`Axis Communications AB 00:40:8c:9f:d7:a4`
and `Axis Communications AB ac:cc:8e:4c:1b:be`) get processed as part
of M.2's first fingerprint-fusion run. Because the httpx pass will
identify them via `Server: Axis` header or the Axis favicon, the
fusion module will emit an Identification pointing at the same vendor
they already have. The auto-promote extension needs a special-case
branch: if a matching Device already exists (by MAC or by
manufacturer+primary_ip), rename the Device to the DNS name from
httpx output, assign `role=Camera`, and update the tag set. No new
Device row created. Belongs to M.2 rather than a M.x sidebar because
it exercises the exact same code path.

### §4. SNMPv3 opt-in profile — second design pass after M.1

Deferred. The M.0 + M.1 + M.2 sequence establishes the credential-
isolation architecture, the vendor OID table, and the fusion module.
Once those land and we have SNMPv1/v2c data, a second design brief
covers SNMPv3 users specifically — with its own risk model
(authenticated-failure account lockouts on Cisco IOS-XE) and its own
default-user wordlist (`admin`, `snmp`, etc.). No implementation work
in Phase M itself.

## Related

- [ADR-013 — pluggable parser dispatch](architecture.md#adr-013-pluggable-parser-dispatch-multi-tool-agent-foundation)
- [ADR-014 — pentest mode permission gating](architecture.md#adr-014-pentest-mode-permission-gating--immutable-audit-flag)
- [ADR-016 — anti-noise ranking for IPAM reconciliation](architecture.md#adr-016-anti-noise-ranking-for-the-ipam-reconciliation-surface)
- [Phase L brainstorm](../../plans/okay-lets-brainstorm-on-bright-dragonfly.md) — original testssl / ssh-audit design that queued this work as Phase L+1/L+2
