# Compatibility Matrix

| nautobot-app-scanner | Nautobot | Python | python-libnmap | nautobot-dns-models |
|----------------------|----------|--------|----------------|---------------------|
| 2026.5.x (current)   | 3.0–3.1  | 3.10–3.13 | 0.7+        | `nautobot-dns-models-bitemporal == 2.2.1` (pinned via git URL @ tag until the fork's PyPI publish flips) |

## Probe tool versions

Each tool is independently dispatched via `ScanProfile.tool`. A profile
that asks for a tool the worker / agent doesn't have fails cleanly
with the missing-tool name in `Scan.error_message`. Only install what
you'll dispatch.

| Tool | Minimum version | Tested with | Notes |
|---|---|---|---|
| nmap | 7.0+ | 7.94+ | XML schema stable since 7.x; `vulners` script needs 7.0+ |
| dig | any modern | bind 9.16+ | Output format is line-stable; the parser is tolerant |
| drill | any modern | ldns 1.8+ | DNSSEC `;; flags:` parsing exercised in tests against ldns 1.8 output |
| curl | 7.50+ | 8.x | `-w` writeout flag is parser-critical; older curls work but the writeout token set has expanded |
| mtr | 0.94+ | 0.95+ | Needs `-j` JSON output flag (introduced in mtr 0.86, mature by 0.94) |
| masscan | 1.3+ | 1.3.2 | `-oJ -` JSON-to-stdout requires 1.3+ |
| openssl | 1.1.1+ | 1.1.1 + 3.x | Parser handles both 1.1.x ("Cipher : X" / "Not Before:") and 3.x ("Cipher is X" / "v:NotBefore:") output shapes |
| testssl.sh | 3.0+ | 3.2.1 | JSON output schema stabilized in 3.x; on Debian the binary is `testssl` (no `.sh`). `--jsonfile` interleaves progress on stdout — use a real temp file (the LocalBackend's argv builder does this). |
| ssh-audit | 3.0+ | 3.3.0 | JSON-mode (`-j`) returns exit code 2/3/4 to signal severity (warn/info/fail). The LocalBackend tolerates non-zero exit for this tool via the `_TOLERATE_NONZERO_EXIT` allowlist. |

## Versioning policy

The app uses **CalVer** (`YYYY.MM.DD`) rather than SemVer. The date
communicates **when** the app was last verified against external
dependencies (Nautobot, python-libnmap, nmap binary itself). Operators
debugging weird behavior want to know "when was this built" before
"what version is this."

Same-day fixes append a post-release suffix: `2026.5.24.1`,
`2026.5.24.2`, etc.

## Tested matrix

The CI matrix tests against:

- Nautobot 3.0 + Python 3.10
- Nautobot 3.0 + Python 3.13
- Nautobot 3.1 + Python 3.12 (primary)

Other combinations are likely fine but not gate-tested.

## What breaks across Nautobot major versions

The app uses these stable Nautobot 3.x APIs:

- `nautobot.apps.NautobotAppConfig`
- `nautobot.apps.models.PrimaryModel` / `BaseModel`
- `nautobot.apps.views.NautobotUIViewSet`
- `nautobot.apps.ui.NavMenuTab` / `ObjectDetailContent`
- `nautobot.extras.models.Status` / `StatusField`
- `nautobot.extras.utils.extras_features`
- `nautobot.ipam.fields.VarbinaryIPField`
- `nautobot.extras.jobs.Job` + `register_jobs()`

These have all been stable since Nautobot 2.x. Upgrading to Nautobot 4.x
when it ships will likely require a one-time `pyproject.toml` bump and
re-running tests; we'll cut a new CalVer release at that point.

## nmap version notes

- nmap **7.0+** is required for `--script vulners` to work correctly
- nmap **7.91+** is recommended for `-sV` accuracy on modern TLS
- The XML output format is stable since 7.x; the parser doesn't
  branch on version
- For Windows host detection (`-O`), nmap **7.94+** has noticeably
  better fingerprints

## nautobot-dns-models-bitemporal note

Phase K (dig/drill record promotion) depends on
`nautobot-dns-models-bitemporal`, a fork of upstream
`nautobot-app-dns-models` that adds `BitemporalMixin` to every record
class plus an explicit `obj.amend()` API for sequenced-amend rotations
on re-scan (separate from `obj.save()`, which keeps the framework-
standard pk-stable UPDATE semantics).

The dist was renamed from `nautobot-dns-models` to
`nautobot-dns-models-bitemporal` at the `v2.2.0a1` tag to signal the
structural divergence from upstream once the API split landed —
upstream `2.1.x` doesn't have `amend()`, so the promoter would
silently fail an `AttributeError` against it. The import path stays
`nautobot_dns_models` (no code-side change).

`pyproject.toml` pins the fork via git URL at tag `v2.2.1`; the
fork's PyPI publish remains deferred. When publish flips, a one-line
follow-up bumps the pin to a plain `nautobot-dns-models-bitemporal ==
2.2.1` specifier. See
[ADR-015](../dev/architecture.md#adr-015-promote-dig-and-drill-into-typed-dns-models)
for the rationale and `docs/agent-threads/bitemporal-dns-integration/`
for the full coordination history (24 messages, 13 bugs caught
across the integration arc).

## What's NOT supported

- nmap versions older than 7.0 (XML schema differences)
- Nautobot versions older than 3.0
- Python 3.9 (Nautobot itself requires 3.10+)
- Upstream `nautobot-dns-models` (any version) — Phase K's amend
  detection depends on `BitemporalMixin.all_versions`, `entry_id`,
  and `obj.amend()`. Use `nautobot-dns-models-bitemporal` instead.
