# Compatibility Matrix

| nautobot-app-scanner | Nautobot | Python | python-libnmap | nmap binary |
|----------------------|----------|--------|----------------|-------------|
| 2026.5.x (current)   | 3.0–3.1  | 3.10–3.13 | 0.7+        | 7.x+        |

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

## What's NOT supported

- nmap versions older than 7.0 (XML schema differences)
- Nautobot versions older than 3.0
- Python 3.9 (Nautobot itself requires 3.10+)
