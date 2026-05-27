"""Seed four Phase J profiles: http-probe, path-baseline, masscan-sweep, tls-quick-check.

Phase J finished wiring the four tools that ToolChoices advertised
since Phase G but had no working parser/agent-builder. Each profile
gives operators a one-click entry point for the new dispatch path:

- **http-probe** (curl) — quick HTTP GET capturing status, size, time,
  redirect count, and response headers. Foundation for HTTP-drift
  detection once a scheduled-rescan layer lands.
- **path-baseline** (mtr) — 20-probe-per-hop path + latency snapshot.
  Detects route changes and silent latency creep over time.
- **masscan-sweep** (masscan) — port 0-65535 sweep at 50k pps.
  Pentest-mode auto-tripped via ``PENTEST_TOOLS`` since masscan at
  this rate is unmistakable to any IDS. Dispatching requires the
  ``use_pentest_profiles`` permission.
- **tls-quick-check** (openssl s_client) — cert + chain + verify
  status for a TLS endpoint. Lighter than ``testssl.sh`` (which
  isn't in netshoot); answers "is this cert valid and chained?"

All profiles are idempotent via ``get_or_create`` — operator edits
survive re-migrate.
"""

from django.db import migrations


PROFILES = (
    {
        "name": "http-probe",
        "scan_type": "discovery",
        "tool": "curl",
        "nmap_arguments": "",
        "tool_arguments": "",  # defaults — bare GET
        "timing_template": "T3",
        "enabled_scripts": [],
        "description": (
            "Quick HTTP GET via curl. Captures status code, response size, "
            "transfer time, redirect count, and key response headers "
            "(Server, Content-Type, etc). Foundation for HTTP-drift detection."
        ),
    },
    {
        "name": "path-baseline",
        "scan_type": "topology",
        "tool": "mtr",
        "nmap_arguments": "",
        "tool_arguments": "-c 20",  # 20 probes/hop for tighter baseline
        "timing_template": "T3",
        "enabled_scripts": [],
        "description": (
            "Path + per-hop latency baseline via mtr in JSON mode. "
            "20 probes per hop gives a tight enough baseline to detect "
            "route changes and silent latency creep on re-scan."
        ),
    },
    {
        "name": "masscan-sweep",
        "scan_type": "port",
        "tool": "masscan",
        "nmap_arguments": "",
        # Full port range at 50k pps. Override per-scan via raw nmap_arguments
        # would be wrong (the tool is masscan); operators tune via tool_arguments.
        "tool_arguments": "-p 0-65535 --rate 50000",
        "timing_template": "T3",  # unused for masscan but required
        "enabled_scripts": [],
        "description": (
            "Full TCP port range sweep at 50,000 packets/sec via masscan. "
            "PENTEST MODE auto-required (masscan at this rate is "
            "unmistakable to any IDS). Use as pre-recon before drilling "
            "down with nmap; masscan covers /24 in seconds and 0.0.0.0/0 "
            "in minutes."
        ),
    },
    {
        "name": "tls-quick-check",
        "scan_type": "version",
        "tool": "openssl-s_client",
        "nmap_arguments": "",
        # Default args: dump full cert chain, force TLS 1.3 to avoid
        # downgrade noise. Operators override via tool_arguments
        # (e.g. add `-servername example.com` for SNI when target is an IP).
        "tool_arguments": "-showcerts -tls1_3",
        "timing_template": "T3",
        "enabled_scripts": [],
        "description": (
            "TLS cert + chain dump via openssl s_client. Captures subject, "
            "issuer, validity, cipher, verify result. Severity escalates "
            "HIGH if expiring <7 days, MEDIUM <30 days or verify fails. "
            "Targets must include port (e.g. example.com:443)."
        ),
    },
)


def seed_profiles(apps, schema_editor):
    """Create the four Phase J profiles if they don't exist."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        defaults = {**spec}
        name = defaults.pop("name")
        ScanProfile.objects.get_or_create(name=name, defaults=defaults)


def remove_profiles(apps, schema_editor):
    """Reverse: drop profiles whose tool_arguments still match the seed."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        ScanProfile.objects.filter(
            name=spec["name"],
            tool=spec["tool"],
            tool_arguments=spec["tool_arguments"],
        ).delete()


class Migration(migrations.Migration):
    """Seed the four Phase J profiles."""

    dependencies = [
        ("nautobot_scanner", "0017_seed_dnssec_trace_profile"),
    ]

    operations = [
        migrations.RunPython(seed_profiles, remove_profiles),
    ]
