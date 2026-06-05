"""Seed the Phase L+1a profile: http-probe-rich (httpx).

Phase L+1a wires httpx (ProjectDiscovery suite, first tool) into the
dispatcher. Adds one seed profile that exercises the JSONL output
with the rich field set httpx produces by default.

The Phase J curl-based ``http-probe`` profile stays alongside —
different speed/depth tradeoff (curl is 9 fields, httpx is ~30 with
TLS sub-dict + tech detection + CDN identification + DNS records).
Same shape as the ``tls-quick-check`` vs ``tls-audit-deep`` pairing
in Phase L.
"""

from django.db import migrations


PROFILES = (
    {
        "name": "http-probe-rich",
        "scan_type": "version",
        "tool": "httpx",
        "nmap_arguments": "",
        # Default tool_arguments enables the rich-field set: TLS grab,
        # tech detection, title + server header + content length + IP +
        # response time + status code. Operators tune per-scan.
        "tool_arguments": "-tls-grab -tech-detect -title -server -web-server "
                          "-content-length -ip -response-time -status-code -timeout 15",
        "timing_template": "T3",
        "enabled_scripts": [],
        "description": (
            "Modern HTTP probe via httpx (ProjectDiscovery) — JSONL "
            "output with ~30 fields per target including status, title, "
            "server, tech-detect, TLS handshake, CDN, response time. "
            "Replaces curl-based http-probe for compliance/inventory."
        ),
    },
)


def seed_profiles(apps, schema_editor):
    """Create the Phase L+1a profile if it doesn't exist."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        defaults = {**spec}
        name = defaults.pop("name")
        ScanProfile.objects.get_or_create(name=name, defaults=defaults)


def remove_profiles(apps, schema_editor):
    """Reverse: drop the http-probe-rich profile."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        ScanProfile.objects.filter(name=spec["name"], tool=spec["tool"]).delete()


class Migration(migrations.Migration):
    """Seed the Phase L+1a http-probe-rich profile."""

    dependencies = [
        ("nautobot_scanner", "0021_seed_phase_l_profiles"),
    ]

    operations = [
        migrations.RunPython(seed_profiles, remove_profiles),
    ]
