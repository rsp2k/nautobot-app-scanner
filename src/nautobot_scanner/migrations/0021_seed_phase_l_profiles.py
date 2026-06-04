"""Seed the two Phase L deep-audit profiles: tls-audit-deep + ssh-audit.

Phase L pairs two compliance-grade audit tools that both produce native
JSON with their own ordinal severity classifications mapping 1:1 onto
SeverityChoices. Neither is pentest-class (both make standard TLS/SSH
handshakes, no exploit attempts), so they ride the existing non-gated
dispatch path.

- **tls-audit-deep** (testssl.sh) — comprehensive TLS audit. Tests every
  protocol (SSLv2 → TLSv1.3), every cipher offered, certificate chain,
  HSTS, OCSP stapling, and named-vulnerability signatures (Heartbleed,
  BEAST, POODLE, ROBOT, LUCKY13, CRIME, BREACH, CCS, ticketbleed, RC4,
  FREAK, LOGJAM, DROWN, SWEET32). The shallow ``tls-quick-check``
  (openssl s_client) stays alongside for the speed/depth tradeoff.

- **ssh-audit** (ssh-audit) — comprehensive SSH server audit. Catalogs
  every algorithm offered (KEX, ciphers, MACs, host-keys), classifies
  each against a CVE-aware rulebook, flags weak/deprecated/dangerous
  algorithms. Deeper than the ``ssh-recon`` NSE pair (ssh-hostkey +
  ssh-auth-methods).

Both profiles are idempotent via ``get_or_create`` — operator edits
survive re-migrate.
"""

from django.db import migrations


PROFILES = (
    {
        "name": "tls-audit-deep",
        "scan_type": "vuln",
        "tool": "testssl",
        "nmap_arguments": "",
        # Default: full audit, no severity filter. Operators can override
        # with `--severity LOW` to drop info noise, or specific test
        # categories via `-p` / `-e` etc. tool_arguments is the per-scan
        # tuning surface.
        "tool_arguments": "",
        "timing_template": "T3",  # unused for non-nmap tools but required
        "enabled_scripts": [],
        "description": (
            "Comprehensive TLS audit via testssl.sh — every protocol, "
            "every cipher, cert chain, HSTS, OCSP, and named vulns "
            "(Heartbleed/BEAST/POODLE/ROBOT/...). Compliance-grade "
            "depth, slower than tls-quick-check. Targets: host[:443]."
        ),
    },
    {
        "name": "ssh-audit",
        "scan_type": "vuln",
        "tool": "ssh-audit",
        "nmap_arguments": "",
        # Default: bare audit (no policy file). The -P flag pins to a
        # named compliance policy (Mozilla intermediate, NSA CNSA, etc.);
        # operators add it via tool_arguments when needed.
        "tool_arguments": "",
        "timing_template": "T3",
        "enabled_scripts": [],
        "description": (
            "SSH server compliance audit via ssh-audit — KEX/ciphers/MACs/"
            "host-keys catalog with CVE-aware rulebook, flags weak/"
            "deprecated algos. Deeper than ssh-recon NSE pair. "
            "Default port 22; override via host:port."
        ),
    },
)


def seed_profiles(apps, schema_editor):
    """Create the two Phase L profiles if they don't exist."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        defaults = {**spec}
        name = defaults.pop("name")
        ScanProfile.objects.get_or_create(name=name, defaults=defaults)


def remove_profiles(apps, schema_editor):
    """Reverse: drop profiles whose tool still matches the seed."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        ScanProfile.objects.filter(name=spec["name"], tool=spec["tool"]).delete()


class Migration(migrations.Migration):
    """Seed the two Phase L deep-audit profiles."""

    dependencies = [
        ("nautobot_scanner", "0020_provenance_use_entry_id"),
    ]

    operations = [
        migrations.RunPython(seed_profiles, remove_profiles),
    ]
