"""Seed a ``dnssec-trace`` profile that exercises drill's DNSSEC chase.

Phase G shipped with ``dig`` as the proof-of-concept second tool.
``drill`` (NLnet Labs / ldns, already in netshoot) was added in a
follow-on commit as a supplement — dig stays the default for plain
record snapshots, drill takes over when the operator cares about
DNSSEC chain validation.

The profile uses ``-DT`` which tells drill to:
- ``-D``: include DNSSEC RRsets in the answer (RRSIG, NSEC, DNSKEY)
- ``-T``: trace from the root, validating each delegation along the way

The parser extracts the ``ad`` (Authenticated Data) flag from drill's
``;; flags:`` header line and stores it as ``elements.dnssec_authenticated``
on the resulting NseFinding. When that flag is False on a query the
operator asked DNSSEC-validation for, the finding escalates to
MEDIUM severity — the actionable signal.

Idempotent via ``get_or_create`` so re-migrate doesn't clobber an
operator's edits.
"""

from django.db import migrations


def seed_dnssec_trace(apps, schema_editor):
    """Create the dnssec-trace profile if it doesn't exist."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    ScanProfile.objects.get_or_create(
        name="dnssec-trace",
        defaults={
            "scan_type": "discovery",
            "tool": "drill",
            "nmap_arguments": "",
            # -D requests DNSSEC RRs; -T traces from root validating each step.
            # Together: full chain validation reported in one run.
            "tool_arguments": "-DT",
            "timing_template": "T3",  # unused for drill but required field
            "enabled_scripts": [],
            "description": (
                "Full DNSSEC chain validation via drill -DT. Walks from the "
                "root validating each delegation; the parser surfaces the "
                "Authenticated Data flag as elements.dnssec_authenticated. "
                "Chain failures escalate the finding to MEDIUM severity."
            ),
        },
    )


def remove_dnssec_trace(apps, schema_editor):
    """Reverse: drop the seeded profile only if its args still match the seed."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    ScanProfile.objects.filter(
        name="dnssec-trace",
        tool="drill",
        tool_arguments="-DT",
    ).delete()


class Migration(migrations.Migration):
    """Seed the dnssec-trace profile that uses drill instead of dig."""

    dependencies = [
        ("nautobot_scanner", "0016_pentest_mode"),
    ]

    operations = [
        migrations.RunPython(seed_dnssec_trace, remove_dnssec_trace),
    ]
