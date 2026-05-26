"""Phase G — multi-tool agent foundation + dig as PoC second tool.

Every code path used to assume "the tool is nmap." This migration
adds the schema surface for ``ScanProfile`` to name a different probe
tool (``tool`` + ``tool_arguments``) and for ``Scan`` to record which
tool actually produced the ingested output (``tool_used`` +
``raw_output``). It also seeds one non-nmap profile (``dns-recon``)
to prove the new dispatch path end-to-end without waiting for a real
operator to construct one.

The choice of ``dig`` as the proof-of-concept tool is deliberate:
- No raw-socket privileges needed (works as unprivileged user)
- Text output, not XML — exercises the pluggable-parser dispatch
- Genuinely useful in isolation: DNS state snapshot per target
- Smallest possible cross-section: one parser, one argv builder,
  one new content type

Existing nmap profiles default to ``tool='nmap'`` automatically
because that's the model field default, and ``nmap_arguments`` is
unchanged. Nothing about the legacy nmap dispatch path moves.
"""

from django.db import migrations, models


def seed_dns_recon(apps, schema_editor):
    """Create the dns-recon profile if it doesn't exist."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    ScanProfile.objects.get_or_create(
        name="dns-recon",
        defaults={
            "scan_type": "discovery",
            "tool": "dig",
            "nmap_arguments": "",
            # Query each target for the common record types. The agent
            # appends the target IP/hostname as the last positional arg.
            "tool_arguments": "+noall +answer ANY",
            "timing_template": "T3",  # unused for dig but required field
            "enabled_scripts": [],
            "description": (
                "DNS record snapshot via dig. Records ANY-query response "
                "for each target. Useful as a baseline for DNS drift "
                "detection and for inventorying DNS-exposed services."
            ),
        },
    )


def remove_dns_recon(apps, schema_editor):
    """Reverse: drop the seeded profile only if its args still match the seed."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    ScanProfile.objects.filter(
        name="dns-recon",
        tool="dig",
        tool_arguments="+noall +answer ANY",
    ).delete()


class Migration(migrations.Migration):
    """Phase G — multi-tool foundation + dig PoC profile."""

    dependencies = [
        ("nautobot_scanner", "0014_completeness_sweep"),
    ]

    operations = [
        # --- ScanProfile: which tool, with what args (non-nmap) ---
        migrations.AddField(
            model_name="scanprofile",
            name="tool",
            field=models.CharField(
                max_length=24,
                default="nmap",
                db_index=True,
                help_text=(
                    "Which probe tool the agent runs for this profile. "
                    "Defaults to 'nmap' for back-compat; pick another value to "
                    "use a different tool from the agent's netshoot toolkit "
                    "(dig, masscan, curl, mtr, openssl-s_client, ...)."
                ),
            ),
        ),
        migrations.AddField(
            model_name="scanprofile",
            name="tool_arguments",
            field=models.TextField(
                blank=True,
                help_text=(
                    "Arguments for the chosen tool when it's not nmap. "
                    "Example for tool='dig': '-t AXFR @1.2.3.4'. "
                    "Example for tool='masscan': '-p 0-65535 --rate=10000'. "
                    "Target list is appended by the backend."
                ),
            ),
        ),
        # ScanProfile.nmap_arguments was required; make it blankable so
        # non-nmap profiles can leave it empty.
        migrations.AlterField(
            model_name="scanprofile",
            name="nmap_arguments",
            field=models.TextField(
                blank=True,
                help_text=(
                    "Raw nmap flags (e.g. '-sS -sV --top-ports 1000') — only "
                    "used when tool='nmap'. Target list is appended by the "
                    "backend. Leave blank for non-nmap profiles."
                ),
            ),
        ),
        # --- Scan: what actually ran, + non-XML output storage ---
        migrations.AddField(
            model_name="scan",
            name="tool_used",
            field=models.CharField(
                max_length=24,
                blank=True,
                db_index=True,
                help_text=(
                    "Which probe tool produced this scan's output (nmap, dig, "
                    "masscan, ...). Stamped at ingest. Empty for pre-Phase-G "
                    "scans where the assumption was always nmap."
                ),
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="raw_output",
            field=models.FileField(
                blank=True,
                null=True,
                upload_to="scanner/output/%Y/%m/",
                help_text=(
                    "Gzipped non-XML output from non-nmap tools (dig text, "
                    "masscan JSON, etc.). nmap scans use raw_xml instead."
                ),
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="raw_output_size",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Uncompressed size of raw_output in bytes.",
            ),
        ),
        # Seed the dns-recon profile so an operator can verify the dig
        # dispatch path immediately after migration without constructing
        # a profile by hand.
        migrations.RunPython(seed_dns_recon, remove_dns_recon),
    ]
