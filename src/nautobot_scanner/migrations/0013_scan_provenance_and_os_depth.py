"""Phase E — scan provenance + DiscoveredHost OS classification depth.

Two independent gap closures rolled into one migration because they're
both about "data that was in the nmap XML but never reached the row":

**Scan provenance** — ``nmap_command``, ``nmap_version``, ``xml_version``,
``ports_scanned`` come straight from ``NmapReport``'s top-level fields.
Scans are bitemporal and long-lived; operators going back to an old scan
need to be able to answer "what did nmap actually run, with what version,
against how many ports?" without unpacking the gzipped XML.

**DiscoveredHost OS depth** — libnmap's ``NmapOSClass`` exposes vendor /
type / osgen / cpelist for the top OS match plus the full list of
alternative matches. We currently keep only ``os_family`` + ``os_type`` +
``os_accuracy`` (the headline). Adding the rest unlocks CVE correlation
via CPE strings and "show me all printers" via ``os_device_type``.

All new fields default to empty/null. No backfill — historical scans get
the new fields populated only if they're re-parsed (deferred amend
workflow, Phase C).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Phase E migration."""

    dependencies = [
        ("nautobot_scanner", "0012_nsefinding_elements"),
    ]

    operations = [
        # --- Scan provenance ---
        migrations.AddField(
            model_name="scan",
            name="nmap_command",
            field=models.TextField(
                blank=True,
                help_text="Full nmap command-line as reported by the XML (provenance + reproduction).",
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="nmap_version",
            field=models.CharField(
                blank=True,
                max_length=32,
                help_text="nmap binary version that produced this scan (e.g. '7.94').",
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="xml_version",
            field=models.CharField(
                blank=True,
                max_length=16,
                help_text="nmap XML schema version (forensic value when parsers drift between nmap releases).",
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="ports_scanned",
            field=models.PositiveIntegerField(
                blank=True,
                null=True,
                help_text=(
                    "Number of ports scanned per host as reported by nmap (the "
                    "denominator for ports_open). Distinguishes 'scanned 1000 "
                    "found 10 open' from 'scanned 100 found 10 open'."
                ),
            ),
        ),
        # --- DiscoveredHost OS depth ---
        migrations.AddField(
            model_name="discoveredhost",
            name="os_vendor",
            field=models.CharField(
                blank=True,
                max_length=64,
                db_index=True,
                help_text="OS vendor from nmap's osclass (Microsoft, Apple, Linux, Cisco, ...).",
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="os_device_type",
            field=models.CharField(
                blank=True,
                max_length=32,
                db_index=True,
                help_text=(
                    "Device class from nmap's osclass type attribute: "
                    "'general purpose', 'router', 'printer', 'firewall', "
                    "'switch', 'storage-misc', 'webcam', etc."
                ),
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="os_gen",
            field=models.CharField(
                blank=True,
                max_length=32,
                help_text="OS generation/version string from nmap's osclass osgen (e.g. '10', '7', '2.4.X').",
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="os_cpe",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "List of CPE strings nmap associates with the OS match "
                    "(e.g. ['cpe:/o:microsoft:windows_10']). Bridges to CVE databases."
                ),
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="os_alternative_matches",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "Alternative OS guesses beyond the top match, as "
                    "[{'name': str, 'accuracy': int}, ...]. Tells operators "
                    "whether the top guess was 95% top / 92% next (close call) "
                    "vs 90% top / 50% next (clear)."
                ),
            ),
        ),
    ]
