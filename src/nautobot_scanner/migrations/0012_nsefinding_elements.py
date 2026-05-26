"""Add ``NseFinding.elements`` for structured NSE script output.

Every NSE script that emits ``<elem>`` or ``<table>`` XML tags surfaces
a structured dict alongside the text output we already capture. Until
now we discarded that structure — an ssl-cert finding became a 30-line
text blob with no way to query ``cert.validity.notAfter``, even though
the data was right there in every scan.

``elements`` is a JSONField defaulting to ``{}``. Scripts that emit
text only (``fingerprint-strings``, banner scripts) end up with empty
dicts; scripts like ``ssl-cert`` / ``smb-os-discovery`` / ``http-headers``
populate it with nested dicts that downstream filters can do JSON-path
lookups against (e.g. ``elements__cert__validity__notAfter__lt=...``).

No backfill — the gzipped XML is still there, but reparsing historical
scans needs the still-deferred Phase C "amend workflow". Existing rows
default to ``{}`` and behave identically to the current text-only state.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Add NseFinding.elements for structured NSE script output."""

    dependencies = [
        ("nautobot_scanner", "0011_scan_target_raw_ips"),
    ]

    operations = [
        migrations.AddField(
            model_name="nsefinding",
            name="elements",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text=(
                    "Structured key-value data emitted by the NSE script "
                    "alongside the text output. ssl-cert populates "
                    "cert.validity.notAfter; smb-os-discovery populates "
                    "os.fqdn; http-headers populates each header as a key. "
                    "Empty dict for scripts that emit text only."
                ),
            ),
        ),
    ]
