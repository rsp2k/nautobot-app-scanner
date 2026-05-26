"""Add ``Scan.target_raw_ips`` for ad-hoc rescans that bypass IPAM.

The Rescan-this-host button on DiscoveredHost detail needs to dispatch
a scan against a single IP without committing it to IPAM. Existing
target fields (``target_prefixes`` M2M → ipam.Prefix, ``target_ipaddresses``
M2M → ipam.IPAddress) both require IPAM rows, which is the wrong
trade-off for ephemeral rescans.

``target_raw_ips`` is a JSONField defaulting to ``[]``. The dispatch
path (LocalBackend + AgentPendingScansView) appends these strings to
the nmap target list alongside the IPAM-anchored targets. Pure
addition — existing scans default to empty list and behave identically.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Add Scan.target_raw_ips for ad-hoc rescans."""

    dependencies = [
        ("nautobot_scanner", "0010_seed_nse_recon_profiles"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="target_raw_ips",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "Raw IP/CIDR strings to scan that aren't IPAM-committed (e.g. "
                    "ad-hoc rescans triggered from a DiscoveredHost detail page). "
                    "Appended to the nmap target list alongside target_prefixes + "
                    "target_ipaddresses. Avoids polluting IPAM with throw-away entries."
                ),
            ),
        ),
    ]
