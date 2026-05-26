"""Phase F — completeness sweep across the remaining libnmap fields.

Closes the long-tail gaps from the nmap-data audit. Each field is a
small win individually; together they take the parser from "captures
the headlines" to "captures everything libnmap exposes that we have a
sensible use for."

**DiscoveredHost**:
- ``hostnames`` — full PTR list (existing ``hostname`` field stays as
  the denormalized first-one for table cells)
- ``ip_sequence_class`` — OS-fingerprint companion to the TCP sequence
  class we already capture
- ``extraports`` — nmap's "997 ports filtered (no-response)" summary

**DiscoveredPort**:
- ``service_method`` — how nmap identified the service ('table' = port
  number lookup, 'probed' = -sV fingerprint)
- ``service_conf`` — 1..10 confidence score for the service identification

All new fields are nullable/blank. No backfill — historical scans get
the new fields populated only on re-parse (deferred amend workflow).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Phase F completeness sweep."""

    dependencies = [
        ("nautobot_scanner", "0013_scan_provenance_and_os_depth"),
    ]

    operations = [
        # --- DiscoveredHost completeness ---
        migrations.AddField(
            model_name="discoveredhost",
            name="hostnames",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "Full list of hostnames nmap reported (PTR + user-supplied). "
                    "The denormalized first one stays in `hostname` for table display."
                ),
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="ip_sequence_class",
            field=models.CharField(
                blank=True,
                max_length=64,
                help_text=(
                    "IP ID sequence class from nmap's IP sequence prediction "
                    "(e.g. 'All zeros', 'Incremental', 'Randomized'). OS "
                    "fingerprinting signal complementary to tcp_sequence_class."
                ),
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="extraports",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text=(
                    "nmap's 'extraports' summary line — when most scanned ports "
                    "share a single state ('Not shown: 997 filtered tcp ports'), "
                    "nmap collapses them. Shape: {state, count, reasons: [{reason, count}, ...]}."
                ),
            ),
        ),
        # --- DiscoveredPort completeness ---
        migrations.AddField(
            model_name="discoveredport",
            name="service_method",
            field=models.CharField(
                blank=True,
                max_length=16,
                help_text=(
                    "How nmap identified the service: 'table' (looked up port number "
                    "in nmap-services — fast but often wrong for non-standard ports), "
                    "'probed' (sent -sV probes and parsed responses — reliable)."
                ),
            ),
        ),
        migrations.AddField(
            model_name="discoveredport",
            name="service_conf",
            field=models.PositiveSmallIntegerField(
                blank=True,
                null=True,
                help_text=(
                    "nmap's confidence in the service identification (1-10). "
                    "Low values indicate the match was port-table-only or a "
                    "weak fingerprint match."
                ),
            ),
        ),
    ]
