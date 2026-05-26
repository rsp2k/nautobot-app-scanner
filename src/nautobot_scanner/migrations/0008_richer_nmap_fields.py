"""Add richer per-port and per-host fields nmap was exposing all along.

The scanner had been extracting ~30% of what python-libnmap exposes per
host and per port. The biggest blind spots fixed here:

Per-port:
- state_reason / state_reason_ttl / state_reason_ip — distinguishes
  "host is silent" from "firewall is blocking us." Critical for
  debugging filtered-vs-closed populations behind real network gear.
- tunnel — 'ssl' for TLS-wrapped services (HTTPS, SMTPS, IMAPS).
  Drives the "is this port speaking TLS?" filter without parsing
  service_name strings.
- service_fp — raw nmap service fingerprint. Useful for submitting
  unknown fingerprints to nmap upstream.

Per-host:
- distance_hops — network hops to target. Populated by ping/traceroute.
- uptime_seconds + last_boot_at — boot inference from TCP timestamps.
  last_boot_at is stored absolute so 'hosts booted in last hour' filters
  work without subtracting at query time.
- tcp_sequence_class — TCP ISN classification ("random positive
  increments" etc.) from -O. OS-family hint independent of os_family.

No backfill — these fields aren't in historical scans because we
discarded them at parse time. Operators who care can re-run scans;
once Phase C (amend workflow) lands, re-parsing stored raw_xml will
populate them retroactively.
"""

from django.db import migrations, models

import nautobot.ipam.fields


class Migration(migrations.Migration):
    """Add the richer-per-port and per-host fields nmap exposes."""

    dependencies = [
        ("nautobot_scanner", "0007_discoveredhost_bitemporal"),
    ]

    operations = [
        # ---- DiscoveredPort: state-reason richness + tunnel + service_fp ----
        migrations.AddField(
            model_name="discoveredport",
            name="state_reason",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text=(
                    "Why nmap chose this state — 'syn-ack' (open), 'no-response' "
                    "(filtered, no packet back), 'port-unreach' (closed via ICMP), "
                    "'tcp-rst' (closed via RST), etc. Filterable to slice firewall vs "
                    "true-closed populations."
                ),
                max_length=64,
            ),
        ),
        migrations.AddField(
            model_name="discoveredport",
            name="state_reason_ttl",
            field=models.PositiveSmallIntegerField(
                blank=True,
                help_text="TTL of the responding packet. Mismatched TTLs hint at firewall interposition.",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="discoveredport",
            name="state_reason_ip",
            field=nautobot.ipam.fields.VarbinaryIPField(
                blank=True,
                help_text=(
                    "IP that actually sent the response — often differs from the target IP when "
                    "an intermediate firewall is rewriting/responding on the host's behalf."
                ),
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="discoveredport",
            name="tunnel",
            field=models.CharField(
                blank=True,
                help_text=(
                    "'ssl' for TLS-wrapped services (HTTPS on 443, SMTPS on 465, IMAPS on 993). "
                    "Empty for plain services. Drives 'is this port speaking TLS?' filters "
                    "without parsing the service_name string."
                ),
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="discoveredport",
            name="service_fp",
            field=models.TextField(
                blank=True,
                help_text=(
                    "Raw nmap service fingerprint string. Useful when service_name is generic "
                    "('unknown') and you want to submit the fingerprint to nmap upstream."
                ),
            ),
        ),
        # ---- DiscoveredHost: topology + uptime hints ----
        migrations.AddField(
            model_name="discoveredhost",
            name="distance_hops",
            field=models.PositiveSmallIntegerField(
                blank=True,
                help_text="Network hops to this host (matches len(traceroute_hops) when -O traceroute ran).",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="uptime_seconds",
            field=models.PositiveBigIntegerField(
                blank=True,
                help_text="Seconds since last boot, derived from TCP timestamps during nmap -O.",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="last_boot_at",
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                help_text=(
                    "Absolute boot timestamp = (scan.completed_at - uptime_seconds). "
                    "Stored so DB filters like 'booted in last hour' work without "
                    "subtracting at query time."
                ),
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="tcp_sequence_class",
            field=models.CharField(
                blank=True,
                help_text=(
                    "TCP ISN classification from nmap -O (e.g. 'random positive increments', "
                    "'trivial time dependency'). OS-family signal independent of os_family."
                ),
                max_length=64,
            ),
        ),
    ]
