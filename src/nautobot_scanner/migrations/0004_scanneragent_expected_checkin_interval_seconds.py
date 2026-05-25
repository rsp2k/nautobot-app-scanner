"""Per-agent override for the MarkStaleAgents threshold.

`MarkStaleAgents` previously used a single PLUGINS_CONFIG-wide checkin
interval for every remote agent. Production reality: a DMZ agent on a
loaded VPN may legitimately checkin every 5 minutes, while an OT-segment
agent on a metered link checks in every 30. One global threshold means
either the slow agent flaps Offline or the fast agent's silence goes
undetected for half an hour.

Nullable on purpose — leaving it blank inherits the plugin-wide default,
so existing installs get the old behavior with no per-row edits.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Add ScannerAgent.expected_checkin_interval_seconds (nullable override)."""

    dependencies = [
        ("nautobot_scanner", "0003_alter_discoveredport_product_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanneragent",
            name="expected_checkin_interval_seconds",
            field=models.PositiveIntegerField(
                blank=True,
                help_text=(
                    "How often this agent is expected to check in. MarkStaleAgents flags the "
                    "agent Offline once last_seen exceeds 3× this value. Leave blank to use the "
                    "plugin-wide default (PLUGINS_CONFIG['nautobot_scanner']['agent_checkin_interval_seconds'])."
                ),
                null=True,
            ),
        ),
    ]
