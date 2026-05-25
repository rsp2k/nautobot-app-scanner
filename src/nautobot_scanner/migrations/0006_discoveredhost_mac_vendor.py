"""Add `mac_vendor` to DiscoveredHost + backfill from existing MAC addresses.

netaddr (a Nautobot dep) ships the full IEEE OUI registry as bundled data,
so this whole feature is "free" in operational terms — no API calls, no
new dependencies. The vendor field is populated at scan ingest going
forward; the backfill in this migration covers historical scans so the
new UI column isn't half-empty on day one.

Best-effort: any MAC that doesn't resolve (locally-administered bit,
unassigned OUI, VM-generated MAC) gets an empty string, never an error.
"""

from django.db import migrations, models


def resolve_vendor(mac: str) -> str:
    """Same logic as nautobot_scanner.parser.resolve_mac_vendor, inlined.

    Inlined because data migrations shouldn't import from non-frozen project
    code — if a future refactor moves/renames `resolve_mac_vendor`, this
    migration still applies cleanly against historical states.
    """
    if not mac:
        return ""
    try:
        import netaddr

        return netaddr.EUI(mac).oui.registration().org or ""
    except (netaddr.AddrFormatError, netaddr.NotRegisteredError, ValueError):
        return ""


def backfill_mac_vendor(apps, schema_editor):
    """Walk every DiscoveredHost with a non-empty MAC and resolve the OUI."""
    DiscoveredHost = apps.get_model("nautobot_scanner", "DiscoveredHost")
    to_update = []
    for host in DiscoveredHost.objects.exclude(mac_address="").iterator():
        vendor = resolve_vendor(host.mac_address)
        if vendor:
            host.mac_vendor = vendor
            to_update.append(host)
    if to_update:
        DiscoveredHost.objects.bulk_update(to_update, ["mac_vendor"], batch_size=500)


def clear_mac_vendor(apps, schema_editor):
    """Reverse: clear the derived field. The mac_address source data is untouched."""
    DiscoveredHost = apps.get_model("nautobot_scanner", "DiscoveredHost")
    DiscoveredHost.objects.exclude(mac_vendor="").update(mac_vendor="")


class Migration(migrations.Migration):
    """Add the mac_vendor field + backfill from existing mac_address values."""

    dependencies = [
        ("nautobot_scanner", "0005_add_os_detect_profile"),
    ]

    operations = [
        migrations.AddField(
            model_name="discoveredhost",
            name="mac_vendor",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text=(
                    "Manufacturer resolved from the MAC's OUI via the IEEE registry "
                    "bundled with netaddr. Filled at ingest; empty when MAC is unknown "
                    "or OUI isn't in the registry (rare — typically VM-generated MACs "
                    "with locally-administered bit set)."
                ),
                max_length=128,
            ),
        ),
        migrations.RunPython(backfill_mac_vendor, clear_mac_vendor),
    ]
