"""Add `os-detect` profile + upgrade `full-tcp` to include OS fingerprinting.

The original seeded catalog (0002) populated DiscoveredPort fingerprint
fields via `-sV` but never the DiscoveredHost OS fields, because no
profile passed `-O`. The parser has always been ready to read
`nmap_host.os_match_probabilities()` — there just was no data to read.

Two changes here:

1. NEW `os-detect` profile — explicit, opt-in OS-fingerprint scan.
   `-sS -sV -O --top-ports 100 --osscan-limit` pairs SYN port scan +
   service version + OS fingerprint, with `--osscan-limit` skipping
   hosts that don't have both an open AND a closed port (nmap needs
   both for a confident TCP/IP-stack guess).

2. UPDATE `full-tcp` to add `-O` — operators reaching for a "full
   TCP" scan reasonably expect everything, including OS data. The
   update is conditional on the args still matching the original
   seed value, so any operator-customized `full-tcp` is left alone.

Both moves preserve the idempotency guarantee from 0002.
"""

from django.db import migrations


OLD_FULL_TCP_ARGS = "-sS -sV -p-"
NEW_FULL_TCP_ARGS = "-sS -sV -O -p-"

OS_DETECT = {
    "name": "os-detect",
    "scan_type": "version",
    "nmap_arguments": "-sS -sV -O --top-ports 100 --osscan-limit",
    "timing_template": "T4",
    "description": (
        "Service + OS fingerprint scan of the top 100 TCP ports. Requires raw "
        "sockets on the scanner (cap_net_raw). --osscan-limit skips hosts that "
        "don't have both an open + closed port pair (cleaner output on "
        "firewalled targets)."
    ),
}


def apply_os_detect(apps, schema_editor):
    """Add os-detect; upgrade full-tcp's args only if untouched since 0002."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")

    # 1. New profile (idempotent — re-run won't duplicate).
    defaults = {**OS_DETECT}
    name = defaults.pop("name")
    ScanProfile.objects.get_or_create(name=name, defaults=defaults)

    # 2. Conditional update of full-tcp. We only touch the row if its
    #    nmap_arguments still equal the original 0002 seed value.
    ScanProfile.objects.filter(
        name="full-tcp",
        nmap_arguments=OLD_FULL_TCP_ARGS,
    ).update(nmap_arguments=NEW_FULL_TCP_ARGS)


def reverse_os_detect(apps, schema_editor):
    """Remove os-detect (only if untouched) + revert full-tcp args if they're our new value."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")

    ScanProfile.objects.filter(
        name=OS_DETECT["name"],
        nmap_arguments=OS_DETECT["nmap_arguments"],
    ).delete()

    ScanProfile.objects.filter(
        name="full-tcp",
        nmap_arguments=NEW_FULL_TCP_ARGS,
    ).update(nmap_arguments=OLD_FULL_TCP_ARGS)


class Migration(migrations.Migration):
    """Data migration: add os-detect profile + upgrade full-tcp with -O."""

    dependencies = [
        ("nautobot_scanner", "0004_scanneragent_expected_checkin_interval_seconds"),
    ]

    operations = [
        migrations.RunPython(apply_os_detect, reverse_os_detect),
    ]
