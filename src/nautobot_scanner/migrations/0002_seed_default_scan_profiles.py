"""Seed the standard ScanProfile catalog so fresh installs have working presets.

Idempotent — uses get_or_create so a re-run never duplicates and operators
can edit any profile in the UI without the migration overwriting their
changes on the next deploy.

Profile design notes:

- `discovery` is the "what's alive" answer. Cheap (one packet per host),
  no `-Pn` so the count is honest.
- `top-100-tcp` is the default "what services are running" answer. No `-Pn`
  here either — pair it with a discovery scan if you have a subnet of
  unknowns. For known-up targets nmap auto-skips host discovery on
  individual IPs.
- `full-tcp` is the deep-dive — every TCP port. Slow (minutes for /24)
  but exhaustive. Use against suspect hosts, not blanket sweeps.
- `vuln` adds the `vulners` NSE script for CVE matching against detected
  services. Same shape as top-100 + CVE annotations on findings.
- `topology` is discovery + traceroute for layer-3 path mapping. Pairs
  well with the TraceRouteHop model the parser already populates.
- `udp-common` is the only UDP profile we ship. UDP scanning is slow
  (ICMP rate-limiting makes it ~50× slower than TCP) so we cap at the
  top-50 ports — that catches DNS, SNMP, NTP, DHCP, and friends without
  taking hours on a /24.
"""

from django.db import migrations


PROFILES = (
    {
        "name": "discovery",
        "scan_type": "discovery",
        "nmap_arguments": "-sn",
        "timing_template": "T4",
        "description": "Host discovery only — find what's alive on a subnet. Fast, no port-scanning.",
    },
    {
        "name": "top-100-tcp",
        "scan_type": "version",
        "nmap_arguments": "-sV --top-ports 100",
        "timing_template": "T4",
        "description": "Service + version detection on the top 100 TCP ports. The default port-scan profile.",
    },
    {
        "name": "full-tcp",
        "scan_type": "version",
        "nmap_arguments": "-sS -sV -p-",
        "timing_template": "T4",
        "description": "Full SYN scan of every TCP port (1–65535) with version detection. Slow but exhaustive.",
    },
    {
        "name": "vuln",
        "scan_type": "vuln",
        "nmap_arguments": "-sV --top-ports 100",
        "timing_template": "T4",
        "enabled_scripts": ["vulners"],
        "description": "Top-100 TCP scan plus the vulners NSE script for CVE matching against detected versions.",
    },
    {
        "name": "topology",
        "scan_type": "topology",
        "nmap_arguments": "-sn --traceroute",
        "timing_template": "T4",
        "description": "Discovery + traceroute for layer-3 topology mapping. Populates TraceRouteHop records.",
    },
    {
        "name": "udp-common",
        "scan_type": "port",
        "nmap_arguments": "-sU --top-ports 50",
        "timing_template": "T4",
        "description": "Top-50 UDP ports — DNS, SNMP, NTP, DHCP, syslog, etc. Slow due to ICMP rate-limiting.",
    },
)


def seed_profiles(apps, schema_editor):
    """Create the default profiles if they don't exist already."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        # enabled_scripts is a JSONField with default=list; pop it so we
        # can pass it through defaults cleanly.
        defaults = {**spec}
        name = defaults.pop("name")
        ScanProfile.objects.get_or_create(name=name, defaults=defaults)


def remove_profiles(apps, schema_editor):
    """Reverse: drop the seeded profiles (but only if they're untouched).

    We don't want to delete a profile an operator has edited — they may
    have made it the default for their team. So we only remove profiles
    whose nmap_arguments still match the seed value (best-effort).
    """
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        ScanProfile.objects.filter(
            name=spec["name"],
            nmap_arguments=spec["nmap_arguments"],
        ).delete()


class Migration(migrations.Migration):
    """Data migration seeding the default ScanProfile catalog."""

    dependencies = [
        ("nautobot_scanner", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_profiles, remove_profiles),
    ]
