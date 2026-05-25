"""Dispatch the seeded `os-detect` profile against 192.168.1.0/24.

Same target as the prior smoke runs, but this profile passes -O so
nmap performs TCP/IP-stack fingerprinting. Verifies the parser's
os_family / os_type / os_accuracy path populates DiscoveredHost rows.
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

active = Status.objects.get(name="Active")
agent = ScannerAgent.objects.get(name="dmz-agent")
profile = ScanProfile.objects.get(name="os-detect")
ns = Namespace.objects.get(name="Global")

lan, _ = Prefix.objects.get_or_create(
    prefix="192.168.1.0/24",
    namespace=ns,
    defaults={"status": active, "description": "Home LAN"},
)

scan = Scan.objects.create(agent=agent, profile=profile)
scan.target_prefixes.add(lan)
get_backend(agent).dispatch(scan)
scan.refresh_from_db()
print(f"Scan {scan.pk} dispatched, status={scan.status}")
