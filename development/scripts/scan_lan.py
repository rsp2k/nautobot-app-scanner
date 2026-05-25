"""Dispatch a discovery scan of 192.168.1.0/24 to the dmz-agent.

The agent (running with network_mode: host) inherits the host's network
namespace and can ARP/ping every device on the LAN bridge.
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

active = Status.objects.get(name="Active")
agent = ScannerAgent.objects.get(name="dmz-agent")
profile = ScanProfile.objects.get(name="smoke-discovery")
ns = Namespace.objects.get(name="Global")

lan, created = Prefix.objects.get_or_create(
    prefix="192.168.1.0/24",
    namespace=ns,
    defaults={"status": active, "description": "Home LAN"},
)
print(f"{'Created' if created else 'Using'} target prefix: {lan.prefix}")

scan = Scan.objects.create(agent=agent, profile=profile)
scan.target_prefixes.add(lan)
print(f"Created scan {scan.pk}")

get_backend(agent).dispatch(scan)
scan.refresh_from_db()
print(f"Status after dispatch: {scan.status}")
print(f"Watch:    docker logs -f scanner-agent-smoke")
print(f"Scan URL: /plugins/scanner/scans/{scan.pk}/")
