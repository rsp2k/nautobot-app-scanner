"""Dispatch a discovery scan of 172.16.1.0/24 from scanhost-01-agent's POV."""

from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

active = Status.objects.get(name="Active")
agent = ScannerAgent.objects.get(name="scanhost-01-agent")
profile = ScanProfile.objects.get(name="smoke-discovery")
ns = Namespace.objects.get(name="Global")

lan, created = Prefix.objects.get_or_create(
    prefix="172.16.1.0/24",
    namespace=ns,
    defaults={"status": active, "description": "scanhost-01 management LAN"},
)
print(f"{'Created' if created else 'Using'} target prefix: {lan.prefix}")

scan = Scan.objects.create(agent=agent, profile=profile)
scan.target_prefixes.add(lan)
get_backend(agent).dispatch(scan)
scan.refresh_from_db()
print(f"Scan {scan.pk} dispatched (status={scan.status})")
print(f"Watch:    ssh rpm@scanhost-01.example.net 'docker logs -f scanner-agent-scanhost-01'")
