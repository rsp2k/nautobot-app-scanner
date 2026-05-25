"""Discovery scan of 10.128.144.0/24 from the dev-bridge agent.

Agent runs inside the docker overlay, so reverse DNS goes through
docker's embedded resolver (127.0.0.11) and returns container names.
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

active = Status.objects.get(name="Active")
agent = ScannerAgent.objects.get(name="dev-bridge-agent")
profile = ScanProfile.objects.get(name="smoke-discovery")
ns = Namespace.objects.get(name="Global")

lan, _ = Prefix.objects.get_or_create(
    prefix="10.128.144.0/24",
    namespace=ns,
    defaults={"status": active, "description": "Docker internal network"},
)

scan = Scan.objects.create(agent=agent, profile=profile)
scan.target_prefixes.add(lan)
get_backend(agent).dispatch(scan)
scan.refresh_from_db()
print(f"Scan {scan.pk} dispatched")
