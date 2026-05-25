"""Dispatch a discovery scan to the remote dmz-agent.

Creates a pending Scan against 127.0.0.0/30 — the agent should pick it
up within POLL_INTERVAL_SECONDS, run nmap, and POST results back.
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

agent = ScannerAgent.objects.get(name="dmz-agent")
profile = ScanProfile.objects.get(name="smoke-discovery")
ns = Namespace.objects.get(name="Global")
prefix = Prefix.objects.get(prefix="127.0.0.0/30", namespace=ns)

scan = Scan.objects.create(agent=agent, profile=profile)
scan.target_prefixes.add(prefix)
print(f"Created scan {scan.pk} (status=pending until agent picks it up)")

# RemoteBackend dispatch just flips state — actual work happens on the agent.
get_backend(agent).dispatch(scan)
scan.refresh_from_db()
print(f"After dispatch: status={scan.status} ingestion_token={scan.ingestion_token}")
print(f"Watch:    docker logs -f scanner-agent-smoke")
print(f"Scan URL: /plugins/scanner/scans/{scan.pk}/")
