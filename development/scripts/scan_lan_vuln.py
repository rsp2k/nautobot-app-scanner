"""Dispatch the seeded `vuln` profile against 192.168.1.0/24.

Same target/agent as the recent top-100-tcp run, but using the
profile that adds the vulners NSE script for CVE matching. Results
land in DiscoveredPort + VulnerabilityFinding rows so we can verify
the vuln panel renders something other than zeros.
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

active = Status.objects.get(name="Active")
agent = ScannerAgent.objects.get(name="dmz-agent")
profile = ScanProfile.objects.get(name="vuln")
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
