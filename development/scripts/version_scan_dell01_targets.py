"""Version-scan scanhost-02 + the c3750 switch from scanhost-01's vantage.

Hits two specific IPs (not the whole /24) since -sV with top-100 ports
takes much longer than -sn discovery. ~2 minutes total expected.
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner.backends import get_backend
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

active = Status.objects.get(name="Active")
agent = ScannerAgent.objects.get(name="scanhost-01-agent")
profile = ScanProfile.objects.get(name="version-scan")
ns = Namespace.objects.get(name="Global")

# Ensure the parent prefix exists so IPAddress.clean() is happy.
Prefix.objects.get_or_create(
    prefix="172.16.1.0/24",
    namespace=ns,
    defaults={"status": active, "description": "scanhost-01 management LAN"},
)

# Targets: scanhost-02 + c3750 mgmt IP. Two IPs is fast (~30s for top-100 each).
targets = []
for ip_str in ("172.16.1.10", "172.16.1.3"):
    ip, _ = IPAddress.objects.get_or_create(
        address=f"{ip_str}/32",
        namespace=ns,
        defaults={"status": active},
    )
    targets.append(ip)

scan = Scan.objects.create(agent=agent, profile=profile)
scan.target_ipaddresses.set(targets)
get_backend(agent).dispatch(scan)
scan.refresh_from_db()
print(f"Scan {scan.pk} dispatched ({scan.status})")
print(f"Targeting: {', '.join(str(ip.address) for ip in targets)}")
