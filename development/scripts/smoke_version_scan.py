"""Real -sV scan against the docker internal network (postgres + redis).

Verifies the full pipeline produces DiscoveredPort + service_name/product/
version fields, not just host-up records like the discovery scan did.

Run via:
    docker compose -f development/docker-compose.yml --env-file development/.env \
      exec -T nautobot-web nautobot-server shell < development/scripts/smoke_version_scan.py
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.backends import LocalBackend
from nautobot_scanner.choices import ScanStateChoices, ScanTypeChoices, TimingTemplateChoices
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

print("=" * 70)
print("Scanner smoke test — -sV against scanner-postgres + scanner-redis")
print("=" * 70)

active = Status.objects.get(name="Active")
agent = ScannerAgent.objects.filter(agent_type="local").first()
print(f"Using agent: {agent.name}")

profile, created = ScanProfile.objects.get_or_create(
    name="version-scan",
    defaults={
        "scan_type": ScanTypeChoices.VERSION,
        "nmap_arguments": "-sV --top-ports 100 -Pn",  # -Pn skips host discovery
        "timing_template": TimingTemplateChoices.T4,
        "description": "Service/version detection on top 100 TCP ports",
    },
)
print(f"{'Created' if created else 'Using'} profile: {profile.name} ({profile.nmap_arguments})")

ns = Namespace.objects.get(name="Global")
# /24 covers the entire docker internal subnet so postgres + redis both fit.
docker_internal, created = Prefix.objects.get_or_create(
    prefix="10.128.144.0/24",
    namespace=ns,
    defaults={"status": active, "description": "Docker internal network (dev stack)"},
)
print(f"{'Created' if created else 'Using'} target prefix: {docker_internal.prefix}")

scan = Scan.objects.create(agent=agent, profile=profile)
scan.target_prefixes.add(docker_internal)
print(f"Created scan: {scan.pk}")

print("\nDispatching LocalBackend.dispatch()... (this scans 254 IPs, may take 30-90s)")
LocalBackend().dispatch(scan)
scan.refresh_from_db()

print(f"\nFinal scan state: {scan.status}")
print(f"  summary: {scan.summary}")
print(f"  raw_xml: {scan.raw_xml.name} ({scan.raw_xml_size} bytes)")

print(f"\n=== Discovered hosts ({scan.hosts.count()}) ===")
for h in scan.hosts.filter(host_state="up").select_related("scan").prefetch_related("ports"):
    print(f"\n{h.ip_address}  hostname={h.hostname or '(none)'}  os={h.os_family or '?'}")
    for p in h.ports.filter(state="open"):
        fp = f"{p.product or '?'} {p.version or ''}".strip()
        print(f"  {p.port}/{p.protocol}  {p.service_name:15s}  {fp}")
