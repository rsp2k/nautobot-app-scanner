"""Seed an IPAddress for 127.0.0.1 so we can validate IPAddressScans panel.

Run via:
    docker compose -f development/docker-compose.yml --env-file development/.env \
      exec -T nautobot-web nautobot-server shell < development/scripts/seed_test_ipam.py
"""

from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace

ns = Namespace.objects.get(name="Global")
active = Status.objects.get(name="Active")

ip, created = IPAddress.objects.get_or_create(
    address="127.0.0.1/32",
    namespace=ns,
    defaults={"status": active, "description": "Smoke-test target"},
)
print(f"{'Created' if created else 'Using'} IPAddress {ip.address} (pk={ip.pk})")
print(f"Detail URL: /ipam/ip-addresses/{ip.pk}/")
