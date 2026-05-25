"""Seed minimum DCIM fixtures so Promote-to-Device has something to pick.

Idempotent — uses get_or_create everywhere.
"""

from django.contrib.contenttypes.models import ContentType
from nautobot.dcim.models import DeviceType, Location, LocationType, Manufacturer
from nautobot.extras.models import Role, Status

active = Status.objects.get(name="Active")

# LocationType "Datacenter" with content_types so we can store Devices/IPs there.
loctype, _ = LocationType.objects.get_or_create(name="Datacenter")
loctype.content_types.add(ContentType.objects.get(app_label="dcim", model="device"))
loctype.content_types.add(ContentType.objects.get(app_label="ipam", model="prefix"))
loctype.content_types.add(ContentType.objects.get(app_label="ipam", model="ipaddress"))

# Two locations — one per household network slice.
for name, desc in [("Mer", "Server room at the house — scanhost-01 + scanhost-02 + APC + Pis"),
                   ("Home", "Living-area LAN — gateway, APs, Sonos, TV, Tesla charger")]:
    Location.objects.get_or_create(
        name=name,
        defaults={"location_type": loctype, "status": active, "description": desc},
    )

# Generic device types we can hang Devices off of.
dell, _ = Manufacturer.objects.get_or_create(name="Dell")
generic, _ = Manufacturer.objects.get_or_create(name="Generic")
cisco, _ = Manufacturer.objects.get_or_create(name="Cisco")

DeviceType.objects.get_or_create(
    manufacturer=dell, model="PowerEdge (unspecified)",
    defaults={"u_height": 1},
)
DeviceType.objects.get_or_create(
    manufacturer=generic, model="Network Appliance",
    defaults={"u_height": 1},
)
DeviceType.objects.get_or_create(
    manufacturer=cisco, model="Catalyst 3750",
    defaults={"u_height": 1},
)

# Roles — at minimum Server + Network so promote-to-device has choices.
device_ct = ContentType.objects.get(app_label="dcim", model="device")
for role_name in ["Server", "Network", "Storage", "Appliance"]:
    role, _ = Role.objects.get_or_create(name=role_name)
    role.content_types.add(device_ct)

print(f"Locations: {Location.objects.count()}")
print(f"Manufacturers: {Manufacturer.objects.count()}")
print(f"DeviceTypes: {[str(d) for d in DeviceType.objects.all()]}")
print(f"Roles: {list(Role.objects.values_list('name', flat=True))}")
