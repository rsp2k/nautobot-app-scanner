"""One-shot: backfill default Status records to scanner content types.

Runs inside the nautobot-web container. Phase 3 hand-fix until the
post_migrate signal in nautobot_scanner.signals (added in Phase 7
bootstrap) handles this automatically for fresh installs.

Usage:
    docker compose exec nautobot-web nautobot-server shell < development/scripts/backfill_statuses.py
"""

from django.contrib.contenttypes.models import ContentType
from nautobot.extras.models import Status

DEFAULT_STATUS_NAMES = [
    "Active",
    "Planned",
    "Available",
    "Reserved",
    "Decommissioning",
    "Failed",
    "Offline",
]

scanner_cts = ContentType.objects.filter(app_label="nautobot_scanner")
print("Scanner content types:", [c.model for c in scanner_cts])

statuses = Status.objects.filter(name__in=DEFAULT_STATUS_NAMES)
for ct in scanner_cts:
    for s in statuses:
        s.content_types.add(ct)

active = Status.objects.get(name="Active")
linked = list(active.content_types.filter(app_label="nautobot_scanner").values_list("model", flat=True))
print(f"Active now linked to {len(linked)} scanner CTs:", linked)
