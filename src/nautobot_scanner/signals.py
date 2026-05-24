"""Signal handlers for nautobot_scanner.

post_migrate hook: associates Nautobot's stock Status records (Active,
Planned, etc.) with every nautobot_scanner content type, so the forms
for ScannerAgent and other status-bearing models actually offer them.
`@extras_features("statuses")` registers the model as status-capable but
does NOT backfill existing Status rows — that's our job.

Idempotent: ContentType.add() is a no-op if the association already
exists, so this signal can fire after every `migrate` safely.
"""

from django.apps import apps as django_apps
from django.db.models.signals import post_migrate


# Names of the default Statuses we want available to every scanner model.
# Subset of Nautobot's stock statuses chosen for relevance to scanning:
#   Active/Planned/Decommissioning — agent operational lifecycle
#   Available/Reserved             — discovered host categorization
#   Failed/Offline                 — failure / unreachable states
_DEFAULT_STATUSES = (
    "Active",
    "Planned",
    "Available",
    "Reserved",
    "Decommissioning",
    "Failed",
    "Offline",
)


def link_default_statuses_to_scanner_models(sender, app_config, **kwargs):
    """Ensure default Status records cover every nautobot_scanner content type."""
    if app_config.name != "nautobot_scanner":
        return

    # Lazy imports — Django app registry isn't ready at module-import time.
    from django.contrib.contenttypes.models import ContentType
    from nautobot.extras.models import Status

    scanner_cts = ContentType.objects.filter(app_label="nautobot_scanner")
    statuses = list(Status.objects.filter(name__in=_DEFAULT_STATUSES))
    for ct in scanner_cts:
        for status in statuses:
            status.content_types.add(ct)


def register_signals():
    """Wire the post_migrate handler — called from NautobotScannerConfig.ready()."""
    scanner_config = django_apps.get_app_config("nautobot_scanner")
    post_migrate.connect(link_default_statuses_to_scanner_models, sender=scanner_config)
