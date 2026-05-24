"""Shared utilities for nautobot_scanner models and views."""

from nautobot.extras.models import Status


def get_default_status():
    """Return the PK of the "Active" Status, used as the StatusField default.

    Called by each PrimaryModel's `status = StatusField(default=...)`.
    Returns the bare PK (not the Status instance) because Django expects the
    default to be JSON-serializable for migrations.
    """
    return Status.objects.get(name="Active").pk
