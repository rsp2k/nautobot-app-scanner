"""Shared utilities for nautobot_scanner models and views."""

from django.core.exceptions import PermissionDenied
from nautobot.extras.models import Status


def get_default_status():
    """Return the PK of the "Active" Status, used as the StatusField default.

    Called by each PrimaryModel's `status = StatusField(default=...)`.
    Returns the bare PK (not the Status instance) because Django expects the
    default to be JSON-serializable for migrations.
    """
    return Status.objects.get(name="Active").pk


PENTEST_PERMISSION = "nautobot_scanner.use_pentest_profiles"

PENTEST_LEGAL_NOTICE = (
    "Pentest-mode profiles use techniques that can violate scanning "
    "authorization (decoy spoofing, IDS evasion via fragmentation, "
    "third-party-traffic generation via idle scan). Only dispatch "
    "against systems you have written authorization to test."
)


def check_pentest_permission(user, profile) -> bool:
    """Raise PermissionDenied if the user can't dispatch this pentest profile.

    Centralized so every dispatch site (RunScan job, ScanPrefix job,
    DiscoveredHostRescanView) enforces the same rule. Returns the
    profile's pentest-mode flag so the caller can stamp it on the Scan
    row in one go.

    The check is no-op for non-pentest profiles — the permission only
    fires when the profile sets at least one pentest field.
    """
    is_pentest = bool(getattr(profile, "is_pentest_mode", False))
    if is_pentest and not user.has_perm(PENTEST_PERMISSION):
        raise PermissionDenied(
            f"Profile {profile.name!r} uses pentest-class flags "
            f"(decoys/fragmentation/idle scan/custom MTU/source-port). "
            f"Dispatching it requires the "
            f"{PENTEST_PERMISSION!r} permission. {PENTEST_LEGAL_NOTICE}",
        )
    return is_pentest
