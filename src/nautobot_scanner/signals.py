"""Signal handlers for nautobot_scanner.

Two handlers:

- post_migrate: associates Nautobot's stock Status records (Active,
  Planned, etc.) with every nautobot_scanner content type, so the forms
  for ScannerAgent and other status-bearing models actually offer them.
  `@extras_features("statuses")` registers the model as status-capable
  but does NOT backfill existing Status rows.

- post_save on ScannerAgent: when a remote agent is created without a
  bound User, auto-create one and issue a DRF Token. The token is the
  agent's bearer credential for the /api/plugins/scanner/agents/<id>/
  endpoints. Idempotent — if user is already set, no-op.

Both signals are idempotent and safe to fire multiple times.
"""

from django.apps import apps as django_apps
from django.db.models.signals import post_migrate, post_save


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


def ensure_remote_agent_user(sender, instance, created, **kwargs):
    """Auto-provision User + DRF Token for remote agents that don't have one.

    Fires on post_save for ScannerAgent. Only acts when:
    - agent_type is "remote"
    - user is not already set

    Username pattern: `scanner-agent-<slugified-name>`. Falls back to
    appending the agent's pk if a name collision happens (very rare —
    requires two agents with the same slug AND no existing user).

    The Token is issued via DRF's default `Token.objects.get_or_create`.
    Operators see the token via the admin User detail page or via the
    Nautobot API token UI. We deliberately don't expose it in the
    ScannerAgent form/admin — encourages operators to use Nautobot's
    standard token-management surface.
    """
    if instance.agent_type != "remote":
        return
    if instance.user is not None:
        return

    from django.contrib.auth import get_user_model
    from django.utils.text import slugify
    from nautobot.users.models import Token

    User = get_user_model()

    # Derive a stable username slug; suffix with short PK on collision.
    base_slug = slugify(instance.name) or "agent"
    username = f"scanner-agent-{base_slug}"
    if User.objects.filter(username=username).exists():
        username = f"scanner-agent-{base_slug}-{str(instance.pk)[:8]}"

    user, _user_created = User.objects.get_or_create(
        username=username,
        defaults={
            "is_active": True,
            "is_staff": False,
            "is_superuser": False,
        },
    )
    # No usable password — agent never logs in interactively.
    user.set_unusable_password()
    user.save()

    Token.objects.get_or_create(user=user)

    # Link back. Re-save WITHOUT firing this signal recursively by using
    # update() instead of save().
    sender.objects.filter(pk=instance.pk).update(user=user)


def register_signals():
    """Wire the post_migrate + post_save handlers — called from NautobotScannerConfig.ready()."""
    scanner_config = django_apps.get_app_config("nautobot_scanner")
    post_migrate.connect(link_default_statuses_to_scanner_models, sender=scanner_config)

    # Lazy resolution to avoid Django app-loading-order issues.
    ScannerAgent = django_apps.get_model("nautobot_scanner", "ScannerAgent")
    post_save.connect(ensure_remote_agent_user, sender=ScannerAgent)
