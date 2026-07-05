"""Seed the reusable ``Provisional`` extras.Status for enrichment-created rows.

Bulk-created IPAddresses and Prefixes from the reconciliation feature's
bulk-promote surfaces get stamped with ``status=Provisional`` so a
downstream reviewer can filter for "created by enrichment, not yet
operator-validated." The status is deliberately **reusable** — not
namespaced under the scanner app — because the same trust-but-verify
signal applies to any auto-import path (DHCP importer, cloud sync,
service-discovery), so future apps can drop into it too.

Idempotent via ``get_or_create`` keyed on name; safe on re-migrate.
Attached to ``ipam.ipaddress`` and ``ipam.prefix`` content types via
the M2M — extending to other content types (e.g. ``dcim.device``) is
a one-line addition in a follow-up migration.

Ships alongside the reconciliation feature (see ADR: docs/agent-threads/
ipam-reconciliation-report/). The bulk-promote view + management
command default to this status; the single-host promote flow keeps
its ``Active`` default because the interactive operator click is
itself the validation.
"""

from django.db import migrations


PROVISIONAL_NAME = "Provisional"
# Amber — the "pending verification" convention. Same hex Bootstrap
# uses for its `warning` button so operator eyes are already trained.
PROVISIONAL_COLOR = "ffc107"
PROVISIONAL_DESCRIPTION = (
    "Auto-created by an enrichment source (scanner bulk-promote, "
    "importer, etc.) and not yet operator-validated. Filter for this "
    "status to find rows needing review."
)

CONTENT_TYPES = (
    ("ipam", "ipaddress"),
    ("ipam", "prefix"),
)


def seed_provisional_status(apps, schema_editor):
    """Create or update the Provisional status and attach it to IPAM content types."""
    Status = apps.get_model("extras", "Status")
    ContentType = apps.get_model("contenttypes", "ContentType")

    status, _ = Status.objects.get_or_create(
        name=PROVISIONAL_NAME,
        defaults={
            "color": PROVISIONAL_COLOR,
            "description": PROVISIONAL_DESCRIPTION,
        },
    )

    for app_label, model in CONTENT_TYPES:
        try:
            ct = ContentType.objects.get(app_label=app_label, model=model)
        except ContentType.DoesNotExist:
            # Foreign app not installed in this deployment. Skip silently
            # rather than fail the migration — the status is still useful
            # for the content types that DO exist.
            continue
        status.content_types.add(ct)


def remove_provisional_status(apps, schema_editor):
    """Reverse: detach the content types then delete the status.

    Deliberately non-destructive of any rows currently using the status —
    those rows are pointed at a status that no longer exists, which
    Nautobot's admin flags on the row's detail page. Operators can
    re-run the forward migration to restore, or reassign the rows to
    ``Active`` manually. We don't cascade-delete rows; they belong to
    the operator, not the migration.
    """
    Status = apps.get_model("extras", "Status")
    try:
        status = Status.objects.get(name=PROVISIONAL_NAME)
    except Status.DoesNotExist:
        return
    status.content_types.clear()
    status.delete()


class Migration(migrations.Migration):
    """Seed the reusable Provisional status for enrichment-created rows."""

    dependencies = [
        ("nautobot_scanner", "0022_seed_phase_lp1a_httpx_profile"),
        ("extras", "0001_initial_part_1"),
        ("ipam", "0001_initial_part_1"),
    ]

    operations = [
        migrations.RunPython(seed_provisional_status, remove_provisional_status),
    ]
