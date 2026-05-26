"""Make DiscoveredHost bitemporal (tier-4 pattern from l2trace.warehack.ing).

Adds two ``TSTZRANGE`` columns and a UUID ``entry_id``:

- ``valid_during``: wire-time. When the host was actually observed by nmap.
  Backfilled from the parent Scan's ``[started_at, completed_at)`` window.
- ``recorded_during``: belief-time. ``[ingest_time, ∞)`` for current beliefs;
  the upper bound gets closed when a re-parse supersedes a row.
  Backfilled from the row's ``created`` timestamp with an open upper bound
  (treating all existing rows as still-current beliefs).
- ``entry_id``: per-row UUID distinguishing successive beliefs about the
  same (scan, ip_address). Generated fresh during backfill.

Schema changes:

1. AddField for the three columns (nullable initially so backfill can run)
2. RunPython: backfill values from scan + created data
3. AlterUniqueTogether to remove the unfilterable ``(scan, ip_address)``
   constraint (the historical constraint can't coexist with multiple
   belief rows for the same (scan, ip))
4. Raw SQL partial unique index: enforce uniqueness only on current beliefs
   (``WHERE upper(recorded_during) IS NULL``). Two superseded beliefs about
   the same (scan, ip) are fine; two CURRENT beliefs are an integrity error.

Why a partial unique index instead of an ExclusionConstraint: the simpler
constraint catches the only case we actually care about (two current beliefs
collide on insert). ExclusionConstraint would also catch overlapping belief
windows, but our amend workflow always closes the prior belief atomically
in a transaction — overlapping windows would only arise from buggy
amendments, which the simpler partial unique catches at insert time anyway.
"""

import uuid

from django.contrib.postgres.fields import DateTimeRangeField
from django.db import migrations, models


def backfill_bitemporal_fields(apps, schema_editor):
    """Derive valid_during from parent Scan, recorded_during from created.

    Uses bulk_update for efficiency — most installs will have at most a few
    thousand DiscoveredHost rows so the per-row Python loop is fine.
    """
    from psycopg2.extras import DateTimeTZRange

    DiscoveredHost = apps.get_model("nautobot_scanner", "DiscoveredHost")

    to_update = []
    for host in DiscoveredHost.objects.select_related("scan").iterator():
        # Wire-time window: [scan.started_at, scan.completed_at).
        # If either is None (incomplete scan), leave the corresponding
        # bound open — range semantics handle that cleanly.
        host.valid_during = DateTimeTZRange(
            lower=host.scan.started_at,
            upper=host.scan.completed_at,
            bounds="[)",
        )
        # Recorded-time: [created, None). All existing rows treated as
        # still-current beliefs; no historical supersedes exist pre-migration.
        host.recorded_during = DateTimeTZRange(
            lower=host.created,
            upper=None,
            bounds="[)",
        )
        host.entry_id = uuid.uuid4()
        to_update.append(host)

    if to_update:
        DiscoveredHost.objects.bulk_update(
            to_update,
            ["valid_during", "recorded_during", "entry_id"],
            batch_size=500,
        )


def revert_bitemporal_fields(apps, schema_editor):
    """No-op reverse — AlterField/RemoveField below handle the schema undo."""


class Migration(migrations.Migration):
    """Add bitemporal axes to DiscoveredHost + partial unique on current beliefs."""

    dependencies = [
        ("nautobot_scanner", "0006_discoveredhost_mac_vendor"),
    ]

    operations = [
        # ---- Add the bitemporal columns (nullable so backfill can run) ----
        migrations.AddField(
            model_name="discoveredhost",
            name="valid_during",
            field=DateTimeRangeField(
                null=True,
                blank=True,
                help_text=(
                    "Wire-time range when the host was actually observed. "
                    "Typically [scan.started_at, scan.completed_at]. NULL only "
                    "for rows backfilled from scans without timestamps."
                ),
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="recorded_during",
            field=DateTimeRangeField(
                null=True,  # nullable during backfill; default-bound by code post-migration
                blank=True,
                help_text=(
                    "Belief-time range. [ingest_time, ∞) while this row is the "
                    "current belief; upper bound is closed when a re-parse "
                    "produces a fresher belief."
                ),
            ),
        ),
        migrations.AddField(
            model_name="discoveredhost",
            name="entry_id",
            field=models.UUIDField(
                null=True,  # backfill assigns; subsequent inserts get default uuid4
                db_index=True,
                editable=False,
                help_text=(
                    "Per-row UUID distinguishing successive beliefs about the "
                    "same (scan, ip_address) observation."
                ),
            ),
        ),
        # ---- Backfill from existing data ----
        migrations.RunPython(backfill_bitemporal_fields, revert_bitemporal_fields),
        # ---- Drop the unfilterable historical unique_together ----
        migrations.AlterUniqueTogether(
            name="discoveredhost",
            unique_together=set(),
        ),
        # ---- Partial unique: only current beliefs collide on (scan, ip) ----
        migrations.RunSQL(
            sql=(
                "CREATE UNIQUE INDEX discoveredhost_unique_current_belief "
                "ON nautobot_scanner_discoveredhost (scan_id, ip_address) "
                "WHERE upper(recorded_during) IS NULL;"
            ),
            reverse_sql=(
                "DROP INDEX IF EXISTS discoveredhost_unique_current_belief;"
            ),
        ),
    ]
