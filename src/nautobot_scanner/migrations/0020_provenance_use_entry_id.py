"""Rename DnsRecordProvenance.record_id → record_entry_id (Phase K').

The bitemporal fork of nautobot-app-dns-models (>= 2.1.2) rebinds the
canonical record's ``pk`` on every sequenced-amend save. Storing ``pk``
in our provenance row was wrong from the start — after one amend, a
GenericForeignKey would silently follow the successor and we'd lose the
"this is the exact belief we observed at scan time" identity.

The fork's ``BitemporalMixin.entry_id`` is stable for one belief row's
lifetime, so we re-target the provenance FK to entry_id. Column rename
only — no data migration needed because 0019 only just shipped and the
provenance table is empty in dev.

The matching ``dnsprov_record_recent_idx`` index also gets recreated
against the new column name.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Rename record_id → record_entry_id and re-target the lookup index."""

    dependencies = [
        ("nautobot_scanner", "0019_dns_record_provenance"),
    ]

    operations = [
        # Drop the old index first — RenameField won't recreate indexes
        # automatically when the column they reference is renamed.
        migrations.RemoveIndex(
            model_name="dnsrecordprovenance",
            name="dnsprov_record_recent_idx",
        ),
        migrations.RenameField(
            model_name="dnsrecordprovenance",
            old_name="record_id",
            new_name="record_entry_id",
        ),
        migrations.AddIndex(
            model_name="dnsrecordprovenance",
            index=models.Index(
                fields=["record_type", "record_entry_id", "-observed_at"],
                name="dnsprov_record_recent_idx",
            ),
        ),
    ]
