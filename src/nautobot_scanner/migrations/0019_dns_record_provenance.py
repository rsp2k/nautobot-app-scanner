"""Create DnsRecordProvenance — the source-of-truth log for Phase K.

Phase K hooks dig/drill findings into nautobot-app-dns-models, promoting
each parsed answer record into a typed dns-models row (ARecord, MXRecord,
etc.). This migration adds the sidecar table that links those records
back to the source NseFinding and preserves the raw wire values
(particularly TTL and TXT length) that upstream dns-models clips.

No schema changes to existing tables — purely additive.
"""

import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    """Add DnsRecordProvenance."""

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("nautobot_scanner", "0018_seed_phase_j_profiles"),
    ]

    operations = [
        migrations.CreateModel(
            name="DnsRecordProvenance",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                ("record_id", models.UUIDField(db_index=True)),
                (
                    "observed_at",
                    models.DateTimeField(db_index=True, default=django.utils.timezone.now),
                ),
                ("record_type_label", models.CharField(max_length=16)),
                ("raw_value", models.CharField(max_length=512)),
                ("raw_ttl", models.PositiveIntegerField(blank=True, null=True)),
                (
                    "finding",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="dns_promotions",
                        to="nautobot_scanner.nsefinding",
                    ),
                ),
                (
                    "record_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="contenttypes.contenttype",
                    ),
                ),
            ],
            options={
                "verbose_name": "DNS record provenance",
                "verbose_name_plural": "DNS record provenances",
                "ordering": ("-observed_at",),
                "indexes": [
                    models.Index(
                        fields=["record_type", "record_id", "-observed_at"],
                        name="dnsprov_record_recent_idx",
                    ),
                ],
            },
        ),
    ]
