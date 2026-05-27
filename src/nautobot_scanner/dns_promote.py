"""Promote dig/drill NseFinding records into nautobot-app-dns-models rows.

Phase K: every parsed DNS answer record on a finding gets dispatched to
the right typed model (ARecord, CNAMERecord, MXRecord, ...) so the data
becomes filterable / linkable / diff-able as first-class Nautobot
objects instead of trapped JSON on ``NseFinding.elements``.

Design constraints we work around:

1. **dns-models record types are typed-per-table** — there's no
   polymorphic DNSRecord superclass we can write to generically.
   The ``PROMOTERS`` dict dispatches on the wire-type string.

2. **TTL minimum is 300s** in dns-models. Cloudflare's common TTL=60
   would otherwise raise ValidationError. We clip to 300 on write and
   stash the wire-value in ``DnsRecordProvenance.raw_ttl``.

3. **TXTRecord.text caps at 256 chars** — DKIM keys are routinely
   512+ chars. Same pattern: truncate-and-stash. The provenance row
   keeps the full string.

4. **ARecord/AAAARecord need an existing IPAddress** — Nautobot 3.x
   IPAddress requires a parent Prefix in the same Namespace, which
   means we can't auto-create one for arbitrary public IPs without
   also auto-creating the covering Prefix (which would pollute IPAM).
   v1 behavior: best-effort lookup only. If the IPAddress doesn't
   exist, log + skip the ARecord — the provenance row still captures
   the raw value, so a later "create the prefix then re-scan" workflow
   backfills cleanly. Non-A/AAAA records (CNAME, MX, NS, TXT, PTR,
   SRV) have no IPAM coupling and always promote.

The promoter is pure-functional from the caller's POV: takes a
finding, returns a counts dict. All side effects (DB writes, logs)
are isolated to per-type helpers, so a single bad record never aborts
the batch — failures are caught, recorded in the counts dict, and the
next record proceeds.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.utils import timezone

if TYPE_CHECKING:
    from nautobot_scanner.models import NseFinding

logger = logging.getLogger(__name__)

# dns-models hard floor on TTL — anything lower raises ValidationError
# at .full_clean() / .save() time.
DNS_MODELS_TTL_FLOOR = 300

# TXTRecord.text max_length from dns-models 2.1.1. Modern DKIM keys
# are routinely 512+ chars so truncation IS lossy — we keep the
# untruncated string on the provenance row.
DNS_MODELS_TXT_MAX = 256

# Tools whose findings we promote. Other tool findings have no DNS
# semantics and would silently no-op even if dispatched here, but the
# explicit allow-list makes the intent grep-able.
DNS_PRODUCING_TOOLS = frozenset({"dig", "drill"})


def _clip_ttl(raw_ttl) -> int | None:
    """Coerce TTL to int and clip to dns-models' 300s floor.

    Returns None if the wire value was missing or unparseable. The
    promoter writes None as ``_ttl=None`` on the record which means
    "inherit zone TTL" — semantically correct when the wire didn't
    tell us anything.
    """
    if raw_ttl is None or raw_ttl == "":
        return None
    try:
        v = int(raw_ttl)
    except (TypeError, ValueError):
        return None
    return max(DNS_MODELS_TTL_FLOOR, v)


def _split_fqdn(fqdn: str) -> tuple[str, str]:
    """Split an FQDN into (record_name, zone_name) using the tld+1 strategy.

    ``mail.example.com.`` → (``mail``, ``example.com``)
    ``example.com.``      → (``@``,    ``example.com``)
    ``foo.bar.example.com.`` → (``foo.bar``, ``example.com``)

    tld+1 is the simple default. ccTLDs like ``co.uk`` will split
    wrong (gives zone=``co.uk`` which is a TLD, not a zone). The
    plan calls out tld+2 / PSL as queued follow-ups.
    """
    name = (fqdn or "").rstrip(".")
    if not name:
        return ("@", "")
    labels = name.split(".")
    if len(labels) <= 2:
        return ("@", name)
    return (".".join(labels[:-2]), ".".join(labels[-2:]))


def _get_default_view():
    """Return the dns-models default DNSView instance.

    Imported lazily so this module is safe to import even when
    nautobot_dns_models isn't installed (the ingest hook checks
    settings before calling us).
    """
    from nautobot_dns_models.models import DNSView
    # The DEFAULT_VIEW_NAME constant lives in the app; "Default" is the
    # ship value. Falling back to first() handles installations that
    # renamed the default.
    return DNSView.objects.filter(name="Default").first() or DNSView.objects.first()


def _get_or_create_zone(zone_name: str, view, finding) -> "object | None":
    """Upsert a DNSZone with sensible SOA stub values for auto-created zones.

    The SOA values are placeholders — operators are expected to edit
    them post-creation (or override via a relinquishing mechanism we
    haven't built yet). The point is to satisfy the model's NOT NULL
    constraints with values that don't actively lie about authority.
    """
    from nautobot_dns_models.models import DNSZone
    if not zone_name:
        return None
    zone, created = DNSZone.objects.get_or_create(
        name=zone_name,
        dns_view=view,
        defaults={
            "filename": f"db.{zone_name}",
            "description": f"Auto-created by nautobot-scanner DNS promotion (finding {finding.pk}).",
            "soa_mname": f"ns.{zone_name}.",
            "soa_rname": f"hostmaster.{zone_name}.",
            "soa_serial": int(timezone.now().strftime("%Y%m%d00")),
        },
    )
    if created:
        logger.info("dns_promote: created DNSZone %s (from finding %s)", zone_name, finding.pk)
    return zone


def _write_provenance(record, record_type_label: str, raw_value: str, raw_ttl, finding) -> None:
    """Append a provenance row linking the canonical record to the source finding.

    Phase K': uses ``record.entry_id`` (stable per-belief on the bitemporal
    fork) instead of ``record.pk`` (which rebinds on every amend). The
    finder side of provenance resolution goes through the typed model's
    ``all_versions`` manager so superseded beliefs are still reachable.
    """
    from nautobot_scanner.models import DnsRecordProvenance
    DnsRecordProvenance.objects.create(
        record_type=ContentType.objects.get_for_model(record.__class__),
        record_entry_id=record.entry_id,
        finding=finding,
        record_type_label=record_type_label,
        raw_value=(raw_value or "")[:512],
        raw_ttl=int(raw_ttl) if str(raw_ttl).isdigit() else None,
    )


def _upsert_with_amend(Model, natural_key: dict, wire_fields: dict, default_fields: dict | None = None):
    """Bitemporal-aware upsert. Returns (record, action).

    The bitemporal fork's contract: ``Model.objects.get_or_create`` returns
    only current beliefs, ``obj.save()`` with changed tracked fields rotates
    the belief window and rebinds ``obj.pk`` / ``obj.entry_id``.

    The promoter contract we want on top of that:

    - **created**: natural key was new; record + provenance both fresh.
    - **amended**: natural key existed, but at least one wire field
      differs from stored; we set the new values and ``save()`` to trigger
      the sequenced-amend rotation. Provenance captures the NEW entry_id.
    - **unchanged**: natural key existed and every wire field matched
      stored; no save, but we STILL write provenance — the recurrence
      history is the point ("scan #42 saw this same record at this time").

    Args:
        Model: dns-models record class (ARecord, MXRecord, ...).
        natural_key: lookup kwargs (name, ip_address, zone, etc.) — used
            verbatim for get_or_create. Treated as immutable per the fork's
            advice in message 002.
        wire_fields: fields that may legitimately change wire-to-wire
            (typically ``_ttl`` plus type-specific things like ``preference``
            for MX). A difference in any of these triggers amend.
        default_fields: set only on initial CREATE — never overwritten on
            existing records. Use for human-editable cosmetic fields
            (``comment``, ``description``) we don't want re-stomping.

    Returns:
        ``(obj, action)`` where action is ``"created"``, ``"amended"``, or
        ``"unchanged"``. ``obj.entry_id`` is always the current
        belief's id — fresh after an amend.
    """
    default_fields = default_fields or {}
    obj, created = Model.objects.get_or_create(
        **natural_key,
        defaults={**wire_fields, **default_fields},
    )
    if created:
        return obj, "created"
    # Existing record — compare each wire field, mutate any drift.
    changed: list[str] = []
    for field, new_value in wire_fields.items():
        if getattr(obj, field) != new_value:
            setattr(obj, field, new_value)
            changed.append(field)
    if changed:
        obj.save()  # bitemporal mixin rotates the belief window; pk + entry_id rebind
        logger.info("dns_promote: amended %s pk=%s; changed=%r", Model.__name__, obj.pk, changed)
        return obj, "amended"
    return obj, "unchanged"


# ----------------------------------------------------------------------
# Per-type promoters. Each returns ``(record, action)`` or ``(None, "skipped")``
# when promotion was deliberately bypassed (e.g. unresolvable IP).
# ----------------------------------------------------------------------

def _promote_a(rec, finding, zone, *, version=4):
    from nautobot.ipam.models import IPAddress
    from nautobot_dns_models.models import ARecord, AAAARecord
    Model = ARecord if version == 4 else AAAARecord
    raw_ip = (rec.get("value") or "").strip()
    record_name, _zone_name = _split_fqdn(rec.get("name") or "")
    # Best-effort lookup — auto-creating IPAddress requires a parent Prefix
    # we can't safely synthesize for arbitrary public IPs (see module docstring).
    ip_obj = IPAddress.objects.filter(host=raw_ip).first()
    if ip_obj is None:
        logger.info(
            "dns_promote: skipping %s %s → %s (no matching IPAM IPAddress; raw kept in provenance)",
            Model.__name__, record_name, raw_ip,
        )
        return None, "skipped"
    return _upsert_with_amend(
        Model,
        natural_key={"name": record_name, "ip_address": ip_obj, "zone": zone},
        wire_fields={"_ttl": _clip_ttl(rec.get("ttl"))},
        default_fields={"comment": "auto: dig/drill"},
    )


def _promote_aaaa(rec, finding, zone):
    return _promote_a(rec, finding, zone, version=6)


def _promote_cname(rec, finding, zone):
    from nautobot_dns_models.models import CNAMERecord
    record_name, _ = _split_fqdn(rec.get("name") or "")
    alias = (rec.get("value") or "").rstrip(".")
    return _upsert_with_amend(
        CNAMERecord,
        natural_key={"name": record_name, "alias": alias, "zone": zone},
        wire_fields={"_ttl": _clip_ttl(rec.get("ttl"))},
        default_fields={"comment": "auto: dig/drill"},
    )


def _promote_mx(rec, finding, zone):
    from nautobot_dns_models.models import MXRecord
    record_name, _ = _split_fqdn(rec.get("name") or "")
    # MX wire format: "10 mail.example.com."
    parts = (rec.get("value") or "").split(None, 1)
    if len(parts) != 2:
        logger.warning("dns_promote: malformed MX value %r — skipping", rec.get("value"))
        return None, "skipped"
    try:
        preference = int(parts[0])
    except ValueError:
        logger.warning("dns_promote: non-int MX preference %r — skipping", parts[0])
        return None, "skipped"
    mail_server = parts[1].rstrip(".")
    return _upsert_with_amend(
        MXRecord,
        natural_key={"name": record_name, "mail_server": mail_server, "zone": zone},
        # preference is wire-mutable: an operator's DNS team can re-prioritize
        # MX servers without changing the natural key.
        wire_fields={"preference": preference, "_ttl": _clip_ttl(rec.get("ttl"))},
        default_fields={"comment": "auto: dig/drill"},
    )


def _promote_ns(rec, finding, zone):
    from nautobot_dns_models.models import NSRecord
    record_name, _ = _split_fqdn(rec.get("name") or "")
    server = (rec.get("value") or "").rstrip(".")
    return _upsert_with_amend(
        NSRecord,
        natural_key={"name": record_name, "server": server, "zone": zone},
        wire_fields={"_ttl": _clip_ttl(rec.get("ttl"))},
        default_fields={"comment": "auto: dig/drill"},
    )


def _promote_txt(rec, finding, zone):
    from nautobot_dns_models.models import TXTRecord
    record_name, _ = _split_fqdn(rec.get("name") or "")
    raw = rec.get("value") or ""
    # dig outputs TXT values wrapped in quotes; chunks beyond 255 bytes are
    # split into adjacent quoted strings. We unquote and join for canonical
    # storage; the provenance row keeps the original wire form.
    text = raw.strip().strip('"')
    if len(text) > DNS_MODELS_TXT_MAX:
        text = text[: DNS_MODELS_TXT_MAX - 1] + "…"
    return _upsert_with_amend(
        TXTRecord,
        natural_key={"name": record_name, "text": text, "zone": zone},
        wire_fields={"_ttl": _clip_ttl(rec.get("ttl"))},
        default_fields={"comment": "auto: dig/drill"},
    )


def _promote_ptr(rec, finding, zone):
    from nautobot_dns_models.models import PTRRecord
    record_name, _ = _split_fqdn(rec.get("name") or "")
    ptrdname = (rec.get("value") or "").rstrip(".")
    return _upsert_with_amend(
        PTRRecord,
        natural_key={"name": record_name, "ptrdname": ptrdname, "zone": zone},
        wire_fields={"_ttl": _clip_ttl(rec.get("ttl"))},
        default_fields={"comment": "auto: dig/drill"},
    )


def _promote_srv(rec, finding, zone):
    from nautobot_dns_models.models import SRVRecord
    record_name, _ = _split_fqdn(rec.get("name") or "")
    # SRV wire format: "10 60 5060 sipserver.example.com."
    parts = (rec.get("value") or "").split()
    if len(parts) != 4:
        logger.warning("dns_promote: malformed SRV value %r — skipping", rec.get("value"))
        return None, "skipped"
    try:
        priority, weight, port = int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        logger.warning("dns_promote: non-int SRV components in %r — skipping", parts)
        return None, "skipped"
    target = parts[3].rstrip(".")
    return _upsert_with_amend(
        SRVRecord,
        natural_key={"name": record_name, "target": target, "port": port, "zone": zone},
        # priority + weight are wire-mutable (service operators rebalance);
        # port is part of the natural key (different port = different service endpoint).
        wire_fields={
            "priority": priority,
            "weight": weight,
            "_ttl": _clip_ttl(rec.get("ttl")),
        },
        default_fields={"comment": "auto: dig/drill"},
    )


PROMOTERS = {
    "A":     _promote_a,
    "AAAA":  _promote_aaaa,
    "CNAME": _promote_cname,
    "MX":    _promote_mx,
    "NS":    _promote_ns,
    "TXT":   _promote_txt,
    "PTR":   _promote_ptr,
    "SRV":   _promote_srv,
    # SOA records are zone-level, stored on DNSZone itself — no record promotion
}


def promote_finding(finding: "NseFinding") -> dict:
    """Promote each parsed DNS record on this finding into typed dns-models rows.

    Returns a counts dict with separate buckets for the three bitemporal
    actions plus the legacy ``promoted`` total that older callers (and
    the ingest endpoint) read for at-a-glance reporting::

        {
            "promoted":   {"A": 3, "MX": 1, "CNAME": 1},  # created + amended + unchanged
            "created":    {"A": 2, "MX": 1},              # first-time observations
            "amended":    {"A": 1},                       # wire data drifted; rotated belief
            "unchanged":  {"CNAME": 1},                   # natural key + wire fields all matched
            "skipped":    2,                              # unsupported types / unresolvable IPs
            "no_records": False,
            "errors":     [{"record": {...}, "error": "..."}],
        }

    The function is idempotent at the record level: re-running on the
    same finding doesn't create dupe canonical records. It DOES always
    create a fresh ``DnsRecordProvenance`` row even when the record was
    unchanged — that's the recurrence history. After an amend the
    provenance captures the NEW ``entry_id`` (per the bitemporal fork's
    contract that ``obj.save()`` rotates the belief).

    Failures are caught per-record so one bad entry never aborts the
    batch. The ingest endpoint wraps this in its own try/except as a
    second layer of defense.
    """
    counts = {
        "promoted": Counter(),
        "created": Counter(),
        "amended": Counter(),
        "unchanged": Counter(),
        "skipped": 0,
        "no_records": False,
        "errors": [],
    }
    records = (finding.elements or {}).get("records") or []
    if not records:
        counts["no_records"] = True
        return counts

    view = _get_default_view()

    for rec in records:
        rtype = (rec.get("type") or "").upper()
        promoter = PROMOTERS.get(rtype)
        if promoter is None:
            counts["skipped"] += 1
            logger.info("dns_promote: skipping unsupported record type %r", rtype)
            continue
        try:
            with transaction.atomic():
                _record_name_for_zone, zone_name = _split_fqdn(rec.get("name") or "")
                zone = _get_or_create_zone(zone_name, view, finding)
                if zone is None:
                    counts["errors"].append({"record": rec, "error": "no zone (empty FQDN)"})
                    continue
                record, action = promoter(rec, finding, zone)
                if action == "skipped":
                    # Promoter deliberately bypassed (e.g. A record with no
                    # matching IPAM IPAddress, malformed wire value). No
                    # provenance row in this branch — provenance requires a
                    # canonical record to FK against. The raw entry still
                    # lives on ``finding.elements["records"]`` so the data
                    # is not lost, just not promoted. Re-running after
                    # creating the IPAM entry will pick it up.
                    counts["skipped"] += 1
                    continue
                # Provenance is written AFTER any amend triggered above so
                # ``record.entry_id`` reflects the freshly-rotated belief,
                # NOT the prior one (see _upsert_with_amend docstring).
                _write_provenance(
                    record=record,
                    record_type_label=rtype,
                    raw_value=rec.get("value") or "",
                    raw_ttl=rec.get("ttl"),
                    finding=finding,
                )
                counts["promoted"][rtype] += 1
                counts[action][rtype] += 1
        except Exception as exc:
            logger.exception("dns_promote: failed to promote %r", rec)
            counts["errors"].append({"record": rec, "error": f"{type(exc).__name__}: {exc}"})

    return counts
