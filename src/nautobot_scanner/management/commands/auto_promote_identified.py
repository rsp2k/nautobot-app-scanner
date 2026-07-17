"""Auto-promote DiscoveredHosts based on fingerprint fusion output.

Phase M.2 of the fingerprint pipeline. Consumes the ``Identification``
records produced by ``fingerprint.fuse_signals()`` — one per currently-
undocumented DiscoveredHost — and promotes those clearing the
``--confidence`` threshold.

**Scope decision (M.2 lean cut):** this command promotes identified
hosts into ``ipam.IPAddress`` records with the identification
metadata stamped in the description + tags. Full ``dcim.Device``
auto-creation is deferred to a follow-up phase (M.2.5) because it
requires Location + DeviceType inputs that the fingerprint pipeline
can't invent — the operator supplies those, then M.2.5 wires them
into the auto-promote flow. In the meantime, the preview surface
(``--dry-run``) is the primary M.2 value: operators see the fusion
output, review confidence scores, and manually promote via the
existing UI flow.

Usage:

    nautobot-server auto_promote_identified                             # preview all
    nautobot-server auto_promote_identified --confidence 0.7            # preview >=0.7
    nautobot-server auto_promote_identified --confidence 0.7 --confirm  # link IPAddresses
    nautobot-server auto_promote_identified --vendor Uniview            # preview Uniview only
    nautobot-server auto_promote_identified --limit 20                  # bounded first pass

Sibling to ``bulk_promote_discovered_hosts``, ``backfill_linked_ipaddress``,
``http_fingerprint_undocumented``, and ``snmp_recon_undocumented``.
Same ``--dry-run`` default / ``--confirm`` gate shape.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand


DEFAULT_NAMESPACE_NAME = "Global"
DEFAULT_STATUS_NAME = "Provisional"
DEFAULT_CONFIDENCE_THRESHOLD = 0.7


class Command(BaseCommand):
    """Auto-promote fingerprint-identified DiscoveredHosts."""

    help = (
        "Compute Identification for each currently-undocumented "
        "DiscoveredHost via the fingerprint fusion module, then "
        "propose or commit IPAddress promotion for identifications "
        "meeting --confidence. Preview-safe by default."
    )

    def add_arguments(self, parser):
        """Define CLI flags."""
        parser.add_argument(
            "--confidence",
            type=float,
            default=DEFAULT_CONFIDENCE_THRESHOLD,
            help=(
                f"Only propose promotes for identifications with "
                f"confidence >= this threshold. Default "
                f"{DEFAULT_CONFIDENCE_THRESHOLD}. Lower values (0.4-0.6) "
                f"widen the surface but include weaker matches; higher "
                f"(0.85+) restricts to near-certain identifications. "
                f"Preview mode (--dry-run) still shows sub-threshold "
                f"identifications so the operator can eyeball where "
                f"the fusion is landing."
            ),
        )
        parser.add_argument(
            "--vendor",
            default=None,
            help=(
                "Filter to a single vendor (e.g. 'Uniview', 'Axis'). "
                "Case-sensitive match against Identification.vendor. "
                "Useful for phased rollout — promote all Uniview "
                "cameras first, then Axis, etc."
            ),
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help=(
                "Cap the number of identifications processed. Useful "
                "for a bounded first --confirm pass in production."
            ),
        )
        parser.add_argument(
            "--namespace",
            default=DEFAULT_NAMESPACE_NAME,
            help=(
                f"IPAM namespace for auto-created IPAddress rows. "
                f"Default: {DEFAULT_NAMESPACE_NAME!r}."
            ),
        )
        parser.add_argument(
            "--status",
            default=DEFAULT_STATUS_NAME,
            help=(
                f"extras.Status name for auto-created IPAddress rows. "
                f"Default: {DEFAULT_STATUS_NAME!r} — the seeded 'pending "
                f"validation' marker."
            ),
        )
        parser.add_argument(
            "--confirm",
            action="store_true",
            help=(
                "Explicit opt-in to actually write. Without this flag "
                "the command prints the identification preview and "
                "exits without modifying any rows."
            ),
        )

    def handle(self, *args, **options):
        """Iterate identifications, preview or commit per --confirm."""
        # Deferred imports so `--help` works before Django app-ready.
        from nautobot.extras.models import Status
        from nautobot.ipam.models import IPAddress, Namespace
        from nautobot_scanner.fingerprint import (
            MAX_SCORE,
            fuse_all_undocumented,
        )
        from nautobot_scanner.models import DiscoveredHost

        confirm = options["confirm"]
        confidence_threshold = options["confidence"]
        vendor_filter = options["vendor"]
        limit = options["limit"]
        namespace_name = options["namespace"]
        status_name = options["status"]

        # --- Validate the target namespace + status up front.
        try:
            namespace = Namespace.objects.get(name=namespace_name)
        except Namespace.DoesNotExist:
            self.stdout.write(self.style.ERROR(
                f"Namespace {namespace_name!r} not found."
            ))
            return
        try:
            status = Status.objects.get(name=status_name)
        except Status.DoesNotExist:
            self.stdout.write(self.style.ERROR(
                f"Status {status_name!r} not found. Run migration 0023 "
                f"if you're expecting the Provisional status."
            ))
            return

        # --- Compute identifications for every undocumented host.
        # Use min_confidence=0.0 so preview mode shows every attempt.
        # We do our own threshold filter here so --dry-run stays
        # observability-friendly.
        idents = list(fuse_all_undocumented(min_confidence=0.0))

        # Vendor filter
        if vendor_filter is not None:
            idents = [i for i in idents if i.vendor == vendor_filter]

        # Sort: high confidence first, then by IP for reproducibility.
        idents.sort(key=lambda i: (-i.confidence, i.ip_address))

        # Split into above-threshold (candidates for --confirm) and below.
        above = [i for i in idents if i.confidence >= confidence_threshold]
        below = [i for i in idents if i.confidence < confidence_threshold]

        if limit is not None:
            above = above[:limit]

        self.stdout.write(
            f"Fusion window: {len(idents)} identifications considered"
            f" ({len(above)} at/above {confidence_threshold}, {len(below)} below)"
        )
        self.stdout.write(f"Vendor filter:  {vendor_filter or '(none)'}")
        self.stdout.write(f"Namespace:      {namespace.name}")
        self.stdout.write(f"Status:         {status.name}")
        self.stdout.write(f"MAX_SCORE:      {MAX_SCORE}")

        # --- Preview: top 20 above-threshold identifications.
        if above:
            self.stdout.write("")
            self.stdout.write("Above-threshold candidates (top 20):")
            self.stdout.write(
                f"  {'confidence':10s}  {'vendor':10s}  {'ip':16s}  {'role':20s}  {'signals'}"
            )
            for ident in above[:20]:
                signals_str = ",".join(f"{s.signal}(+{s.weight})" for s in ident.signals)
                role = ident.proposed_role or "(no mapping)"
                self.stdout.write(
                    f"  {ident.confidence:>10.3f}  {ident.vendor[:10]:10s}  "
                    f"{ident.ip_address[:16]:16s}  {role[:20]:20s}  {signals_str[:60]}"
                )

        # --- Peek at sub-threshold surface too, so the operator can
        #     eyeball whether to lower the threshold. Show up to 5.
        if below:
            self.stdout.write("")
            self.stdout.write(f"Sub-threshold surface (below {confidence_threshold}, top 5):")
            for ident in below[:5]:
                signals_str = ",".join(s.signal for s in ident.signals) or "(no signals)"
                self.stdout.write(
                    f"  {ident.confidence:>10.3f}  {(ident.vendor or '?')[:10]:10s}  "
                    f"{ident.ip_address[:16]:16s}  {signals_str[:60]}"
                )

        if not above:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(
                f"No identifications at or above --confidence "
                f"{confidence_threshold}. Try a lower threshold or "
                f"dispatch more httpx/snmp probes first."
            ))
            return

        if not confirm:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(
                "Dry-run — no rows written. Re-run with --confirm to "
                "link IPAddress records for the above-threshold set. "
                "Note: full Device auto-create is deferred to M.2.5; "
                "--confirm here only creates/links IPAddress rows and "
                "stamps fingerprint metadata in the description."
            ))
            return

        # --- Commit path: create IPAddress with identification metadata.
        # We reuse the idempotent lookup-then-create pattern from
        # views_bulk_promote._commit() — if an IPAddress at (namespace,
        # host_ip) already exists, we link to it rather than raising on
        # the (parent_id, host) unique constraint.
        self.stdout.write("")
        self.stdout.write(f"Committing {len(above)} identifications…")
        created = 0
        linked_existing = 0
        skipped = 0

        for ident in above:
            host = DiscoveredHost.objects.filter(pk=ident.discovered_host_id).first()
            if host is None:
                skipped += 1
                continue
            # If bulk-promote already set linked_ipaddress after this run
            # started, respect that.
            if host.linked_ipaddress_id is not None:
                skipped += 1
                continue

            ip_str = str(host.ip_address)
            mask = "/128" if ":" in ip_str else "/32"
            address = f"{ip_str}{mask}"

            description = (
                f"Auto-identified as {ident.vendor} ({ident.device_type_hint}) "
                f"at confidence {ident.confidence:.3f}. "
                f"Signals: {','.join(s.signal for s in ident.signals)}. "
                f"scanner DH {ident.discovered_host_id[:8]}."
            )[:200]  # IPAddress.description is CharField(200)

            existing = IPAddress.objects.filter(
                parent__namespace=namespace,
                host=ip_str,
            ).first()
            if existing is not None:
                host.linked_ipaddress = existing
                host.save(update_fields=["linked_ipaddress"])
                linked_existing += 1
                continue

            new_ip = IPAddress.objects.create(
                address=address,
                namespace=namespace,
                status=status,
                dns_name=host.hostname or "",
                description=description,
            )
            host.linked_ipaddress = new_ip
            host.save(update_fields=["linked_ipaddress"])
            created += 1

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Done. Created {created} new IPAddress rows, "
            f"linked to {linked_existing} pre-existing, "
            f"skipped {skipped} (concurrent-promoted or missing)."
        ))
        self.stdout.write(
            f"Full Device auto-create (with role assignment) is queued "
            f"for M.2.5 — meantime, review the promoted IPAddresses "
            f"and use the existing 'Promote to Device' UI action to "
            f"finish the promotion with the operator's chosen "
            f"Location + DeviceType."
        )
