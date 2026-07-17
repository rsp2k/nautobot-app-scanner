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
        # -----------------------------------------------------------------
        # M.2.5 — Device auto-create flags. Optional; when omitted, the
        # command falls back to M.2's IPAddress-only promotion path.
        # -----------------------------------------------------------------
        parser.add_argument(
            "--create-devices",
            action="store_true",
            help=(
                "M.2.5: promote identified hosts into full dcim.Device "
                "rows (with Interface + IPAddress + Role assignment) "
                "rather than just IPAddress. Requires --location. "
                "Auto-creates Manufacturer + DeviceType + Role if "
                "they don't exist. Matches existing Devices by MAC / "
                "primary_ip4 to rename rather than duplicate (fixes "
                "MAC-named auto-created rows like the netmon-2 Axis "
                "pair from 2026-07-05)."
            ),
        )
        parser.add_argument(
            "--location",
            default=None,
            help=(
                "Nautobot Location name for auto-created Devices "
                "(required with --create-devices). Every Nautobot "
                "Device requires a Location — the fingerprint pipeline "
                "can't infer this from scan output, so the operator "
                "supplies it."
            ),
        )
        parser.add_argument(
            "--interface-name",
            default="eth0",
            help=(
                "Interface name to auto-create on new Devices. "
                "Default 'eth0'. Not used on the match-existing-Device "
                "path (existing Interfaces are preserved)."
            ),
        )

    def handle(self, *args, **options):
        """Iterate identifications, preview or commit per --confirm."""
        # Deferred imports so `--help` works before Django app-ready.
        from django.db import transaction
        from nautobot.dcim.models import Device, Interface, Location
        from nautobot.extras.models import Status
        from nautobot.ipam.models import IPAddress, Namespace
        from nautobot_scanner.fingerprint import (
            MAX_SCORE,
            VENDOR_CONFIDENCE_OVERRIDES,
            effective_confidence_threshold,
            fuse_all_undocumented,
            match_existing_device,
            resolve_or_create_device_type,
            resolve_or_create_role,
        )
        from nautobot_scanner.models import DiscoveredHost

        confirm = options["confirm"]
        confidence_threshold = options["confidence"]
        vendor_filter = options["vendor"]
        limit = options["limit"]
        namespace_name = options["namespace"]
        status_name = options["status"]
        create_devices = options["create_devices"]
        location_name = options["location"]
        interface_name = options["interface_name"]

        # --- Guardrail: --create-devices requires --location.
        if create_devices and not location_name:
            self.stdout.write(self.style.ERROR(
                "--create-devices requires --location <name>. Every "
                "Nautobot Device requires a Location; the fingerprint "
                "pipeline can't infer this from scan output."
            ))
            return

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

        # --- Resolve location for --create-devices.
        location = None
        if create_devices:
            try:
                location = Location.objects.get(name=location_name)
            except Location.DoesNotExist:
                self.stdout.write(self.style.ERROR(
                    f"Location {location_name!r} not found. Available "
                    f"locations: {list(Location.objects.values_list('name', flat=True)[:10])}"
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

        # M.3: Split above/below using PER-VENDOR effective threshold.
        # An Axis identification at 0.5 clears the 0.45 Axis threshold
        # even when the CLI --confidence is 0.7; a generic-Cisco
        # identification at 0.65 falls below the 0.7 Cisco threshold
        # even when --confidence is 0.6.
        above = [
            i for i in idents
            if i.confidence >= effective_confidence_threshold(i.vendor, confidence_threshold)
        ]
        below = [
            i for i in idents
            if i.confidence < effective_confidence_threshold(i.vendor, confidence_threshold)
        ]

        if limit is not None:
            above = above[:limit]

        self.stdout.write(
            f"Fusion window: {len(idents)} identifications considered"
            f" ({len(above)} above per-vendor threshold, {len(below)} below)"
        )
        self.stdout.write(f"Default threshold: {confidence_threshold}")
        if VENDOR_CONFIDENCE_OVERRIDES:
            overrides_str = ", ".join(
                f"{v}={t}" for v, t in sorted(VENDOR_CONFIDENCE_OVERRIDES.items())
            )
            self.stdout.write(f"Per-vendor overrides: {overrides_str}")
        self.stdout.write(f"Vendor filter:  {vendor_filter or '(none)'}")
        self.stdout.write(f"Namespace:      {namespace.name}")
        self.stdout.write(f"Status:         {status.name}")
        self.stdout.write(f"Create Devices: {create_devices}")
        if create_devices:
            self.stdout.write(f"Location:       {location.name}")
            self.stdout.write(f"Interface:      {interface_name}")
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
            mode_desc = (
                "creates/updates Device+Interface+IPAddress rows"
                if create_devices else
                "creates/links IPAddress rows only (pass --create-devices for full promotion)"
            )
            self.stdout.write(self.style.WARNING(
                f"Dry-run — no rows written. Re-run with --confirm to "
                f"process the above-threshold set. --confirm {mode_desc}."
            ))
            return

        # =================================================================
        # Commit path
        # =================================================================
        self.stdout.write("")
        if create_devices:
            self._commit_with_devices(
                above=above,
                namespace=namespace,
                status=status,
                location=location,
                interface_name=interface_name,
            )
        else:
            self._commit_ipaddress_only(
                above=above,
                namespace=namespace,
                status=status,
            )

    # ------------------------------------------------------------------
    # Commit helpers
    # ------------------------------------------------------------------

    def _commit_ipaddress_only(self, *, above, namespace, status):
        """M.2 legacy path — link IPAddress records with fusion metadata."""
        from nautobot.ipam.models import IPAddress
        from nautobot_scanner.models import DiscoveredHost

        self.stdout.write(f"Committing {len(above)} identifications (IPAddress only)…")
        created = 0
        linked_existing = 0
        skipped = 0

        for ident in above:
            host = DiscoveredHost.objects.filter(pk=ident.discovered_host_id).first()
            if host is None or host.linked_ipaddress_id is not None:
                skipped += 1
                continue

            ip_str = str(host.ip_address)
            mask = "/128" if ":" in ip_str else "/32"
            description = (
                f"Auto-identified as {ident.vendor} ({ident.device_type_hint}) "
                f"at confidence {ident.confidence:.3f}. "
                f"Signals: {','.join(s.signal for s in ident.signals)}. "
                f"scanner DH {ident.discovered_host_id[:8]}."
            )[:200]

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
                address=f"{ip_str}{mask}",
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
            f"skipped {skipped}."
        ))

    def _commit_with_devices(self, *, above, namespace, status, location, interface_name):
        """M.2.5 path — create/update Device+Interface+IPAddress atomically.

        For each identification:
          1. Look for an existing Device (by primary_ip4 or MAC) →
             rename + re-role rather than duplicate.
          2. Otherwise, auto-create Manufacturer + DeviceType + Role,
             then Device + Interface + IPAddress in one transaction.
        """
        from django.db import transaction
        from nautobot.dcim.models import Device, Interface
        from nautobot.ipam.models import IPAddress
        from nautobot_scanner.fingerprint import (
            match_existing_device,
            resolve_or_create_device_type,
            resolve_or_create_role,
        )
        from nautobot_scanner.models import DiscoveredHost

        self.stdout.write(f"Committing {len(above)} identifications (Devices + IPAddress)…")
        created_devices = 0
        updated_devices = 0
        skipped = 0
        no_role = 0

        for ident in above:
            host = DiscoveredHost.objects.filter(pk=ident.discovered_host_id).first()
            if host is None:
                skipped += 1
                continue
            if host.linked_device_id is not None:
                # Already promoted by another flow — respect.
                skipped += 1
                continue
            if ident.proposed_role is None:
                # No VENDOR_TO_ROLE mapping — surface but don't auto-create.
                no_role += 1
                continue

            proposed_name = (host.hostname or str(host.ip_address)).split(".", 1)[0]

            try:
                with transaction.atomic():
                    role = resolve_or_create_role(ident.proposed_role)
                    device_type = resolve_or_create_device_type(ident.vendor, ident.device_type_hint)

                    # --- Match-existing branch: rename + re-role.
                    existing_dev = match_existing_device(host)
                    if existing_dev is not None:
                        existing_dev.name = proposed_name
                        existing_dev.role = role
                        # Only update device_type when the current type
                        # is one of ours ("Auto-identified ..."). Leave
                        # operator-set DeviceTypes alone.
                        if "Auto-identified" in (existing_dev.device_type.model or ""):
                            existing_dev.device_type = device_type
                        existing_dev.save()
                        host.linked_device = existing_dev
                        host.save(update_fields=["linked_device"])
                        updated_devices += 1
                        continue

                    # --- Fresh Device path.
                    device = Device.objects.create(
                        name=proposed_name,
                        location=location,
                        role=role,
                        device_type=device_type,
                        status=status,
                    )

                    # IPAddress: reuse if already linked, otherwise
                    # lookup-or-create against the namespace.
                    if host.linked_ipaddress is not None:
                        ip = host.linked_ipaddress
                    else:
                        ip_str = str(host.ip_address)
                        mask = "/128" if ":" in ip_str else "/32"
                        ip = IPAddress.objects.filter(
                            parent__namespace=namespace,
                            host=ip_str,
                        ).first()
                        if ip is None:
                            ip = IPAddress.objects.create(
                                address=f"{ip_str}{mask}",
                                namespace=namespace,
                                status=status,
                                dns_name=host.hostname or "",
                                description=(
                                    f"Auto-identified as {ident.vendor} "
                                    f"({ident.device_type_hint}) at "
                                    f"confidence {ident.confidence:.3f}."
                                )[:200],
                            )

                    iface = Interface.objects.create(
                        device=device,
                        name=interface_name,
                        type="virtual",
                        mac_address=host.mac_address or None,
                        status=status,
                    )
                    ip.assigned_object = iface
                    ip.save()

                    if ":" in str(host.ip_address):
                        device.primary_ip6 = ip
                    else:
                        device.primary_ip4 = ip
                    device.save()

                    host.linked_ipaddress = ip
                    host.linked_device = device
                    host.save(update_fields=["linked_ipaddress", "linked_device"])
                    created_devices += 1
            except Exception as exc:
                # Fail-open per-row rather than aborting the batch on
                # one bad Identification. The next --confirm run picks
                # up whatever this one skipped.
                self.stdout.write(self.style.WARNING(
                    f"  skipped {ident.ip_address}: {exc}"
                ))
                skipped += 1
                continue

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Done. Created {created_devices} new Devices, "
            f"renamed/re-roled {updated_devices} existing, "
            f"skipped {skipped}, {no_role} had no role mapping."
        ))
