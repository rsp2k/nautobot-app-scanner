"""Batch-promote DiscoveredPorts into ipam.Service rows from the CLI.

The scanner discovers open ports on hosts and records them as
``DiscoveredPort`` rows. When the parent host has been auto-linked to
a Device (via ``linked_device``), those ports are the raw material for
first-class ``ipam.Service`` records — the same shape you'd get from an
operator manually documenting "SSH runs on port 22 of this device."
This command sweeps the eligible set in one bounded pass.

Companion to ``bulk_promote_discovered_hosts`` (which fills the
``linked_ipaddress`` gap) and ``backfill_linked_ipaddress`` (which
retrofits existing rows). This one addresses the parallel gap on the
port side.

Usage:

    nautobot-server bulk_promote_discovered_ports                # dry-run
    nautobot-server bulk_promote_discovered_ports --confirm      # commit
    nautobot-server bulk_promote_discovered_ports --scan <uuid>  # per-scan
    nautobot-server bulk_promote_discovered_ports --device <name>

Design decisions worth calling out:

- **One Service per (device, protocol, port).** Nmap emits one row per
  (host, protocol, port); we mirror that at Service creation time
  rather than aggregating by service_name. An operator can merge
  multi-port Services later by editing the Service.ports array.
- **Idempotency via ports__contains lookup.** Before creating, check
  if any Service on that device+protocol already lists this port.
  Prevents duplicates when this command runs alongside manually-
  created Services or when re-run against the same eligible set.
- **Name derivation.** Prefer the nmap service_name (e.g. "ssh",
  "https") because that's the recognizable label. Fall back to
  ``<protocol>-<port>`` for cases where nmap couldn't identify it.
- **IP association.** If the parent DH has a linked_ipaddress, attach
  it to Service.ip_addresses. That's the second-order value of the
  earlier linked_ipaddress fix — Service records now carry both the
  Device *and* the specific IP the service was discovered on.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """Batch-promote DiscoveredPorts into ipam.Service records."""

    help = (
        "Batch-promote scanner DiscoveredPort rows into ipam.Service records "
        "for the parent DiscoveredHost's linked_device. Preview-safe by "
        "default; requires --confirm to actually write."
    )

    def add_arguments(self, parser):
        """Define CLI flags."""
        scope = parser.add_mutually_exclusive_group()
        scope.add_argument(
            "--scan",
            default=None,
            help=(
                "UUID of a single Scan to promote ports from. Mutually "
                "exclusive with --device."
            ),
        )
        scope.add_argument(
            "--device",
            default=None,
            help=(
                "Device name to scope promotion to (only ports on this "
                "one device get promoted). Mutually exclusive with --scan."
            ),
        )
        parser.add_argument(
            "--confirm",
            action="store_true",
            help=(
                "Explicit opt-in to actually write. Without this flag the "
                "command previews the promotion plan and exits without "
                "modifying any rows."
            ),
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help=(
                "Cap the number of distinct (device, protocol, port) "
                "tuples processed. Useful for a bounded first pass in "
                "production before a full sweep."
            ),
        )
        parser.add_argument(
            "--chunk-size",
            type=int,
            default=500,
            help=(
                "Number of DiscoveredPort rows to load per ORM iteration. "
                "Default 500 — keeps memory footprint bounded on databases "
                "with tens of thousands of scanner rows."
            ),
        )

    def handle(self, *args, **options):
        """Iterate eligible DiscoveredPorts, promote to ipam.Service."""
        # Deferred imports so `--help` works without app-ready.
        from nautobot.dcim.models import Device
        from nautobot.ipam.models import Service
        from nautobot_scanner.models import DiscoveredHost, DiscoveredPort

        confirm = options["confirm"]
        limit = options["limit"]
        chunk_size = options["chunk_size"]
        scan_pk = options["scan"]
        device_name = options["device"]

        # Base set — every DiscoveredPort in state=open on a
        # current-belief DiscoveredHost that has linked_device set.
        # We restrict to current beliefs so historical scans that no
        # longer reflect the live state don't spawn stale Services.
        current_dh_ids = DiscoveredHost.objects.current().filter(
            linked_device__isnull=False,
        )
        if scan_pk is not None:
            current_dh_ids = current_dh_ids.filter(scan_id=scan_pk)
        if device_name is not None:
            try:
                device = Device.objects.get(name=device_name)
            except Device.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Device {device_name!r} not found"))
                return
            current_dh_ids = current_dh_ids.filter(linked_device=device)

        current_dh_ids_list = list(current_dh_ids.values_list("pk", flat=True))
        eligible = DiscoveredPort.objects.filter(
            state="open",
            discovered_host_id__in=current_dh_ids_list,
        ).select_related("discovered_host", "discovered_host__linked_device", "discovered_host__linked_ipaddress")

        # Collapse to distinct (device, protocol, port) tuples — nmap
        # may report the same port on the same device across multiple
        # scans; each tuple → one Service.
        seen_tuples: set[tuple[str, str, int]] = set()
        plan: list[tuple[DiscoveredPort, str, list[str]]] = []
        walked = 0
        would_create = 0
        would_skip_exists = 0

        for dp in eligible.iterator(chunk_size=chunk_size):
            walked += 1
            dev = dp.discovered_host.linked_device
            key = (str(dev.pk), dp.protocol, int(dp.port))
            if key in seen_tuples:
                continue
            seen_tuples.add(key)
            if limit is not None and len(seen_tuples) > limit:
                break

            # Skip if a Service already covers this (device, protocol, port).
            # ports__contains=[port] matches any Service whose ports array
            # already includes this port number.
            already = Service.objects.filter(
                device=dev,
                protocol=dp.protocol,
                ports__contains=[int(dp.port)],
            ).exists()
            if already:
                would_skip_exists += 1
                continue

            # Name preference: nmap-identified service_name, else fallback.
            name = (dp.service_name or "").strip() or f"{dp.protocol}-{dp.port}"

            # Description: combine product / version / extra_info if any.
            desc_parts = [x for x in (dp.product, dp.version, dp.extra_info) if x]
            description = " ".join(desc_parts)[:200]  # Service.description is 200 chars

            plan.append((dp, name, [description]))
            would_create += 1

        self.stdout.write(f"Walked (open DPs on Device-linked DHs, current):  {walked}")
        self.stdout.write(f"Distinct (device, protocol, port) seen:            {len(seen_tuples)}")
        self.stdout.write(f"Already have a matching ipam.Service:              {would_skip_exists}")
        self.stdout.write(f"Would create:                                       {would_create}")

        # Sample the first 5 for eyeball verification.
        if plan:
            self.stdout.write("")
            self.stdout.write("Sample of first 5 planned Services:")
            for dp, name, desc_parts in plan[:5]:
                dev = dp.discovered_host.linked_device
                desc = desc_parts[0] or "-"
                self.stdout.write(
                    f"  {dev.name[:30]:30s}  {dp.protocol}/{dp.port:5d}  name={name!r:16s}  desc={desc!r}"
                )

        if not confirm:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(
                "Dry-run — no rows written. Re-run with --confirm to commit."
            ))
            return

        # Commit phase. One INSERT per Service. No transaction wrapper —
        # a partial run leaves whatever was already created intact and
        # a re-run picks up where this left off (idempotent).
        self.stdout.write("")
        self.stdout.write(f"Creating {len(plan)} Services…")
        created = 0
        for dp, name, desc_parts in plan:
            dev = dp.discovered_host.linked_device
            svc = Service.objects.create(
                device=dev,
                protocol=dp.protocol,
                ports=[int(dp.port)],
                name=name,
                description=desc_parts[0] or "",
            )
            # If the parent DiscoveredHost has a linked IPAddress, tie the
            # Service to it. That's what turns the Service from "runs on
            # this Device" into "runs on this Device at this specific IP".
            linked_ip = dp.discovered_host.linked_ipaddress
            if linked_ip is not None:
                svc.ip_addresses.add(linked_ip)
            created += 1

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Done. Created {created} ipam.Service records."
        ))
