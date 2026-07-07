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
        #
        # Two sinks. The schema has a unique_device_service_name
        # constraint, so a "web server on ports 80 + 8080" case where
        # both ports fingerprint as 'http' must become one Service with
        # ports=[80, 8080], not two Services both named 'http'.
        #
        # - `plan_create` (dict keyed by (device_pk, name)) — a fresh
        #   Service row. Multiple ports with the same (device, name)
        #   collapse into one entry with a growing port list.
        # - `plan_append` — an existing Service (device, name) gets
        #   an additional port added to its ports array.
        seen_tuples: set[tuple[str, str, int]] = set()
        plan_create: dict[tuple[str, str], dict] = {}
        plan_append: list[tuple[Service, int]] = []
        walked = 0
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

            # Case 1: a Service with (device, name) already exists in the
            # DB — append our port to it.
            existing_same_name = Service.objects.filter(device=dev, name=name).first()
            if existing_same_name is not None:
                plan_append.append((existing_same_name, int(dp.port)))
                continue

            # Case 2: another port earlier in this same run is already
            # planning to create (device, name). Collapse: add our port
            # to that pending create's port list.
            plan_key = (str(dev.pk), name)
            if plan_key in plan_create:
                plan_create[plan_key]["ports"].add(int(dp.port))
                continue

            # Case 3: no collision — fresh planned create.
            desc_parts = [x for x in (dp.product, dp.version, dp.extra_info) if x]
            description = " ".join(desc_parts)[:200]  # Service.description is 200 chars
            plan_create[plan_key] = {
                "dp": dp,
                "device": dev,
                "protocol": dp.protocol,
                "name": name,
                "description": description,
                "ports": {int(dp.port)},
            }

        self.stdout.write(f"Walked (open DPs on Device-linked DHs, current):  {walked}")
        self.stdout.write(f"Distinct (device, protocol, port) seen:            {len(seen_tuples)}")
        self.stdout.write(f"Already have a matching ipam.Service:              {would_skip_exists}")
        self.stdout.write(f"Would create new Service:                           {len(plan_create)}")
        self.stdout.write(f"Would append port to existing (same-name) Service:  {len(plan_append)}")

        # Sample the first 5 planned creates for eyeball verification.
        create_list = list(plan_create.values())
        if create_list:
            self.stdout.write("")
            self.stdout.write("Sample of first 5 planned CREATES:")
            for entry in create_list[:5]:
                ports_sorted = sorted(entry["ports"])
                self.stdout.write(
                    f"  {entry['device'].name[:30]:30s}  {entry['protocol']}/{ports_sorted}  "
                    f"name={entry['name']!r:16s}  desc={(entry['description'] or '-')!r}"
                )
        if plan_append:
            self.stdout.write("")
            self.stdout.write("Sample of first 5 planned APPENDS:")
            for svc, port in plan_append[:5]:
                self.stdout.write(
                    f"  {svc.device.name[:30]:30s}  {svc.protocol}/{port:5d} → existing Service {svc.name!r} (currently ports={svc.ports})"
                )

        if not confirm:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(
                "Dry-run — no rows written. Re-run with --confirm to commit."
            ))
            return

        # Commit phase. Two loops:
        # 1. Appends: mutate existing Service.ports arrays (idempotent —
        #    a re-run wouldn't re-append because the port would already
        #    be in the list, hitting the ports__contains skip branch).
        # 2. Creates: insert new Service rows.
        # No transaction wrapper — a partial run's changes persist and
        # a re-run picks up where this left off.
        self.stdout.write("")
        appended = 0
        for svc, port in plan_append:
            if port not in svc.ports:
                svc.ports = sorted(set(svc.ports) | {port})
                svc.save(update_fields=["ports"])
                appended += 1

        created = 0
        for entry in create_list:
            svc = Service.objects.create(
                device=entry["device"],
                protocol=entry["protocol"],
                ports=sorted(entry["ports"]),
                name=entry["name"],
                description=entry["description"],
            )
            # If the parent DiscoveredHost has a linked IPAddress, tie the
            # Service to it. That's what turns the Service from "runs on
            # this Device" into "runs on this Device at this specific IP".
            linked_ip = entry["dp"].discovered_host.linked_ipaddress
            if linked_ip is not None:
                svc.ip_addresses.add(linked_ip)
            created += 1

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Done. Created {created} ipam.Service records, appended ports to {appended} existing Services."
        ))
