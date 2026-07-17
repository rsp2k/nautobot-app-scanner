"""Dispatch httpx probe against the current reconciliation-undocumented set.

Phase M.0 of the fingerprint pipeline: read the same target list the
IPAM Reconciliation surface displays (DiscoveredHosts with no
``linked_device`` AND no ``linked_ipaddress``), and dispatch a
single ``http-probe-rich`` scan against those IPs. The resulting
``NseFinding`` rows carry the httpx JSONL — status, title, server
header, tech-detect, TLS cert, favicon MMH3 — the signal the later
fusion module (M.2) will score for device identity.

The command **never probes documented devices**. That's the load-
bearing operational rule from the design brief — HTTP access logs
on already-in-IPAM gear would create SOC noise on every run.
Restricting to the reconciliation output makes the workflow bounded
and self-shrinking (each successful promote removes a host from the
next target set).

Usage:

    nautobot-server http_fingerprint_undocumented                        # dry-run
    nautobot-server http_fingerprint_undocumented --confirm              # dispatch
    nautobot-server http_fingerprint_undocumented --confirm --limit 50   # bounded first pass
    nautobot-server http_fingerprint_undocumented --confirm --prefix 10.1.3.0/24
    nautobot-server http_fingerprint_undocumented --confirm --cooldown-hours 0  # force re-scan
    nautobot-server http_fingerprint_undocumented --confirm --profile my-httpx-variant

Same ``--dry-run`` default / ``--confirm`` gate shape as the sibling
``bulk_promote_discovered_hosts``, ``backfill_linked_ipaddress``, and
``bulk_promote_discovered_ports`` commands. A caller who forgets
``--confirm`` sees the target list preview and exits without
dispatching.
"""

from __future__ import annotations

import ipaddress as ipmod

from django.core.management.base import BaseCommand


DEFAULT_PROFILE_NAME = "http-probe-rich"


class Command(BaseCommand):
    """Dispatch an httpx scan against undocumented DiscoveredHosts."""

    help = (
        "Dispatch httpx against the current reconciliation-undocumented set "
        "(DiscoveredHosts with no linked_device AND no linked_ipaddress). "
        "Preview-safe by default; requires --confirm to actually dispatch."
    )

    def add_arguments(self, parser):
        """Define CLI flags."""
        parser.add_argument(
            "--confirm",
            action="store_true",
            help=(
                "Explicit opt-in to actually create a Scan record and "
                "dispatch it through the agent. Without this flag the "
                "command prints the target list and exits."
            ),
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help=(
                "Cap the number of target IPs. Useful for a bounded first "
                "pass — start with 50 targets to eyeball the httpx output "
                "before running against the full undocumented set."
            ),
        )
        parser.add_argument(
            "--prefix",
            default=None,
            help=(
                "CIDR to scope targets to (e.g. '10.1.3.0/24'). Only "
                "undocumented hosts inside this prefix are dispatched. "
                "Phased-rollout use case: start with the CAMERAS_NEW /24, "
                "then widen."
            ),
        )
        parser.add_argument(
            "--cooldown-hours",
            type=int,
            default=24,
            help=(
                "Skip hosts touched by an httpx or snmp-info NseFinding "
                "within this many hours. Default 24 — prevents operator-"
                "error re-runs from doubling up scan traffic on the same "
                "target. Pass 0 to disable (forces re-scan of every "
                "undocumented host)."
            ),
        )
        parser.add_argument(
            "--profile",
            default=DEFAULT_PROFILE_NAME,
            help=(
                f"ScanProfile name to dispatch. Default: "
                f"{DEFAULT_PROFILE_NAME!r} (the httpx JSONL rich-field "
                f"profile seeded by migration 0022). Override to use a "
                f"custom httpx profile — e.g. one with a shorter --timeout."
            ),
        )
        parser.add_argument(
            "--agent",
            default=None,
            help=(
                "Agent name to dispatch through. Defaults to the first "
                "agent alphabetically (matches the ScanPrefix Job "
                "convention)."
            ),
        )

    def handle(self, *args, **options):
        """Resolve targets, preview, optionally dispatch."""
        # Deferred imports so `--help` works before Django app-ready.
        from nautobot_scanner.backends import get_backend
        from nautobot_scanner.fingerprint import resolve_undocumented_targets
        from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

        confirm = options["confirm"]
        limit = options["limit"]
        prefix_str = options["prefix"]
        cooldown_hours = options["cooldown_hours"]
        profile_name = options["profile"]
        agent_name = options["agent"]

        # --- Resolve the profile up front so a misspelled name errors
        #     before we do any target-set work.
        try:
            profile = ScanProfile.objects.get(name=profile_name)
        except ScanProfile.DoesNotExist:
            self.stdout.write(self.style.ERROR(
                f"ScanProfile {profile_name!r} does not exist. "
                f"Available httpx profiles: "
                f"{list(ScanProfile.objects.filter(tool='httpx').values_list('name', flat=True))}"
            ))
            return

        if profile.tool != "httpx":
            self.stdout.write(self.style.ERROR(
                f"Profile {profile_name!r} uses tool={profile.tool!r}, not 'httpx'. "
                f"Refusing to dispatch — this command is httpx-specific."
            ))
            return

        # --- Build the optional prefix filter as a queryset transform.
        scope_filter = None
        if prefix_str is not None:
            try:
                network = ipmod.ip_network(prefix_str, strict=False)
            except ValueError as exc:
                self.stdout.write(self.style.ERROR(f"Invalid --prefix: {exc}"))
                return
            # Filter in Python after the initial queryset returns — the
            # DiscoveredHost.ip_address field is a CharField/GenericIP,
            # not a proper inet type, so we can't push the containment
            # into SQL. Cost is bounded by the undocumented set size (~1k).
            def _in_prefix(qs):
                current_ids = []
                for h in qs.only("pk", "ip_address"):
                    try:
                        if ipmod.ip_address(str(h.ip_address)) in network:
                            current_ids.append(h.pk)
                    except ValueError:
                        continue
                return qs.filter(pk__in=current_ids)
            scope_filter = _in_prefix

        targets = resolve_undocumented_targets(
            scope_filter=scope_filter,
            cooldown_hours=cooldown_hours,
        )

        if limit is not None:
            targets = targets[:limit]

        self.stdout.write(f"Profile:             {profile.name!r} (tool={profile.tool})")
        self.stdout.write(f"Prefix scope:        {prefix_str or '(all)'}")
        self.stdout.write(f"Cooldown:            {cooldown_hours}h "
                         f"({'disabled' if cooldown_hours == 0 else 'recent httpx/snmp findings excluded'})")
        self.stdout.write(f"Undocumented targets: {len(targets)}"
                         + (f"  (limited from full set to {limit})" if limit is not None else ""))

        if not targets:
            self.stdout.write(self.style.SUCCESS(
                "Nothing to probe — the reconciliation set is empty at this scope."
            ))
            return

        # Sample the first 5 for eyeball verification.
        self.stdout.write("")
        self.stdout.write("First 5 targets:")
        for ip in targets[:5]:
            self.stdout.write(f"  {ip}")

        if not confirm:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(
                "Dry-run — no Scan dispatched. Re-run with --confirm to fire."
            ))
            return

        # --- Resolve the agent.
        if agent_name is not None:
            try:
                agent = ScannerAgent.objects.get(name=agent_name)
            except ScannerAgent.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Agent {agent_name!r} not found."))
                return
        else:
            agent = ScannerAgent.objects.order_by("name").first()
            if agent is None:
                self.stdout.write(self.style.ERROR(
                    "No ScannerAgent records exist. Create one before dispatching."
                ))
                return

        # --- Create the Scan and dispatch it.
        # was_pentest_mode=False: httpx doesn't emit pentest-class traffic
        # (no exploit attempts, no credential guessing). The scanner's
        # pentest gate stays off for this profile.
        scan = Scan.objects.create(
            agent=agent,
            profile=profile,
            target_raw_ips=targets,
            was_pentest_mode=False,
        )
        self.stdout.write("")
        self.stdout.write(f"Created Scan {scan.pk} with {len(targets)} raw-IP targets.")
        self.stdout.write(f"Dispatching via agent {agent.name!r} ({agent.agent_type})…")

        backend = get_backend(agent)
        backend.dispatch(scan)
        scan.refresh_from_db()

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Done. Scan {scan.pk} status={scan.status!r}, summary={scan.summary!r}"
        ))
        self.stdout.write(f"Review at /plugins/scanner/scans/{scan.pk}/")
