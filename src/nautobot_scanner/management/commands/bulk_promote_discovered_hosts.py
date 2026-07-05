"""Batch-promote DiscoveredHosts into ipam.IPAddress rows from the CLI.

Companion to the ``DiscoveredHostBulkPromoteView`` UI flow — same commit
logic, same defaults (namespace=Global, status=Provisional), but callable
from ``nautobot-server`` for the post-initial-import case where an
operator wants to sweep an entire scan's undocumented hosts into IPAM
without clicking through the preview page. The intended usage is:

    nautobot-server bulk_promote_discovered_hosts --all-current --dry-run
    nautobot-server bulk_promote_discovered_hosts --all-current --confirm

The two-flag design is deliberate. ``--dry-run`` (or NO flag at all) is
the safe default: the command counts + previews and touches no rows.
``--confirm`` is the explicit "yes, actually write" — required. Passing
neither refuses to run rather than silently doing nothing, because
silence would fool a caller who thinks "no output = job done."

Scope selection is mutually exclusive: pass ``--scan <uuid>`` OR
``--all-current``. Both feed into the shared
``build_reconciliation(...)`` engine that the UI + Job artifact use so
the CLI can never disagree with what the UI would have selected for the
same filter set.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


# The management command mirrors the view's defaults so the two entry
# points behave identically for a caller who inspects one and expects
# the other to match.
DEFAULT_NAMESPACE_NAME = "Global"
DEFAULT_STATUS_NAME = "Provisional"


class Command(BaseCommand):
    """Batch-promote DiscoveredHosts into ipam.IPAddress records."""

    help = (
        "Batch-promote scanner DiscoveredHost rows into ipam.IPAddress records. "
        "Preview-safe by default; requires --confirm to actually write."
    )

    def add_arguments(self, parser):
        """Define CLI flags."""
        scope = parser.add_mutually_exclusive_group()
        scope.add_argument(
            "--scan",
            default=None,
            help=(
                "UUID of a single Scan to promote hosts from. Mutually exclusive with "
                "--all-current."
            ),
        )
        scope.add_argument(
            "--all-current",
            action="store_true",
            help=(
                "Promote every currently-believed live DiscoveredHost that "
                "isn't already linked to an IPAddress. Mutually exclusive "
                "with --scan."
            ),
        )
        parser.add_argument(
            "--namespace",
            default=DEFAULT_NAMESPACE_NAME,
            help=(
                f"IPAM namespace to create the IPAddress rows in. "
                f"Default: {DEFAULT_NAMESPACE_NAME!r}."
            ),
        )
        parser.add_argument(
            "--status",
            default=DEFAULT_STATUS_NAME,
            help=(
                f"extras.Status name to stamp on the new IPAddresses. "
                f"Default: {DEFAULT_STATUS_NAME!r} — the seeded 'pending "
                f"validation' marker. Pass --status Active to skip the "
                f"trust-but-verify step."
            ),
        )
        parser.add_argument(
            "--scope",
            default="rfc1918",
            choices=["rfc1918", "all"],
            help=(
                "Prefix scope filter passed to the reconciliation engine. "
                "'rfc1918' (default) restricts to 10/8, 172.16/12, "
                "192.168/16 — the correct answer for almost every "
                "operator. 'all' includes public + reserved ranges too."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=(
                "Preview-only. Prints the candidate rows and exits without "
                "writing. Required for a first pass; combine with --confirm "
                "on a second invocation to commit."
            ),
        )
        parser.add_argument(
            "--confirm",
            action="store_true",
            help=(
                "Explicit opt-in to actually write. Without this flag "
                "(regardless of --dry-run) the command refuses to modify "
                "the database. Split from --dry-run so a caller who "
                "forgets both flags sees a helpful error instead of a "
                "silent no-op."
            ),
        )

    def handle(self, *args, **options):
        """Run the reconciliation query, print a preview, and optionally commit."""
        # Deferred imports so the module can be imported for `--help` without
        # a Django app-ready cycle.
        from nautobot.extras.models import Status
        from nautobot.ipam.models import Namespace

        from nautobot_scanner import reconciliation
        from nautobot_scanner.models import DiscoveredHost, Scan

        scan_uuid = options.get("scan")
        all_current = options.get("all_current")
        namespace_name = options["namespace"]
        status_name = options["status"]
        scope = options["scope"]
        dry_run = options["dry_run"]
        confirm = options["confirm"]

        # ---- Guardrail: must pass --dry-run OR --confirm ------------------
        # This is the "silence would fool the caller" check called out in the
        # module docstring. `--dry-run --confirm` is legal (the doc'd
        # two-step); passing neither is refused.
        if not (dry_run or confirm):
            raise CommandError(
                "Refusing to run without --dry-run or --confirm. Pass --dry-run "
                "for a safe preview, or --confirm to commit. Passing both is "
                "the doc'd two-invocation flow: --dry-run first, --confirm on "
                "the second pass once the preview looks right.",
            )

        # ---- Scope must be picked exactly once ---------------------------
        if not scan_uuid and not all_current:
            raise CommandError(
                "Must pass exactly one of --scan <uuid> or --all-current.",
            )

        # ---- Resolve namespace + status ------------------------------------
        try:
            namespace = Namespace.objects.get(name=namespace_name)
        except Namespace.DoesNotExist as e:
            raise CommandError(
                f"Namespace {namespace_name!r} not found. Available: "
                f"{list(Namespace.objects.values_list('name', flat=True))!r}",
            ) from e
        try:
            status = Status.objects.get(name=status_name)
        except Status.DoesNotExist as e:
            raise CommandError(
                f"Status {status_name!r} not found. Ensure the seeded "
                f"'Provisional' status exists (migration 0023) or pass --status Active.",
            ) from e

        # ---- Resolve scan (if any) --------------------------------------
        scan = None
        if scan_uuid:
            try:
                scan = Scan.objects.get(pk=scan_uuid)
            except Scan.DoesNotExist as e:
                raise CommandError(f"Scan with UUID {scan_uuid!r} not found.") from e

        # ---- Preview via the shared engine -------------------------------
        report = reconciliation.build_reconciliation(scope=scope, scan=scan)
        total = report.total_rows
        self.stdout.write(self.style.NOTICE(
            f"Reconciliation preview — {total} undocumented host(s) across "
            f"{len(report.groups)} prefix bucket(s)."
        ))
        for group in report.groups:
            self.stdout.write("")
            self.stdout.write(self.style.NOTICE(
                f"  Prefix {group.prefix} — {len(group.rows)} candidate(s) "
                f"(rank_signal={group.rank_signal:.3f})"
            ))
            for row in group.rows[:5]:
                hostname = row.hostname or "(no PTR)"
                self.stdout.write(
                    f"    {row.ip_address:<20} {hostname}  scan={row.seen_in_scan_id}"
                )
            if len(group.rows) > 5:
                self.stdout.write(
                    f"    ... and {len(group.rows) - 5} more"
                )

        # ---- Bail if this was a preview-only run -------------------------
        if not confirm:
            self.stdout.write("")
            self.stdout.write(self.style.NOTICE(
                "Dry run — no rows written. Re-run with --confirm to commit."
            ))
            return

        # ---- Commit ------------------------------------------------------
        # We collect the actual host queryset directly (not from the report)
        # because the report has already collapsed hosts into rows for
        # rendering, but the write path needs the ORM rows to link back to.
        # Scope + linked_ipaddress filters mirror the engine's query so the
        # committed set matches the preview count exactly.
        hosts_qs = (
            DiscoveredHost.objects.current()
            .filter(host_state="up")
            .filter(linked_ipaddress__isnull=True)
        )
        if scan is not None:
            hosts_qs = hosts_qs.filter(scan=scan)

        # Restrict to IPs the engine actually returned so the CLI can't
        # drift out of sync with the preview. The engine already applied
        # scope + IPAM-exclusion + prefix-containment filtering.
        candidate_ips = {row.ip_address for group in report.groups for row in group.rows}
        hosts = [h for h in hosts_qs if str(h.ip_address) in candidate_ips]

        promoted, skipped = self._commit(hosts, namespace=namespace, status=status)

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Promoted {len(promoted)} host(s) into {namespace.name!r} with "
            f"status {status.name!r}. Skipped {skipped} host(s) already linked."
        ))

    def _commit(self, hosts, *, namespace, status):
        """Same commit shape as ``DiscoveredHostBulkPromoteView._commit``.

        Purposefully duplicated (not imported) so this command survives if
        the view module gets restructured. Keeps the CLI a first-class
        entry point — it doesn't degrade when a view refactor breaks
        imports.
        """
        # Deferred so this module imports cleanly at `--help` time.
        from nautobot.ipam.models import IPAddress

        promoted: list = []
        skipped = 0
        with transaction.atomic():
            for host in hosts:
                if host.linked_ipaddress_id is not None:
                    skipped += 1
                    continue
                ip_str = str(host.ip_address)
                mask = "/128" if ":" in ip_str else "/32"
                new_ip = IPAddress.objects.create(
                    address=f"{ip_str}{mask}",
                    namespace=namespace,
                    status=status,
                    dns_name=host.hostname or "",
                    description=(
                        f"Bulk-promoted (mgmt command) from scanner "
                        f"DiscoveredHost {host.pk} (scan {host.scan_id})"
                    ),
                )
                host.linked_ipaddress = new_ip
                host.save(update_fields=["linked_ipaddress"])
                promoted.append((host, new_ip))
        return promoted, skipped
