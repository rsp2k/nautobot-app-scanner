"""Retrofit ``DiscoveredHost.linked_ipaddress`` from existing IPAM.

The scan-ingest path in ``parser.persist()`` gained a linked_ipaddress
auto-resolver in the same commit as this file. That resolver only fires
on new scans — every DiscoveredHost row already in the database keeps
``linked_ipaddress=NULL`` even if IPAM already contained a matching
``ipam.IPAddress`` at scan time.

This command sweeps existing rows: for each unlinked DiscoveredHost,
look up an IPAddress at the same host, and wire the FK if found. The
result is an idempotent, safe retrofit — re-runs converge on the same
state, and rows the operator manually linked stay untouched.

Usage:

    nautobot-server backfill_linked_ipaddress                # dry-run
    nautobot-server backfill_linked_ipaddress --confirm      # actually write

Same two-flag design as the sibling ``bulk_promote_discovered_hosts``
command — a caller who forgets ``--confirm`` sees a preview count and
the row-by-row match plan, not silence.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """Set DiscoveredHost.linked_ipaddress on rows that have a matching IPAM record."""

    help = (
        "Retrofit DiscoveredHost.linked_ipaddress on existing rows where the "
        "scan-ingest auto-linker hadn't run yet. Preview-safe by default; "
        "requires --confirm to actually write."
    )

    def add_arguments(self, parser):
        """Define CLI flags."""
        parser.add_argument(
            "--confirm",
            action="store_true",
            help=(
                "Explicit opt-in to actually write. Without this flag the "
                "command previews the retrofit count + a sample of matches "
                "and exits without modifying any rows."
            ),
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help=(
                "Cap the number of rows to process. Useful for a bounded "
                "first pass in production before a full sweep."
            ),
        )
        parser.add_argument(
            "--chunk-size",
            type=int,
            default=500,
            help=(
                "Number of rows to load per ORM iteration. Default 500 — "
                "keeps memory footprint bounded on databases with tens of "
                "thousands of DiscoveredHost rows."
            ),
        )

    def handle(self, *args, **options):
        """Iterate unlinked DiscoveredHosts, look up matching IPAM rows, retrofit."""
        # Deferred imports so `--help` works before Django app-ready.
        from nautobot.ipam.models import IPAddress
        from nautobot_scanner.models import DiscoveredHost

        confirm = options["confirm"]
        limit = options["limit"]
        chunk_size = options["chunk_size"]

        # Only consider current beliefs — historical rows stay historical.
        # An operator inspecting "what was undocumented on 2026-03-01?"
        # wants the answer as it looked then, not retroactively rewritten.
        candidates = DiscoveredHost.objects.current().filter(
            linked_ipaddress__isnull=True,
        ).order_by("scan__completed_at", "ip_address")

        total_candidates = candidates.count()
        self.stdout.write(f"Candidates (linked_ipaddress IS NULL): {total_candidates}")
        if total_candidates == 0:
            self.stdout.write(self.style.SUCCESS("Nothing to backfill."))
            return

        if limit is not None:
            candidates = candidates[:limit]
            self.stdout.write(f"Limited to first {limit} rows.")

        # First pass — walk once to build the match plan. Keep it in memory
        # so we can print a preview before any write. The candidate set is
        # bounded by `limit` so this is safe even on wide fleets.
        matched: list[tuple[str, str, str]] = []  # (host_pk, ip, target_ipaddress_pk)
        no_match = 0
        walked = 0

        for host in candidates.iterator(chunk_size=chunk_size):
            walked += 1
            match = IPAddress.objects.filter(host=str(host.ip_address)).first()
            if match is None:
                no_match += 1
                continue
            matched.append((str(host.pk), str(host.ip_address), str(match.pk)))

        self.stdout.write("")
        self.stdout.write(f"Walked:            {walked}")
        self.stdout.write(f"Would link:        {len(matched)}")
        self.stdout.write(f"No IPAM match:     {no_match}  (still promotion candidates)")

        # Sample the first 5 matches for eyeball verification.
        if matched:
            self.stdout.write("")
            self.stdout.write("Sample matches (first 5):")
            for host_pk, ip, target_pk in matched[:5]:
                self.stdout.write(f"  DiscoveredHost {host_pk[:8]}...  {ip:16s}  →  IPAddress {target_pk[:8]}...")

        if not confirm:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(
                "Dry-run — no rows written. Re-run with --confirm to commit."
            ))
            return

        # Commit phase. One UPDATE per matched host — trivial write cost,
        # no atomic wrapper needed because each update is independent and
        # a partial failure just leaves the rest un-linked (safe: another
        # run picks them up).
        self.stdout.write("")
        self.stdout.write(f"Committing {len(matched)} updates…")
        updated = 0
        for host_pk, _ip, target_pk in matched:
            DiscoveredHost.objects.filter(pk=host_pk).update(linked_ipaddress_id=target_pk)
            updated += 1

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(f"Done. Linked {updated} DiscoveredHost rows to existing IPAM records."))
