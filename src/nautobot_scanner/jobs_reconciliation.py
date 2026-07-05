"""IPAM reconciliation CSV Job.

Emits the same :class:`ReconciliationReport` the standalone view and the
per-Scan tab already surface, but delivered as a downloadable CSV
artifact on the resulting JobResult. Scheduling is handled by Nautobot's
built-in job scheduler (weekly / nightly runs surface stale IPAM the
same way).

Class-only. The registration step (adding to
``jobs.py``'s ``jobs = [...]`` list and to ``register_jobs(*jobs)``) is
deferred to the main-branch integration commit — this file exists so
tests and future integrations import from a stable location.
"""

from __future__ import annotations

from datetime import datetime

from django.utils import timezone
from nautobot.apps.jobs import BooleanVar, ChoiceVar, Job, StringVar

from nautobot_scanner.reconciliation import build_reconciliation, groups_to_csv


class ReconciliationReport(Job):
    """Emit an IPAM reconciliation CSV as a JobResult artifact.

    Runs the same query engine (:func:`build_reconciliation`) the view
    surfaces use, so the CSV rows are byte-for-byte the same shape the
    UI shows. That's a deliberate contract: operators bounce between
    the tab, the standalone rollup, and the CSV, and the row semantics
    have to line up across all three.
    """

    scope = ChoiceVar(
        choices=[
            ("rfc1918", "RFC1918 only"),
            ("all", "All ranges"),
        ],
        default="rfc1918",
        description=(
            "Scope filter. RFC1918-only is the safe default; 'all' includes "
            "public ranges which are almost never actionable for a "
            "reconciliation report."
        ),
    )
    include_stale_ipam = BooleanVar(
        default=False,
        description=(
            "Also include the inverse direction — IPAM IPAddress records "
            "that no live host has ever matched at the anchor time."
        ),
    )
    as_of = StringVar(
        required=False,
        default="",
        description=(
            "ISO-8601 recording-time anchor; empty = current beliefs. "
            "Pass an earlier datetime (e.g. 2026-06-01T00:00:00) to "
            "reproduce the report as it appeared then."
        ),
    )

    class Meta:
        """Nautobot Job runner metadata."""

        name = "IPAM Reconciliation Report"
        description = (
            "Emit a CSV artifact listing undocumented live hosts (and "
            "optionally stale IPAM records) grouped by containing "
            "prefix, ranked by anti-noise signal."
        )
        has_sensitive_variables = False
        commit_default = True

    def run(self, scope="rfc1918", include_stale_ipam=False, as_of=""):
        """Compute the reconciliation, serialize to CSV, attach as artifact.

        Behavior on unparseable ``as_of``: fall back to current beliefs
        with a warning. Two rationales:

        1. Scheduled runs shouldn't fail on cosmetic bad input — the
           point of the Job is that operators get a fresh CSV in their
           inbox regardless of what got typed into the scheduled-run
           form six months ago.
        2. Empty string and unparseable are semantically the same
           ("give me what you can figure out"), so treating them the
           same way is the least-surprise choice.
        """
        anchor: datetime | None = None
        if as_of:
            try:
                parsed = datetime.fromisoformat(as_of)
            except (TypeError, ValueError):
                self.logger.warning(
                    "Could not parse as_of=%r as ISO-8601; falling back to "
                    "current beliefs.",
                    as_of,
                )
            else:
                if parsed.tzinfo is None:
                    parsed = timezone.make_aware(
                        parsed, timezone.get_current_timezone(),
                    )
                anchor = parsed

        report = build_reconciliation(
            as_of=anchor,
            scope=scope,
            include_stale_ipam=include_stale_ipam,
        )
        csv_bytes = groups_to_csv(report)

        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        filename = f"reconciliation-{stamp}.csv"
        self.create_file(filename, csv_bytes)

        self.logger.info(
            "Reconciliation report: %d undocumented rows across %d "
            "prefixes; stale-IPAM=%s (%d rows).",
            report.total_rows,
            len(report.groups),
            include_stale_ipam,
            report.total_stale_rows,
        )
        return f"{report.total_rows} rows across {len(report.groups)} prefixes"
