"""Tests for the ReconciliationReport CSV Job.

Instantiate the ``Job`` subclass directly and call ``.run(**kwargs)``.
``self.create_file`` requires a real ``JobResult`` when invoked through
Nautobot's full runner; we patch it to a spy so the tests can assert
what filename + bytes the Job asked to persist without wiring up the
Celery result plumbing.

Chosen behavior for invalid ``as_of``: **graceful fallback to current
beliefs** (with a logged warning). Rationale is in
``jobs_reconciliation.ReconciliationReport.run``'s docstring — scheduled
runs shouldn't fail on cosmetic bad input, and empty-string vs.
unparseable are semantically the same "figure out what you can" case.
Committed intent, not accident.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner.choices import (
    AgentTypeChoices,
    HostStateChoices,
    ScanTypeChoices,
    TimingTemplateChoices,
)
from nautobot_scanner.jobs_reconciliation import ReconciliationReport
from nautobot_scanner.models import DiscoveredHost, Scan, ScannerAgent, ScanProfile


class ReconciliationJobTests(TestCase):
    """End-to-end run() → CSV artifact test.

    Same fixture pattern as the engine tests (``test_reconciliation.py``):
    an agent, a profile, a completed scan, one prefix, one undocumented
    host, plus a documented control that should NOT appear in the output.
    """

    @classmethod
    def setUpTestData(cls):
        active = Status.objects.get(name="Active")
        cls.agent = ScannerAgent.objects.create(
            name="job-test",
            agent_type=AgentTypeChoices.LOCAL,
            status=active,
        )
        cls.profile = ScanProfile.objects.create(
            name="job-discovery",
            scan_type=ScanTypeChoices.DISCOVERY,
            nmap_arguments="-sn",
            timing_template=TimingTemplateChoices.T3,
        )
        cls.scan = Scan.objects.create(
            agent=cls.agent,
            profile=cls.profile,
            completed_at=timezone.now(),
        )
        cls.namespace = Namespace.objects.get(name="Global")
        Prefix.objects.create(
            prefix="192.168.55.0/24",
            namespace=cls.namespace,
            status=active,
            description="job test VLAN",
        )
        # Undocumented — should appear in the CSV.
        DiscoveredHost.objects.create(
            scan=cls.scan,
            ip_address="192.168.55.10",
            host_state=HostStateChoices.UP,
            hostname="undocumented-job-a",
        )
        # Documented — should NOT appear in the CSV.
        cls.documented_ip = IPAddress.objects.create(
            address="192.168.55.20/32",
            namespace=cls.namespace,
            status=active,
        )
        DiscoveredHost.objects.create(
            scan=cls.scan,
            ip_address="192.168.55.20",
            host_state=HostStateChoices.UP,
            hostname="documented",
        )
        cls.active = active

    def _instantiate_job(self):
        """Return a ReconciliationReport instance with ``create_file`` spied.

        The Job base's ``__init__`` doesn't need arguments; it wires
        ``self.logger`` from the task-logger factory. We patch
        ``create_file`` to a MagicMock so the test can assert what the
        run asked to persist without needing a real JobResult row.
        """
        job = ReconciliationReport()
        job.create_file = MagicMock(return_value=None)
        return job

    # ------------------------------------------------------------------

    def test_run_defaults_completes_without_exception(self):
        """Baseline: default kwargs succeed, artifact is CSV, return string matches shape."""
        job = self._instantiate_job()
        result = job.run(scope="rfc1918", include_stale_ipam=False, as_of="")

        job.create_file.assert_called_once()
        args, _kwargs = job.create_file.call_args
        filename, content = args[0], args[1]

        self.assertTrue(filename.endswith(".csv"),
                        f"Expected CSV filename, got {filename!r}")
        self.assertTrue(filename.startswith("reconciliation-"),
                        f"Expected 'reconciliation-' prefix, got {filename!r}")

        # Header row is fixed regardless of contents.
        first_line = content.split(b"\n", 1)[0].decode("utf-8")
        for expected in ("direction", "prefix", "ip_address"):
            self.assertIn(expected, first_line,
                          f"CSV header missing {expected!r}: {first_line!r}")

        # The undocumented host appears; the documented one does not.
        text = content.decode("utf-8")
        self.assertIn("192.168.55.10", text)
        self.assertNotIn("192.168.55.20", text)

        # Return-value shape: 'N rows across M prefixes'.
        self.assertRegex(result, r"\d+ rows across \d+ prefixes")

    def test_run_reports_expected_row_and_prefix_counts(self):
        """The return-value counts should line up with the fixture — 1 row, 1 prefix."""
        job = self._instantiate_job()
        result = job.run(scope="rfc1918", include_stale_ipam=False, as_of="")
        match = re.match(r"(\d+) rows across (\d+) prefixes", result)
        self.assertIsNotNone(match, f"Return value didn't match pattern: {result!r}")
        rows, prefixes = int(match.group(1)), int(match.group(2))
        self.assertEqual(rows, 1)
        self.assertEqual(prefixes, 1)

    def test_run_with_include_stale_ipam_true(self):
        """Stale-IPAM opt-in emits a second-direction section in the CSV."""
        # Extra IPAM record with no matching live host — this is the stale row.
        IPAddress.objects.create(
            address="192.168.55.99/32",
            namespace=self.namespace,
            status=self.active,
        )
        job = self._instantiate_job()
        job.run(scope="rfc1918", include_stale_ipam=True, as_of="")
        args, _ = job.create_file.call_args
        content = args[1].decode("utf-8")
        self.assertIn("stale_ipam", content,
                      "include_stale_ipam=True should emit the stale-IPAM direction.")
        self.assertIn("192.168.55.99", content)

    def test_invalid_as_of_falls_back_to_current_beliefs(self):
        """Cosmetically-bad ``as_of`` → warning + fallback, NOT an exception.

        Decision matches the docstring on ``ReconciliationReport.run``:
        scheduled runs shouldn't fail on unparseable input. A warning is
        emitted; the report is produced against current beliefs.
        """
        job = self._instantiate_job()
        # Stand up a logger spy so we can assert on the warning too.
        with patch.object(job, "logger") as spy_logger:
            result = job.run(
                scope="rfc1918",
                include_stale_ipam=False,
                as_of="not a datetime",
            )
        job.create_file.assert_called_once()
        self.assertRegex(result, r"\d+ rows across \d+ prefixes")
        # Assert we logged a warning about the unparseable input.
        warning_calls = [c for c in spy_logger.warning.call_args_list
                         if "as_of" in str(c) or "parse" in str(c)]
        self.assertTrue(
            warning_calls,
            "Expected a logger.warning about unparseable as_of input.",
        )

    def test_iso_as_of_is_accepted(self):
        """A well-formed ISO-8601 ``as_of`` shouldn't warn or error."""
        job = self._instantiate_job()
        anchor = timezone.now().isoformat()
        with patch.object(job, "logger") as spy_logger:
            result = job.run(
                scope="rfc1918",
                include_stale_ipam=False,
                as_of=anchor,
            )
        job.create_file.assert_called_once()
        self.assertRegex(result, r"\d+ rows across \d+ prefixes")
        # No parse warning expected on valid input.
        parse_warnings = [c for c in spy_logger.warning.call_args_list
                          if "parse" in str(c).lower() or "as_of" in str(c)]
        self.assertFalse(
            parse_warnings,
            f"Well-formed as_of shouldn't warn; got {parse_warnings!r}",
        )
