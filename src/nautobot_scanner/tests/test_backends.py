"""Tests for nautobot_scanner.backends.

LocalBackend tests mock `subprocess.run` so we don't actually invoke
nmap during the test suite. The fixture XML from test_parser is
re-used as the simulated nmap stdout.
"""

from pathlib import Path
from unittest.mock import patch

from django.test import TestCase
from nautobot.extras.models import Status

from nautobot_scanner.backends import LocalBackend, RemoteBackend, get_backend
from nautobot_scanner.choices import AgentTypeChoices, ScanStateChoices, ScanTypeChoices, TimingTemplateChoices
from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

FIXTURES = Path(__file__).parent / "fixtures"


def _make_agent(name: str, agent_type: str) -> ScannerAgent:
    """Test helper — create a ScannerAgent with the Active status."""
    status = Status.objects.get(name="Active")
    return ScannerAgent.objects.create(name=name, agent_type=agent_type, status=status)


def _make_profile(name: str = "discovery") -> ScanProfile:
    return ScanProfile.objects.create(
        name=name,
        scan_type=ScanTypeChoices.DISCOVERY,
        nmap_arguments="-sn",
        timing_template=TimingTemplateChoices.T3,
    )


class TestGetBackendFactory(TestCase):
    """get_backend(agent) returns the right implementation."""

    def test_local_agent_returns_local_backend(self):
        agent = _make_agent("local-1", AgentTypeChoices.LOCAL)
        self.assertIsInstance(get_backend(agent), LocalBackend)

    def test_remote_agent_returns_remote_backend(self):
        agent = _make_agent("remote-1", AgentTypeChoices.REMOTE)
        self.assertIsInstance(get_backend(agent), RemoteBackend)


class TestLocalBackend(TestCase):
    """LocalBackend.dispatch executes nmap (mocked) and persists results."""

    def setUp(self):
        self.agent = _make_agent("local-test", AgentTypeChoices.LOCAL)
        self.profile = _make_profile()
        self.scan = Scan.objects.create(agent=self.agent, profile=self.profile)

    def _fake_completed_subprocess(self, xml_path: str):
        """Build a CompletedProcess-shaped object with our fixture XML as stdout."""
        from subprocess import CompletedProcess

        return CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout=(FIXTURES / xml_path).read_text(),
            stderr="",
        )

    def test_dispatch_with_no_targets_fails_cleanly(self):
        LocalBackend().dispatch(self.scan)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, ScanStateChoices.FAILED)
        self.assertIn("No targets", self.scan.error_message)

    @patch("nautobot_scanner.backends.local.subprocess.run")
    def test_dispatch_discovery_completes_and_creates_hosts(self, mock_run):
        from nautobot.ipam.models import IPAddress, Namespace, Prefix

        ns = Namespace.objects.get(name="Global")
        prefix_status = Status.objects.get(name="Active")
        ip_status = Status.objects.get(name="Active")
        # /24 wide enough to be parent for both the prefix-target hosts
        # AND the stray 192.0.2.10 IPAddress added below — Nautobot's
        # IPAddress.clean() requires a parent Prefix to exist.
        prefix = Prefix.objects.create(prefix="192.0.2.0/24", namespace=ns, status=prefix_status)
        self.scan.target_prefixes.add(prefix)
        ip = IPAddress.objects.create(address="192.0.2.10/32", namespace=ns, status=ip_status)
        self.scan.target_ipaddresses.add(ip)

        mock_run.return_value = self._fake_completed_subprocess("discovery.xml")

        LocalBackend().dispatch(self.scan)
        self.scan.refresh_from_db()

        self.assertEqual(self.scan.status, ScanStateChoices.COMPLETED)
        self.assertEqual(self.scan.hosts.count(), 3)
        self.assertEqual(self.scan.summary["hosts_up"], 2)
        self.assertEqual(self.scan.summary["hosts_down"], 1)
        # One-shot token cleared on success.
        self.assertIsNone(self.scan.ingestion_token)
        # Raw XML stored.
        self.assertTrue(self.scan.raw_xml.name)
        self.assertGreater(self.scan.raw_xml_size, 0)

    @patch("nautobot_scanner.backends.local.subprocess.run")
    def test_dispatch_nonzero_exit_marks_scan_failed(self, mock_run):
        from nautobot.ipam.models import Namespace, Prefix
        from subprocess import CompletedProcess

        ns = Namespace.objects.get(name="Global")
        prefix = Prefix.objects.create(
            prefix="192.0.2.0/24",
            namespace=ns,
            status=Status.objects.get(name="Active"),
        )
        self.scan.target_prefixes.add(prefix)

        mock_run.return_value = CompletedProcess(
            args=["nmap"],
            returncode=2,
            stdout="",
            stderr="Failed to resolve target",
        )

        LocalBackend().dispatch(self.scan)
        self.scan.refresh_from_db()

        self.assertEqual(self.scan.status, ScanStateChoices.FAILED)
        self.assertIn("nmap exited 2", self.scan.error_message)
        self.assertIn("Failed to resolve target", self.scan.error_message)

    @patch("nautobot_scanner.backends.local.subprocess.run")
    def test_dispatch_argv_includes_profile_args_timing_and_targets(self, mock_run):
        from nautobot.ipam.models import Namespace, Prefix

        ns = Namespace.objects.get(name="Global")
        prefix = Prefix.objects.create(
            prefix="192.0.2.0/24",
            namespace=ns,
            status=Status.objects.get(name="Active"),
        )
        self.scan.target_prefixes.add(prefix)
        self.profile.enabled_scripts = ["vulners", "http-title"]
        self.profile.save()

        mock_run.return_value = self._fake_completed_subprocess("discovery.xml")

        LocalBackend().dispatch(self.scan)

        argv = mock_run.call_args.args[0]
        # First arg = nmap binary
        self.assertEqual(argv[0], "/usr/bin/nmap")
        # XML to stdout
        self.assertIn("-oX", argv)
        self.assertIn("-", argv)
        # Profile args
        self.assertIn("-sn", argv)
        # Timing template
        self.assertIn("-T3", argv)
        # NSE scripts
        self.assertIn("--script", argv)
        self.assertIn("vulners,http-title", argv)
        # Target list
        self.assertIn("192.0.2.0/24", argv)


class TestRemoteBackend(TestCase):
    """RemoteBackend.dispatch flips state to pending and rotates the token."""

    def test_dispatch_sets_pending_and_token(self):
        agent = _make_agent("remote-test", AgentTypeChoices.REMOTE)
        profile = _make_profile("port-scan")
        scan = Scan.objects.create(agent=agent, profile=profile)
        original_token = scan.ingestion_token  # auto-set by model default

        RemoteBackend().dispatch(scan)
        scan.refresh_from_db()

        self.assertEqual(scan.status, ScanStateChoices.PENDING)
        self.assertIsNotNone(scan.started_at)
        # Token rotated (or set if it was None).
        self.assertIsNotNone(scan.ingestion_token)
        self.assertNotEqual(scan.ingestion_token, original_token)
