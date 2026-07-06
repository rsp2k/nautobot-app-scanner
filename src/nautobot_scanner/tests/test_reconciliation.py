"""Tests for nautobot_scanner.reconciliation.

The engine is a pure function over the ORM — tests build DiscoveredHost
+ IPAddress + Prefix rows via factories, then assert on the returned
dataclass shapes. No Playwright, no HTTP layer.

Test targets, mapped to the four things the engine promises:

1. Base diff shape — live host with no matching IPAM lands in ``groups``.
2. Anti-noise ranking — sparse-but-real prefix sorts ABOVE phantom-full.
3. Scope + exclusion filters — RFC1918 accepts 10/172.16/192.168 and
   rejects everything else; ``exclude_reserved=True`` drops 6to4 relay,
   TEST-NET, benchmarking, multicast, reserved-future.
4. Bitemporal ``as_of`` — historic anchor returns historic-belief rows.

Plus a stale-IPAM opt-in test and a CSV round-trip smoke.
"""

from __future__ import annotations

import datetime as _dt
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner.choices import AgentTypeChoices, HostStateChoices, ScanTypeChoices, TimingTemplateChoices
from nautobot_scanner.models import DiscoveredHost, Scan, ScannerAgent, ScanProfile
from nautobot_scanner.reconciliation import (
    ReconciliationGroup,
    ReconciliationReport,
    ReconciliationRow,
    _is_reserved,
    _is_rfc1918,
    build_reconciliation,
    groups_to_csv,
)


class ReconciliationTestBase(TestCase):
    """Shared fixture: an agent, a profile, one completed scan, and a Namespace.

    Individual tests add DiscoveredHost / Prefix / IPAddress rows on top.
    """

    @classmethod
    def setUpTestData(cls):
        active = Status.objects.get(name="Active")
        cls.agent = ScannerAgent.objects.create(
            name="recon-test", agent_type=AgentTypeChoices.LOCAL, status=active,
        )
        cls.profile = ScanProfile.objects.create(
            name="recon-discovery",
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
        cls.active = active

    def _make_host(self, ip: str, state: str = HostStateChoices.UP, hostname: str = "",
                   mac: str = "", os_family: str = "", scan=None):
        """Create a DiscoveredHost. Defaults produce an up-host with no IPAM link."""
        return DiscoveredHost.objects.create(
            scan=scan or self.scan,
            ip_address=ip,
            host_state=state,
            hostname=hostname,
            mac_address=mac,
            os_family=os_family,
        )

    def _make_prefix(self, cidr: str, role_name: str = "", description: str = ""):
        """Create a Prefix in the default Namespace with the given CIDR."""
        return Prefix.objects.create(
            prefix=cidr,
            namespace=self.namespace,
            status=self.active,
            description=description,
        )


class TestClassifierHelpers(TestCase):
    """The ``_is_rfc1918`` and ``_is_reserved`` helpers are the anti-noise
    heart of the engine — worth locking down before wiring the ORM."""

    def test_rfc1918_accepts_10_slash_8(self):
        import ipaddress
        self.assertTrue(_is_rfc1918(ipaddress.ip_network("10.0.0.0/8")))
        self.assertTrue(_is_rfc1918(ipaddress.ip_network("10.42.0.0/16")))

    def test_rfc1918_accepts_172_16_slash_12(self):
        import ipaddress
        self.assertTrue(_is_rfc1918(ipaddress.ip_network("172.16.0.0/12")))
        self.assertTrue(_is_rfc1918(ipaddress.ip_network("172.20.5.0/24")))

    def test_rfc1918_accepts_192_168_slash_16(self):
        import ipaddress
        self.assertTrue(_is_rfc1918(ipaddress.ip_network("192.168.0.0/16")))
        self.assertTrue(_is_rfc1918(ipaddress.ip_network("192.168.42.0/24")))

    def test_rfc1918_rejects_globals(self):
        import ipaddress
        self.assertFalse(_is_rfc1918(ipaddress.ip_network("8.8.8.0/24")))
        self.assertFalse(_is_rfc1918(ipaddress.ip_network("192.88.99.0/24")))

    def test_reserved_flags_6to4_relay(self):
        import ipaddress
        # The specific phantom-noise case from the feature request.
        self.assertTrue(_is_reserved(ipaddress.ip_network("192.88.99.0/24")))

    def test_reserved_flags_test_nets(self):
        import ipaddress
        for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
            self.assertTrue(_is_reserved(ipaddress.ip_network(cidr)),
                            f"{cidr} should be reserved")

    def test_reserved_does_not_flag_ordinary_rfc1918(self):
        import ipaddress
        # Real subnets should pass through.
        self.assertFalse(_is_reserved(ipaddress.ip_network("192.168.1.0/24")))
        self.assertFalse(_is_reserved(ipaddress.ip_network("10.10.10.0/24")))


class TestUndocumentedDirection(ReconciliationTestBase):
    """The core question: live host with no ipam.IPAddress → in groups."""

    def test_undocumented_host_lands_in_report(self):
        prefix = self._make_prefix("192.168.42.0/24", description="Test VLAN")
        self._make_host("192.168.42.10", hostname="undocumented-a")

        report = build_reconciliation()

        self.assertEqual(report.total_rows, 1)
        self.assertEqual(len(report.groups), 1)
        group = report.groups[0]
        self.assertEqual(group.prefix, "192.168.42.0/24")
        self.assertEqual(len(group.rows), 1)
        self.assertEqual(group.rows[0].ip_address, "192.168.42.10")
        self.assertEqual(group.rows[0].hostname, "undocumented-a")

    def test_host_with_existing_ipam_is_filtered_out(self):
        prefix = self._make_prefix("192.168.42.0/24")
        # IP that IS in IPAM — should be excluded from the report.
        IPAddress.objects.create(address="192.168.42.20/32", namespace=self.namespace,
                                 status=self.active)
        self._make_host("192.168.42.20", hostname="already-in-ipam")
        # IP that is NOT in IPAM — should appear.
        self._make_host("192.168.42.21", hostname="not-yet")

        report = build_reconciliation()
        self.assertEqual(report.total_rows, 1)
        self.assertEqual(report.groups[0].rows[0].ip_address, "192.168.42.21")

    def test_host_marked_down_is_excluded(self):
        self._make_prefix("192.168.42.0/24")
        self._make_host("192.168.42.30", hostname="down-host", state=HostStateChoices.DOWN)
        report = build_reconciliation()
        self.assertEqual(report.total_rows, 0)

    def test_host_with_linked_ipaddress_is_excluded(self):
        # linked_ipaddress means the operator already promoted this row.
        self._make_prefix("192.168.42.0/24")
        ip = IPAddress.objects.create(address="192.168.42.40/32", namespace=self.namespace,
                                      status=self.active)
        host = self._make_host("192.168.42.40")
        host.linked_ipaddress = ip
        host.save()

        report = build_reconciliation()
        self.assertEqual(report.total_rows, 0)


class TestAntiNoiseRanking(ReconciliationTestBase):
    """The load-bearing anti-noise property: sparse-but-real sorts above phantom-full.

    This is the specific case bingham-ops flagged — one device ARP-answering
    for the entire 6to4 block shouldn't drown a real clinical VLAN with 12
    genuinely-undocumented hosts.
    """

    def test_sparse_real_sorts_above_dense_phantom(self):
        # Real clinical VLAN: 12 hosts in a /24 (~0.047 ratio)
        self._make_prefix("192.168.10.0/24", description="clinical")
        for i in range(1, 13):
            self._make_host(f"192.168.10.{i}", hostname=f"med-{i}")

        # Phantom /24 (still RFC1918 to make it comparable):
        # a single device ARP-answering for the full /24 (1.0 ratio).
        # 254 hosts in the same /24.
        self._make_prefix("192.168.99.0/24", description="phantom")
        for i in range(1, 255):
            self._make_host(f"192.168.99.{i}", hostname=f"phantom-{i}")

        report = build_reconciliation()

        self.assertEqual(len(report.groups), 2)
        first, second = report.groups
        self.assertEqual(first.prefix, "192.168.10.0/24",
                         "Sparse-but-real should rank first (lowest ratio)")
        self.assertEqual(second.prefix, "192.168.99.0/24",
                         "Phantom-full should rank last (highest ratio)")
        self.assertLess(first.rank_signal, second.rank_signal)


class TestScopeFilter(ReconciliationTestBase):
    """rfc1918 vs. all — controls which prefixes appear."""

    def test_rfc1918_rejects_public_ranges(self):
        # Public /24 — should NOT appear in rfc1918 scope.
        self._make_prefix("8.8.8.0/24", description="Google DNS")
        self._make_host("8.8.8.9")

        report = build_reconciliation(scope="rfc1918")
        self.assertEqual(report.total_rows, 0)

    def test_all_scope_accepts_public_ranges(self):
        self._make_prefix("8.8.8.0/24", description="Google DNS")
        self._make_host("8.8.8.9")

        report = build_reconciliation(scope="all")
        self.assertEqual(report.total_rows, 1)


class TestReservedExclusion(ReconciliationTestBase):
    """exclude_reserved=True drops IANA special-use ranges — the 6to4 fix."""

    def test_exclude_reserved_drops_6to4_relay(self):
        # This is 192.88.99.0/24 — the phantom noise case, deprecated
        # 6to4 relay. Even in "all" scope, exclude_reserved should drop it.
        self._make_prefix("192.88.99.0/24", description="6to4 (deprecated)")
        # Not creating 254 hosts — one is enough to prove the exclusion.
        self._make_host("192.88.99.1")

        report = build_reconciliation(scope="all", exclude_reserved=True)
        self.assertEqual(report.total_rows, 0)

    def test_exclude_reserved_false_keeps_6to4(self):
        self._make_prefix("192.88.99.0/24")
        self._make_host("192.88.99.1")

        report = build_reconciliation(scope="all", exclude_reserved=False)
        self.assertEqual(report.total_rows, 1)


class TestBitemporalAsOf(ReconciliationTestBase):
    """The recording-time axis — anchoring at past T returns historic beliefs."""

    def test_as_of_before_scan_completed_shows_no_beliefs(self):
        self._make_prefix("192.168.5.0/24")
        self._make_host("192.168.5.5", hostname="host-a")

        # Anchor at long before this test suite ran — no beliefs existed.
        ancient = _dt.datetime(2020, 1, 1, tzinfo=_dt.timezone.utc)
        report = build_reconciliation(as_of=ancient)
        self.assertEqual(report.total_rows, 0)

    def test_as_of_now_returns_current(self):
        # Default matches passing timezone.now() — should be identical.
        self._make_prefix("192.168.5.0/24")
        self._make_host("192.168.5.6")

        report_default = build_reconciliation()
        report_now = build_reconciliation(as_of=timezone.now())
        self.assertEqual(report_default.total_rows, report_now.total_rows)


class TestScanScoping(ReconciliationTestBase):
    """scan=<pk> pre-scopes the discovered-host side to one scan."""

    def test_scan_arg_restricts_rows_to_that_scan(self):
        # A second scan with a different host set.
        other_scan = Scan.objects.create(
            agent=self.agent, profile=self.profile,
            completed_at=timezone.now(),
        )
        self._make_prefix("192.168.7.0/24")
        self._make_host("192.168.7.10", hostname="in-scan-1", scan=self.scan)
        self._make_host("192.168.7.11", hostname="in-scan-2", scan=other_scan)

        report = build_reconciliation(scan=self.scan)
        ips = {row.ip_address for group in report.groups for row in group.rows}
        self.assertEqual(ips, {"192.168.7.10"})


class TestStaleIPAM(ReconciliationTestBase):
    """include_stale_ipam=True populates the inverse — IPAM never seen live."""

    def test_stale_ipam_ip_lands_in_stale_groups(self):
        prefix = self._make_prefix("192.168.8.0/24")
        # IPAM has this — but no live host reports it.
        IPAddress.objects.create(address="192.168.8.100/32", namespace=self.namespace,
                                 status=self.active)

        report = build_reconciliation(include_stale_ipam=True)
        self.assertEqual(report.total_rows, 0)
        self.assertEqual(report.total_stale_rows, 1)
        self.assertEqual(report.stale_groups[0].rows[0].ip_address, "192.168.8.100")

    def test_stale_ipam_off_by_default(self):
        self._make_prefix("192.168.8.0/24")
        IPAddress.objects.create(address="192.168.8.101/32", namespace=self.namespace,
                                 status=self.active)

        report = build_reconciliation()
        self.assertEqual(report.total_stale_rows, 0)
        self.assertEqual(report.include_stale_ipam, False)

    def test_stale_ipam_ip_matched_by_live_host_is_not_stale(self):
        prefix = self._make_prefix("192.168.8.0/24")
        # IPAM knows this IP, AND a live host reports it too — not stale.
        IPAddress.objects.create(address="192.168.8.102/32", namespace=self.namespace,
                                 status=self.active)
        self._make_host("192.168.8.102")

        report = build_reconciliation(include_stale_ipam=True)
        self.assertEqual(report.total_stale_rows, 0)


class TestCSVExport(ReconciliationTestBase):
    """groups_to_csv returns valid CSV bytes with the expected header + rows."""

    def test_csv_has_expected_header_and_row(self):
        import csv
        import io

        self._make_prefix("192.168.9.0/24")
        self._make_host("192.168.9.42", hostname="host-csv")

        report = build_reconciliation()
        raw = groups_to_csv(report).decode("utf-8")

        reader = csv.reader(io.StringIO(raw))
        header = next(reader)
        self.assertIn("direction", header)
        self.assertIn("prefix", header)
        self.assertIn("ip_address", header)
        self.assertIn("rank_signal", header)

        row = next(reader)
        row_dict = dict(zip(header, row))
        self.assertEqual(row_dict["direction"], "undocumented")
        self.assertEqual(row_dict["prefix"], "192.168.9.0/24")
        self.assertEqual(row_dict["ip_address"], "192.168.9.42")
        self.assertEqual(row_dict["hostname"], "host-csv")
