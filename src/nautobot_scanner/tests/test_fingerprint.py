"""Tests for nautobot_scanner.fingerprint.

Locks in the three properties resolve_undocumented_targets() promises:

1. Both-null filter — only DiscoveredHosts where linked_device AND
   linked_ipaddress are BOTH NULL land in the result. A host with
   just linked_device set (auto-linker matched primary_ip4) or just
   linked_ipaddress set (bulk-promote flow ran) is "documented enough"
   and gets excluded.
2. scope_filter callable — narrows the base queryset. Exercised by
   passing a prefix-in filter that mimics what the management
   command's --prefix flag does.
3. cooldown_hours — hosts touched by a recent httpx/snmp-info
   NseFinding get excluded. Verifies both the cutoff time and the
   nse_script name matching.

Plus determinism sanity: the returned list is sorted, deduped, and
strings-only.
"""

from __future__ import annotations

from datetime import timedelta
from ipaddress import ip_address, ip_network

from django.test import TestCase
from django.utils import timezone
from nautobot.dcim.models import (
    Device,
    DeviceType,
    Location,
    LocationType,
    Manufacturer,
)
from nautobot.extras.models import Role, Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner.choices import (
    AgentTypeChoices,
    HostStateChoices,
    ScanTypeChoices,
    SeverityChoices,
    TimingTemplateChoices,
)
from nautobot_scanner.fingerprint import resolve_undocumented_targets
from nautobot_scanner.models import (
    DiscoveredHost,
    NseFinding,
    Scan,
    ScannerAgent,
    ScanProfile,
)


class FingerprintTestBase(TestCase):
    """Shared fixture: agent + profile + scan, plus a Device for linked_device tests."""

    @classmethod
    def setUpTestData(cls):
        active = Status.objects.get(name="Active")
        cls.active = active

        cls.agent = ScannerAgent.objects.create(
            name="fingerprint-test",
            agent_type=AgentTypeChoices.LOCAL,
            status=active,
        )
        cls.profile = ScanProfile.objects.create(
            name="fingerprint-discovery",
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

        # Make one Device so we can point a DiscoveredHost's
        # linked_device at it. LocationType / Role bootstraps are
        # get_or_create'd because Nautobot's test-DB template doesn't
        # seed either — a real deployment gets them via post_migrate,
        # but the isolated test DB starts empty.
        from django.contrib.contenttypes.models import ContentType
        device_ct = ContentType.objects.get(app_label="dcim", model="device")
        loc_type, _ = LocationType.objects.get_or_create(name="Campus")
        loc_type.content_types.add(device_ct)
        cls.location = Location.objects.create(
            name="Fingerprint Test Site",
            location_type=loc_type,
            status=active,
        )
        mfg = Manufacturer.objects.create(name="Fingerprint Test Mfg")
        cls.device_type = DeviceType.objects.create(
            manufacturer=mfg,
            model="Fingerprint Test Model",
        )
        cls.device_role, _ = Role.objects.get_or_create(name="fingerprint-router")
        cls.device_role.content_types.add(device_ct)
        cls.device = Device.objects.create(
            name="fingerprint-test-device",
            device_type=cls.device_type,
            role=cls.device_role,
            location=cls.location,
            status=active,
        )
        # Prefix + IPAddress so the "already linked" DHs can point at one.
        Prefix.objects.create(prefix="192.0.2.0/24", namespace=cls.namespace, status=active)
        cls.ip_docked = IPAddress.objects.create(
            address="192.0.2.10/32",
            namespace=cls.namespace,
            status=active,
        )

    def _make_host(self, ip: str, linked_device=None, linked_ipaddress=None,
                   hostname: str = "", scan=None):
        """Create a current-belief DiscoveredHost with optional FK links set."""
        return DiscoveredHost.objects.create(
            scan=scan or self.scan,
            ip_address=ip,
            host_state=HostStateChoices.UP,
            hostname=hostname,
            linked_device=linked_device,
            linked_ipaddress=linked_ipaddress,
        )


class TestBothNullFilter(FingerprintTestBase):
    """Only DiscoveredHosts with linked_device AND linked_ipaddress both NULL."""

    def test_undocumented_host_lands_in_result(self):
        """A DH with neither FK set is the target case."""
        self._make_host("10.0.0.1")
        self.assertEqual(resolve_undocumented_targets(), ["10.0.0.1"])

    def test_linked_device_only_excluded(self):
        """DH with linked_device set (auto-linker matched primary_ip) is documented enough."""
        self._make_host("10.0.0.1")  # undocumented, should be included
        self._make_host("10.0.0.2", linked_device=self.device)  # excluded
        self.assertEqual(resolve_undocumented_targets(), ["10.0.0.1"])

    def test_linked_ipaddress_only_excluded(self):
        """DH with linked_ipaddress set (bulk-promote flow ran) is documented enough."""
        self._make_host("10.0.0.1")
        self._make_host("10.0.0.2", linked_ipaddress=self.ip_docked)
        self.assertEqual(resolve_undocumented_targets(), ["10.0.0.1"])

    def test_both_links_excluded(self):
        """DH with both FKs set is thoroughly documented."""
        self._make_host("10.0.0.1")
        self._make_host("10.0.0.2", linked_device=self.device, linked_ipaddress=self.ip_docked)
        self.assertEqual(resolve_undocumented_targets(), ["10.0.0.1"])

    def test_empty_when_all_documented(self):
        """No undocumented hosts → empty list, not None."""
        self._make_host("10.0.0.2", linked_device=self.device)
        result = resolve_undocumented_targets()
        self.assertEqual(result, [])
        self.assertIsInstance(result, list)


class TestScopeFilter(FingerprintTestBase):
    """scope_filter callable narrows the base queryset."""

    def test_prefix_scope_narrows(self):
        """A scope_filter that keeps only 10.1.x hosts drops 10.2.x hosts."""
        self._make_host("10.1.0.1")
        self._make_host("10.1.0.2")
        self._make_host("10.2.0.1")

        net = ip_network("10.1.0.0/16")

        def _in_prefix(qs):
            keep = []
            for h in qs.only("pk", "ip_address"):
                try:
                    if ip_address(str(h.ip_address)) in net:
                        keep.append(h.pk)
                except ValueError:
                    continue
            return qs.filter(pk__in=keep)

        result = resolve_undocumented_targets(scope_filter=_in_prefix)
        self.assertEqual(result, ["10.1.0.1", "10.1.0.2"])

    def test_scope_filter_none_no_narrowing(self):
        """scope_filter=None returns the full undocumented set."""
        self._make_host("10.1.0.1")
        self._make_host("10.2.0.1")
        result = resolve_undocumented_targets(scope_filter=None)
        self.assertEqual(sorted(result), ["10.1.0.1", "10.2.0.1"])


class TestCooldown(FingerprintTestBase):
    """cooldown_hours excludes hosts touched by recent fingerprint findings."""

    def _make_recent_httpx_finding(self, host, completed_at):
        """Attach an 'httpx' NseFinding to a host, backdated to a specific time."""
        # NseFinding's discovered_host FK is where the cooldown query lands.
        # We backdate the parent scan's completed_at so the finding falls
        # inside (or outside) the cooldown window depending on the caller's
        # `completed_at`.
        scan = Scan.objects.create(
            agent=self.agent,
            profile=self.profile,
            completed_at=completed_at,
        )
        host.scan = scan
        host.save(update_fields=["scan"])
        return NseFinding.objects.create(
            discovered_host=host,
            nse_script="httpx",
            severity=SeverityChoices.INFO,
            output="{}",
        )

    def test_recent_httpx_finding_excludes_host(self):
        """A host scanned by httpx within the cooldown window is excluded."""
        h = self._make_host("10.0.0.1")
        self._make_recent_httpx_finding(h, completed_at=timezone.now() - timedelta(hours=6))
        # Default cooldown 24h — 6h ago is inside the window.
        self.assertEqual(resolve_undocumented_targets(cooldown_hours=24), [])

    def test_old_httpx_finding_does_not_exclude(self):
        """A host last scanned before the cooldown window is included."""
        h = self._make_host("10.0.0.1")
        self._make_recent_httpx_finding(h, completed_at=timezone.now() - timedelta(hours=48))
        # 48h ago is outside the default 24h window — host should re-enter target set.
        self.assertEqual(resolve_undocumented_targets(cooldown_hours=24), ["10.0.0.1"])

    def test_cooldown_disabled_zero(self):
        """cooldown_hours=0 disables the exclusion — even a fresh finding is ignored."""
        h = self._make_host("10.0.0.1")
        self._make_recent_httpx_finding(h, completed_at=timezone.now() - timedelta(minutes=5))
        self.assertEqual(resolve_undocumented_targets(cooldown_hours=0), ["10.0.0.1"])

    def test_include_recently_scanned_flag(self):
        """include_recently_scanned=True bypasses cooldown even with hours>0."""
        h = self._make_host("10.0.0.1")
        self._make_recent_httpx_finding(h, completed_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(
            resolve_undocumented_targets(cooldown_hours=24, include_recently_scanned=True),
            ["10.0.0.1"],
        )

    def test_non_fingerprint_finding_does_not_exclude(self):
        """A recent NseFinding with a NON-fingerprint nse_script (e.g. 'ssl-cert') is irrelevant."""
        h = self._make_host("10.0.0.1")
        scan = Scan.objects.create(
            agent=self.agent, profile=self.profile,
            completed_at=timezone.now() - timedelta(hours=1),
        )
        h.scan = scan
        h.save(update_fields=["scan"])
        NseFinding.objects.create(
            discovered_host=h,
            nse_script="ssl-cert",  # not httpx / snmp-info / snmp-sysdescr
            severity=SeverityChoices.INFO,
            output="{}",
        )
        # ssl-cert isn't a fingerprint tool — host stays in target set.
        self.assertEqual(resolve_undocumented_targets(), ["10.0.0.1"])


class TestDeterminism(FingerprintTestBase):
    """Result list is sorted, deduped, and string-typed."""

    def test_result_is_sorted(self):
        """Insertion order shouldn't leak — sort is deterministic."""
        for ip in ("10.0.0.9", "10.0.0.1", "10.0.0.5"):
            self._make_host(ip)
        self.assertEqual(resolve_undocumented_targets(), ["10.0.0.1", "10.0.0.5", "10.0.0.9"])

    def test_result_deduped(self):
        """Two DiscoveredHost rows for the same IP (different scans) → one entry."""
        second_scan = Scan.objects.create(
            agent=self.agent, profile=self.profile, completed_at=timezone.now(),
        )
        self._make_host("10.0.0.1")
        self._make_host("10.0.0.1", scan=second_scan)
        self.assertEqual(resolve_undocumented_targets(), ["10.0.0.1"])

    def test_result_is_str_list(self):
        """Return type is list[str] — no IPv4Address or Django wrapper leaks."""
        self._make_host("10.0.0.1")
        result = resolve_undocumented_targets()
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(x, str) for x in result))
