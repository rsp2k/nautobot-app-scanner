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
from nautobot_scanner.fingerprint import (
    Identification,
    MAX_SCORE,
    SIGNAL_WEIGHTS,
    VENDOR_CONFIDENCE_OVERRIDES,
    VENDOR_PATTERNS,
    effective_confidence_threshold,
    fuse_signals,
    match_existing_device,
    resolve_or_create_device_type,
    resolve_or_create_manufacturer,
    resolve_or_create_role,
    resolve_undocumented_targets,
)
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


# =====================================================================
# M.2 — fuse_signals() tests
# =====================================================================


class FusionTestBase(FingerprintTestBase):
    """Shared helpers for fusion tests — build NseFinding attachments quickly."""

    def _attach_httpx(self, host, *, webserver="", title="", tls_subject=""):
        """Create an httpx NseFinding on the host with the given elements."""
        elements = {}
        if webserver:
            elements["webserver"] = webserver
        if title:
            elements["title"] = title
        if tls_subject:
            elements["tls"] = {"subject_cn": tls_subject}
        return NseFinding.objects.create(
            discovered_host=host,
            nse_script="httpx",
            severity=SeverityChoices.INFO,
            output=f"httpx: {host.ip_address}",
            elements=elements,
        )

    def _attach_snmp_info(self, host, *, sysobjectid):
        """Create an snmp-info NseFinding with a sysObjectID line in the output."""
        return NseFinding.objects.create(
            discovered_host=host,
            nse_script="snmp-info",
            severity=SeverityChoices.INFO,
            output=(
                f"SNMPv2-MIB::sysObjectID.0 = OID: .{sysobjectid}\n"
                f"SNMPv2-MIB::sysDescr.0 = STRING: Test device"
            ),
        )


class TestFuseSignalsBasics(FusionTestBase):
    """No-signal edge cases + return-type sanity."""

    def test_no_signals_returns_empty_identification(self):
        """A DH with no findings and no MAC/hostname → empty ident, confidence 0.0."""
        host = self._make_host("10.0.0.1")
        ident = fuse_signals(host)
        self.assertIsInstance(ident, Identification)
        self.assertEqual(ident.vendor, "")
        self.assertEqual(ident.confidence, 0.0)
        self.assertEqual(ident.raw_score, 0)
        self.assertEqual(ident.signals, [])
        self.assertFalse(ident.has_identification)
        self.assertIsNone(ident.proposed_role)

    def test_denormalized_fields_populated(self):
        """discovered_host_id and ip_address are always populated."""
        host = self._make_host("10.0.0.42")
        ident = fuse_signals(host)
        self.assertEqual(ident.discovered_host_id, str(host.pk))
        self.assertEqual(ident.ip_address, "10.0.0.42")


class TestFuseSignalsSingleSignal(FusionTestBase):
    """Single signal fires — vendor identified, confidence proportional."""

    def test_snmp_only_cisco(self):
        """Cisco sysObjectID alone → Cisco identification at 3/15 confidence."""
        host = self._make_host("10.0.0.1")
        self._attach_snmp_info(host, sysobjectid="1.3.6.1.4.1.9.1.1745")  # Catalyst
        ident = fuse_signals(host)
        self.assertEqual(ident.vendor, "Cisco")
        self.assertEqual(ident.device_type_hint, "network-equipment")
        self.assertEqual(ident.raw_score, SIGNAL_WEIGHTS["snmp_sysobjectid"])
        self.assertEqual(ident.confidence, round(3 / MAX_SCORE, 3))
        self.assertEqual(ident.proposed_role, "Network Equipment")
        self.assertEqual(len(ident.signals), 1)
        self.assertEqual(ident.signals[0].signal, "snmp_sysobjectid")

    def test_httpx_webserver_only_axis(self):
        """Axis Server header alone → Axis identification at 2/15 confidence."""
        host = self._make_host("10.0.0.1")
        self._attach_httpx(host, webserver="AXIS Communications AB")
        ident = fuse_signals(host)
        self.assertEqual(ident.vendor, "Axis")
        self.assertEqual(ident.device_type_hint, "camera")
        self.assertEqual(ident.proposed_role, "Camera")
        self.assertEqual(ident.raw_score, SIGNAL_WEIGHTS["httpx_webserver"])

    def test_dns_only_uniview(self):
        """Uniview DNS prefix alone → Uniview identification at 2/15 confidence."""
        host = self._make_host("10.1.3.6", hostname="qnv-c8011r-e43022bf7ee6.example.local")
        ident = fuse_signals(host)
        self.assertEqual(ident.vendor, "Uniview")
        self.assertEqual(ident.proposed_role, "Camera")
        self.assertEqual(ident.raw_score, SIGNAL_WEIGHTS["dns_hostname"])
        self.assertEqual(len(ident.signals), 1)
        self.assertEqual(ident.signals[0].signal, "dns_hostname")


class TestFuseSignalsMultipleSignals(FusionTestBase):
    """Multiple signals — strongest confidence, correct aggregation."""

    def test_camera_fires_all_signals(self):
        """A well-fingerprinted Uniview camera → high confidence, all signals sum."""
        host = DiscoveredHost.objects.create(
            scan=self.scan,
            ip_address="10.1.3.6",
            host_state=HostStateChoices.UP,
            hostname="qnv-c8011r-e43022bf7ee6.example.local",
            mac_address="E4:30:22:BF:7E:E6",
            mac_vendor="Uniview Technologies",
            os_vendor="Uniview",
        )
        self._attach_snmp_info(host, sysobjectid="1.3.6.1.4.1.31460.1.20.7")
        self._attach_httpx(
            host,
            webserver="Uniview-Web/1.0",
            title="Uniview NVR Login",
            tls_subject="CN=Uniview NVR",
        )
        ident = fuse_signals(host)

        self.assertEqual(ident.vendor, "Uniview")
        self.assertEqual(ident.device_type_hint, "camera")
        self.assertEqual(ident.proposed_role, "Camera")
        # 6 signals should fire: SNMP (3) + webserver (2) + title (2) + tls (3) + mac (2) + dns (2) + sv (1) = 15
        self.assertEqual(ident.raw_score, MAX_SCORE)
        self.assertEqual(ident.confidence, 1.0)
        # Signals sorted by weight descending
        weights_seen = [s.weight for s in ident.signals]
        self.assertEqual(weights_seen, sorted(weights_seen, reverse=True))

    def test_conflicting_vendors_higher_score_wins(self):
        """One weak Cisco signal vs three strong Axis signals — Axis wins."""
        host = self._make_host("10.0.0.1")
        # Cisco: one signal, weight 1 (weakest — nmap_sv_product)
        host.os_vendor = "Cisco"
        host.save(update_fields=["os_vendor"])
        # Axis: SNMP OID + webserver + tls_subject = 3+2+3 = 8
        self._attach_snmp_info(host, sysobjectid="1.3.6.1.4.1.368.1.1.6.2.1")
        self._attach_httpx(host, webserver="AXIS Q3505-VE", tls_subject="CN=axis-b8a44f00abcd")

        ident = fuse_signals(host)
        self.assertEqual(ident.vendor, "Axis")
        self.assertGreater(ident.raw_score, SIGNAL_WEIGHTS["nmap_sv_product"])
        # The winning vendor's signals only — no Cisco signal in the list
        for s in ident.signals:
            self.assertEqual(s.vendor, "Axis")

    def test_snmp_hint_overrides_role_fallback(self):
        """When SNMP fires, its device_type_hint drives the identification.

        A Cisco AP (wireless-ap hint via 14179 OID) shouldn't fall back to
        the VENDOR_TO_ROLE 'Network Equipment' generic.
        """
        host = self._make_host("10.0.0.1")
        self._attach_snmp_info(host, sysobjectid="1.3.6.1.4.1.14179.2.1.4.0")
        ident = fuse_signals(host)
        self.assertEqual(ident.vendor, "Cisco WLC")
        self.assertEqual(ident.device_type_hint, "wireless-ap")


class TestFuseSignalsAuditTrail(FusionTestBase):
    """SignalHit records the evidence — reviewer can trace WHY a vendor won."""

    def test_signals_contain_evidence(self):
        """Each SignalHit's evidence field is a non-empty string."""
        host = self._make_host("10.0.0.1")
        self._attach_httpx(host, title="Uniview NVR Login")
        ident = fuse_signals(host)
        self.assertGreater(len(ident.signals), 0)
        for s in ident.signals:
            self.assertIsInstance(s.evidence, str)
            self.assertGreater(len(s.evidence), 0)


class TestFuseSignalsPatternIntegrity(FusionTestBase):
    """Structural checks on the VENDOR_PATTERNS table."""

    def test_all_vendors_have_role_mapping(self):
        """Every vendor in VENDOR_PATTERNS gets a Role — or None is documented."""
        from nautobot_scanner.fingerprint import VENDOR_TO_ROLE
        for vendor in VENDOR_PATTERNS:
            # None is allowed (means "surface for operator review") but
            # every current vendor in the table is expected to have a role.
            self.assertIn(vendor, VENDOR_TO_ROLE,
                          f"Vendor {vendor!r} has patterns but no VENDOR_TO_ROLE entry")

    def test_all_pattern_lists_are_regex(self):
        """Every pattern is a compiled regex, not a raw string."""
        import re
        for vendor, cats in VENDOR_PATTERNS.items():
            for cat, patterns in cats.items():
                self.assertIsInstance(patterns, list)
                for p in patterns:
                    self.assertIsInstance(p, re.Pattern,
                                          f"{vendor}.{cat} has non-regex entry: {p!r}")


# =====================================================================
# M.2.5 — auto-provision helpers + match-existing tests
# =====================================================================


class TestResolveOrCreateManufacturer(FingerprintTestBase):
    """resolve_or_create_manufacturer() reuses existing / creates fresh."""

    def test_creates_fresh_manufacturer(self):
        """Unknown vendor → new Manufacturer row."""
        result = resolve_or_create_manufacturer("Nonexistent Vendor XYZ")
        self.assertEqual(result.name, "Nonexistent Vendor XYZ")
        self.assertTrue(Manufacturer.objects.filter(name="Nonexistent Vendor XYZ").exists())

    def test_reuses_existing_manufacturer_by_substring(self):
        """'Axis' vendor matches existing 'Axis Communications AB' via icontains."""
        pre_existing = Manufacturer.objects.create(name="Axis Communications AB")
        result = resolve_or_create_manufacturer("Axis")
        self.assertEqual(result.pk, pre_existing.pk)
        # Confirm we didn't create a duplicate
        self.assertEqual(Manufacturer.objects.filter(name__icontains="axis").count(), 1)


class TestResolveOrCreateDeviceType(FingerprintTestBase):
    """resolve_or_create_device_type() builds vendor + hint model naming."""

    def test_creates_fresh_device_type_with_naming_convention(self):
        """DeviceType model name follows 'Vendor Auto-identified hint' convention."""
        result = resolve_or_create_device_type("Uniview", "camera")
        self.assertEqual(result.model, "Uniview Auto-identified camera")
        self.assertEqual(result.manufacturer.name, "Uniview")

    def test_reuses_existing_device_type(self):
        """Second call with same vendor+hint reuses row (unique key semantics)."""
        first = resolve_or_create_device_type("Bosch", "camera")
        second = resolve_or_create_device_type("Bosch", "camera")
        self.assertEqual(first.pk, second.pk)


class TestResolveOrCreateRole(FingerprintTestBase):
    """resolve_or_create_role() attaches dcim.device content type."""

    def test_creates_role_with_device_content_type(self):
        """New Role can be assigned to a Device immediately."""
        from django.contrib.contenttypes.models import ContentType
        role = resolve_or_create_role("M2.5 test role")
        device_ct = ContentType.objects.get(app_label="dcim", model="device")
        self.assertTrue(role.content_types.filter(pk=device_ct.pk).exists())

    def test_second_call_does_not_duplicate_content_type(self):
        """Idempotent — content type stays attached exactly once."""
        role1 = resolve_or_create_role("M2.5 idempotent role")
        role2 = resolve_or_create_role("M2.5 idempotent role")
        self.assertEqual(role1.pk, role2.pk)
        device_ct_count = role2.content_types.filter(app_label="dcim", model="device").count()
        self.assertEqual(device_ct_count, 1)


class TestMatchExistingDevice(FingerprintTestBase):
    """match_existing_device() finds Devices by primary_ip4 or MAC."""

    def _make_ip(self, host_str):
        """Create an IPAddress and its containing Prefix."""
        Prefix.objects.get_or_create(
            prefix="10.100.0.0/24",
            namespace=self.namespace,
            defaults={"status": self.active},
        )
        return IPAddress.objects.create(
            address=f"{host_str}/32",
            namespace=self.namespace,
            status=self.active,
        )

    def test_match_by_primary_ip4(self):
        """A Device with primary_ip4 matching the DH IP is returned."""
        ip = self._make_ip("10.100.0.5")
        self.device.primary_ip4 = ip
        self.device.save(update_fields=["primary_ip4"])
        host = self._make_host("10.100.0.5")
        result = match_existing_device(host)
        self.assertIsNotNone(result)
        self.assertEqual(result.pk, self.device.pk)

    def test_match_by_interface_mac(self):
        """A Device with an Interface carrying the DH's MAC is returned."""
        from nautobot.dcim.models import Interface
        Interface.objects.create(
            device=self.device,
            name="eth0-match",
            type="virtual",
            mac_address="AA:BB:CC:DD:EE:FF",
            status=self.active,
        )
        host = self._make_host("10.100.0.99")
        host.mac_address = "AA:BB:CC:DD:EE:FF"
        host.save(update_fields=["mac_address"])
        result = match_existing_device(host)
        self.assertIsNotNone(result)
        self.assertEqual(result.pk, self.device.pk)

    def test_no_match_returns_none(self):
        """A DH with no matching IP or MAC returns None."""
        host = self._make_host("10.200.0.1")  # not in DB anywhere
        result = match_existing_device(host)
        self.assertIsNone(result)

    def test_empty_mac_does_not_false_match(self):
        """A DH with empty mac_address doesn't accidentally match Interfaces with empty MAC."""
        from nautobot.dcim.models import Interface
        Interface.objects.create(
            device=self.device,
            name="eth0-empty-mac",
            type="virtual",
            mac_address=None,
            status=self.active,
        )
        host = self._make_host("10.200.0.2")  # no matching IP
        # host.mac_address defaults to empty
        result = match_existing_device(host)
        self.assertIsNone(result)


# =====================================================================
# M.3 — per-vendor confidence override tests
# =====================================================================


class TestPerVendorConfidence(FingerprintTestBase):
    """effective_confidence_threshold() honors per-vendor overrides."""

    def test_vendor_with_override_uses_override(self):
        """Axis identification uses its 0.45 override, not the CLI default."""
        result = effective_confidence_threshold("Axis", default=0.9)
        self.assertEqual(result, VENDOR_CONFIDENCE_OVERRIDES["Axis"])
        self.assertLess(result, 0.9)  # override is lower than default

    def test_vendor_without_override_falls_through(self):
        """Unknown vendor gets the CLI default."""
        result = effective_confidence_threshold("Unmapped Vendor XYZ", default=0.7)
        self.assertEqual(result, 0.7)

    def test_cisco_higher_than_axis(self):
        """Cisco requires MORE corroboration than Axis (broader vendor → weaker single-signal)."""
        cisco = effective_confidence_threshold("Cisco", default=0.5)
        axis = effective_confidence_threshold("Axis", default=0.5)
        self.assertGreater(cisco, axis)

    def test_empty_vendor_falls_through_to_default(self):
        """Empty-string vendor (no identification) gets the default."""
        result = effective_confidence_threshold("", default=0.65)
        self.assertEqual(result, 0.65)


# =====================================================================
# M.3 — dispatch view tests
# =====================================================================


class TestFingerprintDispatchViews(TestCase):
    """POST-only views that dispatch httpx / snmp-recon-deep from the reconciliation UI."""

    @classmethod
    def setUpTestData(cls):
        from django.contrib.auth import get_user_model
        active = Status.objects.get(name="Active")
        cls.active = active

        cls.agent = ScannerAgent.objects.create(
            name="m3-dispatch-test",
            agent_type=AgentTypeChoices.LOCAL,
            status=active,
        )
        # Seed the profiles the views expect. In prod they come from
        # migrations 0022 (httpx) and 0025 (snmp-recon-deep); tests
        # create matching-name profiles so `get(name=…)` succeeds.
        cls.httpx_profile = ScanProfile.objects.get_or_create(
            name="http-probe-rich",
            defaults={
                "scan_type": ScanTypeChoices.VERSION,
                "tool": "httpx",
                "nmap_arguments": "",
                "tool_arguments": "-status-code -title",
                "timing_template": TimingTemplateChoices.T3,
            },
        )[0]
        cls.snmp_profile = ScanProfile.objects.get_or_create(
            name="snmp-recon-deep",
            defaults={
                "scan_type": ScanTypeChoices.VERSION,
                "tool": "nmap",
                "nmap_arguments": (
                    "-sU -p 161 --script snmp-info,snmp-sysdescr,snmp-brute "
                    "--script-args snmpcommunity.wordlist=/etc/scanner/snmp-defaults.txt"
                ),
                "timing_template": TimingTemplateChoices.T4,
                "enabled_scripts": ["snmp-info", "snmp-sysdescr", "snmp-brute"],
            },
        )[0]
        scan = Scan.objects.create(
            agent=cls.agent, profile=cls.httpx_profile, completed_at=timezone.now(),
        )
        cls.host_a = DiscoveredHost.objects.create(
            scan=scan, ip_address="10.100.1.1",
            host_state=HostStateChoices.UP, hostname="host-a",
        )
        cls.host_b = DiscoveredHost.objects.create(
            scan=scan, ip_address="10.100.1.2",
            host_state=HostStateChoices.UP, hostname="host-b",
        )

        # Test user + permission.
        User = get_user_model()
        cls.user = User.objects.create_user(username="m3-dispatch-user")
        cls.user.is_superuser = True  # sidesteps ObjectPermission complexity
        cls.user.save()

    def setUp(self):
        from django.test import Client
        self.client = Client()
        self.client.force_login(self.user)

    def test_httpx_get_returns_405(self):
        """GET on the httpx dispatch view is not allowed."""
        from django.urls import reverse
        with self.settings(ALLOWED_HOSTS=["*"]):
            resp = self.client.get(reverse("plugins:nautobot_scanner:discoveredhost_fingerprint_httpx"))
        self.assertEqual(resp.status_code, 405)

    def test_snmp_get_returns_405(self):
        """GET on the snmp dispatch view is not allowed."""
        from django.urls import reverse
        with self.settings(ALLOWED_HOSTS=["*"]):
            resp = self.client.get(reverse("plugins:nautobot_scanner:discoveredhost_fingerprint_snmp"))
        self.assertEqual(resp.status_code, 405)

    def test_empty_selection_redirects_with_warning(self):
        """POST with no discovered_host_id → redirect to reconciliation with warning."""
        from django.urls import reverse
        url = reverse("plugins:nautobot_scanner:discoveredhost_fingerprint_httpx")
        with self.settings(ALLOWED_HOSTS=["*"]):
            resp = self.client.post(url, {})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/reconciliation/", resp["Location"])
        # No Scan should have been created.
        # (Only the setup-fixture Scan should exist.)
        self.assertEqual(Scan.objects.count(), 1)

    def test_httpx_dispatch_creates_scan_with_selected_ips(self):
        """Valid POST creates a Scan against the selected IPs."""
        from django.urls import reverse
        url = reverse("plugins:nautobot_scanner:discoveredhost_fingerprint_httpx")
        with self.settings(ALLOWED_HOSTS=["*"]):
            resp = self.client.post(url, {
                "discovered_host_id": [str(self.host_a.pk), str(self.host_b.pk)],
            })
        # 302 to the resulting Scan detail.
        self.assertEqual(resp.status_code, 302)

        # One new Scan against http-probe-rich with two target IPs.
        new_scans = Scan.objects.filter(profile=self.httpx_profile).exclude(pk=self.host_a.scan_id)
        self.assertEqual(new_scans.count(), 1)
        scan = new_scans.first()
        self.assertEqual(sorted(scan.target_raw_ips), ["10.100.1.1", "10.100.1.2"])

    def test_snmp_dispatch_creates_scan(self):
        """SNMP dispatch creates a Scan with the snmp-recon-deep profile."""
        from django.urls import reverse
        url = reverse("plugins:nautobot_scanner:discoveredhost_fingerprint_snmp")
        with self.settings(ALLOWED_HOSTS=["*"]):
            resp = self.client.post(url, {
                "discovered_host_id": [str(self.host_a.pk)],
            })
        self.assertEqual(resp.status_code, 302)
        new_scans = Scan.objects.filter(profile=self.snmp_profile)
        self.assertEqual(new_scans.count(), 1)
        self.assertEqual(new_scans.first().target_raw_ips, ["10.100.1.1"])
