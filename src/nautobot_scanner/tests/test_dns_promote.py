"""Tests for Phase K — dig/drill → nautobot-app-dns-models promotion.

Two layers of tests:

1. **Pure helpers** (no DB): TTL clipping, FQDN splitting. Catch the
   shape of the input/output contract; cheap to extend when we add new
   zone strategies.

2. **End-to-end promoter**: takes a synthetic NseFinding, runs
   ``promote_finding``, asserts the canonical dns-models records +
   provenance rows match expectations. Tests the contract that matters
   to a caller (the ingest endpoint).

The "killer" test — ``test_arecord_cross_references_existing_ipaddress``
— proves the whole point of Phase K: that an A record from DNS lines up
with an IPAM row we already have, making the "this name → this host"
cross-reference a single queryable join.
"""

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner.choices import (
    AgentTypeChoices,
    ScanStateChoices,
    ScanTypeChoices,
    TimingTemplateChoices,
)
from nautobot_scanner.dns_promote import (
    DNS_MODELS_TTL_FLOOR,
    PROMOTERS,
    _clip_ttl,
    _split_fqdn,
    promote_finding,
)
from nautobot_scanner.models import (
    DiscoveredHost,
    DnsRecordProvenance,
    NseFinding,
    Scan,
    ScannerAgent,
    ScanProfile,
)


# ---------------------------------------------------------------------
# Helpers — no DB, no fixtures
# ---------------------------------------------------------------------

class TestClipTtl(TestCase):
    """TTL clipping has to floor at 300s for dns-models compatibility."""

    def test_none_returns_none(self):
        self.assertIsNone(_clip_ttl(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(_clip_ttl(""))

    def test_unparseable_returns_none(self):
        self.assertIsNone(_clip_ttl("not-a-number"))

    def test_value_below_floor_is_raised_to_floor(self):
        # The actual Cloudflare-common case: TTL=60 must become 300.
        self.assertEqual(_clip_ttl(60), DNS_MODELS_TTL_FLOOR)
        self.assertEqual(_clip_ttl("60"), DNS_MODELS_TTL_FLOOR)

    def test_value_at_floor_passes_through(self):
        self.assertEqual(_clip_ttl(300), 300)

    def test_value_above_floor_passes_through(self):
        self.assertEqual(_clip_ttl(3600), 3600)
        self.assertEqual(_clip_ttl("86400"), 86400)


class TestSplitFqdn(TestCase):
    """tld+1 zone strategy must produce predictable (record, zone) pairs."""

    def test_two_label_fqdn_uses_at_for_apex(self):
        self.assertEqual(_split_fqdn("example.com"), ("@", "example.com"))
        # Trailing dot from wire shouldn't change the result.
        self.assertEqual(_split_fqdn("example.com."), ("@", "example.com"))

    def test_three_label_fqdn_strips_zone(self):
        self.assertEqual(_split_fqdn("mail.example.com"), ("mail", "example.com"))

    def test_underscore_records_preserved(self):
        # DKIM, DMARC, SRV records all use underscore-prefixed names.
        self.assertEqual(_split_fqdn("_dmarc.example.com"), ("_dmarc", "example.com"))

    def test_deeply_nested_fqdn_keeps_full_record_name(self):
        # `foo.bar.baz.example.com.` → record="foo.bar.baz", zone="example.com"
        self.assertEqual(_split_fqdn("foo.bar.baz.example.com"), ("foo.bar.baz", "example.com"))

    def test_empty_input_returns_safe_default(self):
        self.assertEqual(_split_fqdn(""), ("@", ""))
        self.assertEqual(_split_fqdn(None or ""), ("@", ""))


# ---------------------------------------------------------------------
# End-to-end promoter — needs a NseFinding to act on
# ---------------------------------------------------------------------

class PromoterTestBase(TestCase):
    """Builds the minimum object graph each promoter test needs.

    Scan → DiscoveredHost → NseFinding with a customizable ``elements["records"]``.
    Helper methods make each test read like "given THIS finding, promote
    returns THAT result."
    """

    def setUp(self):
        active = Status.objects.get(name="Active")
        scan_status = Status.objects.filter(content_types__model="scan").first()
        self.agent = ScannerAgent.objects.create(
            name="test-agent-for-dns-promote",
            agent_type=AgentTypeChoices.REMOTE,
            status=active,
        )
        self.profile = ScanProfile.objects.create(
            name="dns-test-profile",
            scan_type=ScanTypeChoices.DISCOVERY,
            tool="dig",
            tool_arguments="",
            timing_template=TimingTemplateChoices.T3,
        )
        self.scan = Scan.objects.create(
            agent=self.agent, profile=self.profile, status=scan_status or ScanStateChoices.PENDING,
        )
        self.host = DiscoveredHost.objects.create(
            scan=self.scan, ip_address="198.51.100.10", host_state="up",
        )

    def _make_finding(self, records):
        """Build a synthetic dig finding carrying ``records`` in elements."""
        return NseFinding.objects.create(
            discovered_host=self.host,
            nse_script="dig-answer",
            severity="info",
            output="(synthetic)",
            elements={"records": records, "record_count": len(records)},
        )


class TestPromoteNonARecords(PromoterTestBase):
    """The easy path — record types that don't need IPAM."""

    def test_cname_record_promoted(self):
        from nautobot_dns_models.models import CNAMERecord
        f = self._make_finding([
            {"name": "www.example.com.", "ttl": "300", "type": "CNAME", "value": "example.com."},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["promoted"]["CNAME"], 1)
        rec = CNAMERecord.objects.get(name="www", alias="example.com")
        self.assertEqual(rec.zone.name, "example.com")

    def test_mx_record_parses_preference(self):
        from nautobot_dns_models.models import MXRecord
        f = self._make_finding([
            {"name": "example.com.", "ttl": "3600", "type": "MX", "value": "10 mail.example.com."},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["promoted"]["MX"], 1)
        rec = MXRecord.objects.get(mail_server="mail.example.com")
        self.assertEqual(rec.preference, 10)

    def test_ns_record_promoted(self):
        from nautobot_dns_models.models import NSRecord
        f = self._make_finding([
            {"name": "example.com.", "ttl": "3600", "type": "NS", "value": "ns1.example.com."},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["promoted"]["NS"], 1)
        self.assertEqual(NSRecord.objects.get().server, "ns1.example.com")

    def test_txt_record_strips_quotes(self):
        from nautobot_dns_models.models import TXTRecord
        f = self._make_finding([
            {"name": "_dmarc.example.com.", "ttl": "3600", "type": "TXT",
             "value": '"v=DMARC1; p=none"'},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["promoted"]["TXT"], 1)
        self.assertEqual(TXTRecord.objects.get().text, "v=DMARC1; p=none")

    def test_srv_record_parses_components(self):
        from nautobot_dns_models.models import SRVRecord
        f = self._make_finding([
            {"name": "_sip._tcp.example.com.", "ttl": "3600", "type": "SRV",
             "value": "10 60 5060 sipserver.example.com."},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["promoted"]["SRV"], 1)
        rec = SRVRecord.objects.get()
        self.assertEqual((rec.priority, rec.weight, rec.port), (10, 60, 5060))
        self.assertEqual(rec.target, "sipserver.example.com")


class TestARecordIpamCoupling(PromoterTestBase):
    """A/AAAA records require an existing IPAddress — verify both branches."""

    def test_a_record_skipped_when_ipam_missing(self):
        """Most realistic case: most A record values aren't in IPAM."""
        from nautobot_dns_models.models import ARecord
        f = self._make_finding([
            {"name": "example.com.", "ttl": "60", "type": "A", "value": "93.184.216.34"},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["skipped"], 1)
        self.assertEqual(ARecord.objects.count(), 0)

    def test_a_record_created_when_ipam_exists(self):
        """When the IP is already in IPAM, the FK links correctly."""
        from nautobot_dns_models.models import ARecord
        # Build the minimal IPAM scaffolding: Namespace + Prefix + IPAddress.
        # (Real environments would already have these.)
        ns = Namespace.objects.get(name="Global")
        active = Status.objects.get(name="Active")
        Prefix.objects.create(
            prefix="192.0.2.0/24", namespace=ns, status=active, type="network",
        )
        ip = IPAddress.objects.create(
            host="192.0.2.10", mask_length=32, namespace=ns, status=active, type="host",
        )
        f = self._make_finding([
            {"name": "alpha.example.com.", "ttl": "3600", "type": "A", "value": "192.0.2.10"},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["promoted"]["A"], 1)
        rec = ARecord.objects.get(name="alpha")
        self.assertEqual(rec.ip_address, ip)


class TestPromoteSkipsUnknownTypes(PromoterTestBase):
    """CAA / DNSKEY / SVCB / HTTPS records are out of scope for v1."""

    def test_caa_record_skipped_without_raising(self):
        f = self._make_finding([
            {"name": "example.com.", "ttl": "3600", "type": "CAA",
             "value": '0 issue "letsencrypt.org"'},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["skipped"], 1)
        self.assertEqual(counts["errors"], [])
        # CAA isn't in our PROMOTERS dispatch table.
        self.assertNotIn("CAA", PROMOTERS)


class TestPromoteIdempotency(PromoterTestBase):
    """Re-running on the same finding must not duplicate canonical records."""

    def test_second_run_reuses_record_creates_second_provenance(self):
        from nautobot_dns_models.models import CNAMERecord
        f = self._make_finding([
            {"name": "www.example.com.", "ttl": "300", "type": "CNAME", "value": "example.com."},
        ])
        counts1 = promote_finding(f)
        counts2 = promote_finding(f)
        self.assertEqual(counts1["promoted"]["CNAME"], 1)
        self.assertEqual(counts2["promoted"]["CNAME"], 1)
        # First run created the record, second run found it unchanged.
        self.assertEqual(counts1["created"]["CNAME"], 1)
        self.assertEqual(counts2["unchanged"]["CNAME"], 1)
        # ONE canonical record, despite two promotion runs.
        self.assertEqual(CNAMERecord.objects.count(), 1)
        # TWO provenance rows — that's the recurrence history.
        self.assertEqual(DnsRecordProvenance.objects.filter(finding=f).count(), 2)


class TestBitemporalAmend(PromoterTestBase):
    """K': sequenced amend triggers when wire data changes between scans.

    The contract from agent-thread message 002:
    - `obj.save()` after mutating a tracked field rotates the belief window.
    - `obj.pk` rebinds; `obj.entry_id` rotates.
    - `Model.objects` returns only the current belief (1 row); `all_versions`
      returns the full history (>1 after an amend).

    These tests lock that contract in so a future regression in the fork
    (or in our amend-detection logic) is caught immediately.
    """

    def test_changed_ttl_triggers_amend_and_rotates_entry_id(self):
        """The headline amend case: TTL drift between two scans."""
        from nautobot_dns_models.models import CNAMERecord

        # Scan 1: ttl=3600
        f1 = self._make_finding([
            {"name": "drift.example.com.", "ttl": "3600", "type": "CNAME", "value": "tgt.example.com."},
        ])
        counts1 = promote_finding(f1)
        rec1 = CNAMERecord.objects.get(name="drift")
        original_pk, original_entry = rec1.pk, rec1.entry_id
        self.assertEqual(counts1["created"]["CNAME"], 1)
        self.assertEqual(counts1["amended"]["CNAME"], 0)

        # Scan 2: same target, different TTL (DNS team lowered it)
        f2 = self._make_finding([
            {"name": "drift.example.com.", "ttl": "600", "type": "CNAME", "value": "tgt.example.com."},
        ])
        counts2 = promote_finding(f2)

        # Promoter detected drift and rotated.
        self.assertEqual(counts2["amended"]["CNAME"], 1)
        self.assertEqual(counts2["created"]["CNAME"], 0)
        self.assertEqual(counts2["unchanged"]["CNAME"], 0)

        # Current row shows the new TTL; pk and entry_id both rebound.
        rec2 = CNAMERecord.objects.get(name="drift")
        self.assertEqual(rec2._ttl, 600)
        self.assertNotEqual(rec2.pk, original_pk, "amend should rebind pk")
        self.assertNotEqual(rec2.entry_id, original_entry, "amend should rotate entry_id")

        # all_versions has both beliefs; objects has only the current.
        self.assertEqual(CNAMERecord.all_versions.filter(name="drift").count(), 2)
        self.assertEqual(CNAMERecord.objects.filter(name="drift").count(), 1)

    def test_amend_provenance_captures_new_entry_id_not_prior(self):
        """Provenance written after save() must reflect the rotated belief."""
        from nautobot_dns_models.models import CNAMERecord

        f1 = self._make_finding([
            {"name": "prov.example.com.", "ttl": "3600", "type": "CNAME", "value": "x.example.com."},
        ])
        promote_finding(f1)
        original_entry = CNAMERecord.objects.get(name="prov").entry_id

        f2 = self._make_finding([
            {"name": "prov.example.com.", "ttl": "600", "type": "CNAME", "value": "x.example.com."},
        ])
        promote_finding(f2)
        new_entry = CNAMERecord.objects.get(name="prov").entry_id
        self.assertNotEqual(original_entry, new_entry)

        # Two provenance rows total: one per finding.
        provs = list(DnsRecordProvenance.objects.order_by("observed_at"))
        self.assertEqual(len(provs), 2)
        # First provenance row points at the original belief.
        self.assertEqual(provs[0].record_entry_id, original_entry)
        self.assertEqual(provs[0].raw_ttl, 3600)
        # Second provenance row points at the NEW belief (amend captured the
        # rotated entry_id, not the prior one). This is the property test
        # that locks in the "write provenance AFTER save()" ordering.
        self.assertEqual(provs[1].record_entry_id, new_entry)
        self.assertEqual(provs[1].raw_ttl, 600)

    def test_unchanged_wire_data_does_not_rotate_belief(self):
        """The negative control: identical re-scan must NOT spuriously amend."""
        from nautobot_dns_models.models import CNAMERecord

        f1 = self._make_finding([
            {"name": "stable.example.com.", "ttl": "3600", "type": "CNAME", "value": "x.example.com."},
        ])
        promote_finding(f1)
        rec1 = CNAMERecord.objects.get(name="stable")
        original_pk, original_entry = rec1.pk, rec1.entry_id

        # Identical re-scan
        f2 = self._make_finding([
            {"name": "stable.example.com.", "ttl": "3600", "type": "CNAME", "value": "x.example.com."},
        ])
        counts = promote_finding(f2)

        self.assertEqual(counts["unchanged"]["CNAME"], 1)
        self.assertEqual(counts["amended"]["CNAME"], 0)
        # Same canonical row — pk and entry_id unchanged.
        rec2 = CNAMERecord.objects.get(name="stable")
        self.assertEqual(rec2.pk, original_pk)
        self.assertEqual(rec2.entry_id, original_entry)
        # Only ONE belief in all_versions (no spurious rotation).
        self.assertEqual(CNAMERecord.all_versions.filter(name="stable").count(), 1)

    def test_provenance_record_property_resolves_through_all_versions(self):
        """The record resolver must find rows even after their belief is closed."""
        from nautobot_dns_models.models import CNAMERecord

        # Two scans → one amend → original belief is now superseded.
        f1 = self._make_finding([
            {"name": "resolve.example.com.", "ttl": "3600", "type": "CNAME", "value": "x.example.com."},
        ])
        promote_finding(f1)
        f2 = self._make_finding([
            {"name": "resolve.example.com.", "ttl": "600", "type": "CNAME", "value": "x.example.com."},
        ])
        promote_finding(f2)

        provs = list(DnsRecordProvenance.objects.order_by("observed_at"))
        self.assertEqual(len(provs), 2)

        # The first provenance row points at a now-SUPERSEDED belief.
        # If our resolver used CNAMERecord.objects (current only) it'd return
        # None here; using all_versions makes it find the prior belief.
        resolved_old = provs[0].record
        self.assertIsNotNone(resolved_old, "Resolver must find superseded beliefs via all_versions")
        self.assertEqual(resolved_old._ttl, 3600, "Should resolve to the ORIGINAL belief, not the current")

        # The second provenance row points at the current belief.
        resolved_new = provs[1].record
        self.assertIsNotNone(resolved_new)
        self.assertEqual(resolved_new._ttl, 600)


class TestPromoteHandlesEdgeCases(PromoterTestBase):
    """Bad input shouldn't take down the batch."""

    def test_ttl_below_300_clipped_with_raw_preserved(self):
        f = self._make_finding([
            {"name": "ttl-low.example.com.", "ttl": "60", "type": "CNAME", "value": "x.example.com."},
        ])
        promote_finding(f)
        # Canonical record clipped to floor.
        from nautobot_dns_models.models import CNAMERecord
        rec = CNAMERecord.objects.get(name="ttl-low")
        self.assertEqual(rec._ttl, DNS_MODELS_TTL_FLOOR)
        # Provenance preserves the wire value AND uses entry_id, not pk, so
        # the row stays anchored to the specific belief we observed even
        # after future amends would rebind pk.
        prov = DnsRecordProvenance.objects.get(record_entry_id=rec.entry_id)
        self.assertEqual(prov.raw_ttl, 60)

    def test_oversized_txt_truncated_with_raw_preserved(self):
        big_txt = "x" * 600  # ~512+ chars (DKIM-class) but unquoted
        f = self._make_finding([
            {"name": "big.example.com.", "ttl": "3600", "type": "TXT", "value": big_txt},
        ])
        promote_finding(f)
        from nautobot_dns_models.models import TXTRecord
        # dns-models cap is 256; we end-trim with ellipsis.
        rec = TXTRecord.objects.first()
        self.assertEqual(len(rec.text), 256)
        # raw_value is capped at 512 by our own provenance field, but it's
        # still strictly more than the canonical record can hold.
        prov = DnsRecordProvenance.objects.first()
        self.assertEqual(len(prov.raw_value), 512)

    def test_malformed_mx_logged_and_skipped_not_raised(self):
        f = self._make_finding([
            {"name": "example.com.", "ttl": "3600", "type": "MX", "value": "garbage-no-priority"},
        ])
        counts = promote_finding(f)
        self.assertEqual(counts["skipped"], 1)
        # No errors recorded — the per-promoter logger.warning caught it cleanly.
        self.assertEqual(counts["errors"], [])

    def test_empty_records_list_returns_clean_no_records_flag(self):
        f = self._make_finding([])
        counts = promote_finding(f)
        self.assertTrue(counts["no_records"])
        self.assertEqual(dict(counts["promoted"]), {})


class TestKillerCrossReference(PromoterTestBase):
    """The whole point of Phase K — DNS records line up with IPAM/scanned hosts."""

    def test_arecord_cross_references_existing_ipaddress(self):
        """Query: "which DNS A records point at hosts we've scanned?"

        After promotion, this should answer in one ORM query, not a manual
        join — proving the DNS layer and the discovery layer share IPAM as
        the common key.
        """
        from nautobot_dns_models.models import ARecord

        # Set up an IPAddress that matches our self.host.ip_address.
        ns = Namespace.objects.get(name="Global")
        active = Status.objects.get(name="Active")
        Prefix.objects.create(
            prefix="198.51.100.0/24", namespace=ns, status=active, type="network",
        )
        ip = IPAddress.objects.create(
            host="198.51.100.10", mask_length=32, namespace=ns, status=active, type="host",
        )

        # Promote an A record pointing at that IP.
        f = self._make_finding([
            {"name": "scanned.example.com.", "ttl": "3600", "type": "A", "value": "198.51.100.10"},
        ])
        promote_finding(f)

        # The killer query: A records whose ip_address is the same IP our
        # scanner discovered. In real life this would be a powerful filter:
        # "show me all DNS A records for hosts we've fingerprinted."
        scanned_ips = DiscoveredHost.objects.values_list("ip_address", flat=True)
        cross_refs = ARecord.objects.filter(ip_address__host__in=list(scanned_ips))
        self.assertEqual(cross_refs.count(), 1)
        self.assertEqual(cross_refs.first().name, "scanned")

        # And the reverse — from the host, find DNS records pointing here.
        # This is what the new DiscoveredHostDnsRecordsPanel uses.
        records = self.host.dns_records_pointing_here
        self.assertEqual(len(records["a"]), 1)
        self.assertEqual(records["a"][0].ip_address, ip)
