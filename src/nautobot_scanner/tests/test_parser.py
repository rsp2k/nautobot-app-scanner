"""Pure-function tests for nautobot_scanner.parser.

These tests run without the Django test runner — they just import the
parser module and feed it fixture XML, asserting on the returned
dataclasses. The persist() function is exercised separately (when present)
in a TransactionTestCase that uses the ORM.
"""

from pathlib import Path
from unittest import TestCase

from nautobot_scanner.choices import (
    HostStateChoices,
    PortStateChoices,
    ProtocolChoices,
    SeverityChoices,
)
from nautobot_scanner.parser import parse_xml

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


class TestParseDiscovery(TestCase):
    """Host-discovery scan: -sn output, no ports."""

    def test_three_hosts_two_up_one_down(self):
        hosts = parse_xml(_load("discovery.xml"))
        self.assertEqual(len(hosts), 3)
        states = sorted(h.host_state for h in hosts)
        self.assertEqual(states, [HostStateChoices.DOWN, HostStateChoices.UP, HostStateChoices.UP])

    def test_hostnames_populated_from_ptr(self):
        hosts = parse_xml(_load("discovery.xml"))
        by_ip = {h.ip_address: h for h in hosts}
        self.assertEqual(by_ip["192.0.2.1"].hostname, "gateway.example")
        self.assertEqual(by_ip["192.0.2.2"].hostname, "host2.example")
        # Down host has no PTR — should be empty string, not None
        self.assertEqual(by_ip["192.0.2.3"].hostname, "")

    def test_mac_address_populated_when_arp_resolved(self):
        hosts = parse_xml(_load("discovery.xml"))
        by_ip = {h.ip_address: h for h in hosts}
        self.assertEqual(by_ip["192.0.2.1"].mac_address, "00:11:22:33:44:55")
        # The second host has no MAC — empty string
        self.assertEqual(by_ip["192.0.2.2"].mac_address, "")

    def test_no_ports_in_discovery_scan(self):
        hosts = parse_xml(_load("discovery.xml"))
        for h in hosts:
            self.assertEqual(h.ports, [])


class TestParseVersionScan(TestCase):
    """Service/version scan: -sV with OS detection and CPE strings."""

    def test_single_host_with_four_ports(self):
        hosts = parse_xml(_load("version_scan.xml"))
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host.ip_address, "192.0.2.10")
        self.assertEqual(len(host.ports), 4)

    def test_port_states_and_protocols(self):
        host = parse_xml(_load("version_scan.xml"))[0]
        by_port = {(p.port, p.protocol): p for p in host.ports}
        self.assertEqual(by_port[(22, ProtocolChoices.TCP)].state, PortStateChoices.OPEN)
        self.assertEqual(by_port[(80, ProtocolChoices.TCP)].state, PortStateChoices.OPEN)
        self.assertEqual(by_port[(443, ProtocolChoices.TCP)].state, PortStateChoices.FILTERED)
        self.assertEqual(by_port[(53, ProtocolChoices.UDP)].state, PortStateChoices.CLOSED)

    def test_service_fingerprint_fields_populated(self):
        host = parse_xml(_load("version_scan.xml"))[0]
        ssh = next(p for p in host.ports if p.port == 22)
        self.assertEqual(ssh.service_name, "ssh")
        self.assertEqual(ssh.product, "OpenSSH")
        self.assertEqual(ssh.version, "9.6p1")
        self.assertEqual(ssh.extra_info, "Debian 4")
        self.assertIn("cpe:/a:openbsd:openssh:9.6p1", ssh.cpe)

    def test_os_detection(self):
        host = parse_xml(_load("version_scan.xml"))[0]
        self.assertEqual(host.os_family, "Linux")
        self.assertEqual(host.os_type, "Linux 5.15 - 6.5")
        self.assertEqual(host.os_accuracy, 95)


class TestParseVulnScan(TestCase):
    """NSE vulnerability script output (vulners format)."""

    def test_vulners_findings_attached_to_port(self):
        host = parse_xml(_load("vuln_scan.xml"))[0]
        port_80 = next(p for p in host.ports if p.port == 80)
        # Two scripts: vulners + http-title
        self.assertEqual(len(port_80.vulnerabilities), 2)

    def test_vulners_severity_promoted_to_critical_from_98_score(self):
        host = parse_xml(_load("vuln_scan.xml"))[0]
        port_80 = next(p for p in host.ports if p.port == 80)
        vulners = next(v for v in port_80.vulnerabilities if v.nse_script == "vulners")
        # Highest score in our fixture is 9.8 → critical
        self.assertEqual(vulners.severity, SeverityChoices.CRITICAL)

    def test_vulners_extracts_references_from_output(self):
        host = parse_xml(_load("vuln_scan.xml"))[0]
        port_80 = next(p for p in host.ports if p.port == 80)
        vulners = next(v for v in port_80.vulnerabilities if v.nse_script == "vulners")
        self.assertIn("https://vulners.com/cve/CVE-2021-44790", vulners.references)
        self.assertIn("https://vulners.com/cve/CVE-2022-22720", vulners.references)
        self.assertIn("https://vulners.com/cve/CVE-2020-11984", vulners.references)

    def test_http_title_classified_as_info(self):
        host = parse_xml(_load("vuln_scan.xml"))[0]
        port_80 = next(p for p in host.ports if p.port == 80)
        http_title = next(v for v in port_80.vulnerabilities if v.nse_script == "http-title")
        self.assertEqual(http_title.severity, SeverityChoices.INFO)


class TestParseEdgeCases(TestCase):
    """Empty / malformed / no-host inputs."""

    def test_empty_string_returns_empty_list(self):
        self.assertEqual(parse_xml(""), [])
        self.assertEqual(parse_xml("   \n\n"), [])

    def test_malformed_xml_raises_valueerror(self):
        with self.assertRaises(ValueError):
            parse_xml("<not even close to nmap xml>")


class TestParseTestsslJson(TestCase):
    """Phase L: testssl.sh deep TLS audit parser.

    Fixture captured against example.com:443 via:
        docker exec -T web testssl --jsonfile /tmp/x.json --quiet --color 0 example.com:443
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from nautobot_scanner.parser import parse_testssl_json
        cls.parse = staticmethod(parse_testssl_json)
        cls.raw = _load("testssl-example.com.json")

    def test_multi_target_produces_one_host_per_resolved_ip(self):
        """testssl emits the same test-set per resolved IP; group accordingly."""
        _, hosts = self.parse(self.raw, ["example.com:443"])
        self.assertGreaterEqual(len(hosts), 1)
        # example.com has multiple Cloudflare edge IPs; each is its own host
        for h in hosts:
            self.assertEqual(h.host_state, "up")
            self.assertEqual(len(h.host_findings), 1)
            self.assertEqual(h.host_findings[0].nse_script, "testssl")

    def test_protocols_offered_extracted(self):
        _, hosts = self.parse(self.raw, ["example.com:443"])
        elements = hosts[0].host_findings[0].elements
        # TLS 1.2 and 1.3 should be offered by any modern cert
        self.assertIn("TLSv1.2", elements["protocols_offered"])
        self.assertIn("TLSv1.3", elements["protocols_offered"])

    def test_vulnerability_signatures_present(self):
        _, hosts = self.parse(self.raw, ["example.com:443"])
        elements = hosts[0].host_findings[0].elements
        vuln_ids = {v["id"] for v in elements["vulnerabilities"]}
        # The canonical named-vuln set: testssl runs all of these on every target
        for name in ("heartbleed", "BEAST", "POODLE_SSL", "FREAK", "DROWN", "ROBOT"):
            self.assertIn(name, vuln_ids)

    def test_severity_rolls_up_to_worst_per_test(self):
        _, hosts = self.parse(self.raw, ["example.com:443"])
        finding = hosts[0].host_findings[0]
        # Fixture has at least one HIGH row (severity_counts confirms)
        self.assertIn(finding.severity, ("medium", "high", "critical"))
        self.assertGreater(finding.elements["severity_counts"].get("INFO", 0), 0)

    def test_hsts_and_ocsp_flags_set(self):
        _, hosts = self.parse(self.raw, ["example.com:443"])
        elements = hosts[0].host_findings[0].elements
        self.assertIn(elements["hsts"], ("present", "absent"))
        self.assertIn(elements["ocsp_stapling"], ("present", "absent", "unknown"))

    def test_empty_input_returns_empty_list(self):
        _, hosts = self.parse("", ["example.com:443"])
        self.assertEqual(hosts, [])
        _, hosts = self.parse("not json", ["example.com:443"])
        self.assertEqual(hosts, [])


class TestParseSshAuditJson(TestCase):
    """Phase L: ssh-audit deep SSH server audit parser.

    Fixture captured against github.com via:
        docker exec -T web ssh-audit -j github.com
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from nautobot_scanner.parser import parse_ssh_audit_json
        cls.parse = staticmethod(parse_ssh_audit_json)
        cls.raw = _load("ssh-audit-github.com.json")

    def test_single_target_produces_one_host(self):
        _, hosts = self.parse(self.raw, ["github.com"])
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].host_state, "up")
        self.assertEqual(len(hosts[0].host_findings), 1)
        self.assertEqual(hosts[0].host_findings[0].nse_script, "ssh-audit")

    def test_banner_and_algorithm_lists_populated(self):
        _, hosts = self.parse(self.raw, ["github.com"])
        elements = hosts[0].host_findings[0].elements
        self.assertTrue(elements["banner"].startswith("SSH-2."))
        # GitHub offers a known set of algos
        self.assertGreater(len(elements["kex_algos"]), 0)
        self.assertGreater(len(elements["host_keys"]), 0)
        self.assertGreater(len(elements["macs"]), 0)
        self.assertGreater(len(elements["ciphers"]), 0)
        # Fingerprints (SHA256 + MD5 per host-key type)
        self.assertGreater(len(elements["fingerprints"]), 0)

    def test_weak_algos_extracted_with_fail_and_warn_notes(self):
        _, hosts = self.parse(self.raw, ["github.com"])
        elements = hosts[0].host_findings[0].elements
        # GitHub's daemon offers ECDH curves that ssh-audit flags
        # (NSA-suspected backdoor); the fixture has at least one such fail.
        weak = elements["weak_algos"]
        self.assertGreater(len(weak), 0)
        self.assertTrue(any(w["fail"] for w in weak))
        # Each weak-algo entry has the expected shape
        for w in weak:
            self.assertIn("category", w)
            self.assertIn("algorithm", w)
            self.assertIn(w["category"], ("kex", "key", "mac", "enc"))

    def test_severity_climbs_with_fail_notes_present(self):
        _, hosts = self.parse(self.raw, ["github.com"])
        finding = hosts[0].host_findings[0]
        # has_fail → medium (or higher)
        self.assertIn(finding.severity, ("medium", "high", "critical"))

    def test_hostname_resolved_to_ip(self):
        """Parser resolves hostname to IP for the DiscoveredHost record."""
        _, hosts = self.parse(self.raw, ["github.com"])
        ip = hosts[0].ip_address
        # Should not be the literal hostname — resolved via DNS
        self.assertNotEqual(ip, "github.com")
        # IPv4 dot-quad expected
        parts = ip.split(".")
        self.assertEqual(len(parts), 4)
        for p in parts:
            self.assertTrue(p.isdigit())

    def test_empty_input_returns_empty_list(self):
        _, hosts = self.parse("", ["github.com"])
        self.assertEqual(hosts, [])
        _, hosts = self.parse("garbage{", ["github.com"])
        self.assertEqual(hosts, [])


class TestToolRegistriesInParity(TestCase):
    """Closes the Phase J/L 'dropdown doesn't lie' invariant.

    Adding tool #8 (Phase J) and tools #9-10 (Phase L) both proved the
    server-side registries can silently drift from ToolChoices. This
    locks that down: every enum value MUST have a PARSERS entry, and
    vice-versa. The agent's TOOL_REGISTRY isn't importable here without
    the agent dir on sys.path; rely on the agent's own CI to assert
    its half.
    """

    def test_tool_choices_match_parsers(self):
        from nautobot_scanner.choices import ToolChoices
        from nautobot_scanner.parser import PARSERS

        choices = set(ToolChoices.values())
        parsers = set(PARSERS.keys())

        choices_only = choices - parsers
        parsers_only = parsers - choices

        self.assertFalse(
            choices_only,
            f"ToolChoices advertises tools with no parser: {choices_only}",
        )
        self.assertFalse(
            parsers_only,
            f"PARSERS has entries not in ToolChoices: {parsers_only}",
        )
