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
