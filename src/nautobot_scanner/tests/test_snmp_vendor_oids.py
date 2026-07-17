"""Tests for nautobot_scanner.snmp_vendor_oids.

Locks in the four properties vendor_from_oid() promises:

1. Basic vendor match — a well-known enterprise number returns the
   right (vendor, device_type_hint) tuple.
2. Longest-prefix-match — Dell iDRAC (a sub-tree) wins over the Dell
   root when both match the same OID.
3. Leading-dot tolerance — ``.1.3.6.1.…`` and ``1.3.6.1.…`` return
   the same result.
4. No-match returns None (not raises).

Plus the ``all_camera_vendors()`` helper exhaustively lists the
camera-tagged entries.
"""

from __future__ import annotations

import unittest

from nautobot_scanner.snmp_vendor_oids import (
    VENDOR_OIDS,
    all_camera_vendors,
    vendor_from_oid,
)


class TestVendorFromOid(unittest.TestCase):
    """Direct lookup semantics."""

    # --- Basic vendor matches, one per major category -------------------

    def test_cisco_root_matches(self):
        """A raw Cisco enterprise-number OID returns the Cisco tuple."""
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.9"),
            ("Cisco", "network-equipment"),
        )

    def test_cisco_subtree_matches(self):
        """A specific Cisco product OID matches via prefix."""
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.9.1.1745"),  # Catalyst 3650 series
            ("Cisco", "network-equipment"),
        )

    def test_axis_camera_matches(self):
        """Axis cameras land in the 'camera' hint category."""
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.368.1.1.6.2.1"),  # Axis network camera OID subtree
            ("Axis", "camera"),
        )

    def test_uniview_camera_matches(self):
        """Uniview cameras land in the 'camera' hint category."""
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.31460.1.20.7"),
            ("Uniview", "camera"),
        )

    def test_apc_ups_matches(self):
        """APC UPSes land in the 'ups' hint category."""
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.318.1.1.1.1.1.1.0"),  # sysDescr location on APC PDU
            ("APC", "ups"),
        )

    # --- Longest-prefix-match: sub-tree wins over root -----------------

    def test_dell_idrac_beats_dell_root(self):
        """Dell iDRAC's deep subtree (1.3.6.1.4.1.674.10892) wins over Dell root (1.3.6.1.4.1.674)."""
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.674.10892.5.4.100.1"),
            ("Dell iDRAC", "server"),
        )
        # Confirm plain Dell root still matches when the deeper subtree isn't present
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.674.999.1"),  # some other Dell subtree
            ("Dell", "server"),
        )

    def test_cisco_wlc_distinct_from_cisco_root(self):
        """Cisco WLC's separate enterprise number (14179) doesn't collide with Cisco root (9)."""
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.14179.2.1.4.0"),
            ("Cisco WLC", "wireless-ap"),
        )
        # Cisco root still returns network-equipment
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.9.5.1.3.1.1.4"),
            ("Cisco", "network-equipment"),
        )

    # --- Leading-dot tolerance ----------------------------------------

    def test_leading_dot_stripped(self):
        """Both '.1.3.6.…' and '1.3.6.…' produce the same result."""
        with_dot = vendor_from_oid(".1.3.6.1.4.1.9.1.1745")
        without_dot = vendor_from_oid("1.3.6.1.4.1.9.1.1745")
        self.assertEqual(with_dot, without_dot)
        self.assertEqual(with_dot, ("Cisco", "network-equipment"))

    # --- No-match returns None ----------------------------------------

    def test_unknown_enterprise_returns_none(self):
        """An enterprise number not in the table returns None, not raises."""
        # 99999 is not an assigned IANA enterprise number as of writing.
        self.assertIsNone(vendor_from_oid("1.3.6.1.4.1.99999"))

    def test_completely_off_tree_returns_none(self):
        """Something not even in the private-enterprises subtree returns None."""
        self.assertIsNone(vendor_from_oid("1.3.6.1.2.1.1.1.0"))  # standard sysDescr, no vendor prefix

    def test_empty_string_returns_none(self):
        """Empty input is graceful."""
        self.assertIsNone(vendor_from_oid(""))

    # --- Avoid false-positive prefix collisions ------------------------

    def test_partial_digit_match_does_not_collide(self):
        """OID '1.3.6.1.4.1.99' should NOT match the Cisco root '1.3.6.1.4.1.9'.

        Both start with the digits '1.3.6.1.4.1.9', but the '99' case
        has a distinct enterprise number. Guard: match only on full
        component boundary, not string startswith.
        """
        self.assertIsNone(vendor_from_oid("1.3.6.1.4.1.99"))
        # And the Cisco root itself still matches
        self.assertEqual(
            vendor_from_oid("1.3.6.1.4.1.9"),
            ("Cisco", "network-equipment"),
        )


class TestCameraVendorHelper(unittest.TestCase):
    """all_camera_vendors() returns exactly the camera-tagged entries."""

    def test_axis_uniview_hikvision_bosch_vivotek_present(self):
        """The known camera vendors all appear."""
        cameras = set(all_camera_vendors())
        expected = {"Axis", "Uniview", "Hikvision", "Bosch", "Vivotek"}
        self.assertEqual(cameras, expected)

    def test_non_camera_vendors_absent(self):
        """Cisco / APC / Dell should NOT appear in the camera list."""
        cameras = set(all_camera_vendors())
        for non_camera in ("Cisco", "APC", "Dell", "Juniper", "HP", "Lexmark"):
            self.assertNotIn(non_camera, cameras)


class TestTableIntegrity(unittest.TestCase):
    """Structural checks on the VENDOR_OIDS table itself."""

    def test_all_prefixes_dotted_form(self):
        """Every table key is a dotted OID string, not a leading-dot form."""
        for prefix in VENDOR_OIDS:
            self.assertFalse(prefix.startswith("."), f"prefix {prefix!r} shouldn't have leading dot")
            self.assertTrue(prefix.startswith("1.3.6.1.4.1."),
                            f"prefix {prefix!r} should be in the private-enterprises subtree")

    def test_hints_are_from_known_set(self):
        """Every device_type_hint is one of the documented categories."""
        known_hints = {
            "camera", "network-equipment", "server-or-printer", "printer",
            "server", "ups", "phone", "wireless-ap", "unknown",
        }
        for prefix, (vendor, hint) in VENDOR_OIDS.items():
            self.assertIn(hint, known_hints,
                          f"prefix {prefix!r} ({vendor}) has unknown hint {hint!r}")
