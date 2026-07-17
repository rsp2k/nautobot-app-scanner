"""SNMP sysObjectID prefix → vendor lookup.

SNMP devices publish their vendor + product line via the
``sysObjectID`` OID (``.1.3.6.1.2.1.1.2.0``). The returned OID starts
with an **IANA enterprise number** — a globally-unique per-vendor
prefix, assigned by IANA in the private-enterprises subtree
(``.1.3.6.1.4.1.<enterprise>``). Common camera vendors:

- ``.1.3.6.1.4.1.9`` → Cisco
- ``.1.3.6.1.4.1.368`` → Axis Communications
- ``.1.3.6.1.4.1.31460`` → Uniview
- ``.1.3.6.1.4.1.36849`` → Bosch Security Systems

Longest-prefix-match: ``.1.3.6.1.4.1.9.1.1745`` (a specific Cisco
router model) matches Cisco's ``.1.3.6.1.4.1.9`` root cleanly, so we
don't need per-model entries. This module is the source-of-truth for
the fingerprint pipeline's "does this OID identify a vendor we
recognize?" question, plus the "if so, what device type is it likely
to be?" hint used by the M.2 auto-promote step.

Add a new vendor by:
    1. Look up the IANA enterprise number at
       https://www.iana.org/assignments/enterprise-numbers/
    2. Add an entry to ``VENDOR_OIDS`` below.
    3. Add a test case in ``tests/test_snmp_vendor_oids.py`` with a
       captured sysObjectID string that should match.

The table is deliberately conservative — only vendors that either
(a) have shown up in real scan output during bingham deployment, or
(b) are camera vendors (the M.2 driving use case), or (c) are common
network gear (Cisco/Juniper/etc.). Extension is easy; over-scoping
here adds maintenance load with no immediate value.
"""

from __future__ import annotations

from typing import Optional


# Mapping: enterprise-number OID prefix → (vendor_name, device_type_hint).
# Longest-prefix-match applied by vendor_from_oid() below.
#
# Format:  "<oid_prefix>": ("<vendor>", "<device_type_hint>")
#
# device_type_hint is a coarse category used by M.2's auto-promote
# step to propose a Device role. Values:
#   - "camera"              → propose role=Camera
#   - "network-equipment"   → propose role=Switch or Router (M.2 refines by product)
#   - "server-or-printer"   → propose role=Printer or Server (M.2 refines)
#   - "printer"             → propose role=Printer
#   - "server"              → propose role=Server
#   - "ups"                 → propose role=UPS
#   - "phone"               → propose role=Phone
#   - "wireless-ap"         → propose role=AccessPoint
#   - "unknown"             → don't propose (surface for operator review)
VENDOR_OIDS: dict[str, tuple[str, str]] = {
    # Network vendors — bingham's core router/switch fleet
    "1.3.6.1.4.1.9":     ("Cisco",           "network-equipment"),
    "1.3.6.1.4.1.2636":  ("Juniper",         "network-equipment"),
    "1.3.6.1.4.1.4526":  ("Netgear",         "network-equipment"),
    "1.3.6.1.4.1.6027":  ("Force10 / Dell",  "network-equipment"),
    "1.3.6.1.4.1.171":   ("D-Link",          "network-equipment"),
    "1.3.6.1.4.1.11":    ("HP",              "server-or-printer"),
    "1.3.6.1.4.1.674":   ("Dell",            "server"),
    # Camera vendors — M.2 driving use case
    "1.3.6.1.4.1.368":   ("Axis",            "camera"),
    "1.3.6.1.4.1.31460": ("Uniview",         "camera"),
    "1.3.6.1.4.1.11048": ("Hikvision",       "camera"),
    "1.3.6.1.4.1.36849": ("Bosch",           "camera"),
    "1.3.6.1.4.1.14501": ("Vivotek",         "camera"),
    # Facility infrastructure
    "1.3.6.1.4.1.318":   ("APC",             "ups"),
    "1.3.6.1.4.1.850":   ("Eaton",           "ups"),
    "1.3.6.1.4.1.1918":  ("Liebert",         "ups"),
    "1.3.6.1.4.1.641":   ("Lexmark",         "printer"),
    "1.3.6.1.4.1.367":   ("Ricoh",           "printer"),
    "1.3.6.1.4.1.1602":  ("Canon",           "printer"),
    "1.3.6.1.4.1.253":   ("Xerox",           "printer"),
    # VoIP / phones
    "1.3.6.1.4.1.6889":  ("Avaya",           "phone"),
    "1.3.6.1.4.1.6486":  ("Alcatel",         "phone"),
    # Wireless APs
    "1.3.6.1.4.1.14179": ("Cisco WLC",       "wireless-ap"),
    "1.3.6.1.4.1.14988": ("MikroTik",        "wireless-ap"),
    "1.3.6.1.4.1.7362":  ("Ruckus",          "wireless-ap"),
    "1.3.6.1.4.1.14823": ("Aruba",           "wireless-ap"),
    # Server BMC (IPMI-adjacent SNMP)
    "1.3.6.1.4.1.232":   ("HP iLO",          "server"),
    "1.3.6.1.4.1.674.10892": ("Dell iDRAC",  "server"),
    "1.3.6.1.4.1.311":   ("Microsoft",       "server"),
    "1.3.6.1.4.1.8072":  ("Net-SNMP",        "unknown"),  # Linux/BSD generic
}


def _normalize_oid(oid: str) -> str:
    """Strip a leading dot if present so both ``.1.3.6.1.4.1.9`` and ``1.3.6.1.4.1.9`` match the same table entries."""
    return oid.lstrip(".")


def vendor_from_oid(oid: str) -> Optional[tuple[str, str]]:
    """Return ``(vendor, device_type_hint)`` for an sysObjectID, or ``None``.

    Longest-prefix-match is applied so specific sub-tree entries win
    over shorter parent prefixes. For example, ``Dell iDRAC`` at
    ``1.3.6.1.4.1.674.10892`` matches before the parent Dell entry at
    ``1.3.6.1.4.1.674``.

    Args:
        oid: An sysObjectID string, with or without leading dot. Trailing
            path components (``…9.1.1745``) are fine — matching is done
            on the enterprise-number prefix.

    Returns:
        ``(vendor_name, device_type_hint)`` on match, ``None`` otherwise.
        The hint is one of the values documented at the top of the
        VENDOR_OIDS dict.

    Examples:
        >>> vendor_from_oid("1.3.6.1.4.1.9.1.1745")
        ('Cisco', 'network-equipment')

        >>> vendor_from_oid(".1.3.6.1.4.1.31460.1.20.7")
        ('Uniview', 'camera')

        >>> vendor_from_oid("1.3.6.1.4.1.674.10892.5.4.100.1")
        ('Dell iDRAC', 'server')

        >>> vendor_from_oid("1.3.6.1.4.1.99999") is None
        True
    """
    normalized = _normalize_oid(oid)

    # Longest-prefix-match. Sort prefixes by length descending so a
    # deeper sub-tree (Dell iDRAC) wins over its parent (Dell root).
    for prefix in sorted(VENDOR_OIDS.keys(), key=len, reverse=True):
        # `<prefix>` matches `<prefix>` or `<prefix>.<anything>` — but
        # NOT a wholly-different string that just happens to start with
        # the same digits (that shouldn't happen for well-formed OIDs
        # but guards against fuzzed input).
        if normalized == prefix or normalized.startswith(prefix + "."):
            return VENDOR_OIDS[prefix]

    return None


def all_camera_vendors() -> list[str]:
    """Return the names of all vendors whose device_type_hint is 'camera'.

    Used by the M.2 fusion module to flag any host whose SNMP OID
    matches a camera vendor. Order matches VENDOR_OIDS insertion order.
    """
    return [vendor for vendor, hint in VENDOR_OIDS.values() if hint == "camera"]
