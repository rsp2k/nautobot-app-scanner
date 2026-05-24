"""Model package for nautobot_scanner.

Models are split across topical modules (agents, scans, results) and
re-exported here so Django's app loading discovers them all and callers can
`from nautobot_scanner.models import ScannerAgent` regardless of where the
class actually lives. Mirrors the pattern used by nautobot-app-phones.
"""

from nautobot_scanner.models.agents import ScannerAgent, ScanProfile
from nautobot_scanner.models.results import (
    DiscoveredHost,
    DiscoveredPort,
    TraceRouteHop,
    VulnerabilityFinding,
)
from nautobot_scanner.models.scans import Scan

__all__ = [
    "DiscoveredHost",
    "DiscoveredPort",
    "Scan",
    "ScanProfile",
    "ScannerAgent",
    "TraceRouteHop",
    "VulnerabilityFinding",
]
