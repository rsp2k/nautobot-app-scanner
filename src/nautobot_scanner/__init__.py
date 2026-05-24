"""Nautobot app for nmap-based network scanning.

Runs scans against IPAM-defined targets (Prefixes, IPAddresses) using either
an in-worker local nmap process or remote agents deployed in isolated network
segments. Stores discovered hosts, ports, service fingerprints, vulnerability
findings, and traceroute hops as first-class models, and surfaces them on the
existing Device, IPAddress, and Prefix detail pages.

Discovered hosts are read-only by default. Users can explicitly promote a
discovered host into an `ipam.IPAddress` record via the Promote action.
"""

from importlib.metadata import PackageNotFoundError, version

from nautobot.apps import NautobotAppConfig

try:
    __version__ = version("nautobot-app-scanner")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"


class NautobotScannerConfig(NautobotAppConfig):
    """App configuration for nautobot-app-scanner."""

    name = "nautobot_scanner"
    verbose_name = "Scanner"
    description = "nmap-based network scanning with remote agents and IPAM integration."
    version = __version__
    author = "Ryan Malloy"
    author_email = "ryan@supported.systems"
    base_url = "scanner"
    required_settings: list[str] = []
    default_settings: dict = {
        # Default cadence (seconds) at which remote agents are expected to check in.
        # MarkStaleAgents flips status to offline when last_seen exceeds 3× this value.
        "agent_checkin_interval_seconds": 60,
        # Maximum nmap subprocess runtime for LocalBackend, in seconds.
        "local_scan_timeout_seconds": 3600,
        # TTL for cached Prefix scan-coverage summary on the prefix detail panel.
        "prefix_coverage_cache_ttl_seconds": 300,
    }
    caching_config: dict = {}

    def ready(self):
        """Wire signal handlers after the app registry is fully loaded."""
        super().ready()
        from nautobot_scanner.signals import register_signals

        register_signals()


config = NautobotScannerConfig
