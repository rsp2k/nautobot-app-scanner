"""Choice sets for nautobot_scanner models.

All choice classes inherit from Nautobot's `ChoiceSet` so they integrate with
the forms/tables/filters machinery and produce stable, queryable string values
(never raw integers) for the API.
"""

from nautobot.apps.choices import ChoiceSet


class AgentTypeChoices(ChoiceSet):
    """How a ScannerAgent executes scans."""

    LOCAL = "local"
    REMOTE = "remote"

    CHOICES = (
        (LOCAL, "Local (in Nautobot worker)"),
        (REMOTE, "Remote (standalone agent)"),
    )


class ScanTypeChoices(ChoiceSet):
    """Coarse classification of what a ScanProfile is meant to do.

    These map roughly to nmap operating modes — useful for filtering and for
    panel rendering decisions, but `nmap_arguments` is the source of truth for
    what actually gets passed to the binary.
    """

    DISCOVERY = "discovery"  # host discovery only (-sn)
    PORT = "port"  # TCP/UDP port scan (-sS / -sU)
    VERSION = "version"  # service/version detection (-sV)
    VULN = "vuln"  # NSE vuln scripts (--script vuln, vulners, etc.)
    TOPOLOGY = "topology"  # traceroute (--traceroute)

    CHOICES = (
        (DISCOVERY, "Host discovery"),
        (PORT, "Port scan"),
        (VERSION, "Service / version detection"),
        (VULN, "Vulnerability scripts"),
        (TOPOLOGY, "Topology / traceroute"),
    )


class TimingTemplateChoices(ChoiceSet):
    """nmap -T0..-T5 timing templates (paranoid through insane)."""

    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"

    CHOICES = (
        (T0, "T0 — Paranoid (IDS evasion)"),
        (T1, "T1 — Sneaky"),
        (T2, "T2 — Polite"),
        (T3, "T3 — Normal (default)"),
        (T4, "T4 — Aggressive"),
        (T5, "T5 — Insane"),
    )


class ScanStateChoices(ChoiceSet):
    """Lifecycle states for a Scan record."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    CHOICES = (
        (PENDING, "Pending"),
        (RUNNING, "Running"),
        (COMPLETED, "Completed"),
        (FAILED, "Failed"),
        (CANCELLED, "Cancelled"),
    )


class ProtocolChoices(ChoiceSet):
    """L4 protocols nmap reports for DiscoveredPort."""

    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"

    CHOICES = (
        (TCP, "TCP"),
        (UDP, "UDP"),
        (SCTP, "SCTP"),
    )


class PortStateChoices(ChoiceSet):
    """Port state as reported by nmap."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"

    CHOICES = (
        (OPEN, "Open"),
        (CLOSED, "Closed"),
        (FILTERED, "Filtered"),
        (UNFILTERED, "Unfiltered"),
        (OPEN_FILTERED, "Open or filtered"),
        (CLOSED_FILTERED, "Closed or filtered"),
    )


class HostStateChoices(ChoiceSet):
    """Host reachability state as reported by nmap."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"

    CHOICES = (
        (UP, "Up"),
        (DOWN, "Down"),
        (UNKNOWN, "Unknown"),
        (SKIPPED, "Skipped"),
    )


class SeverityChoices(ChoiceSet):
    """Severity for VulnerabilityFinding.

    Default is `unknown` (not nullable) so filter/table code never has to
    branch on missing values.
    """

    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    CHOICES = (
        (UNKNOWN, "Unknown"),
        (INFO, "Informational"),
        (LOW, "Low"),
        (MEDIUM, "Medium"),
        (HIGH, "High"),
        (CRITICAL, "Critical"),
    )
