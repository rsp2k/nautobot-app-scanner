"""Scanner agent and reusable scan-profile models.

A `ScannerAgent` is the identity of a scan executor — either local (nmap in
the Nautobot worker) or remote (a standalone agent in an isolated network
segment, authenticated by a DRF Token on its auto-created `auth.User`).

A `ScanProfile` is a reusable nmap argument template (e.g., "discovery"
scans `-sn`, "full TCP version scan" `-sS -sV --top-ports 1000`). Profiles
are referenced by Scan records so a single profile change cascades to all
future scans using it.
"""

from django.conf import settings
from django.db import models
from nautobot.apps.constants import CHARFIELD_MAX_LENGTH
from nautobot.apps.models import PrimaryModel
from nautobot.extras.models import StatusField
from nautobot.extras.utils import extras_features

from nautobot_scanner.choices import AgentTypeChoices, ScanTypeChoices, TimingTemplateChoices, ToolChoices
from nautobot_scanner.utils import get_default_status


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "statuses",
    "webhooks",
)
class ScannerAgent(PrimaryModel):
    """A scan executor — either in-worker (local) or a registered remote process."""

    name = models.CharField(max_length=CHARFIELD_MAX_LENGTH, unique=True)
    agent_type = models.CharField(
        max_length=16,
        choices=AgentTypeChoices,
        default=AgentTypeChoices.LOCAL,
        help_text="Local agents run nmap in the Nautobot worker; remote agents authenticate by Token.",
    )
    status = StatusField(
        on_delete=models.PROTECT,
        related_name="%(app_label)s_%(class)s_related",
        default=get_default_status,
    )
    location = models.ForeignKey(
        to="dcim.Location",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
        help_text="Optional — where the agent is physically deployed.",
    )
    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scanner_agent",
        help_text="Bound user account; the DRF Token on this user is the agent's bearer credential. Auto-created for remote agents.",
    )
    last_seen = models.DateTimeField(null=True, blank=True, db_index=True)
    expected_checkin_interval_seconds = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=(
            "How often this agent is expected to check in. MarkStaleAgents flags the "
            "agent Offline once last_seen exceeds 3× this value. Leave blank to use the "
            "plugin-wide default (PLUGINS_CONFIG['nautobot_scanner']['agent_checkin_interval_seconds'])."
        ),
    )
    version = models.CharField(max_length=64, blank=True, help_text="Agent software version reported at checkin.")
    capabilities = models.JSONField(
        default=dict,
        blank=True,
        help_text="Free-form dict reported at checkin (nmap version, NSE scripts available, OS, etc.).",
    )
    description = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)

    natural_key_field_names = ["name"]

    class Meta:
        """Meta options."""

        ordering = ("name",)
        verbose_name = "scanner agent"
        verbose_name_plural = "scanner agents"

    def __str__(self) -> str:
        """Display string."""
        return self.name


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class ScanProfile(PrimaryModel):
    """Reusable probe-tool argument template.

    Originally nmap-only; Phase G generalized to any tool the agent
    image bundles. ``tool`` defaults to ``nmap`` so existing seeded
    profiles continue to work without migration data. New tools
    (``dig``, ``masscan``, etc.) leave ``nmap_arguments`` blank and use
    ``tool_arguments`` instead — the dispatch path picks one based on
    ``tool``.
    """

    name = models.CharField(max_length=CHARFIELD_MAX_LENGTH, unique=True)
    scan_type = models.CharField(
        max_length=16,
        choices=ScanTypeChoices,
        help_text="Coarse classification — actual behavior is determined by nmap_arguments.",
    )
    # Phase G: which underlying probe tool this profile invokes. Defaults
    # to nmap for back-compat with every pre-Phase-G profile (the seed
    # migrations 0002, 0005, 0010 all create nmap-shaped profiles).
    tool = models.CharField(
        max_length=24,
        choices=ToolChoices,
        default=ToolChoices.NMAP,
        db_index=True,
        help_text=(
            "Which probe tool the agent runs for this profile. "
            "Defaults to 'nmap' for back-compat; pick another value to "
            "use a different tool from the agent's netshoot toolkit "
            "(dig, masscan, curl, mtr, openssl-s_client, ...)."
        ),
    )
    nmap_arguments = models.TextField(
        blank=True,
        help_text=(
            "Raw nmap flags (e.g. '-sS -sV --top-ports 1000') — only "
            "used when tool='nmap'. Target list is appended by the "
            "backend. Leave blank for non-nmap profiles."
        ),
    )
    # Phase G: generic argument string used when tool != 'nmap'. Kept
    # separate from nmap_arguments so each can be validated against the
    # right tool's syntax independently.
    tool_arguments = models.TextField(
        blank=True,
        help_text=(
            "Arguments for the chosen tool when it's not nmap. "
            "Example for tool='dig': '-t AXFR @1.2.3.4'. "
            "Example for tool='masscan': '-p 0-65535 --rate=10000'. "
            "Target list is appended by the backend."
        ),
    )
    timing_template = models.CharField(
        max_length=4,
        choices=TimingTemplateChoices,
        default=TimingTemplateChoices.T3,
        help_text="nmap -T0..-T5; controls aggressiveness and detection footprint.",
    )
    enabled_scripts = models.JSONField(
        default=list,
        blank=True,
        help_text="List of NSE script names or categories (e.g. ['vulners', 'http-title']).",
    )
    description = models.CharField(max_length=CHARFIELD_MAX_LENGTH, blank=True)

    # ----- Phase I: pentest / red-team mode fields -----
    # Each maps directly to an nmap flag. All have empty/false defaults
    # so the existing seeded profiles are unaffected. Dispatching ANY
    # profile that sets one or more of these flags requires the new
    # ``use_pentest_profiles`` permission — see _is_pentest_mode() below.
    decoy_addresses = models.TextField(
        blank=True,
        help_text=(
            "nmap -D: comma-separated IPs to spoof as additional source "
            "addresses alongside the agent's real address. Use 'ME' to "
            "position the real address in the decoy list. Example: "
            "'192.0.2.1,192.0.2.2,ME,192.0.2.3'. PENTEST MODE."
        ),
    )
    fragment_packets = models.BooleanField(
        default=False,
        help_text="nmap -f: fragment outgoing packets to confuse simple IDS rules. PENTEST MODE.",
    )
    mtu = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text=(
            "nmap --mtu N: fragment with custom MTU (must be a multiple "
            "of 8). Overrides -f when set. PENTEST MODE."
        ),
    )
    source_port = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text=(
            "nmap --source-port N: spoof a specific source port for "
            "outgoing probes. Useful for bypassing rules that allow "
            "traffic from common-service source ports (53, 88, 443). "
            "PENTEST MODE."
        ),
    )
    idle_scan_zombie = models.CharField(
        max_length=64,
        blank=True,
        help_text=(
            "nmap -sI <ip>: idle scan via a zombie host. Routes all "
            "probes through the zombie so the target sees the zombie "
            "as the attacker. Only one zombie per profile. PENTEST MODE."
        ),
    )

    natural_key_field_names = ["name"]

    class Meta:
        """Meta options."""

        ordering = ("name",)
        verbose_name = "scan profile"
        verbose_name_plural = "scan profiles"
        # Phase I: gate dispatch of pentest-flagged profiles behind an
        # explicit Django permission. The dispatch path checks this
        # against the user that triggered the scan; without it, the
        # scan is rejected before any nmap argv is constructed.
        permissions = [
            (
                "use_pentest_profiles",
                "Can dispatch scan profiles using pentest flags "
                "(decoys, fragmentation, idle scan, custom MTU/source-port). "
                "Restricted because these flags are dual-use and "
                "misuse can violate scanning authorization.",
            ),
        ]

    def __str__(self) -> str:
        """Display string."""
        return self.name

    # Phase J: tool-shapes that are recon-aggressive enough to auto-trip
    # the pentest gate regardless of any nmap-specific flags being set.
    # masscan at 10M pps is unmistakable to any IDS; profiles that use it
    # should require the same legal-authorization permission as nmap-decoy
    # / fragmentation / idle-scan profiles. Add new entries here when
    # another tool earns the same warning.
    PENTEST_TOOLS = frozenset({"masscan"})

    @property
    def is_pentest_mode(self) -> bool:
        """True when any pentest-class flag is set OR the tool is recon-aggressive.

        Used by dispatch + UI gating: pentest-mode profiles render a
        yellow banner, require ``nautobot_scanner.use_pentest_profiles``
        to dispatch, and stamp Scan.was_pentest_mode = True at runtime
        for filterable audit queries.
        """
        if self.tool in self.PENTEST_TOOLS:
            return True
        return bool(
            self.decoy_addresses
            or self.fragment_packets
            or self.mtu
            or self.source_port
            or self.idle_scan_zombie,
        )
