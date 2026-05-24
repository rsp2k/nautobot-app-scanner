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

from nautobot_scanner.choices import AgentTypeChoices, ScanTypeChoices, TimingTemplateChoices
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
    """Reusable nmap argument template."""

    name = models.CharField(max_length=CHARFIELD_MAX_LENGTH, unique=True)
    scan_type = models.CharField(
        max_length=16,
        choices=ScanTypeChoices,
        help_text="Coarse classification — actual behavior is determined by nmap_arguments.",
    )
    nmap_arguments = models.TextField(
        help_text="Raw nmap flags (e.g. '-sS -sV --top-ports 1000'). Target list is appended by the backend.",
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

    natural_key_field_names = ["name"]

    class Meta:
        """Meta options."""

        ordering = ("name",)
        verbose_name = "scan profile"
        verbose_name_plural = "scan profiles"

    def __str__(self) -> str:
        """Display string."""
        return self.name
