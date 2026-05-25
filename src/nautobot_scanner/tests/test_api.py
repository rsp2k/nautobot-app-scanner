"""Tests for nautobot_scanner agent endpoints.

The race-protection test is the headline one — the Plan agent's review
flagged double-ingest from retried agent POSTs as a real failure mode,
and these tests prove the select_for_update + one-shot token combination
catches it.
"""

import uuid
from pathlib import Path

from django.test import TestCase, override_settings
from django.urls import reverse
from nautobot.extras.models import Status
from nautobot.users.models import Token
from rest_framework.test import APIClient

from nautobot_scanner.choices import AgentTypeChoices, ScanStateChoices, ScanTypeChoices, TimingTemplateChoices
from nautobot_scanner.models import DiscoveredHost, Scan, ScannerAgent, ScanProfile

FIXTURES = Path(__file__).parent / "fixtures"


def _xml(name: str) -> str:
    return (FIXTURES / name).read_text()


@override_settings(ALLOWED_HOSTS=["*"])
class AgentEndpointTestBase(TestCase):
    """Shared setup — one remote agent + token + profile + pending scan.

    `ALLOWED_HOSTS=["*"]` because Nautobot's test runner doesn't auto-add
    'testserver' to the hosts list the way Django's stock runner does, and
    APIClient defaults to Host: testserver.
    """

    def setUp(self):
        active = Status.objects.get(name="Active")
        # Creating a remote agent triggers the auto-User signal.
        self.agent = ScannerAgent.objects.create(
            name="remote-test",
            agent_type=AgentTypeChoices.REMOTE,
            status=active,
        )
        self.agent.refresh_from_db()
        self.assertIsNotNone(self.agent.user, "Signal should auto-create a User for remote agents")
        self.token = Token.objects.get(user=self.agent.user)

        self.profile = ScanProfile.objects.create(
            name="discovery",
            scan_type=ScanTypeChoices.DISCOVERY,
            nmap_arguments="-sn",
            timing_template=TimingTemplateChoices.T3,
        )
        self.scan = Scan.objects.create(
            agent=self.agent,
            profile=self.profile,
            status=ScanStateChoices.PENDING,
        )
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")


class TestPendingScansEndpoint(AgentEndpointTestBase):
    """GET /agents/<id>/pending-scans/."""

    def test_returns_pending_scan_and_transitions_to_running(self):
        url = reverse("plugins-api:nautobot_scanner-api:agent_pending_scans", kwargs={"pk": self.agent.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], str(self.scan.pk))
        self.assertEqual(data[0]["profile"]["nmap_arguments"], "-sn")

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, ScanStateChoices.RUNNING)
        self.assertIsNotNone(self.scan.started_at)

    def test_second_call_does_not_return_already_picked_scan(self):
        url = reverse("plugins-api:nautobot_scanner-api:agent_pending_scans", kwargs={"pk": self.agent.pk})
        first = self.client.get(url).json()
        second = self.client.get(url).json()
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 0, "Pending scan should only be handed out once")

    def test_other_agents_token_rejected(self):
        """Token bound to agent A can't poll for agent B's scans."""
        other_agent = ScannerAgent.objects.create(
            name="other-remote",
            agent_type=AgentTypeChoices.REMOTE,
            status=Status.objects.get(name="Active"),
        )
        other_agent.refresh_from_db()
        url = reverse("plugins-api:nautobot_scanner-api:agent_pending_scans", kwargs={"pk": other_agent.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)


class TestScanIngestRaceProtection(AgentEndpointTestBase):
    """POST /scans/<id>/ingest/ — the critical race-protection path."""

    def _ingest(self, token, body=None):
        url = reverse("plugins-api:nautobot_scanner-api:scan_ingest", kwargs={"pk": self.scan.pk})
        return self.client.post(
            url,
            data=body if body is not None else _xml("discovery.xml"),
            content_type="application/xml",
            HTTP_X_INGESTION_TOKEN=str(token),
        )

    def setUp(self):
        super().setUp()
        # Move scan to running state (as if pending-scans pop already happened).
        self.scan.status = ScanStateChoices.RUNNING
        self.scan.save(update_fields=["status"])
        self.ingest_token = self.scan.ingestion_token  # captured from default uuid4

    def test_first_ingest_succeeds_and_clears_token(self):
        response = self._ingest(self.ingest_token)
        self.assertEqual(response.status_code, 200, response.content)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, ScanStateChoices.COMPLETED)
        self.assertIsNone(self.scan.ingestion_token, "Token should be cleared after consumption")
        self.assertEqual(DiscoveredHost.objects.filter(scan=self.scan).count(), 3)

    def test_second_ingest_with_same_token_rejected(self):
        """The headline race-protection test — retry after success is denied."""
        first = self._ingest(self.ingest_token)
        self.assertEqual(first.status_code, 200)

        second = self._ingest(self.ingest_token)
        self.assertEqual(second.status_code, 403, "Second ingest with consumed token must be denied")

        # Idempotency check — no duplicate hosts inserted.
        self.scan.refresh_from_db()
        self.assertEqual(DiscoveredHost.objects.filter(scan=self.scan).count(), 3)

    def test_wrong_token_rejected(self):
        response = self._ingest(uuid.uuid4())  # fresh uuid that's not on the scan
        self.assertEqual(response.status_code, 403)

    def test_missing_token_header_rejected(self):
        url = reverse("plugins-api:nautobot_scanner-api:scan_ingest", kwargs={"pk": self.scan.pk})
        response = self.client.post(url, data=_xml("discovery.xml"), content_type="application/xml")
        self.assertEqual(response.status_code, 400)

    def test_malformed_xml_rejected_without_touching_scan(self):
        response = self._ingest(self.ingest_token, body="<not even valid")
        self.assertEqual(response.status_code, 400)
        self.scan.refresh_from_db()
        # Scan stayed in running state — no partial state.
        self.assertEqual(self.scan.status, ScanStateChoices.RUNNING)
        self.assertIsNotNone(self.scan.ingestion_token, "Token preserved on parse failure")


class TestAgentCheckin(AgentEndpointTestBase):
    """POST /agents/<id>/checkin/."""

    def test_checkin_updates_last_seen(self):
        url = reverse("plugins-api:nautobot_scanner-api:agent_checkin", kwargs={"pk": self.agent.pk})
        response = self.client.post(
            url,
            data={"version": "agent-test-1", "capabilities": {"nmap": "7.94"}},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.agent.refresh_from_db()
        self.assertIsNotNone(self.agent.last_seen)
        self.assertEqual(self.agent.version, "agent-test-1")
        self.assertEqual(self.agent.capabilities, {"nmap": "7.94"})


@override_settings(
    ALLOWED_HOSTS=["*"],
    REST_FRAMEWORK={"DEFAULT_AUTHENTICATION_CLASSES": []},
)
class TestAuthRequired(TestCase):
    """Unauthenticated requests get 401, not the agent's data."""

    def test_anonymous_pending_scans_401(self):
        # Use a fresh ScannerAgent for the URL.
        active = Status.objects.get(name="Active")
        agent = ScannerAgent.objects.create(
            name="another-remote",
            agent_type=AgentTypeChoices.REMOTE,
            status=active,
        )
        client = APIClient()  # no auth credentials
        url = reverse("plugins-api:nautobot_scanner-api:agent_pending_scans", kwargs={"pk": agent.pk})
        response = client.get(url)
        # 401 if auth required, 403 if not — either is acceptable; key is "not 200".
        self.assertIn(response.status_code, (401, 403))
