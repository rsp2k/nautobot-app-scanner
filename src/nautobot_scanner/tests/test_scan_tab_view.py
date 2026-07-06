"""Tests for the per-Scan reconciliation tab view.

The follow-up integration commit wires the view into ``urls.py``; until
then, the tests call the view through Django's ``RequestFactory``
directly so no URL registration is required. That's also faster — the
tests never go through the middleware stack, so setup is a few
milliseconds instead of a few tenths of a second.

Test targets:

1. Authed GET renders 200 and includes the undocumented IP in the body.
2. Unknown scan pk raises Http404 (which the view's real HTTP surface
   would translate to a 404 response).
3. Unauthenticated GET returns 302 (login redirect) or 403 (permission
   denial) — the mixin ordering is
   ``LoginRequiredMixin, PermissionRequiredMixin`` so anonymous users
   hit the login redirect first.
"""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone
from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace, Prefix

from nautobot_scanner.choices import (
    AgentTypeChoices,
    HostStateChoices,
    ScanTypeChoices,
    TimingTemplateChoices,
)
from nautobot_scanner.models import DiscoveredHost, Scan, ScannerAgent, ScanProfile
from nautobot_scanner.views_scan_tab import ScanReconciliationTabView


@override_settings(ALLOWED_HOSTS=["*"])
class ScanReconciliationTabViewTests(TestCase):
    """Exercise ScanReconciliationTabView through RequestFactory.

    Same fixture shape as ``test_reconciliation.py`` — a local agent, a
    profile, a completed scan, one undocumented DiscoveredHost inside a
    Prefix.
    """

    @classmethod
    def setUpTestData(cls):
        active = Status.objects.get(name="Active")
        cls.agent = ScannerAgent.objects.create(
            name="tab-view-test",
            agent_type=AgentTypeChoices.LOCAL,
            status=active,
        )
        cls.profile = ScanProfile.objects.create(
            name="tab-view-discovery",
            scan_type=ScanTypeChoices.DISCOVERY,
            nmap_arguments="-sn",
            timing_template=TimingTemplateChoices.T3,
        )
        cls.scan = Scan.objects.create(
            agent=cls.agent,
            profile=cls.profile,
            completed_at=timezone.now(),
        )
        cls.namespace = Namespace.objects.get(name="Global")
        Prefix.objects.create(
            prefix="192.168.42.0/24",
            namespace=cls.namespace,
            status=active,
            description="tab-view test VLAN",
        )
        DiscoveredHost.objects.create(
            scan=cls.scan,
            ip_address="192.168.42.10",
            host_state=HostStateChoices.UP,
            hostname="undocumented-tab-a",
        )
        cls.active = active

    def setUp(self):
        self.factory = RequestFactory()

    @staticmethod
    def _make_user(with_perm: bool = True):
        User = get_user_model()
        # Randomize username so parallel tests don't collide on the unique index.
        # Nautobot 3.x uses ObjectPermissions (not Django's user_permissions)
        # in most view paths, so the simple "add view_discoveredhost to
        # user_permissions" pattern that works for stock Django doesn't
        # cover the full mixin. Sidestep by making the test user superuser
        # when the permission is required — this exercises the view logic
        # cleanly; permission-gate correctness is tested separately by
        # test_unauth_get_is_denied where no user is set at all.
        user = User.objects.create_user(username=f"tab-tester-{uuid.uuid4().hex[:8]}")
        if with_perm:
            user.is_superuser = True
            user.save()
        return user

    # ------------------------------------------------------------------

    def test_authed_get_renders_200_with_undocumented_ip(self):
        """Happy path — authed user sees the reconciliation content."""
        user = self._make_user(with_perm=True)
        request = self.factory.get(f"/scans/{self.scan.pk}/reconciliation/")
        request.user = user

        response = ScanReconciliationTabView.as_view()(request, pk=self.scan.pk)

        self.assertEqual(response.status_code, 200)
        # render() lazily materializes TemplateResponse; harmless if already rendered.
        if hasattr(response, "render") and not getattr(response, "is_rendered", False):
            response.render()
        body = response.content.decode("utf-8")
        self.assertIn("192.168.42.10", body,
                      "Undocumented IP should appear in the tab body.")
        self.assertIn("Reconciliation", body,
                      "Tab header should mention 'Reconciliation'.")

    def test_authed_get_empty_scan_shows_empty_state(self):
        """A scan with no undocumented hosts should render the empty-state copy."""
        empty_scan = Scan.objects.create(
            agent=self.agent, profile=self.profile,
            completed_at=timezone.now(),
        )
        user = self._make_user(with_perm=True)
        request = self.factory.get(f"/scans/{empty_scan.pk}/reconciliation/")
        request.user = user

        response = ScanReconciliationTabView.as_view()(request, pk=empty_scan.pk)

        self.assertEqual(response.status_code, 200)
        if hasattr(response, "render") and not getattr(response, "is_rendered", False):
            response.render()
        body = response.content.decode("utf-8")
        self.assertIn("No undocumented hosts", body,
                      "Zero-row scan should render the empty-state copy.")

    def test_unknown_scan_pk_raises_404(self):
        """Nonexistent scan → Http404, which HTTP surface translates to 404."""
        user = self._make_user(with_perm=True)
        bogus_pk = uuid.uuid4()
        request = self.factory.get(f"/scans/{bogus_pk}/reconciliation/")
        request.user = user
        with self.assertRaises(Http404):
            ScanReconciliationTabView.as_view()(request, pk=bogus_pk)

    def test_anonymous_user_redirects_or_forbids(self):
        """Unauth GET → 302 (login redirect) or 403.

        LoginRequiredMixin's default is a redirect to LOGIN_URL, so 302
        is the expected code — but we accept 403 to stay portable if a
        deployment overrides the mixin behavior.
        """
        request = self.factory.get(f"/scans/{self.scan.pk}/reconciliation/")
        request.user = AnonymousUser()

        response = ScanReconciliationTabView.as_view()(request, pk=self.scan.pk)
        self.assertIn(
            response.status_code, (302, 403),
            f"Expected redirect or forbidden for anonymous user, got {response.status_code}.",
        )

    def test_authed_but_no_perm_gets_403(self):
        """Authed-but-unprivileged user should not see reconciliation data.

        ``PermissionRequiredMixin.handle_no_permission`` raises
        ``PermissionDenied`` when the user is authenticated (Django's
        middleware translates that to a 403 at the HTTP layer). Without
        middleware in this factory-driven test, we assert on the raise.
        """
        user = self._make_user(with_perm=False)
        request = self.factory.get(f"/scans/{self.scan.pk}/reconciliation/")
        request.user = user

        with self.assertRaises(PermissionDenied):
            ScanReconciliationTabView.as_view()(request, pk=self.scan.pk)
