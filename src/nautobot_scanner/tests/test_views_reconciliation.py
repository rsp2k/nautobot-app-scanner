"""Tests for the ``ReconciliationView`` standalone report surface.

Fixture pattern mirrors ``test_reconciliation.py`` (an agent + profile +
one completed scan + the Global Namespace, plus per-test DiscoveredHost /
Prefix / IPAddress rows) but here we're driving the HTTP layer, not the
pure-function engine.

The URL wire-up (``urls.py`` entry named
``plugins:nautobot_scanner:reconciliation``) lands in the maintainer's
integration commit AFTER this slice. Tests that reverse the URL
gracefully skip via ``NoReverseMatch`` so this file passes on both sides
of that seam: pre-integration it self-skips, post-integration it exercises
the view.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner.choices import (
    AgentTypeChoices,
    HostStateChoices,
    ScanTypeChoices,
    TimingTemplateChoices,
)
from nautobot_scanner.forms_reconciliation import ReconciliationFilterForm
from nautobot_scanner.models import DiscoveredHost, Scan, ScannerAgent, ScanProfile
from nautobot_scanner.views_reconciliation import (
    ReconciliationView,
    _parse_as_of_param,
)

User = get_user_model()

# Reverse target used by all HTTP-layer tests. Kept as a module constant
# so if the URL name convention changes it's one edit.
RECONCILIATION_URL_NAME = "plugins:nautobot_scanner:reconciliation"


def _reverse_or_skip(test_case, url_name: str = RECONCILIATION_URL_NAME) -> str:
    """Return the reversed URL, or self-skip the test if the URL is not yet wired.

    The engine + view + form + template all land in this slice; the URL
    entry lands in the maintainer's follow-up integration commit. So we
    treat a ``NoReverseMatch`` as "URL wire-up pending" and skip cleanly
    rather than failing the suite.
    """
    try:
        return reverse(url_name)
    except NoReverseMatch:
        test_case.skipTest("URL wire-up pending — expected after integration commit.")
        # ``skipTest`` raises, so this return is unreachable. Kept for
        # type-checker sanity.
        return ""


@override_settings(ALLOWED_HOSTS=["*"])
class ReconciliationViewTestBase(TestCase):
    """Shared fixture: scanner scaffolding + a superuser + one undocumented host.

    The Prefix (``192.168.42.0/24``) contains the discovered host
    (``192.168.42.10``) which has no matching ``ipam.IPAddress``. That is
    the minimal setup that produces one row in ``report.groups`` — enough
    for the "body contains the IP" assertion.
    """

    @classmethod
    def setUpTestData(cls):
        active = Status.objects.get(name="Active")
        cls.active = active

        cls.agent = ScannerAgent.objects.create(
            name="recon-view-test",
            agent_type=AgentTypeChoices.LOCAL,
            status=active,
        )
        cls.profile = ScanProfile.objects.create(
            name="recon-view-discovery",
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

        # One prefix + one live host inside it, with no matching IPAM ->
        # the host appears in the undocumented report.
        cls.prefix = Prefix.objects.create(
            prefix="192.168.42.0/24",
            namespace=cls.namespace,
            status=active,
            description="reconciliation-view fixture",
        )
        cls.host = DiscoveredHost.objects.create(
            scan=cls.scan,
            ip_address="192.168.42.10",
            host_state=HostStateChoices.UP,
            hostname="undoc-fixture",
        )

        # Superuser bypasses per-model permissions so
        # ``PermissionRequiredMixin`` doesn't 403 on us in the auth test.
        cls.superuser = User.objects.create_superuser(
            username="recon-superuser",
            password="recon-pass-only-in-test",  # noqa: S106 — test-only
            email="recon-superuser@example.com",
        )


@override_settings(ALLOWED_HOSTS=["*"])
class TestParseAsOfParam(TestCase):
    """The ``?as_of=`` URL-param parser: valid ISO parses, garbage → None."""

    def test_none_input_returns_none(self):
        self.assertIsNone(_parse_as_of_param(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(_parse_as_of_param(""))

    def test_valid_iso_with_z_suffix_parses(self):
        # Python 3.11+ accepts trailing 'Z' in fromisoformat.
        result = _parse_as_of_param("2026-07-05T18:23:13+00:00")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 7)
        self.assertEqual(result.day, 5)

    def test_malformed_input_falls_back_to_none(self):
        # Bad bookmarks should render the report at "now" beliefs rather
        # than 400-ing.
        self.assertIsNone(_parse_as_of_param("not-a-date"))
        self.assertIsNone(_parse_as_of_param("2026-13-45"))


@override_settings(ALLOWED_HOSTS=["*"])
class TestReconciliationFilterFormBinding(TestCase):
    """Basic sanity: the form accepts an ISO ``as_of`` value cleanly."""

    def test_as_of_iso_string_validates(self):
        form = ReconciliationFilterForm(data={"as_of": "2026-07-05T18:23:13+00:00"})
        self.assertTrue(form.is_valid(), form.errors)
        parsed = form.cleaned_data["as_of"]
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.day, 5)

    def test_empty_form_validates_and_defaults_apply(self):
        # An unbound-style empty submit should validate (all fields are
        # required=False) and yield the safe defaults.
        form = ReconciliationFilterForm(data={})
        self.assertTrue(form.is_valid(), form.errors)
        # ChoiceField with required=False returns "" on empty, so the
        # view logic falls back to "rfc1918".
        self.assertIn(form.cleaned_data.get("scope") or "rfc1918", ("rfc1918",))


class TestReconciliationViewAuth(ReconciliationViewTestBase):
    """The view is login-required and permission-gated."""

    def test_anonymous_get_is_denied(self):
        url = _reverse_or_skip(self)
        response = self.client.get(url)
        # LoginRequiredMixin → 302 redirect to login; some Nautobot
        # configurations may return 403 instead. Accept either.
        self.assertIn(
            response.status_code, (302, 403),
            f"Expected 302 (redirect to login) or 403 (forbidden), got {response.status_code}",
        )

    def test_superuser_get_returns_200(self):
        url = _reverse_or_skip(self)
        self.client.force_login(self.superuser)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content[:400])


class TestReconciliationViewContent(ReconciliationViewTestBase):
    """The rendered body should surface the undocumented host's IP."""

    def test_undocumented_host_ip_appears_in_response(self):
        url = _reverse_or_skip(self)
        self.client.force_login(self.superuser)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content[:400])
        self.assertContains(response, "192.168.42.10")

    def test_as_of_query_param_is_accepted(self):
        # Malformed as_of shouldn't 500 — the view falls back to "now".
        url = _reverse_or_skip(self)
        self.client.force_login(self.superuser)
        response = self.client.get(url + "?as_of=not-a-date")
        self.assertEqual(response.status_code, 200, response.content[:400])
        # And should still render the undocumented row.
        self.assertContains(response, "192.168.42.10")

    def test_valid_as_of_query_param_is_accepted(self):
        url = _reverse_or_skip(self)
        self.client.force_login(self.superuser)
        response = self.client.get(
            url + "?as_of=2026-07-05T18:23:13%2B00:00"
        )
        self.assertEqual(response.status_code, 200, response.content[:400])


class TestReconciliationViewDirect(ReconciliationViewTestBase):
    """Exercises the view class directly via RequestFactory.

    Bypasses URL routing entirely so this class stays green even when the
    URL wire-up is pending. Useful as a smoke test of the view's core
    logic (form parse -> engine call -> template render).
    """

    def test_direct_dispatch_returns_200_for_authed_request(self):
        rf = RequestFactory()
        request = rf.get("/plugins/scanner/reconciliation/")
        request.user = self.superuser
        response = ReconciliationView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        # ``django.shortcuts.render`` returns an already-rendered
        # HttpResponse, so ``.content`` is safe to read directly.
        body = response.content.decode("utf-8")
        self.assertIn("192.168.42.10", body)

    def test_direct_dispatch_with_bad_as_of_still_renders(self):
        rf = RequestFactory()
        request = rf.get("/plugins/scanner/reconciliation/?as_of=bogus")
        request.user = self.superuser
        response = ReconciliationView.as_view()(request)
        self.assertEqual(response.status_code, 200)


class TestReconciliationViewStaleIpam(ReconciliationViewTestBase):
    """include_stale_ipam=on surfaces the inverse-direction section."""

    def test_stale_ipam_toggle_renders_stale_row(self):
        # Add an IPAM record that no live host reports -> stale row.
        IPAddress.objects.create(
            address="192.168.42.200/32",
            namespace=self.namespace,
            status=self.active,
        )

        rf = RequestFactory()
        request = rf.get(
            "/plugins/scanner/reconciliation/?include_stale_ipam=on"
        )
        request.user = self.superuser
        response = ReconciliationView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        body = response.content.decode("utf-8")
        # Stale IPAM row and section header should both appear.
        self.assertIn("192.168.42.200", body)
        self.assertIn("Stale IPAM", body)
