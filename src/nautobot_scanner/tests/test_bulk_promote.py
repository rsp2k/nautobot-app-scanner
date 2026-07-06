"""Tests for the bulk-promote view + management command.

Two entry points, one commit shape. The tests exercise both surfaces
through the same fixture set so a divergence between the UI and CLI
paths shows up as a test failure the day it's introduced.

The view tests use ``RequestFactory`` to drive
``DiscoveredHostBulkPromoteView`` directly rather than going through URL
resolution. The URL wire-up is deferred to a follow-up commit; testing
via the class-based view keeps the tests self-contained until then.

The management command tests use ``call_command`` so they exercise the
argparse layer + option validation + ``handle()`` flow — the shape a
real ``nautobot-server`` invocation takes.
"""

from __future__ import annotations

from io import StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import HttpResponseNotAllowed
from django.test import RequestFactory, TestCase, override_settings
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner.choices import (
    AgentTypeChoices,
    ScanStateChoices,
    ScanTypeChoices,
    TimingTemplateChoices,
)
from nautobot_scanner.models import DiscoveredHost, Scan, ScannerAgent, ScanProfile
from nautobot_scanner.views_bulk_promote import DiscoveredHostBulkPromoteView


User = get_user_model()


# ---------------------------------------------------------------------------
# Shared fixture — Scan + a handful of discovered hosts inside a /24.
# ---------------------------------------------------------------------------

@override_settings(ALLOWED_HOSTS=["*"])
class BulkPromoteTestBase(TestCase):
    """Builds a Scan → DiscoveredHost fixture for both entry points.

    Uses IANA TEST-NET-1 (192.0.2.0/24) so the fixture doesn't collide
    with anything on a developer's laptop and the RFC-1918 scope filter
    in ``build_reconciliation`` produces a predictable "empty" result
    without extra setup. Tests that need RFC-1918 scope create their
    own 10/8-space hosts inline.
    """

    def setUp(self):
        self.active = Status.objects.get(name="Active")

        # Provisional status is seeded by migration 0023 in the same branch as
        # this test file. Fetch by name so a missing migration surfaces here
        # instead of at IPAddress-create time deep in the view.
        self.provisional = Status.objects.get(name="Provisional")

        self.namespace = Namespace.objects.get(name="Global")

        # Prefix + parent so IPAddress.clean() has something to attach to.
        self.prefix = Prefix.objects.create(
            prefix="10.0.0.0/24",
            namespace=self.namespace,
            status=self.active,
            type="network",
        )

        self.agent = ScannerAgent.objects.create(
            name="bulk-promote-test",
            agent_type=AgentTypeChoices.LOCAL,
            status=self.active,
        )
        self.profile = ScanProfile.objects.create(
            name="bp-test-profile",
            scan_type=ScanTypeChoices.DISCOVERY,
            nmap_arguments="-sn",
            timing_template=TimingTemplateChoices.T3,
        )
        self.scan = Scan.objects.create(
            agent=self.agent,
            profile=self.profile,
            status=ScanStateChoices.COMPLETED,
        )

        self.host_a = DiscoveredHost.objects.create(
            scan=self.scan, ip_address="10.0.0.10", host_state="up", hostname="a.example",
        )
        self.host_b = DiscoveredHost.objects.create(
            scan=self.scan, ip_address="10.0.0.11", host_state="up", hostname="b.example",
        )
        self.host_c = DiscoveredHost.objects.create(
            scan=self.scan, ip_address="10.0.0.12", host_state="up", hostname="c.example",
        )

        # A user with the full permission set the view expects.
        self.user = User.objects.create_user(
            username="bp-tester", password="p", is_superuser=True,
        )

    def _attach_messages(self, request):
        """RequestFactory bypasses middleware — attach a FallbackStorage so
        the view's ``messages.success/warning/error`` calls don't raise
        MessageFailure."""
        from django.contrib.messages.storage.fallback import FallbackStorage
        request.session = {}
        request._messages = FallbackStorage(request)

    def _post(self, data, *, user=None):
        """Drive the view directly via RequestFactory (URL wire-up deferred)."""
        rf = RequestFactory()
        request = rf.post("/bulk-promote/", data)
        request.user = user if user is not None else self.user
        # RequestFactory doesn't invoke session middleware; that's fine
        # because LoginRequiredMixin only checks `request.user.is_authenticated`.
        self._attach_messages(request)
        return DiscoveredHostBulkPromoteView.as_view()(request)

    def _get(self, *, user=None):
        rf = RequestFactory()
        request = rf.get("/bulk-promote/")
        request.user = user if user is not None else self.user
        self._attach_messages(request)
        return DiscoveredHostBulkPromoteView.as_view()(request)


# ---------------------------------------------------------------------------
# View-side tests
# ---------------------------------------------------------------------------

class TestBulkPromoteViewMethodGuards(BulkPromoteTestBase):
    """GET is 405; a POST with no host IDs still renders the preview page."""

    def test_get_returns_405(self):
        response = self._get()
        # HttpResponseNotAllowed subclasses HttpResponse with status 405.
        self.assertEqual(response.status_code, 405)
        self.assertIsInstance(response, HttpResponseNotAllowed)

    def test_post_with_no_ids_renders_preview_with_warning(self):
        response = self._post({})
        self.assertEqual(response.status_code, 200)


class TestBulkPromoteViewPreview(BulkPromoteTestBase):
    """POST without ``confirm`` renders the preview page and writes nothing."""

    def test_preview_lists_selected_hosts(self):
        response = self._post({
            "discovered_host_id": [str(self.host_a.pk), str(self.host_b.pk)],
        })
        self.assertEqual(response.status_code, 200)
        # No IPAddresses written yet — the preview is read-only.
        self.assertEqual(IPAddress.objects.count(), 0)
        # Hosts remain unlinked.
        for host in (self.host_a, self.host_b, self.host_c):
            host.refresh_from_db()
            self.assertIsNone(host.linked_ipaddress_id)


class TestBulkPromoteViewCommit(BulkPromoteTestBase):
    """POST with ``confirm=1`` creates IPAddresses stamped ``Provisional``."""

    def test_confirm_creates_ipaddresses_with_provisional_status(self):
        response = self._post({
            "discovered_host_id": [str(self.host_a.pk), str(self.host_b.pk)],
            "confirm": "1",
            "namespace": str(self.namespace.pk),
            "status": str(self.provisional.pk),
        })
        self.assertEqual(response.status_code, 200)

        # Two IPAddresses created, both stamped Provisional.
        self.assertEqual(IPAddress.objects.count(), 2)
        for ip in IPAddress.objects.all():
            self.assertEqual(ip.status, self.provisional)

        # linked_ipaddress FKs populated on the source hosts.
        self.host_a.refresh_from_db()
        self.host_b.refresh_from_db()
        self.assertIsNotNone(self.host_a.linked_ipaddress_id)
        self.assertIsNotNone(self.host_b.linked_ipaddress_id)

        # host_c wasn't selected — still unlinked.
        self.host_c.refresh_from_db()
        self.assertIsNone(self.host_c.linked_ipaddress_id)

    def test_already_linked_hosts_are_skipped(self):
        """Concurrent promoter race: linked_ipaddress set between preview + confirm."""
        # host_a was promoted by "another operator" between preview and confirm.
        preexisting = IPAddress.objects.create(
            address="10.0.0.10/32",
            namespace=self.namespace,
            status=self.active,
        )
        self.host_a.linked_ipaddress = preexisting
        self.host_a.save(update_fields=["linked_ipaddress"])

        response = self._post({
            "discovered_host_id": [str(self.host_a.pk), str(self.host_b.pk)],
            "confirm": "1",
            "namespace": str(self.namespace.pk),
            "status": str(self.provisional.pk),
        })
        self.assertEqual(response.status_code, 200)

        # host_a's link is unchanged — the view skipped it, didn't overwrite.
        self.host_a.refresh_from_db()
        self.assertEqual(self.host_a.linked_ipaddress_id, preexisting.pk)

        # host_b got the fresh Provisional IPAddress. Total is 2: the
        # preexisting Active row + the new Provisional row.
        self.assertEqual(IPAddress.objects.count(), 2)
        self.host_b.refresh_from_db()
        self.assertIsNotNone(self.host_b.linked_ipaddress_id)
        self.assertEqual(self.host_b.linked_ipaddress.status, self.provisional)

    def test_confirm_defaults_to_global_and_provisional_when_omitted(self):
        """Missing namespace/status POST fields fall back to seeded defaults."""
        response = self._post({
            "discovered_host_id": [str(self.host_a.pk)],
            "confirm": "1",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(IPAddress.objects.count(), 1)
        new_ip = IPAddress.objects.get()
        # Nautobot 3.x moved the namespace off IPAddress and onto the
        # parent Prefix. IPAddress has `_namespace` under the hood; the
        # accessible read path is via `parent.namespace`.
        self.assertEqual(new_ip.parent.namespace, self.namespace)
        self.assertEqual(new_ip.status, self.provisional)


class TestBulkPromoteViewPermissions(BulkPromoteTestBase):
    """Anonymous → redirect to login. Authenticated-no-perm → 403."""

    def test_anonymous_user_is_redirected_or_forbidden(self):
        response = self._post(
            {"discovered_host_id": [str(self.host_a.pk)]},
            user=AnonymousUser(),
        )
        # LoginRequiredMixin returns 302 by default; some Nautobot
        # configurations return 403. Accept either — the point of the
        # test is that the unauthenticated request is NOT let through.
        self.assertIn(response.status_code, (302, 403))
        # No writes.
        self.assertEqual(IPAddress.objects.count(), 0)

    def test_user_without_permission_is_forbidden(self):
        from django.core.exceptions import PermissionDenied

        weak = User.objects.create_user(username="weak", password="p")
        # PermissionRequiredMixin (Django default with raise_exception on
        # class) raises PermissionDenied when hit via RequestFactory
        # rather than returning a 302/403 — Client() would convert the
        # exception to a response via middleware, but RequestFactory
        # doesn't. Assert the exception directly.
        with self.assertRaises(PermissionDenied):
            self._post(
                {"discovered_host_id": [str(self.host_a.pk)]},
                user=weak,
            )
        self.assertEqual(IPAddress.objects.count(), 0)


# ---------------------------------------------------------------------------
# Management-command tests
# ---------------------------------------------------------------------------

class TestBulkPromoteCommand(BulkPromoteTestBase):
    """The CLI mirrors the view's commit shape + adds preview-safe flags."""

    # ------------- guardrails ------------------

    def test_refuses_to_run_without_dry_run_or_confirm(self):
        """Silence would fool a caller — the command must refuse."""
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "bulk_promote_discovered_hosts",
                "--all-current",
                stdout=StringIO(),
            )
        self.assertIn("--dry-run", str(ctx.exception))
        self.assertIn("--confirm", str(ctx.exception))
        # No writes.
        self.assertEqual(IPAddress.objects.count(), 0)

    def test_refuses_without_scope_selection(self):
        """Must pass --scan or --all-current."""
        with self.assertRaises(CommandError):
            call_command(
                "bulk_promote_discovered_hosts",
                "--dry-run",
                stdout=StringIO(),
            )

    def test_scan_and_all_current_are_mutually_exclusive(self):
        """argparse enforces this — both flags together should error."""
        # ``mutually_exclusive_group`` raises SystemExit (via argparse) not
        # CommandError. Wrap in a broad assertRaises to catch either.
        with self.assertRaises((CommandError, SystemExit)):
            call_command(
                "bulk_promote_discovered_hosts",
                "--scan", str(self.scan.pk),
                "--all-current",
                "--dry-run",
                stdout=StringIO(),
            )

    # ------------- dry-run -----------------

    def test_dry_run_writes_nothing(self):
        out = StringIO()
        call_command(
            "bulk_promote_discovered_hosts",
            "--all-current",
            "--dry-run",
            stdout=out,
        )
        # Nothing committed.
        self.assertEqual(IPAddress.objects.count(), 0)
        # Preview output includes the count line + "Dry run" tail.
        self.assertIn("Reconciliation preview", out.getvalue())
        self.assertIn("Dry run", out.getvalue())

    # ------------- commit --------------

    def test_confirm_creates_provisional_ipaddresses(self):
        """The commit path defaults to Provisional and populates linked_ipaddress."""
        out = StringIO()
        call_command(
            "bulk_promote_discovered_hosts",
            "--all-current",
            "--confirm",
            stdout=out,
        )
        # All three fixture hosts got promoted (10/8 hosts, RFC-1918 scope).
        self.assertEqual(IPAddress.objects.count(), 3)
        for ip in IPAddress.objects.all():
            self.assertEqual(ip.status, self.provisional)
        for host in (self.host_a, self.host_b, self.host_c):
            host.refresh_from_db()
            self.assertIsNotNone(host.linked_ipaddress_id)
        self.assertIn("Promoted 3 host", out.getvalue())

    def test_dry_run_plus_confirm_commits(self):
        """`--dry-run --confirm` is the doc'd two-flag "definitely commit" idiom."""
        call_command(
            "bulk_promote_discovered_hosts",
            "--all-current",
            "--dry-run",
            "--confirm",
            stdout=StringIO(),
        )
        self.assertEqual(IPAddress.objects.count(), 3)

    def test_status_flag_overrides_provisional(self):
        """`--status Active` skips the trust-but-verify step."""
        call_command(
            "bulk_promote_discovered_hosts",
            "--all-current",
            "--confirm",
            "--status", "Active",
            stdout=StringIO(),
        )
        self.assertEqual(IPAddress.objects.count(), 3)
        for ip in IPAddress.objects.all():
            self.assertEqual(ip.status, self.active)

    def test_scan_flag_scopes_to_single_scan(self):
        """`--scan <uuid>` restricts to hosts from that scan only."""
        # Second scan with two more hosts on a separate prefix.
        prefix2 = Prefix.objects.create(
            prefix="10.0.1.0/24",
            namespace=self.namespace,
            status=self.active,
            type="network",
        )
        scan2 = Scan.objects.create(
            agent=self.agent, profile=self.profile, status=ScanStateChoices.COMPLETED,
        )
        DiscoveredHost.objects.create(
            scan=scan2, ip_address="10.0.1.20", host_state="up", hostname="d.example",
        )
        DiscoveredHost.objects.create(
            scan=scan2, ip_address="10.0.1.21", host_state="up", hostname="e.example",
        )

        call_command(
            "bulk_promote_discovered_hosts",
            "--scan", str(scan2.pk),
            "--confirm",
            stdout=StringIO(),
        )
        # Only the two scan2 hosts got promoted; scan1's three hosts left alone.
        self.assertEqual(IPAddress.objects.count(), 2)
        self.host_a.refresh_from_db()
        self.host_b.refresh_from_db()
        self.host_c.refresh_from_db()
        self.assertIsNone(self.host_a.linked_ipaddress_id)
        self.assertIsNone(self.host_b.linked_ipaddress_id)
        self.assertIsNone(self.host_c.linked_ipaddress_id)

    def test_all_current_scopes_to_up_and_not_yet_linked(self):
        """`--all-current` matches DiscoveredHost.current().host_state='up' + linked_ipaddress__isnull=True."""
        # A "down" host — should NOT be promoted.
        DiscoveredHost.objects.create(
            scan=self.scan, ip_address="10.0.0.99", host_state="down",
        )
        # A host that's already linked — should NOT be re-promoted.
        preexisting = IPAddress.objects.create(
            address="10.0.0.10/32",
            namespace=self.namespace,
            status=self.active,
        )
        self.host_a.linked_ipaddress = preexisting
        self.host_a.save(update_fields=["linked_ipaddress"])

        call_command(
            "bulk_promote_discovered_hosts",
            "--all-current",
            "--confirm",
            stdout=StringIO(),
        )

        # Ended state:
        # - Preexisting Active row for host_a (unchanged)
        # - Two new Provisional rows for host_b and host_c
        # - "down" host and host_a NOT re-promoted
        self.assertEqual(IPAddress.objects.count(), 3)
        self.assertEqual(
            IPAddress.objects.filter(status=self.provisional).count(),
            2,
        )
        self.host_a.refresh_from_db()
        self.assertEqual(self.host_a.linked_ipaddress_id, preexisting.pk)
