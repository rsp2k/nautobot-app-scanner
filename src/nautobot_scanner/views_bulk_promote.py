"""Bulk-promote DiscoveredHosts into ipam.IPAddress records.

Two-step POST-only workflow. The list surface (reconciliation view) posts a
batch of host IDs here without ``confirm``; the view renders a preview page
that lists exactly which IPAddresses will be created, in which namespace,
with which status. A second POST from that preview page — carrying the
same host IDs and ``confirm=1`` — commits inside one ``transaction.atomic()``.

The commit path mirrors ``DiscoveredHostPromoteView`` (``views.py:31``) so
operators get IPAddress rows with identical shape regardless of which path
they came in through: same ``address`` mask logic (/32 v4, /128 v6), same
``namespace`` + ``status`` + ``dns_name`` + ``description`` fields. The
only intentional divergences:

- Default status is ``Provisional`` (seeded by migration 0023) not
  ``Active``. Bulk actions default to trust-but-verify so downstream
  reviewers can find the not-yet-validated rows via a status filter.
- Hosts with ``linked_ipaddress`` already set are silently skipped — this
  is a race guard for the case where another operator promoted the same
  host between the preview and the confirm click. The skip count is
  surfaced on the success page so the operator sees what happened.

Wire-up: ``urls.py`` will add
``path("discovered-hosts/bulk-promote/",
       views_bulk_promote.DiscoveredHostBulkPromoteView.as_view(),
       name="discoveredhost_bulk_promote")`` in the main-branch follow-up.
"""

from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db import transaction
from django.http import HttpResponseNotAllowed
from django.shortcuts import render
from django.views import View
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_scanner import models

# Names of the pre-seeded objects the view expects to exist. If either is
# missing at request time we still render the preview / success page — the
# operator sees the failure state up-front rather than a 500.
DEFAULT_NAMESPACE_NAME = "Global"
PROVISIONAL_STATUS_NAME = "Provisional"


class DiscoveredHostBulkPromoteView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """Preview + confirm batch-promote of DiscoveredHosts into ipam.IPAddress.

    Permissions match the single-host promote view — a caller with only
    scanner permissions can't spawn IPAM rows via this side door.

    Method semantics:

    - ``GET`` → 405. This is a POST-only flow because the entry point is
      "operator ticked N rows on the reconciliation table and clicked
      Bulk Promote"; there is no meaningful URL to bookmark.
    - ``POST`` without ``confirm`` → render preview page with the list of
      selected hosts and the current defaults for namespace + status. The
      preview page's form re-emits the host IDs and adds ``confirm=1``.
    - ``POST`` with ``confirm=1`` → commit inside ``transaction.atomic()``,
      then render success page.
    """

    permission_required = ("nautobot_scanner.change_discoveredhost", "ipam.add_ipaddress")

    def get(self, request):
        """Reject GET — this flow is POST-only."""
        return HttpResponseNotAllowed(["POST"])

    def post(self, request):
        """Preview if ``confirm`` absent; commit if ``confirm=1``."""
        host_ids = request.POST.getlist("discovered_host_id")
        if not host_ids:
            messages.warning(
                request,
                "No hosts were selected for bulk promotion. Pick one or more "
                "rows on the reconciliation view and try again.",
            )
            return render(
                request,
                "nautobot_scanner/bulk_promote_preview.html",
                self._preview_context(request, hosts=[]),
            )

        # Preserve caller-supplied host ordering so the preview page and
        # the success page list them in the same sequence. Falls back to
        # pk order for whichever ones are missing.
        hosts_qs = models.DiscoveredHost.objects.filter(pk__in=host_ids)
        hosts_by_pk = {str(h.pk): h for h in hosts_qs}
        hosts = [hosts_by_pk[hid] for hid in host_ids if hid in hosts_by_pk]

        confirm = request.POST.get("confirm") == "1"
        if not confirm:
            return render(
                request,
                "nautobot_scanner/bulk_promote_preview.html",
                self._preview_context(request, hosts=hosts),
            )

        namespace = self._resolve_namespace(request.POST.get("namespace"))
        status = self._resolve_status(request.POST.get("status"))
        if namespace is None or status is None:
            messages.error(
                request,
                "Bulk promote requires a valid Namespace and a Status. "
                f"Requested namespace={request.POST.get('namespace')!r}, "
                f"status={request.POST.get('status')!r}. "
                "Confirm the seeded 'Provisional' status + your Namespace exist.",
            )
            return render(
                request,
                "nautobot_scanner/bulk_promote_preview.html",
                self._preview_context(request, hosts=hosts),
            )

        promoted, skipped = self._commit(hosts, namespace=namespace, status=status)

        messages.success(
            request,
            f"Promoted {len(promoted)} host(s) into {namespace.name!r} with status {status.name!r}. "
            f"Skipped {skipped} host(s) already linked to an IPAddress.",
        )
        return render(
            request,
            "nautobot_scanner/bulk_promote_success.html",
            {
                "promoted": promoted,
                "skipped": skipped,
                "namespace": namespace,
                "status": status,
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _preview_context(self, request, *, hosts):
        """Compute the context dict for the preview template.

        Includes the current namespace + status choice sets and their
        defaults so the template can render <select> widgets without any
        additional lookups. Also pre-computes the containing IPAM Prefix
        (if any) for each host so the preview table can show "which
        prefix bucket will this land in" — matching the reconciliation
        view's grouping.
        """
        namespaces = list(Namespace.objects.all().order_by("name"))
        statuses = self._ipaddress_statuses()

        default_namespace = next(
            (ns for ns in namespaces if ns.name == DEFAULT_NAMESPACE_NAME),
            namespaces[0] if namespaces else None,
        )
        default_status = next(
            (s for s in statuses if s.name == PROVISIONAL_STATUS_NAME),
            statuses[0] if statuses else None,
        )

        # Small lookup for the "containing prefix" column. We do this
        # in a single query per namespace + a Python containment test
        # rather than N `Prefix.objects.get(prefix__net_contains=ip)`
        # queries — same anti-N+1 pattern the reconciliation engine uses.
        containing_by_host_pk = self._containing_prefixes(hosts, default_namespace)

        return {
            "hosts": hosts,
            "host_rows": [
                {
                    "host": host,
                    "containing_prefix": containing_by_host_pk.get(str(host.pk)),
                }
                for host in hosts
            ],
            "namespaces": namespaces,
            "statuses": statuses,
            "default_namespace": default_namespace,
            "default_status": default_status,
        }

    def _ipaddress_statuses(self):
        """Statuses valid for ``ipam.IPAddress`` content type."""
        return list(
            Status.objects.filter(content_types__model="ipaddress").order_by("name")
        )

    def _containing_prefixes(self, hosts, namespace):
        """Map ``str(host.pk)`` → containing ``Prefix`` (or None).

        Falls back to all-namespace lookup if the given namespace has no
        matching prefix — the preview is best-effort context, not the
        commit-time authority (the commit uses whatever namespace the
        operator picked in the confirm form).
        """
        import ipaddress as ipmod

        if not hosts:
            return {}

        prefixes_qs = Prefix.objects.all()
        if namespace is not None:
            prefixes_qs = prefixes_qs.filter(namespace=namespace)
        parsed: list[tuple[Prefix, ipmod._BaseNetwork]] = []
        for p in prefixes_qs:
            try:
                parsed.append((p, ipmod.ip_network(str(p.prefix))))
            except ValueError:
                continue
        # Most-specific-first so the smallest containing prefix wins.
        parsed.sort(key=lambda pair: -pair[1].prefixlen)

        result: dict[str, Prefix] = {}
        for host in hosts:
            try:
                ip = ipmod.ip_address(str(host.ip_address))
            except ValueError:
                continue
            for p, net in parsed:
                if ip.version == net.version and ip in net:
                    result[str(host.pk)] = p
                    break
        return result

    def _resolve_namespace(self, raw):
        """Resolve a namespace pk (or name) from POST data.

        Accepts pk (UUID) OR name so the template can post either without
        the view caring which the widget produced.
        """
        if not raw:
            try:
                return Namespace.objects.get(name=DEFAULT_NAMESPACE_NAME)
            except Namespace.DoesNotExist:
                return None
        try:
            return Namespace.objects.get(pk=raw)
        except (Namespace.DoesNotExist, ValueError, TypeError):
            pass
        try:
            return Namespace.objects.get(name=raw)
        except Namespace.DoesNotExist:
            return None

    def _resolve_status(self, raw):
        """Resolve an IPAddress status pk (or name) from POST data."""
        if not raw:
            try:
                return Status.objects.get(name=PROVISIONAL_STATUS_NAME)
            except Status.DoesNotExist:
                return None
        try:
            return Status.objects.get(pk=raw)
        except (Status.DoesNotExist, ValueError, TypeError):
            pass
        try:
            return Status.objects.get(name=raw)
        except Status.DoesNotExist:
            return None

    def _commit(self, hosts, *, namespace, status):
        """Create IPAddresses (or link to existing ones) for each host.

        Runs in one ``transaction.atomic()`` so a mid-batch failure rolls
        the whole set back — an operator would rather retry a batch than
        end up with N/2 rows created and no clear record of which ones.
        Hosts already carrying a ``linked_ipaddress`` are skipped
        silently (race protection against concurrent promoters).

        If an ``IPAddress`` already exists at ``(namespace, host_ip)`` —
        because an operator added it manually, or an earlier partial
        batch left an orphan row — this method LINKS to the existing
        row rather than trying to create a duplicate (which would blow
        up the whole batch on the (parent_id, host) unique constraint).
        That makes bulk-promote idempotent and self-healing.

        Returns ``(promoted_list, skipped_count)`` where ``promoted_list``
        is a list of ``(host, ip)`` tuples ready for the success page.
        """
        promoted: list[tuple[models.DiscoveredHost, IPAddress]] = []
        skipped = 0
        with transaction.atomic():
            for host in hosts:
                if host.linked_ipaddress_id is not None:
                    skipped += 1
                    continue

                ip_str = str(host.ip_address)
                mask = "/128" if ":" in ip_str else "/32"
                address = f"{ip_str}{mask}"

                existing = IPAddress.objects.filter(
                    parent__namespace=namespace,
                    host=ip_str,
                ).first()
                if existing is not None:
                    host.linked_ipaddress = existing
                    host.save(update_fields=["linked_ipaddress"])
                    promoted.append((host, existing))
                    continue

                new_ip = IPAddress.objects.create(
                    address=address,
                    namespace=namespace,
                    status=status,
                    dns_name=host.hostname or "",
                    description=(
                        f"Bulk-promoted from scanner DiscoveredHost {host.pk} "
                        f"(scan {host.scan_id})"
                    ),
                )
                host.linked_ipaddress = new_ip
                host.save(update_fields=["linked_ipaddress"])
                promoted.append((host, new_ip))
        return promoted, skipped
