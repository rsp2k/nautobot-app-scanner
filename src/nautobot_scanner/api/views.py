"""DRF viewsets for nautobot_scanner REST API.

NautobotModelViewSet bundles list/retrieve/create/update/destroy actions
plus filterset support, pagination, and the standard tags/notes/changelog
relations.

Also defines three agent-specific endpoints below the CRUD viewsets:
- AgentPendingScansView    GET    /agents/<id>/pending-scans/
- ScanIngestView           POST   /scans/<id>/ingest/
- AgentCheckinView         POST   /agents/<id>/checkin/

These three use AgentTokenAuthentication instead of Nautobot's standard
auth — only a token bound to a ScannerAgent can call them, and the
agent in the URL must match the one bound to the token.
"""

import logging
import uuid

from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from nautobot.apps.api import NautobotModelViewSet
from rest_framework import status as drf_status
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from nautobot_scanner import filters, models, parser
from nautobot_scanner.api import serializers
from nautobot_scanner.api.auth import AgentTokenAuthentication
from nautobot_scanner.choices import ScanStateChoices

logger = logging.getLogger(__name__)


class ScannerAgentAPIViewSet(NautobotModelViewSet):
    queryset = models.ScannerAgent.objects.all()
    serializer_class = serializers.ScannerAgentSerializer
    filterset_class = filters.ScannerAgentFilterSet


class ScanProfileAPIViewSet(NautobotModelViewSet):
    queryset = models.ScanProfile.objects.all()
    serializer_class = serializers.ScanProfileSerializer
    filterset_class = filters.ScanProfileFilterSet


class ScanAPIViewSet(NautobotModelViewSet):
    queryset = models.Scan.objects.all()
    serializer_class = serializers.ScanSerializer
    filterset_class = filters.ScanFilterSet


class DiscoveredHostAPIViewSet(NautobotModelViewSet):
    queryset = models.DiscoveredHost.objects.all()
    serializer_class = serializers.DiscoveredHostSerializer
    filterset_class = filters.DiscoveredHostFilterSet


# DiscoveredPort / NseFinding / TraceRouteHop don't currently
# have FilterSets (BaseModel children, only rendered nested), so they get
# the default no-filter viewset. Phase 7 may add filtersets if the
# Nautobot SDK clients ask for them.
class DiscoveredPortAPIViewSet(NautobotModelViewSet):
    queryset = models.DiscoveredPort.objects.all()
    serializer_class = serializers.DiscoveredPortSerializer


class NseFindingAPIViewSet(NautobotModelViewSet):
    queryset = models.NseFinding.objects.all()
    serializer_class = serializers.NseFindingSerializer


class TraceRouteHopAPIViewSet(NautobotModelViewSet):
    queryset = models.TraceRouteHop.objects.all()
    serializer_class = serializers.TraceRouteHopSerializer


# ----------------------------------------------------------------------------
# Remote-agent endpoints — token-authenticated, not under the standard router.
# ----------------------------------------------------------------------------


class _AgentEndpointMixin:
    """Shared auth + agent-match check for the three agent endpoints."""

    authentication_classes = [AgentTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_agent_or_403(self, request, pk):
        """Return the agent named in the URL, or 403 if the token's agent doesn't match."""
        agent = get_object_or_404(models.ScannerAgent, pk=pk, agent_type="remote")
        token_agent = getattr(request.auth, "scanner_agent", None)
        if token_agent is None or token_agent.pk != agent.pk:
            raise PermissionDenied("Token does not belong to this agent.")
        return agent


class AgentPendingScansView(_AgentEndpointMixin, APIView):
    """GET /api/plugins/scanner/agents/<id>/pending-scans/.

    Lists scans assigned to this agent that are waiting to be picked up,
    AND atomically transitions them to "running" so a second agent (or a
    second poll from the same agent) can't grab the same scan twice.

    Returns a JSON list:
        [
          {
            "id": "<uuid>",
            "ingestion_token": "<uuid>",
            "profile": {"name": "...", "nmap_arguments": "...", "timing_template": "T3", "enabled_scripts": [...]},
            "targets": {"prefixes": ["192.0.2.0/24", ...], "ipaddresses": ["192.0.2.10", ...]},
          },
          ...
        ]

    Each scan is returned exactly once across all calls — the SELECT FOR
    UPDATE + status flip is the de-duplication mechanism.
    """

    def get(self, request, pk):
        """Pop pending scans for this agent, mark them running, return them."""
        agent = self.get_agent_or_403(request, pk)

        out = []
        with transaction.atomic():
            pending = list(
                models.Scan.objects.select_for_update(skip_locked=True)
                .filter(agent=agent, status=ScanStateChoices.PENDING)
                .select_related("profile")
                .prefetch_related("target_prefixes", "target_ipaddresses"),
            )
            now = timezone.now()
            for scan in pending:
                scan.status = ScanStateChoices.RUNNING
                scan.started_at = scan.started_at or now
                scan.save(update_fields=["status", "started_at"])
                out.append(
                    {
                        "id": str(scan.pk),
                        "ingestion_token": str(scan.ingestion_token),
                        "profile": {
                            "name": scan.profile.name,
                            "scan_type": scan.profile.scan_type,
                            "nmap_arguments": scan.profile.nmap_arguments,
                            "timing_template": scan.profile.timing_template,
                            "enabled_scripts": scan.profile.enabled_scripts or [],
                        },
                        "targets": {
                            "prefixes": [str(p.prefix) for p in scan.target_prefixes.all()],
                            "ipaddresses": [str(ip.host) for ip in scan.target_ipaddresses.all()],
                            # Raw IPs/CIDRs for ad-hoc rescans that bypass IPAM
                            # (added in migration 0011). Agents built before this
                            # field existed should default to ignoring it; new
                            # agents append it to the nmap target list.
                            "raw_ips": list(scan.target_raw_ips or []),
                        },
                    },
                )

        # Update agent.last_seen as a side-effect (a poll counts as a checkin).
        models.ScannerAgent.objects.filter(pk=agent.pk).update(last_seen=timezone.now())
        return Response(out)


class ScanIngestView(_AgentEndpointMixin, APIView):
    """POST /api/plugins/scanner/scans/<id>/ingest/.

    Body: raw nmap XML (text/xml or application/xml).
    Header: X-Ingestion-Token: <uuid> — must match scan.ingestion_token.

    Race protection: select_for_update locks the Scan row inside a
    transaction; the WHERE clause requires status=running AND
    ingestion_token matches. A second POST with the same token gets
    410 GONE (token consumed) or 404 NOT FOUND (wrong scan id).
    """

    def post(self, request, pk):
        """Validate token + parse + persist + flip status to completed."""
        # Token comes in via header — uppercased and HTTP_-prefixed by WSGI.
        posted_token = request.META.get("HTTP_X_INGESTION_TOKEN", "")
        if not posted_token:
            return Response(
                {"detail": "Missing X-Ingestion-Token header."},
                status=drf_status.HTTP_400_BAD_REQUEST,
            )
        try:
            posted_uuid = uuid.UUID(posted_token)
        except ValueError:
            return Response(
                {"detail": "X-Ingestion-Token is not a valid UUID."},
                status=drf_status.HTTP_400_BAD_REQUEST,
            )

        raw_xml = request.body.decode("utf-8", errors="replace") if request.body else ""

        # Parse outside the transaction — it's CPU-bound, no need to hold
        # the row lock across it. If parse fails we return 400 without ever
        # touching the Scan row.
        try:
            parsed_hosts = parser.parse_xml(raw_xml)
        except ValueError as exc:
            return Response(
                {"detail": f"Invalid nmap XML: {exc}"},
                status=drf_status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            scan_qs = models.Scan.objects.select_for_update().filter(
                pk=pk,
                ingestion_token=posted_uuid,
            )
            try:
                scan = scan_qs.get()
            except models.Scan.DoesNotExist as exc:
                # Either the scan id is wrong OR the token has been consumed
                # (ingestion_token gets cleared on success). Either way the
                # agent shouldn't retry with the same payload.
                raise PermissionDenied("Scan not found or ingestion token already consumed.") from exc

            # Agent-binding check — even with valid token, the calling agent
            # must own this scan.
            token_agent = getattr(request.auth, "scanner_agent", None)
            if token_agent is None or scan.agent_id != token_agent.pk:
                raise PermissionDenied("Scan does not belong to this agent.")

            if scan.status not in (ScanStateChoices.PENDING, ScanStateChoices.RUNNING):
                return Response(
                    {"detail": f"Scan is in state {scan.status!r}; cannot ingest."},
                    status=drf_status.HTTP_409_CONFLICT,
                )

            # Persist + transition. Token cleared inside the lock = one-shot.
            summary = parser.persist(scan, parsed_hosts)
            scan.summary = summary
            scan.status = ScanStateChoices.COMPLETED
            scan.completed_at = timezone.now()
            scan.ingestion_token = None
            scan.save(update_fields=["summary", "status", "completed_at", "ingestion_token"])

            # Save the raw XML too (gzipped). Done inside the lock so a
            # crashed worker doesn't leave a half-saved Scan with no XML.
            from nautobot_scanner.backends.local import LocalBackend

            LocalBackend._save_raw_xml(scan, raw_xml)  # noqa: SLF001 — share the same helper

        # Update agent.last_seen.
        models.ScannerAgent.objects.filter(pk=scan.agent_id).update(last_seen=timezone.now())

        return Response(
            {"scan_id": str(scan.pk), "status": scan.status, "summary": summary},
            status=drf_status.HTTP_200_OK,
        )


class AgentCheckinView(_AgentEndpointMixin, APIView):
    """POST /api/plugins/scanner/agents/<id>/checkin/.

    Heartbeat. Updates last_seen, optionally also version + capabilities
    if those are in the body. Lightweight — every alive agent should call
    this every ~60s so MarkStaleAgents doesn't flip them offline.

    Body (all fields optional):
        {"version": "agent-2026.05.24", "capabilities": {"nmap": "7.94", ...}}
    """

    def post(self, request, pk):
        """Stamp last_seen, optionally update reported metadata."""
        agent = self.get_agent_or_403(request, pk)
        updates = {"last_seen": timezone.now()}
        if "version" in request.data:
            updates["version"] = str(request.data["version"])[:64]
        if "capabilities" in request.data and isinstance(request.data["capabilities"], dict):
            updates["capabilities"] = request.data["capabilities"]
        models.ScannerAgent.objects.filter(pk=agent.pk).update(**updates)
        agent.refresh_from_db()
        return Response(
            {
                "agent_id": str(agent.pk),
                "last_seen": agent.last_seen,
                "version": agent.version,
                "capabilities": agent.capabilities,
            },
        )
