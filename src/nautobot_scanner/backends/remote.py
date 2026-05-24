"""Remote backend — dispatches scans to a registered remote agent.

`dispatch()` does NOT execute nmap. It flips the scan into `pending`
state and writes a one-shot `ingestion_token`. The remote agent (a
standalone process registered as a ScannerAgent with agent_type=remote)
polls `GET /api/plugins/scanner/agents/<id>/pending-scans/` to discover
the scan and then POSTs back to `/scans/<id>/ingest/` with the raw nmap
XML in the body. The POST handler (Phase 7) is where parse + persist
actually happens, guarded by a select_for_update lock against double-
ingest from retried agent requests.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from django.utils import timezone

from nautobot_scanner.backends.base import ScannerBackend
from nautobot_scanner.choices import ScanStateChoices

if TYPE_CHECKING:
    from nautobot_scanner.models import Scan

logger = logging.getLogger(__name__)


class RemoteBackend(ScannerBackend):
    """Hands off the scan to a registered remote agent and returns immediately."""

    def dispatch(self, scan: Scan) -> None:
        """Mark the scan as pending and rotate the one-shot ingestion token.

        Returns instantly; the agent picks the scan up on its next poll.
        """
        scan.status = ScanStateChoices.PENDING
        scan.started_at = timezone.now()
        # Rotate the token — even if a previous dispatch left one set,
        # we want a fresh one to prevent a delayed POST from a prior
        # attempt from being accepted against the new dispatch.
        scan.ingestion_token = uuid.uuid4()
        scan.save(update_fields=["status", "started_at", "ingestion_token"])
        logger.info(
            "RemoteBackend dispatched %s to agent %s — awaiting POST /ingest/",
            scan.pk,
            scan.agent.name,
        )
