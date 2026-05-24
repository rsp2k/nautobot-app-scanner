"""Backend abstraction — ABC + factory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from nautobot_scanner.choices import AgentTypeChoices

if TYPE_CHECKING:
    from nautobot_scanner.models import Scan, ScannerAgent


class ScannerBackend(ABC):
    """Strategy interface for executing a scan.

    Implementations are free to be synchronous (LocalBackend blocks until
    persist() finishes) or asynchronous (RemoteBackend returns instantly;
    results arrive later via POST /ingest/).
    """

    @abstractmethod
    def dispatch(self, scan: Scan) -> None:
        """Start (or hand off) the scan.

        For sync backends, this should populate `scan.raw_xml`, call
        `parser.parse_xml` + `parser.persist`, flip `scan.status` to
        `completed`/`failed`, and save. For async backends, this should
        set `scan.status = pending` and return immediately.
        """


def get_backend(agent: ScannerAgent) -> ScannerBackend:
    """Return the right backend implementation for `agent`.

    Imports happen inside the function to avoid circular imports between
    `backends/__init__.py` and the concrete backend modules.
    """
    from nautobot_scanner.backends.local import LocalBackend
    from nautobot_scanner.backends.remote import RemoteBackend

    if agent.agent_type == AgentTypeChoices.LOCAL:
        return LocalBackend()
    if agent.agent_type == AgentTypeChoices.REMOTE:
        return RemoteBackend()
    raise ValueError(f"Unknown agent_type for {agent.name!r}: {agent.agent_type}")
