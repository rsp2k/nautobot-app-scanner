"""Pluggable scan backends.

Two backends ship out of the box:

- `LocalBackend` runs nmap via `subprocess.run` inside the Nautobot Celery
  worker. Simplest deploy; only works for networks the Nautobot host can
  reach.
- `RemoteBackend` dispatches scans to a registered remote agent which
  pulls work via the REST API and POSTs results back. Enables scanning
  isolated segments (DMZ, OT, branch offices).

Pick the backend at runtime via `get_backend(agent)` — it inspects the
agent's `agent_type` and returns the right implementation.
"""

from nautobot_scanner.backends.base import ScannerBackend, get_backend
from nautobot_scanner.backends.local import LocalBackend
from nautobot_scanner.backends.remote import RemoteBackend

__all__ = ["LocalBackend", "RemoteBackend", "ScannerBackend", "get_backend"]
