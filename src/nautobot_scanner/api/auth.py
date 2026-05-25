"""Custom DRF authentication for remote-agent endpoints.

`AgentTokenAuthentication` wraps Nautobot's standard TokenAuthentication
and adds one extra check: the token's user must be bound to a ScannerAgent
(via the `user` OneToOne). If it isn't, auth fails — a regular Nautobot
user with a valid Token shouldn't be able to hit /pending-scans/ or
/ingest/ as if they were an agent.

Successful authentication stashes the agent on `token.scanner_agent` so
the views can check `agent == self.kwargs["pk"]` without re-querying.
"""

from nautobot.core.api.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed


class AgentTokenAuthentication(TokenAuthentication):
    """Token auth that also requires the user be bound to a ScannerAgent."""

    def authenticate_credentials(self, key):
        """Standard token lookup + ScannerAgent association check."""
        # Imports inside to avoid Django app-loading-order issues.
        from nautobot_scanner.models import ScannerAgent

        user, token = super().authenticate_credentials(key)

        try:
            agent = ScannerAgent.objects.get(user=user, agent_type="remote")
        except ScannerAgent.DoesNotExist as exc:
            raise AuthenticationFailed("Token is not associated with a remote scanner agent.") from exc

        # Stash the agent on the token so views can access it without a
        # second query. DRF copies request.auth = token, so this becomes
        # request.auth.scanner_agent.
        token.scanner_agent = agent
        return (user, token)
