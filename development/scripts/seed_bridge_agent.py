"""Create the dev-bridge agent + print its bootstrap env."""

from nautobot.extras.models import Status
from nautobot.users.models import Token

from nautobot_scanner.models import ScannerAgent

active = Status.objects.get(name="Active")
agent, created = ScannerAgent.objects.get_or_create(
    name="dev-bridge-agent",
    defaults={
        "agent_type": "remote",
        "status": active,
        "description": "Reference agent attached to nautobot-scanner-dev_internal "
                       "for scanning docker overlay services with container DNS resolution.",
    },
)
agent.refresh_from_db()
token, _ = Token.objects.get_or_create(user=agent.user)

print(f"{'Created' if created else 'Using existing'} agent: {agent.name}")
print(f"AGENT_ID={agent.pk}")
print(f"AGENT_TOKEN={token.key}")
