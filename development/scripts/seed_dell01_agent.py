"""Create the scanhost-01 remote agent + print its bootstrap env."""

from nautobot.extras.models import Status
from nautobot.users.models import Token

from nautobot_scanner.models import ScannerAgent

active = Status.objects.get(name="Active")

agent, created = ScannerAgent.objects.get_or_create(
    name="scanhost-01-agent",
    defaults={
        "agent_type": "remote",
        "status": active,
        "description": "Reference agent on scanhost-01.example.net — scans from that host's network POV.",
    },
)
agent.refresh_from_db()
token, _ = Token.objects.get_or_create(user=agent.user)

print(f"{'Created' if created else 'Using existing'} agent: {agent.name}")
print()
print("Copy these into the agent/.env on scanhost-01:")
print("---")
print(f"NAUTOBOT_URL=http://127.0.0.1:8087")
print(f"AGENT_ID={agent.pk}")
print(f"AGENT_TOKEN={token.key}")
print(f"VERIFY_TLS=false")
print(f"COMPOSE_PROJECT_NAME=scanner-agent-scanhost-01")
