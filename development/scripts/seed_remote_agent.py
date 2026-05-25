"""Create a remote ScannerAgent + show its token + UUID.

Run via:
    docker compose -f development/docker-compose.yml --env-file development/.env \
      exec -T nautobot-web nautobot-server shell < development/scripts/seed_remote_agent.py
"""

from nautobot.extras.models import Status
from nautobot.users.models import Token

from nautobot_scanner.models import ScannerAgent

active = Status.objects.get(name="Active")

agent, created = ScannerAgent.objects.get_or_create(
    name="dmz-agent",
    defaults={
        "agent_type": "remote",
        "status": active,
        "description": "Reference docker agent for end-to-end smoke testing.",
    },
)

# Reload to pick up the auto-created user from the post_save signal.
agent.refresh_from_db()

if created:
    print(f"Created agent: {agent.name}")
else:
    print(f"Using existing agent: {agent.name}")

token, _ = Token.objects.get_or_create(user=agent.user)

print(f"AGENT_ID={agent.pk}")
print(f"AGENT_TOKEN={token.key}")
print(f"USER={agent.user.username}")
