"""Management command for provisioning remote-agent credentials.

Without this command, standing up a new remote scanner agent requires:

  1. ``nautobot-server shell`` → create ``ScannerAgent(agent_type='remote',
     location=...)``
  2. Wait for the post_save signal to auto-create the ``User``
  3. ``Token.objects.create(user=agent.user)`` to issue the DRF token
  4. Copy UUID + token into the agent's ``.env``

That sequence is fragile (the signal can silently no-op if Location
isn't set right; ``Token.objects.create`` raises if a token already
exists), and it leaks the secret through shell history. This command
makes the path one line:

    nautobot-server scanner_agent_token <name>            # print existing
    nautobot-server scanner_agent_token <name> --create   # create if missing
    nautobot-server scanner_agent_token <name> --rotate   # mint new token

The command always prints UUID + token + recommended .env stanza on
success; ``--create`` and ``--rotate`` are explicit opt-in flags so
this command is safe to run idempotently in CI.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    """Print, create, or rotate the UUID + DRF token for a remote scanner agent."""

    help = "Print, create, or rotate the UUID + DRF token for a remote scanner agent."

    def add_arguments(self, parser):
        """Define CLI flags."""
        parser.add_argument(
            "name",
            help="Agent name (e.g. dev-host-agent). Used as the ScannerAgent.name lookup key.",
        )
        parser.add_argument(
            "--create",
            action="store_true",
            help=(
                "Create the agent if it doesn't exist. --location is optional; "
                "defaults to the first Location in the database."
            ),
        )
        parser.add_argument(
            "--location",
            default=None,
            help=(
                "Location name for a newly-created agent. Defaults to the first "
                "Location in the database when --create is set and --location is omitted."
            ),
        )
        parser.add_argument(
            "--rotate",
            action="store_true",
            help=(
                "Delete the existing token (if any) and mint a fresh one. Useful for "
                "incident response or when the .env leaked. The agent must reconnect "
                "with the new token."
            ),
        )
        parser.add_argument(
            "--env-stanza",
            action="store_true",
            help=(
                "Print the .env stanza ready to paste into the agent's .env file. "
                "Default output is human-readable; --env-stanza makes the output "
                "machine-friendly for `>>` redirection."
            ),
        )

    def handle(self, *args, **options):
        """Run the command."""
        from nautobot_scanner.models import ScannerAgent

        name = options["name"]
        create = options["create"]
        rotate = options["rotate"]
        env_stanza = options["env_stanza"]

        try:
            agent = ScannerAgent.objects.get(name=name)
        except ScannerAgent.DoesNotExist:
            if not create:
                raise CommandError(
                    f"No ScannerAgent named {name!r}. Pass --create to provision one, "
                    f"or list existing with: "
                    f"`nautobot-server shell -c 'from nautobot_scanner.models import ScannerAgent; "
                    f"print(list(ScannerAgent.objects.values_list(\"name\", flat=True)))'`",
                )
            agent = self._create_agent(name, options.get("location"))

        if agent.agent_type != "remote":
            raise CommandError(
                f"Agent {name!r} is type {agent.agent_type!r}, not 'remote'. "
                f"Local agents don't use tokens — they run nmap in-process.",
            )

        if agent.user is None:
            # The post_save signal should have auto-provisioned the User.
            # If it didn't, the most likely cause is the agent was created
            # before the signal was registered, or via a path that bypassed
            # the model's save() method.
            raise CommandError(
                f"Agent {name!r} has no linked User. The post_save signal that "
                f"auto-creates one didn't fire. Touch the agent to re-trigger: "
                f"`ScannerAgent.objects.get(name={name!r}).save()` from a shell.",
            )

        token = self._get_or_create_token(agent.user, rotate=rotate)

        if env_stanza:
            self.stdout.write(self._format_env_stanza(agent, token))
        else:
            self._print_human(agent, token, rotate=rotate, created=create)

    def _create_agent(self, name, location_name):
        """Create a new remote ScannerAgent with the given name + location."""
        from nautobot.dcim.models import Location
        from nautobot.extras.models import Status
        from nautobot_scanner.models import ScannerAgent

        location_qs = Location.objects.all()
        if location_name:
            try:
                location = location_qs.get(name=location_name)
            except Location.DoesNotExist:
                raise CommandError(
                    f"Location {location_name!r} not found. Existing locations: "
                    f"{list(location_qs.values_list('name', flat=True))!r}",
                ) from None
        else:
            location = location_qs.first()
            if location is None:
                raise CommandError(
                    "No Locations exist in the database. Create one via the Nautobot "
                    "UI (Organization → Locations) or via shell before running --create.",
                )

        agent_status = Status.objects.get_for_model(ScannerAgent).get(name="Active")
        agent = ScannerAgent.objects.create(
            name=name,
            agent_type="remote",
            location=location,
            status=agent_status,
        )
        # The post_save signal fires inside .create() but our local `agent`
        # reference is stale on the user FK. Refresh.
        agent.refresh_from_db()
        return agent

    def _get_or_create_token(self, user, *, rotate):
        """Return the token, rotating if requested."""
        from nautobot.users.models import Token

        existing = Token.objects.filter(user=user).order_by("-created").first()
        if existing and not rotate:
            return existing
        if existing and rotate:
            existing.delete()
        return Token.objects.create(user=user)

    def _format_env_stanza(self, agent, token):
        """Compose a .env-ready block. Suitable for `> .env.fragment` redirection."""
        return (
            f"SCANNER_AGENT_ID={agent.pk}\n"
            f"SCANNER_AGENT_TOKEN={token.key}\n"
        )

    def _print_human(self, agent, token, *, rotate, created):
        """Default operator-friendly output — UUID, token, ready-to-paste stanza."""
        verb = "Created" if created else ("Rotated token for" if rotate else "Found")
        self.stdout.write(self.style.SUCCESS(f"{verb} agent {agent.name!r}"))
        self.stdout.write("")
        self.stdout.write(f"  UUID:     {agent.pk}")
        self.stdout.write(f"  Token:    {token.key}")
        self.stdout.write(f"  Location: {agent.location.name if agent.location else '(none)'}")
        self.stdout.write(f"  User:     {agent.user.username}")
        self.stdout.write("")
        self.stdout.write(self.style.NOTICE("Add to your agent's .env:"))
        self.stdout.write("")
        self.stdout.write(f"    SCANNER_AGENT_ID={agent.pk}")
        self.stdout.write(f"    SCANNER_AGENT_TOKEN={token.key}")
        self.stdout.write("")
        self.stdout.write(self.style.NOTICE(
            "Tokens are shown once — store them in a secret manager. To rotate later: "
            f"`nautobot-server scanner_agent_token {agent.name} --rotate`.",
        ))
