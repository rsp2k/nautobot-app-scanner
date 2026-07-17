"""Dispatch snmp-recon-deep against the reconciliation-undocumented set.

Phase M.1 of the fingerprint pipeline. Companion to
``http_fingerprint_undocumented`` — same reconciliation-driven target
resolver, but dispatches the ``snmp-recon-deep`` profile (nmap
``snmp-info`` + ``snmp-sysdescr`` + ``snmp-brute`` NSE bundle with a
25-entry default-community wordlist) instead of httpx.

Credential isolation (design brief §Credential isolation):
    The SNMP community wordlist ships as a static file at
    ``/etc/scanner/snmp-defaults.txt`` in the agent image, chmod 444.
    The command does NOT read the operator's real communities from
    ``extras.Secret`` — the isolation is code-level, not policy-level.
    The wordlist path is hardcoded inside the ``snmp-recon-deep``
    profile's ``nmap_arguments``, not injected here.

Operational rule (why this command exists at all):
    Never SNMP-probe an already-documented device. Doing so would
    generate SNMP auth-trap logs on the operator's own gear —
    tripping the operator's own SOC on every scanner run. Restricting
    targets to ``linked_device IS NULL AND linked_ipaddress IS NULL``
    makes the workflow bounded and self-shrinking.

Usage:

    nautobot-server snmp_recon_undocumented                        # dry-run
    nautobot-server snmp_recon_undocumented --confirm              # dispatch
    nautobot-server snmp_recon_undocumented --confirm --limit 20   # bounded first pass
    nautobot-server snmp_recon_undocumented --confirm --prefix 10.24.144.0/24
    nautobot-server snmp_recon_undocumented --confirm --cooldown-hours 0
    nautobot-server snmp_recon_undocumented --confirm --profile my-snmp-variant

Same ``--dry-run`` default / ``--confirm`` gate as sibling commands.
"""

from __future__ import annotations

import ipaddress as ipmod

from django.core.management.base import BaseCommand


DEFAULT_PROFILE_NAME = "snmp-recon-deep"


class Command(BaseCommand):
    """Dispatch snmp-recon-deep against undocumented DiscoveredHosts."""

    help = (
        "Dispatch snmp-recon-deep (nmap SNMP NSE bundle with default-"
        "community wordlist) against the reconciliation-undocumented "
        "set. Preview-safe by default; requires --confirm to dispatch."
    )

    def add_arguments(self, parser):
        """Define CLI flags — parallel to http_fingerprint_undocumented."""
        parser.add_argument(
            "--confirm",
            action="store_true",
            help=(
                "Explicit opt-in to actually create a Scan record and "
                "dispatch. Without this flag the command prints the "
                "target list and exits."
            ),
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help=(
                "Cap the number of target IPs. Useful for a bounded "
                "first pass — start with 20 targets to eyeball the "
                "auth-log noise before running against the full "
                "undocumented set."
            ),
        )
        parser.add_argument(
            "--prefix",
            default=None,
            help=(
                "CIDR to scope targets to (e.g. '10.24.144.0/24'). Only "
                "undocumented hosts inside this prefix are dispatched. "
                "Phased-rollout use case: start with a single VLAN, "
                "then widen."
            ),
        )
        parser.add_argument(
            "--cooldown-hours",
            type=int,
            default=24,
            help=(
                "Skip hosts touched by an httpx or snmp-info NseFinding "
                "within this many hours. Default 24 — prevents operator-"
                "error re-runs from doubling up SNMP auth-log noise on "
                "the same target. Pass 0 to disable."
            ),
        )
        parser.add_argument(
            "--profile",
            default=DEFAULT_PROFILE_NAME,
            help=(
                f"ScanProfile name to dispatch. Default: "
                f"{DEFAULT_PROFILE_NAME!r} (the credential-attempt "
                f"variant seeded by migration 0025). Override to use a "
                f"custom SNMP profile — must be tool=nmap with the "
                f"snmp-info/snmp-sysdescr NSE scripts enabled."
            ),
        )
        parser.add_argument(
            "--agent",
            default=None,
            help=(
                "Agent name to dispatch through. Defaults to the first "
                "agent alphabetically."
            ),
        )

    def handle(self, *args, **options):
        """Resolve targets, preview, optionally dispatch."""
        # Deferred imports so `--help` works before Django app-ready.
        from nautobot_scanner.backends import get_backend
        from nautobot_scanner.fingerprint import resolve_undocumented_targets
        from nautobot_scanner.models import Scan, ScannerAgent, ScanProfile

        confirm = options["confirm"]
        limit = options["limit"]
        prefix_str = options["prefix"]
        cooldown_hours = options["cooldown_hours"]
        profile_name = options["profile"]
        agent_name = options["agent"]

        # --- Resolve + validate the profile.
        try:
            profile = ScanProfile.objects.get(name=profile_name)
        except ScanProfile.DoesNotExist:
            snmp_profiles = list(
                ScanProfile.objects.filter(tool="nmap",
                                            enabled_scripts__contains=["snmp-info"])
                .values_list("name", flat=True)
            )
            self.stdout.write(self.style.ERROR(
                f"ScanProfile {profile_name!r} does not exist. "
                f"Available SNMP-capable nmap profiles: {snmp_profiles}"
            ))
            return

        # Validate the profile is actually SNMP-capable. We check both
        # tool and enabled_scripts because a nmap profile with, say,
        # only ssh-hostkey would silently do nothing useful here.
        if profile.tool != "nmap":
            self.stdout.write(self.style.ERROR(
                f"Profile {profile_name!r} uses tool={profile.tool!r}, not 'nmap'. "
                f"Refusing to dispatch — this command is SNMP-nmap-specific."
            ))
            return
        enabled = set(profile.enabled_scripts or [])
        if "snmp-info" not in enabled and "snmp-sysdescr" not in enabled:
            self.stdout.write(self.style.ERROR(
                f"Profile {profile_name!r} doesn't enable any SNMP NSE script. "
                f"enabled_scripts = {sorted(enabled)}. Add snmp-info or "
                f"snmp-sysdescr to make it usable here."
            ))
            return

        # --- Build the optional prefix filter as a queryset transform.
        scope_filter = None
        if prefix_str is not None:
            try:
                network = ipmod.ip_network(prefix_str, strict=False)
            except ValueError as exc:
                self.stdout.write(self.style.ERROR(f"Invalid --prefix: {exc}"))
                return
            def _in_prefix(qs):
                current_ids = []
                for h in qs.only("pk", "ip_address"):
                    try:
                        if ipmod.ip_address(str(h.ip_address)) in network:
                            current_ids.append(h.pk)
                    except ValueError:
                        continue
                return qs.filter(pk__in=current_ids)
            scope_filter = _in_prefix

        targets = resolve_undocumented_targets(
            scope_filter=scope_filter,
            cooldown_hours=cooldown_hours,
        )

        if limit is not None:
            targets = targets[:limit]

        self.stdout.write(f"Profile:              {profile.name!r} "
                          f"(tool={profile.tool}, scripts={profile.enabled_scripts})")
        self.stdout.write(f"Prefix scope:         {prefix_str or '(all)'}")
        self.stdout.write(f"Cooldown:             {cooldown_hours}h "
                          f"({'disabled' if cooldown_hours == 0 else 'recent httpx/snmp findings excluded'})")
        self.stdout.write(f"Undocumented targets: {len(targets)}"
                          + (f"  (limited from full set to {limit})" if limit is not None else ""))

        # Loud credential-attempt banner. Even in dry-run, make sure the
        # operator sees that the confirmed run will hit the target set
        # with default communities.
        self.stdout.write("")
        self.stdout.write(self.style.WARNING(
            "!!! CREDENTIAL ATTEMPT !!!  --confirm will dispatch nmap "
            "snmp-brute against the target IPs, trying every community "
            "in /etc/scanner/snmp-defaults.txt (~25 well-known defaults). "
            "Successful auths + failed auths WILL land in the target "
            "device's SNMP logs. This is why the target set is restricted "
            "to undocumented hosts only."
        ))

        if not targets:
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS(
                "Nothing to probe — the reconciliation set is empty at this scope."
            ))
            return

        # Sample the first 5 for eyeball verification.
        self.stdout.write("")
        self.stdout.write("First 5 targets:")
        for ip in targets[:5]:
            self.stdout.write(f"  {ip}")

        if not confirm:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(
                "Dry-run — no Scan dispatched. Re-run with --confirm to fire."
            ))
            return

        # --- Resolve the agent.
        if agent_name is not None:
            try:
                agent = ScannerAgent.objects.get(name=agent_name)
            except ScannerAgent.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Agent {agent_name!r} not found."))
                return
        else:
            agent = ScannerAgent.objects.order_by("name").first()
            if agent is None:
                self.stdout.write(self.style.ERROR(
                    "No ScannerAgent records exist. Create one before dispatching."
                ))
                return

        # --- Create the Scan and dispatch it.
        # was_pentest_mode kept in sync with the profile's is_pentest_mode
        # property, which currently returns False for snmp-recon-deep
        # (no schema field for credential-attempt yet — see the
        # migration's module docstring for the deferred-refactor note).
        scan = Scan.objects.create(
            agent=agent,
            profile=profile,
            target_raw_ips=targets,
            was_pentest_mode=bool(profile.is_pentest_mode),
        )
        self.stdout.write("")
        self.stdout.write(f"Created Scan {scan.pk} with {len(targets)} raw-IP targets.")
        self.stdout.write(f"Dispatching via agent {agent.name!r} ({agent.agent_type})…")

        backend = get_backend(agent)
        backend.dispatch(scan)
        scan.refresh_from_db()

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Done. Scan {scan.pk} status={scan.status!r}, summary={scan.summary!r}"
        ))
        self.stdout.write(f"Review at /plugins/scanner/scans/{scan.pk}/")
