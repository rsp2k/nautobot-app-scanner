"""Seed the Phase M.1 profile: snmp-recon-deep.

Phase M.1 upgrades SNMP fingerprinting from single-community probing
(the existing ``snmp-recon`` profile from Phase G, migration 0010,
which just tries ``public``) to a wordlist-driven community discovery
plus vendor OID identification via ``snmp-brute`` + ``snmp-info`` +
``snmp-sysdescr``.

The existing ``snmp-recon`` profile stays untouched — it's used for
"quiet single-community" recon where the operator explicitly wants
minimal auth-log noise. ``snmp-recon-deep`` is the credential-attempt
variant, dispatched only against the reconciliation-undocumented set
via the ``snmp_recon_undocumented`` management command.

Credential isolation (design brief §Credential isolation):
    The community wordlist path ``/etc/scanner/snmp-defaults.txt`` is
    hardcoded in ``nmap_arguments`` — no PLUGIN_CONFIG pulldown, no
    template variable, no ``extras.Secret`` read. The file is baked
    into the agent image at build time (see agent/Dockerfile) with
    ``chmod 444``. The scanner code path physically cannot read the
    operator's real communities from any secret store.

Credential-attempt gating:
    ``ScanProfile.is_pentest_mode`` is a computed property that fires
    on ``tool in PENTEST_TOOLS`` (nmap is not in that set) or on
    specific nmap flag fields (decoys/fragments/MTU/source-port). None
    of those apply to snmp-recon-deep — it uses stock nmap with NSE
    scripts. Proper credential-attempt gating requires a schema field
    (``is_credential_attempt`` or similar) which is deferred to a
    follow-up. Until then, the profile description carries the
    warning explicitly and the sibling ``snmp_recon_undocumented``
    management command restricts targeting to the undocumented set —
    both of which reduce risk without requiring a schema migration.
"""

from django.db import migrations


PROFILES = (
    {
        "name": "snmp-recon-deep",
        "scan_type": "version",
        "tool": "nmap",
        # nmap args: UDP scan of port 161 with the three SNMP NSE scripts
        # snmp-brute (tries every community in the wordlist and reports
        # any that answered), snmp-info (dumps sysObjectID + sysDescr +
        # sysContact + sysLocation + uptime), snmp-sysdescr (fallback
        # sysDescr grab without brute-force).
        #
        # --script-args points snmp-brute at the baked-in wordlist. The
        # path is hardcoded here — the whole architectural point of
        # credential isolation is that no runtime data path can inject
        # a different wordlist.
        "nmap_arguments": (
            "-sU -p 161 "
            "--script snmp-info,snmp-sysdescr,snmp-brute "
            "--script-args snmpcommunity.wordlist=/etc/scanner/snmp-defaults.txt"
        ),
        "timing_template": "T4",
        "enabled_scripts": ["snmp-info", "snmp-sysdescr", "snmp-brute"],
        # Description trimmed to fit CharField(255). Full credential-
        # isolation rationale is in the module-level docstring above
        # and in docs/dev/phase-m-fingerprint-design.md.
        "description": (
            "*** CREDENTIAL ATTEMPT ***  SNMP fingerprint via nmap's "
            "snmp-brute+snmp-info+snmp-sysdescr NSE with ~25 default "
            "communities from /etc/scanner/snmp-defaults.txt. Dispatch "
            "only via snmp_recon_undocumented mgmt command."
        ),
    },
)


def seed_profiles(apps, schema_editor):
    """Create the Phase M.1 profile if it doesn't exist."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        defaults = {**spec}
        name = defaults.pop("name")
        ScanProfile.objects.get_or_create(name=name, defaults=defaults)


def remove_profiles(apps, schema_editor):
    """Reverse: drop the snmp-recon-deep profile."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        ScanProfile.objects.filter(name=spec["name"], tool=spec["tool"]).delete()


class Migration(migrations.Migration):
    """Seed the Phase M.1 snmp-recon-deep profile."""

    dependencies = [
        ("nautobot_scanner", "0024_alter_discoveredhost_entry_id_and_more"),
    ]

    operations = [
        migrations.RunPython(seed_profiles, remove_profiles),
    ]
