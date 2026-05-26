"""Seed five NSE-script-driven recon profiles.

Now that NseFinding supports host-scope output (migration 0009), the
scanner can usefully run NSE script categories that produce per-host
findings — SMB OS discovery, SNMP info, SSH host keys, etc. — alongside
the per-port script output it already handled.

Each profile is opinionated:

- **web-recon** — `-sV -p 80,443,8080,8443 --script http-title,http-headers,http-methods,http-server-header`
  Web fleet inventory: what's running on every HTTP/S port, what
  methods are allowed, what server header leaks (Apache, IIS, nginx).
- **tls-audit** — `-sV -p 443,465,993,995,8443 --script ssl-cert,ssl-enum-ciphers`
  TLS-positioned ports: extracts cert subject/issuer/validity/SANs +
  enumerates the cipher suites the server actually accepts. Compliance
  scanning gold.
- **smb-recon** — `-sV -p 139,445 --script smb-os-discovery,smb-protocols`
  Windows fleet discovery: OS version, domain, NetBIOS name, and which
  SMB protocol versions the host negotiates (SMB1 still alive somewhere?).
- **snmp-recon** — `-sU -p 161 --script snmp-info,snmp-sysdescr`
  SNMP probe with default `public` community. Routinely surfaces sysDescr,
  uptime, contact info on consumer/SMB gear that nobody bothered to lock down.
- **ssh-recon** — `-sV -p 22 --script ssh-hostkey,ssh-auth-methods`
  Per-host SSH key inventory + supported auth methods (password vs
  publickey only). Auth-method enumeration tells you which hosts are
  enforcing key-only logins.

All profiles are idempotent via `get_or_create` — operators editing
these in the UI don't get clobbered on re-migrate.
"""

from django.db import migrations


PROFILES = (
    {
        "name": "web-recon",
        "scan_type": "version",
        "nmap_arguments": "-sV -p 80,443,8080,8443 --script http-title,http-headers,http-methods,http-server-header",
        "timing_template": "T4",
        "enabled_scripts": ["http-title", "http-headers", "http-methods", "http-server-header"],
        "description": (
            "Web stack identity, allowed HTTP methods, response-header inventory. "
            "Surfaces titles + Server/X-Powered-By/etc headers per port."
        ),
    },
    {
        "name": "tls-audit",
        "scan_type": "version",
        "nmap_arguments": "-sV -p 443,465,993,995,8443 --script ssl-cert,ssl-enum-ciphers",
        "timing_template": "T4",
        "enabled_scripts": ["ssl-cert", "ssl-enum-ciphers"],
        "description": (
            "TLS cert + cipher inventory on standard TLS-wrapped ports. "
            "Extracts subject/issuer/validity/SANs and enumerates accepted ciphers."
        ),
    },
    {
        "name": "smb-recon",
        "scan_type": "version",
        "nmap_arguments": "-sV -p 139,445 --script smb-os-discovery,smb-protocols",
        "timing_template": "T4",
        "enabled_scripts": ["smb-os-discovery", "smb-protocols"],
        "description": (
            "Windows / SMB fleet discovery: OS version, domain, NetBIOS name, "
            "and which SMB dialects the server negotiates (catches lingering SMBv1)."
        ),
    },
    {
        "name": "snmp-recon",
        "scan_type": "version",
        "nmap_arguments": "-sU -p 161 --script snmp-info,snmp-sysdescr",
        "timing_template": "T4",
        "enabled_scripts": ["snmp-info", "snmp-sysdescr"],
        "description": (
            "SNMP probe with default 'public' community. Routinely surfaces "
            "sysDescr/uptime/contact on consumer + SMB gear nobody locked down."
        ),
    },
    {
        "name": "ssh-recon",
        "scan_type": "version",
        "nmap_arguments": "-sV -p 22 --script ssh-hostkey,ssh-auth-methods",
        "timing_template": "T4",
        "enabled_scripts": ["ssh-hostkey", "ssh-auth-methods"],
        "description": (
            "SSH per-host key inventory + supported auth methods. Identifies hosts "
            "still allowing password auth vs key-only, and detects key reuse across hosts."
        ),
    },
)


def seed_profiles(apps, schema_editor):
    """Create the NSE recon profiles if they don't exist already."""
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        defaults = {**spec}
        name = defaults.pop("name")
        ScanProfile.objects.get_or_create(name=name, defaults=defaults)


def remove_profiles(apps, schema_editor):
    """Reverse: drop the seeded profiles only if their args still match the seed.

    Same operator-friendly behavior as migration 0002 — we only delete a
    profile when its ``nmap_arguments`` still equal the seed value, so any
    customization an operator made survives the rollback.
    """
    ScanProfile = apps.get_model("nautobot_scanner", "ScanProfile")
    for spec in PROFILES:
        ScanProfile.objects.filter(
            name=spec["name"],
            nmap_arguments=spec["nmap_arguments"],
        ).delete()


class Migration(migrations.Migration):
    """Seed the five NSE-driven recon profiles."""

    dependencies = [
        ("nautobot_scanner", "0009_rename_vulnerabilityfinding_to_nsefinding"),
    ]

    operations = [
        migrations.RunPython(seed_profiles, remove_profiles),
    ]
