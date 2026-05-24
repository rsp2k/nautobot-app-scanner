"""Top-level Nav Menu entries for nautobot_scanner.

Adds a 'Scanner' tab to the Nautobot top nav with three groups:
Agents (executors + profiles), Scans (runs), Results (what was found).
"""

from nautobot.apps.ui import NavMenuGroup, NavMenuItem, NavMenuTab

menu_items = (
    NavMenuTab(
        name="Scanner",
        # Weight 1000+ keeps us out of the way of the core tabs (Org=100,
        # Devices=200, IPAM=300, etc.) so we render to the right.
        weight=1000,
        # Custom SVG icon shipped under static/nautobot_scanner/img/.
        # Any value containing '/' is treated as a static URL; bare names
        # would resolve against nautobot-icons/<name>.svg.
        icon="nautobot_scanner/img/scanner.svg",
        groups=(
            NavMenuGroup(
                name="Configuration",
                weight=100,
                items=(
                    NavMenuItem(
                        link="plugins:nautobot_scanner:scanneragent_list",
                        name="Agents",
                        permissions=["nautobot_scanner.view_scanneragent"],
                    ),
                    NavMenuItem(
                        link="plugins:nautobot_scanner:scanprofile_list",
                        name="Scan Profiles",
                        permissions=["nautobot_scanner.view_scanprofile"],
                    ),
                ),
            ),
            NavMenuGroup(
                name="Activity",
                weight=200,
                items=(
                    NavMenuItem(
                        link="plugins:nautobot_scanner:scan_list",
                        name="Scans",
                        permissions=["nautobot_scanner.view_scan"],
                    ),
                ),
            ),
            NavMenuGroup(
                name="Results",
                weight=300,
                items=(
                    NavMenuItem(
                        link="plugins:nautobot_scanner:discoveredhost_list",
                        name="Discovered Hosts",
                        permissions=["nautobot_scanner.view_discoveredhost"],
                    ),
                ),
            ),
        ),
    ),
)
