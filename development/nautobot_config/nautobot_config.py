"""Nautobot config for the nautobot-app-scanner dev stack.

Loaded via volume mount at /opt/nautobot/nautobot_config.py in each Nautobot
container. Imports the upstream defaults and overrides only what we need:
PLUGINS, PLUGINS_CONFIG, and a couple of dev toggles.
"""

import os

# Pull in Nautobot's default settings (DB/cache/Celery wiring from env vars).
from nautobot.core.settings import *  # noqa: F401,F403
from nautobot.core.settings_funcs import is_truthy

DEBUG = is_truthy(os.environ.get("NAUTOBOT_DEBUG", "true"))

PLUGINS = [
    "nautobot_scanner",
]

PLUGINS_CONFIG = {
    "nautobot_scanner": {
        # Override the defaults from NautobotScannerConfig.default_settings here
        # if you want to tune them per-environment.
    },
}
