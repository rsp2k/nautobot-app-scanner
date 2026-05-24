# Dev image: Nautobot 3.1 + nautobot-app-scanner (editable install) + nmap.
#
# Build context is the repo root (see development/docker-compose.yml). We
# pip install -e /opt/plugin so the editable metadata is registered, then
# bind-mount the host's src/ over /opt/plugin/src at runtime for hot-reload.
# Restart nautobot-web to pick up code changes.
#
# nmap is installed in the same image so the LocalBackend can shell out to
# it without a second container. The worker only needs it for `local`-type
# agents; remote agents bring their own nmap.

FROM ghcr.io/nautobot/nautobot:3.1-py3.12

USER 0

# nmap for the LocalBackend; libcap so nmap can bind raw sockets without
# requiring CAP_NET_RAW on the whole container (caller can grant it per-
# scan via setcap if they want privileged scans).
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# Source baked in for the editable install; runtime bind-mount overlays src/.
COPY pyproject.toml /opt/plugin/
COPY src /opt/plugin/src
RUN pip install --no-cache-dir -e "/opt/plugin[dev]"

USER nautobot
