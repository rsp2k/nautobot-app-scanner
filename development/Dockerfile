# Dev image: Nautobot 3.1 + nautobot-app-scanner (editable install) +
# every probe tool the LocalBackend can dispatch.
#
# Build context is the repo root (see development/docker-compose.yml). We
# pip install -e /opt/plugin so the editable metadata is registered, then
# bind-mount the host's src/ over /opt/plugin/src at runtime for hot-reload.
# Restart nautobot-web to pick up code changes.
#
# Tools (matched to the seven ToolChoices values + Phase L):
#   nmap, masscan, mtr, dig (bind9-dnsutils), drill (ldnsutils),
#   curl, openssl, testssl.sh (Phase L), ssh-audit (Phase L, pip-installed).
# Raw-socket scans need CAP_NET_RAW + setcap on /usr/bin/nmap +
# no-new-privs disabled in the compose service. See ADR-013.
FROM ghcr.io/nautobot/nautobot:3.1-py3.12

USER 0

# Tool binaries for the LocalBackend. libcap ships setcap so raw-socket
# scans (-sS / -sI / -O / -f / --mtu) work as non-root once the container
# grants NET_RAW.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         nmap masscan mtr-tiny \
         bind9-dnsutils ldnsutils \
         curl openssl \
         testssl.sh \
         libcap2-bin \
    && pip install --no-cache-dir ssh-audit \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/bin/nmap \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/bin/masscan || true \
    && rm -rf /var/lib/apt/lists/*

# Source baked in for the editable install; runtime bind-mount overlays src/.
COPY pyproject.toml /opt/plugin/
COPY src /opt/plugin/src
RUN pip install --no-cache-dir -e "/opt/plugin[dev]"

USER nautobot
