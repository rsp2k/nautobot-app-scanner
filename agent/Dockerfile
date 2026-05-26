# Reference scanner agent image — Phase G: netshoot-based, ~700 MB.
#
# Why netshoot: nicolaka/netshoot bundles ~50 networking tools in one
# Debian image (nmap, masscan, dig, mtr, hping3, scapy, tcpdump,
# openssl, curl, ...). The Phase G tool-dispatch abstraction means
# new probe types are additive: register an argv-builder in
# agent.py:TOOL_REGISTRY and a parser in parser.py:PARSERS, and the
# same agent runs them all. Pre-Phase-G agents were Alpine + nmap-only
# at ~100 MB; the bloat is one-time pull, not run-cost.
#
# Build:    docker build -t nautobot-scanner-agent ./agent
# Run:      see docker-compose.host-mode.yml and docker-compose.bridge-mode.yml
#
# Privileges: nmap SYN scans + masscan + hping3 all need CAP_NET_RAW.
# --privileged is NOT required. The compose examples set the cap
# explicitly; the setcap calls below carry it into each binary's
# effective+permitted sets so the non-root agent user can use them.

FROM nicolaka/netshoot:v0.13

# netshoot ships nmap, dig, mtr, tcpdump, tshark, openssl, curl out
# of the box. masscan + hping3 (needed for Phase I pentest mode) are
# in Alpine's community repo; we add them here.
#
# scapy is bundled as a Python package — agent.py can `import scapy`
# directly without further setup.
RUN apk add --no-cache libcap masscan hping3 \
    && adduser -D -u 1001 agent \
    # Raw-socket caps for the binaries that need them. nmap (SYN scans
    # + ARP probes), masscan (raw packet send at 10M pps), hping3
    # (manual TCP/UDP/ICMP probes). Without this, a non-root container
    # falls back to TCP connect() for nmap and refuses to run for
    # masscan/hping3. dig + curl + mtr + openssl don't need raw sockets.
    #
    # NOTE: setcap REPLACES any existing setuid bits. After this, the
    # container needs cap_add: [NET_RAW] in compose for the file caps
    # to activate via the kernel bounding set — running without that
    # cap_add (e.g. plain `docker run`) breaks `nmap --version` with
    # a PermissionError. The capabilities() probe in agent.py catches
    # PermissionError so the agent still starts in degraded mode.
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/bin/nmap \
    && if [ -x /usr/bin/masscan ]; then \
         setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/bin/masscan; \
       fi \
    && if [ -x /usr/sbin/hping3 ]; then \
         setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/sbin/hping3; \
       fi

WORKDIR /app
COPY agent.py /app/agent.py
RUN chmod +x /app/agent.py && chown -R agent:agent /app

# Drop to non-root by default. For raw-socket scans, the compose stack
# adds cap_add: [NET_RAW] — the binary file caps from setcap above
# combine with the kernel-level grant to make the calls work.
USER agent

# Standard library only — no `pip install` needed.
ENTRYPOINT ["python3", "/app/agent.py"]
