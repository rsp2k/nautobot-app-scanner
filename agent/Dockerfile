# Reference scanner agent image. ~100 MB — Alpine + nmap + nmap-scripts + cpython.
#
# Build:    docker build -t nautobot-scanner-agent ./agent
# Run:      see docker-compose.host-mode.yml and docker-compose.bridge-mode.yml
#
# nmap SYN scans need CAP_NET_RAW; --privileged is not required. The compose
# examples set the cap explicitly. Without it, the agent falls back to TCP
# connect() scans, which work but are slower and look different in logs.

FROM alpine:3.20

RUN apk add --no-cache nmap nmap-scripts python3 ca-certificates \
    && adduser -D -u 1001 agent

WORKDIR /app
COPY agent.py /app/agent.py
RUN chmod +x /app/agent.py && chown -R agent:agent /app

# Drop to non-root by default. For SYN scans, the compose stack adds
# cap_add: [NET_RAW] — the binary's file caps handle the rest.
USER agent

# Standard library only — no `pip install` needed.
ENTRYPOINT ["python3", "/app/agent.py"]
