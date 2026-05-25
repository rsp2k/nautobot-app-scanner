# Development Environment

The repo ships a complete Docker-Compose dev stack under `development/`:
Postgres + Redis + Nautobot web + Nautobot worker, with the app source
bind-mounted for hot reload.

## One-time setup

```bash
git clone https://github.com/rsp2k/nautobot-app-scanner
cd nautobot-app-scanner

# Generate .env with random dev secrets
cp development/.env.example development/.env
# (then edit development/.env — at minimum set DOMAIN and rotate the
# changeme- placeholders for the four passwords)
```

The dev stack expects a Docker external network named `caddy` for
reverse-proxy integration. If you don't have one yet:

```bash
docker network create caddy
```

If you don't have caddy-docker-proxy running, just hit the loopback
port at `http://127.0.0.1:8087/` instead (the compose maps it for
direct host access).

## Build the image

```bash
make build
```

First build pulls `ghcr.io/nautobot/nautobot:3.1-py3.12` (~2GB
compressed). Subsequent builds reuse cached layers, ~10s.

## Start the stack

```bash
make up
```

Wait ~60s for first-boot migrations and superuser creation. Tail logs:

```bash
make logs-web
```

## Working with the code

The `src/nautobot_scanner/` directory is bind-mounted into the
container at `/opt/plugin/src/`. Most code changes take effect after a
container restart:

```bash
make restart
```

Model / settings changes that require a migration:

```bash
make makemigrations    # generates 0002_*.py
make migrate           # applies it
```

Note: `makemigrations` runs the container as root and chowns the
generated file back to the host UID — bypasses the container's
nautobot user (UID 999) vs host user (UID 1000) bind-mount mismatch.

## Run the tests

```bash
make test
```

This invokes `nautobot-server test nautobot_scanner --keepdb` which
keeps the test DB around between runs for speed. To force a fresh
DB:

```bash
docker compose exec nautobot-web nautobot-server test nautobot_scanner
```

## Lint

```bash
make ruff
```

Runs `ruff check` + `ruff format --check` on `src/`.

## Useful shells

```bash
make shell    # bash on the web container
make nbshell  # nautobot-server shell_plus (Django shell + auto-imports)
```

## Tearing down

```bash
make down      # stop containers, keep volumes
make clean     # DESTRUCTIVE — drop all volumes (wipes DB)
```

## Build the docs locally

```bash
pip install -r docs/requirements.txt
mkdocs serve
```

Visit `http://127.0.0.1:8001/`. See [Publishing Docs](../admin/install_docs_site.md)
for the production deploy flow.
