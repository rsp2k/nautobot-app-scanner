.PHONY: help build up down restart logs logs-web ps shell nbshell migrate makemigrations test ruff clean

DC := docker compose
WEB := nautobot-web

help:
	@echo "nautobot-app-scanner — dev stack"
	@echo ""
	@echo "Stack:"
	@echo "  make build           Build the dev image (after src/ structural changes)"
	@echo "  make up              Start postgres + redis + web + worker"
	@echo "  make down            Stop containers (data persists in volumes)"
	@echo "  make restart         Restart the web container (after code changes)"
	@echo "  make logs            Tail logs for the whole stack"
	@echo "  make logs-web        Tail only nautobot-web"
	@echo "  make ps              Container status"
	@echo "  make clean           DESTRUCTIVE — drop all volumes (wipes DB)"
	@echo ""
	@echo "Workflows:"
	@echo "  make shell           Bash shell on web container"
	@echo "  make nbshell         nautobot-server shell_plus"
	@echo "  make migrate         Apply Django migrations"
	@echo "  make makemigrations  Generate migrations for nautobot_scanner"
	@echo "  make test            Run the project test suite"
	@echo "  make ruff            Run ruff lint + format check"

build:
	$(DC) build

up:
	$(DC) up -d
	@echo ""
	@echo "Stack starting. First boot ~60s for migrations + superuser."
	@echo "URL:   https://$$(grep ^DOMAIN .env | cut -d= -f2)/"
	@echo "Tail:  make logs-web"

down:
	$(DC) down

restart:
	$(DC) restart $(WEB)

logs:
	$(DC) logs -f --tail=100

logs-web:
	$(DC) logs -f --tail=100 $(WEB)

ps:
	$(DC) ps

shell:
	$(DC) exec $(WEB) bash

nbshell:
	$(DC) exec $(WEB) nautobot-server shell_plus

migrate:
	$(DC) exec $(WEB) nautobot-server migrate

HOST_UID := $(shell id -u)
HOST_GID := $(shell id -g)

makemigrations:
	# Run as root inside the container so writes through the bind mount
	# succeed, then chown the result back to the host UID. Bypasses the
	# nautobot user (UID 999) vs host user (typically 1000) bind-mount mismatch.
	$(DC) exec --user 0 $(WEB) bash -c "nautobot-server makemigrations nautobot_scanner && chown -R $(HOST_UID):$(HOST_GID) /opt/plugin/src/nautobot_scanner"

test:
	$(DC) exec $(WEB) nautobot-server test nautobot_scanner --keepdb

ruff:
	$(DC) exec $(WEB) ruff check /opt/plugin/src
	$(DC) exec $(WEB) ruff format --check /opt/plugin/src

clean:
	@echo "WARNING: this will delete all dev data."
	@printf "Type 'yes' to confirm: " && read confirm && [ "$$confirm" = "yes" ]
	$(DC) down -v
