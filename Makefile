# Webhook Delivery — blessed compose entrypoints.
#
# Production MUST always include the prod overlay:
#   docker compose -f compose.yaml -f compose.prod.yaml ...
#
# Bare `docker compose -f compose.yaml up` exposes DB/Redis ports, serves
# plain-HTTP nginx (deploy/nginx.dev.conf), and skips prod secret guards —
# NEVER use it for production. Preferred prod paths (both enforce the overlay):
#   make deploy-prod                  # full production deploy
#   ./scripts/deploy_prod.sh up --build -d
#
# CI enforces this via `scripts/enforce_prod_compose.sh`
# (job `enforce-prod-compose` in .github/workflows/ci.yml).

COMPOSE_BASE := docker compose -f compose.yaml
COMPOSE_PROD := docker compose -f compose.yaml -f compose.prod.yaml
DEPLOY_SCRIPT := ./scripts/deploy_prod.sh

.PHONY: help enforce-prod-compose config-prod build-prod up-prod deploy-prod \
	migrate-prod ps-prod logs-prod down-prod config-dev build-dev up-dev down-dev migrate-dev

help:
	@echo "Webhook Delivery compose targets:"
	@echo "  make deploy-prod            Full production deploy (enforces compose.prod.yaml)"
	@echo "  make up-prod [ARGS='...']   Start prod stack (always with overlay)"
	@echo "  make build-prod             Build prod images (always with overlay)"
	@echo "  make config-prod            Render/validate prod compose config"
	@echo "  make migrate-prod           Run the single migrations service (prod overlay)"
	@echo "  make ps-prod / logs-prod / down-prod"
  @echo "  make up-dev / build-dev / config-dev / down-dev   Local dev only (base file)"
  @echo "  make migrate-dev          Run the base-stack migrations service"

enforce-prod-compose:
	bash scripts/enforce_prod_compose.sh

config-prod:
	$(COMPOSE_PROD) config -q

build-prod:
	$(COMPOSE_PROD) build

up-prod:
	$(COMPOSE_PROD) up -d $(ARGS)

# Full production deploy: guard + wrapper (fixed overlay).
# Schema runs via the single `migrations` service; web/workers gate on it.
deploy-prod: enforce-prod-compose
	$(DEPLOY_SCRIPT) up --build -d $(ARGS)

# Single manual entrypoint (same job `up` runs automatically via gating).
migrate-prod:
	$(COMPOSE_PROD) up --build migrations

ps-prod:
	$(COMPOSE_PROD) ps

logs-prod:
	$(COMPOSE_PROD) logs -f $(ARGS)

down-prod:
	$(COMPOSE_PROD) down $(ARGS)

# ---- Local development only (base compose file, no prod overlay) ----
config-dev:
	$(COMPOSE_BASE) config -q

build-dev:
	$(COMPOSE_BASE) build

up-dev:
	$(COMPOSE_BASE) up $(ARGS)

# Single manual entrypoint for the base-stack migrations job
# (same job `up-dev` runs automatically via gating).
migrate-dev:
	$(COMPOSE_BASE) up --build migrations

down-dev:
	$(COMPOSE_BASE) down $(ARGS)
