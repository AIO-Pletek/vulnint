SHELL := /bin/bash
.PHONY: help build up down restart logs ps shell-api shell-db migrate revision seed test lint fmt clean reindex

help:
	@echo "Targets:"
	@echo "  build        Build all images"
	@echo "  up           Start the stack (detached)"
	@echo "  down         Stop the stack"
	@echo "  restart      Restart all services"
	@echo "  logs         Tail logs"
	@echo "  ps           Show service status"
	@echo "  shell-api    Open shell in api container"
	@echo "  shell-db     psql into postgres"
	@echo "  migrate      Run alembic upgrade head"
	@echo "  revision m=  Create alembic revision (autogenerate)"
	@echo "  seed         Seed initial admin and roles"
	@echo "  reindex      Reindex CVEs into OpenSearch"
	@echo "  test         Run backend tests"
	@echo "  lint         Run linters"
	@echo "  clean        Remove volumes (DESTRUCTIVE)"

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f --tail=200

ps:
	docker compose ps

shell-api:
	docker compose exec api /bin/bash

shell-db:
	docker compose exec postgres psql -U $${POSTGRES_USER:-vulnint} -d $${POSTGRES_DB:-vulnint}

migrate:
	docker compose exec api alembic upgrade head

revision:
	docker compose exec api alembic revision --autogenerate -m "$(m)"

seed:
	docker compose exec api python -m app.scripts.seed

reindex:
	docker compose exec api python -m app.scripts.reindex_opensearch

test:
	docker compose exec api pytest -q

lint:
	docker compose exec api ruff check app
	docker compose exec api mypy app || true

clean:
	docker compose down -v
