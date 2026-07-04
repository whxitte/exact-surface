.DEFAULT_GOAL := help
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip

.PHONY: help venv install dev test lint typecheck fmt health dry-run api docker-build up down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtualenv
	python3 -m venv .venv

install: ## Install runtime + dev dependencies into the venv
	$(PIP) install -U pip
	$(PIP) install -e ".[dev]"

dev: install ## Alias for install (dev setup)

test: ## Run the test suite
	$(PY) -m pytest

lint: ## Lint with ruff
	$(PY) -m ruff check .

fmt: ## Auto-format with ruff
	$(PY) -m ruff format .

typecheck: ## Type-check with mypy --strict
	$(PY) -m mypy core db modules taskqueue daemon api

health: dry-run ## Alias for dry-run

dry-run: ## Health checks + module registry, no network I/O
	$(PY) -m daemon.main --dry-run

api: ## Run the API locally
	$(PY) -m uvicorn api.main:app --reload --port 8000

seed: ## Seed a demo tenant + sample findings (needs Mongo)
	$(PY) -m scripts.seed_dev

backup: ## Back up MongoDB (mongodump)
	$(PY) -m scripts.backup

update-feeds: ## Refresh CDN/cloud scope feeds
	$(PY) -m scripts.update_scope_feeds

docker-build: ## Build all images
	docker compose -f docker/docker-compose.yml build

up: ## Start the full local stack
	docker compose -f docker/docker-compose.yml up -d

down: ## Stop the local stack
	docker compose -f docker/docker-compose.yml down
