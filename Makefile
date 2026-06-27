.DEFAULT_GOAL := help

# Use venv binaries directly — no need to `source .venv/bin/activate` in recipes.
# To activate in your shell: source .venv/bin/activate
PYTHON   := .venv/bin/python
PIP      := .venv/bin/pip
PYTEST   := .venv/bin/pytest
BLACK    := .venv/bin/black
RUFF     := .venv/bin/ruff
MYPY     := .venv/bin/mypy
UVICORN  := .venv/bin/uvicorn
ALEMBIC  := .venv/bin/alembic

# ── Environment ───────────────────────────────────────────────────────────────

.venv:
	python3 -m venv .venv

.PHONY: venv
venv: .venv  ## Create .venv and print the activation command to run
	@echo ""
	@echo "  Virtual environment ready. Now run:"
	@echo ""
	@echo "    source .venv/bin/activate"
	@echo ""

.PHONY: install
install: .venv  ## Create .venv and install all dependencies + package (editable)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

.PHONY: env
env:  ## Copy .env.example → .env (skips if .env already exists)
	@[ -f .env ] && echo ".env already exists — skipping." || (cp .env.example .env && echo "Created .env from .env.example")

# ── Docker / Database ─────────────────────────────────────────────────────────

.PHONY: db-up
db-up:  ## Start Postgres in Docker (detached)
	docker compose up -d postgres

.PHONY: db-down
db-down:  ## Stop Postgres container
	docker compose stop postgres

.PHONY: db-reset
db-reset:  ## Destroy Postgres container + volume (wipes all data)
	docker compose down -v

.PHONY: docker-up
docker-up:  ## Start full stack — postgres + migrate + server (detached)
	docker compose up -d

.PHONY: docker-down
docker-down:  ## Stop full Docker stack
	docker compose down

.PHONY: docker-logs
docker-logs:  ## Tail logs for all Docker services
	docker compose logs -f

# ── Migrations ────────────────────────────────────────────────────────────────

.PHONY: migrate
migrate:  ## Apply all pending Alembic migrations
	$(ALEMBIC) upgrade head

.PHONY: migrate-down
migrate-down:  ## Roll back all Alembic migrations
	$(ALEMBIC) downgrade base

.PHONY: migrate-new
migrate-new:  ## Create a new migration — usage: make migrate-new m="add users table"
	$(ALEMBIC) revision --autogenerate -m "$(m)"

# ── Server ────────────────────────────────────────────────────────────────────

.PHONY: serve
serve:  ## Run the FastAPI dev server with hot-reload on :8000
	$(UVICORN) server.app:app --host 0.0.0.0 --port 8000 --reload

# ── Tests ─────────────────────────────────────────────────────────────────────

.PHONY: test
test:  ## Run the full test suite
	$(PYTEST) -v

.PHONY: test-bench
test-bench:  ## Run benchmark tests only
	$(PYTEST) --benchmark-only -v

# ── Code Quality ──────────────────────────────────────────────────────────────

.PHONY: fmt
fmt:  ## Auto-format code with black
	$(BLACK) .

.PHONY: fmt-check
fmt-check:  ## Check formatting without modifying files (used in CI)
	$(BLACK) --check .

.PHONY: lint
lint:  ## Run ruff linter
	$(RUFF) check .

.PHONY: lint-fix
lint-fix:  ## Run ruff and auto-fix fixable issues
	$(RUFF) check . --fix

.PHONY: typecheck
typecheck:  ## Run mypy strict type-checking on sdk/ and contracts/
	$(MYPY) --strict sdk/ contracts/

.PHONY: check
check: fmt-check lint typecheck  ## Run all quality checks (format + lint + types)

# ── Build ─────────────────────────────────────────────────────────────────────

.PHONY: build
build:  ## Build the distributable wheel + sdist
	$(PYTHON) -m build

# ── Demo ──────────────────────────────────────────────────────────────────────

.PHONY: demo
demo:  ## Run the functional injection demo
	$(PYTHON) demo/injection_demo.py

# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
help:  ## List all available targets
	@echo "Usage: make <target>\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
