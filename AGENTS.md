# AGENTS.md

This file provides context for AI coding assistants (Cursor, GitHub Copilot, Claude Code, OpenAI, etc.) working with the **openscript** repository.

## Project Overview

**OpenScript** by OrdinalScale is a **Python SDK** for building **prompt-secured LLM/agent workflows**. It helps detect injection-style risks, reduce data leaks, and validate or gate LLM I/O—aimed at teams that need compliance, risk reduction, and protection across providers.

- **Repository**: _(add your Git remote URL)_
- **Documentation**: `README.md`; internal product notes under `.cursor/prd.md` if present
- **License**: _(add `LICENSE` at repo root when published)_

## Repository Structure

This is a **single-package Python library** (setuptools) with a flat layout: importable top-level packages `sdk` and `contracts`. There is **no** pnpm/npm workspace or Turborepo.

### Key directories

| Directory | Description | Example(s) |
|-----------|-------------|------------|
| `sdk/` | Middleware orchestration, base interceptors, framework hooks | `sdk/middleware/middleware.py`, `sdk/interceptors/base.py` |
| `sdk/integrations/` | Wrappers for agent frameworks (e.g. LangChain, LangGraph) | `langchain.py`, `langgraph.py` |
| `contracts/` | Shared types and the `Interceptor` protocol | `types.py`, `interceptor.py` |
| `tests/` | Pytest suite | `test_middleware.py`, `test_noop_benchmark.py` |
| `directive/` | Team notes, git/commit conventions (human-oriented) | `commit-msg-guideline.md` |
| `.github/workflows/` | CI definitions | `ci.yml` |

### Core runtime dependencies (high level)

Declared in `requirements.txt` / `pyproject.toml` as the project evolves. Typical stack includes **pytest** (dev), **black** (formatting), **pydantic**, **structlog**, and optional **FastAPI** / **httpx** / **prometheus-client** where integrations or observability need them. Prefer minimal additions to the published surface.

## Development setup

### Requirements

- **Python**: **3.10+** (`requires-python` in `pyproject.toml`)
- **pip**: current stable; install deps from `requirements.txt`

### Initial setup

```bash
python3 -m venv venv
# Windows: .venv\Scripts\activate
# Unix: source .venv/bin/activate
pip install -r requirements.txt
pip install -e .   # optional editable install so imports match package layout
```

## Development commands

### Root-level commands

| Command | Description |
|---------|-------------|
| `pytest` | Run tests (`testpaths`: `tests/`; `pythonpath` includes repo root) |
| `pytest tests/test_middleware.py` | Run a single file |
| `pytest -q --benchmark-only` | Benchmark-related tests (if using pytest-benchmark) |
| `black .` | Format Python (Black is in `requirements.txt`) |
| `black --check .` | Verify formatting without writing |

There is no root `lint`/`type-check` script yet; add **ruff** / **mypy** in CI when you standardize on them.

### Package / import layout

- Tests and apps run with repo root on `PYTHONPATH` (see `[tool.pytest.ini_options]` in `pyproject.toml`).
- Public re-exports live in `sdk/__init__.py`; keep that module the stable entry point for consumers.

## Core APIs

| Symbol | Purpose | Module |
|--------|---------|--------|
| `OpenScriptMiddleware` | Runs ordered `Interceptor`s around `invoke` / `stream` on a wrapped agent | `sdk.middleware.middleware` |
| `NoopInterceptor` | Pass-through interceptor for wiring/tests | `sdk.interceptors.base` |
| `wrap_agent` | LangChain-oriented integration | `sdk.integrations.langchain` |
| `wrap_graph_agent` | LangGraph-oriented integration | `sdk.integrations.langgraph` |
| `Interceptor` | Protocol: `before_action` / `after_action`, `failure_mode` | `contracts.interceptor` |
| `ActionContext`, `InterceptorResult`, `InterceptorDecision`, `FailureMode`, `AgentCapabilities` | Context and decision model | `contracts.types` |

## Import patterns

| What | Import from |
|------|-------------|
| Middleware + noop interceptor + framework wrappers + types | `sdk` (package `__init__` re-exports) |
| Protocol-only or types without pulling integrations | `contracts.interceptor`, `contracts.types` |

Prefer explicit imports inside the codebase (`from contracts.types import ...`) for clarity; re-export `sdk` for library users.

## Coding standards

### Formatting

- **Tool**: Black (version pinned in `requirements.txt`).
- Run `black .` before PRs unless CI enforces `--check`.

### Testing

- **Framework**: pytest + pytest-asyncio (`asyncio_mode = auto`).
- **Focus**: Behavior of middleware and interceptors; integration smoke for LangChain/LangGraph when those modules change.
- Avoid testing framework internals; test observable decisions and context flow.

### Logging and errors

- Use **structlog** where logging exists; include context (agent/session/action).
- **No silent failures** in security paths: fail with clear errors or explicit `FailureMode` behavior—document which mode applies.

### Types

- Use type hints on new public APIs; `Interceptor` is a **Protocol**—implementations must match it.

## Architecture

### Interceptor pattern

1. **`contracts`**: `Interceptor` protocol + immutable-ish context types (`ActionContext`, `InterceptorResult`, etc.).
2. **`OpenScriptMiddleware`**: Builds `ActionContext`, calls `before_action` → agent → `after_action`; no built-in detection logic—all policy lives in interceptors.
3. **Integrations**: Thin wrappers that attach middleware to LangChain / LangGraph agents.

Adding a new integration should not change the protocol without a deliberate version bump and migration notes.

## Contributing / team docs

| Task | Location |
|------|----------|
| Commit message style | `directive/commit-msg-guideline.md` |
| Git commands / workflow | `directive/git-command-list.md` |

## Task completion guidelines

### Bug fixes

1. Repro (test or minimal script).
2. Failing test that encodes expected behavior.
3. Fix + green tests.

### New features

1. Implementation + tests.
2. Update `sdk/__init__.py` exports if the API is public.
3. Short note in `README.md` if user-facing.

### Refactors

- Preserve behavior or adjust tests to reflect an intentional change.

## Do not

- Add detection or policy **inside** `OpenScriptMiddleware`; keep it orchestration-only.
- Break the **`Interceptor`** protocol without updating every implementation and tests.
- Swallow exceptions in interceptor or middleware paths without logging and an explicit failure policy.
- Add dependencies without updating `requirements.txt` / `pyproject.toml` and documenting why.
- Duplicate path layouts (e.g. `sdk\` vs `sdk/` on Windows)—normalize on forward slashes in docs and single canonical tree.

When scope is unclear (e.g. new provider vs. new interceptor), ask the maintainer before expanding the public API.
