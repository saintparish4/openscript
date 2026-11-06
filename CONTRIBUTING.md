# Contributing to OpenScript

## Setup

```bash
git clone https://github.com/saintparish4/openscript.git
cd openscript
python -m venv .venv && source .venv/bin/activate   # .venv/Scripts/activate on Windows
pip install -r requirements.txt
pip install -e .
```

`requirements.txt` installs the full dev + server stack (FastAPI, SQLAlchemy, Postgres/Redis clients, pytest, mypy, ruff, black) needed to run everything below. If you're only working on core policy logic and don't need the server or test suite, `pip install -e .` alone is enough — see the README's Getting Started section.

## Before opening a PR

```bash
pytest                          # full test suite
ruff check .                    # lint
black .                         # format
mypy --strict openscript_sdk/ --exclude openscript_sdk/server/   # type-check — this is what CI runs, not plain `mypy`
```

All four run in CI (`.github/workflows/ci.yml`) and must pass.

One test file needs a service. `tests/test_redis_approvals.py` checks the Redis approval store against a real Redis, and skips when it is not told where one is:

```bash
docker compose up -d redis
OPENSCRIPT_TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/test_redis_approvals.py
```

CI runs it against a Redis service container, and fails rather than skips if that is missing.

## The browser-compatibility constraint

This is the one architectural rule that isn't optional: every built-in policy must stay pure-Python with zero network calls, because the same `openscript_sdk` package is compiled to WebAssembly via Pyodide and runs the live browser demo (`site/`) with nothing behind it. `tests/test_audit.py` enforces this in CI — it fails if any policy grows a network call or an import Pyodide can't supply. If a change needs either, that's a deliberate architecture decision (bringing a backend service back into scope), not something to slip in quietly.

If you touch anything under `openscript_sdk/policies/` or `openscript_sdk/interceptors/`, also run:

```bash
python tools/policy_audit.py
pytest tests/test_audit.py tests/test_pyodide_compat.py
```

## Adding a new built-in policy

1. Implement it satisfying the `Policy` protocol (`openscript_sdk/contracts/interceptor.py`) — `before_action`, `after_action`, `failure_mode`; subclass `BasePolicy` for pass-through defaults.
2. Standardize its metadata shape: `context.metadata["your_category"] = {"risk": float, "category": str, ...}` — this is what `RiskScorer`/`MetricsRecorder` read.
3. Register a factory in `openscript_sdk/policies/config.py`'s `_REGISTRY` so it's usable from YAML via `load_policies()`.
4. Add it to the README's "Built-in Policies" table and, if it changes wire-visible behavior, to `openscript_sdk/policies/policies_example.yaml`.
5. Write tests under `tests/`, following the existing `test_<policy>.py` naming.

## Deprecating / renaming public API

Follow the existing pattern (see `PIIInterceptor` → `PIIPolicy`, `OpenScriptMiddleware` → `SecureAgent`): keep the old name as a subclass/alias that emits `DeprecationWarning` via `warnings.warn(..., stacklevel=2)`, rather than removing it outright.

## Commit messages

Plain, descriptive commit messages about what changed. No phase numbers or references to internal planning docs — those don't mean anything to someone reading `git log` outside the project.

## The stack and the layout

Moved here from the README on 2026-11-04, unchanged.

#### Technologies

| Layer | Built with |
|---|---|
| Core SDK | Python 3.11+, with three runtime dependencies: pydantic 2 (≥ 2.10), structlog, PyYAML |
| In the browser | Pyodide 0.28.3 (CPython on WebAssembly), Next.js 16 static export, React 19, TypeScript |
| Browser extension | Chrome Manifest V3, with Pyodide running in the side panel |
| Optional server | FastAPI, SQLAlchemy with asyncpg on Postgres, Alembic, Redis, Prometheus, OpenTelemetry |
| Java client | Java 17, the JDK's `HttpClient`, Maven; JUnit 5 for its tests |
| Evaluation | Labelled corpora (1,799 prompts, 1,451 of them public), AgentDojo 0.1.35, the Anthropic Python SDK for runs with a model |
| Quality | pytest, mypy `--strict`, ruff, black, GitHub Actions, a daily check of the deployed demo |

#### Repository layout

```
openscript/
├── openscript_sdk/           the package: `pip install openscript-sdk`, `import openscript_sdk`
│   ├── middleware/           SecureAgent (middleware.py) and SecureTool (tool.py)
│   ├── policies/             the built-in policies, the YAML loader, example configs
│   ├── interceptors/         PII, threat scoring and the event writer (the pre-1.0 names)
│   ├── hooks/                openscript-hook for Claude Code, its config model and examples
│   ├── integrations/         wrap_agent / wrap_graph_agent for LangChain and LangGraph
│   ├── observability/        risk scoring, Prometheus metrics, OpenTelemetry tracing
│   ├── contracts/            the Policy protocol, ActionContext, decisions, failure modes
│   ├── events/               event writer and store; approval stores (in-memory, Redis)
│   └── server/               optional FastAPI server ([server] extra): events, SSE, dashboard, approvals, /v1/guard, /metrics
├── clients/java/             a Java client: SecureAgent and SecureTool over /v1/guard
├── site/                     the live demo: a Next.js static export that runs the package via Pyodide
├── extension/                a Chrome extension: the package around a scripted browsing agent
├── web/                      a bare Pyodide probe page and its headless check
├── evals/                    labelled corpora and run.py; agentdojo/ is the benchmark harness; ledger.py is the effect side
├── demo/                     a terminal walkthrough of the pipeline
├── tools/                    policy audit, browser wheel builds, hook latency, the Java client's live check
├── tests/                    the test suite; bypass/ holds the red team's searches
└── docs/                     guide.md (the full reference), metrics.md (every number), threat-model.md,
                              red-team.md, raw-material.md, submission.md, the demo recording
```
