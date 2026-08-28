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
mypy --strict sdk/ contracts/   # type-check — this is what CI runs, not plain `mypy`
```

All four run in CI (`.github/workflows/ci.yml`) and must pass.

## The browser-compatibility constraint

This is the one architectural rule that isn't optional: every built-in policy must stay pure-Python with zero network calls, because the same `sdk` package is compiled to WebAssembly via Pyodide and runs the live browser demo (`site/`) with nothing behind it. `tests/test_audit.py` enforces this in CI — it fails if any policy grows a network call or an import Pyodide can't supply. If a change needs either, that's a deliberate architecture decision (bringing a backend service back into scope), not something to slip in quietly.

If you touch anything under `sdk/policies/` or `sdk/interceptors/`, also run:

```bash
python tools/policy_audit.py
pytest tests/test_audit.py tests/test_pyodide_compat.py
```

## Adding a new built-in policy

1. Implement it satisfying the `Policy` protocol (`contracts/interceptor.py`) — `before_action`, `after_action`, `failure_mode`; subclass `BasePolicy` for pass-through defaults.
2. Standardize its metadata shape: `context.metadata["your_category"] = {"risk": float, "category": str, ...}` — this is what `RiskScorer`/`MetricsRecorder` read.
3. Register a factory in `sdk/policies/config.py`'s `_REGISTRY` so it's usable from YAML via `load_policies()`.
4. Add it to the README's "Built-in Policies" table and, if it changes wire-visible behavior, to `sdk/policies/policies_example.yaml`.
5. Write tests under `tests/`, following the existing `test_<policy>.py` naming.

## Deprecating / renaming public API

Follow the existing pattern (see `PIIInterceptor` → `PIIPolicy`, `OpenScriptMiddleware` → `SecureAgent`): keep the old name as a subclass/alias that emits `DeprecationWarning` via `warnings.warn(..., stacklevel=2)`, rather than removing it outright.

## Commit messages

Plain, descriptive commit messages about what changed. No phase numbers or references to internal planning docs — those don't mean anything to someone reading `git log` outside the project.
