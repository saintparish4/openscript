# Contributing to OpenScript

Thank you for your interest in contributing to OpenScript! This guide will help
you get started.

## Development Setup

```bash
python3 -m venv .venv

# Windows
.venv\Scripts\activate

# Unix/macOS
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

## Running Tests

```bash
# Full test suite
pytest

# Single file
pytest tests/test_middleware.py

# With benchmark
pytest -q --benchmark-only
```

## Code Quality

Run these before submitting a PR:

```bash
# Lint
ruff check .

# Format
black .

# Type check
mypy sdk/ contracts/
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Write tests for new behavior. Aim for behavior-based tests, not
   implementation tests.
3. Ensure all checks pass: `ruff check .`, `black --check .`, `mypy sdk/ contracts/`,
   `pytest`.
4. Keep PRs focused — one feature or fix per PR.
5. Update `sdk/__init__.py` exports if adding a new public API.

## Architecture

OpenScript uses an **Interceptor protocol** pattern:

- **`contracts/`** defines the `Interceptor` protocol and shared types.
  All types here are public and Apache 2.0 licensed.
- **`sdk/`** provides `OpenScriptMiddleware` (orchestrator), `NoopInterceptor`
  (pass-through default), and framework integrations (LangChain, LangGraph).
- The middleware contains **zero detection or security logic** — all policy
  is provided by interceptor implementations.

## Commit Messages

Follow the conventions in `directive/commit-msg-guideline.md` if present.

## Code Style

- **Formatter:** Black
- **Linter:** Ruff
- **Type checker:** mypy (strict on `sdk/` and `contracts/`)
- Use type hints on all public APIs.
- Use `structlog` for logging with bound context fields.
- No silent failures in security paths — use explicit `FailureMode` behavior.

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0.