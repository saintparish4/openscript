# OpenScript

**Prompt security SDK for LLM/agent workflows.** Detect injection risks, reduce data leaks, and validate LLM I/O — built for teams that need compliance, risk reduction, and real-time protection across any LLM provider.

OpenScript provides an **Interceptor protocol** and **middleware pipeline** that wraps any LLM agent. You register interceptors that run before and after every agent action. The SDK ships with a `NoopInterceptor` for wiring and testing — proprietary security interceptors are available separately via `openscript-server`.

## Getting Started in 5 Minutes    

### 1. Install

```bash
pip install openscript
```

Or from source:

```bash
git clone https://github.com/OrdinalScale/openscript.git
cd openscript
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Unix
pip install -r requirements.txt
pip install -e .
```

### 2. Wrap an Agent

```python
import asyncio
from sdk import OpenScriptMiddleware, NoopInterceptor

class MyAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": f"Hello, {input_data.get('input', 'world')}!"}

async def main():
    agent = MyAgent()
    secure = OpenScriptMiddleware(
        agent=agent,
        interceptors=[NoopInterceptor()],
    )
    result = await secure.invoke({"input": "OpenScript"})
    print(result)  # {"output": "Hello, OpenScript!"}

asyncio.run(main())
```

### 3. Use the LangChain Convenience Wrapper

```python
from sdk import wrap_agent, NoopInterceptor

# agent = ... your LangChain AgentExecutor ...
secure = wrap_agent(agent, interceptors=[NoopInterceptor()])
result = await secure.invoke({"input": "What is prompt injection?"})
```

### 4. Write a Custom Interceptor

```python
from contracts.types import ActionContext, FailureMode

class LoggingInterceptor:
    failure_mode = FailureMode.FAIL_OPEN

    async def before_action(self, context: ActionContext) -> ActionContext:
        print(f"[BEFORE] action={context.action} input={context.input_data}")
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        print(f"[AFTER] action={context.action} output={context.output_data}")
        return context

# Register it:
secure = OpenScriptMiddleware(agent=agent, interceptors=[LoggingInterceptor()])
```

Any class that implements `before_action`, `after_action`, and `failure_mode` satisfies the `Interceptor` protocol — no base class inheritance required.

## Architecture

```
User Request
    │
    ▼
┌───────────────────────────┐
│  OpenScriptMiddleware     │
│                           │
│  ┌─ before_action ──────┐ │
│  │  Interceptor 1       │ │
│  │  Interceptor 2       │ │
│  │  ...                 │ │
│  └──────────────────────┘ │
│           │               │
│     Agent.invoke()        │
│           │               │
│  ┌─ after_action ───────┐ │
│  │  Interceptor 1       │ │
│  │  Interceptor 2       │ │
│  │  ...                 │ │
│  └──────────────────────┘ │
└───────────────────────────┘
    │
    ▼
  Response
```

The middleware is a **dumb pipeline** — zero detection or security logic built in. All policy is provided by interceptor implementations. This makes the SDK genuinely usable standalone with custom interceptors.

## FailureMode

Each interceptor declares how the middleware handles errors:

| Mode | Behavior |
|------|----------|
| `FAIL_OPEN` | Log warning, allow action to proceed |
| `FAIL_CLOSED` | Log error, block action (raises `RuntimeError`) |
| `FAIL_EXCEPTION` | Re-raise the original exception |

Default for observability interceptors: `FAIL_OPEN`. Default for security interceptors: `FAIL_CLOSED`.

## Development

```bash
# Setup
python -m venv .venv && .venv/Scripts/activate
pip install -r requirements.txt && pip install -e .

# Test
pytest

# Lint + format + type-check
ruff check .
black .
mypy sdk/ contracts/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

## License

Apache 2.0 — see [LICENSE](LICENSE).