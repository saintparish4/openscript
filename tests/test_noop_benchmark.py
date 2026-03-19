import asyncio
import time
import warnings

import pytest

from sdk import NoopInterceptor, OpenScriptMiddleware

WARMUP_ROUNDS = 5
BENCH_ROUNDS = 50
SOFT_LIMIT_MS = 1.0


class FakeAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": "ok"}


def _run_once(mw):
    return asyncio.run(mw.invoke({"input": "bench"}))


@pytest.mark.benchmark
def test_noop_overhead(benchmark):
    """Baseline benchmark for NoopInterceptor middleware overhead."""
    agent = FakeAgent()
    mw = OpenScriptMiddleware(agent=agent, interceptors=[NoopInterceptor()])

    result = benchmark(_run_once, mw)
    assert result["output"] == "ok"


@pytest.mark.benchmark
def test_noop_overhead_baseline():
    """Records per-call overhead as a visible baseline in test output."""
    agent = FakeAgent()
    mw = OpenScriptMiddleware(agent=agent, interceptors=[NoopInterceptor()])

    for _ in range(WARMUP_ROUNDS):
        _run_once(mw)

    elapsed = []
    for _ in range(BENCH_ROUNDS):
        start = time.perf_counter()
        result = _run_once(mw)
        elapsed.append(time.perf_counter() - start)

    assert result["output"] == "ok"

    mean_ms = (sum(elapsed) / len(elapsed)) * 1_000
    p95_ms = sorted(elapsed)[int(len(elapsed) * 0.95)] * 1_000
    min_ms = min(elapsed) * 1_000
    max_ms = max(elapsed) * 1_000

    print(
        f"\n--- NoopInterceptor baseline ({BENCH_ROUNDS} calls) ---"
        f"\n  mean : {mean_ms:.3f} ms"
        f"\n  p95  : {p95_ms:.3f} ms"
        f"\n  min  : {min_ms:.3f} ms"
        f"\n  max  : {max_ms:.3f} ms"
    )

    if mean_ms > SOFT_LIMIT_MS:
        warnings.warn(
            f"NoopInterceptor mean overhead ({mean_ms:.3f} ms) exceeded "
            f"soft target of {SOFT_LIMIT_MS} ms",
            stacklevel=1,
        )
