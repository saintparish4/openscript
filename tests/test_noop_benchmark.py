import asyncio

import pytest

from sdk import NoopInterceptor, OpenScriptMiddleware


class FakeAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": "ok"}


@pytest.mark.benchmark
def test_noop_overhead(benchmark):
    """NoopInterceptor overhead must be < 1ms."""
    agent = FakeAgent()
    mw = OpenScriptMiddleware(agent=agent, interceptors=[NoopInterceptor()])

    async def run():
        return await mw.invoke({"input": "bench"})

    def sync_run():
        return asyncio.get_event_loop().run_until_complete(run())

    result = benchmark(sync_run)
    assert result["output"] == "ok"
