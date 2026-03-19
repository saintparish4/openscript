"""PRD-style integration tests using a mock LLM with NoopInterceptor.

These tests mirror the code patterns shown in the PRD (§ Technical Architecture,
Integration Pattern) to prove the SDK's public API works end-to-end against a
realistic mock LLM agent.
"""

from __future__ import annotations

from typing import Any

import pytest

from sdk import (
    NoopInterceptor,
    OpenScriptMiddleware,
    wrap_agent,
    wrap_graph_agent,
)


class MockLLMAgent:
    """Simulates a LangChain/LangGraph agent backed by a mock LLM.

    Provides both sync and async invoke/stream interfaces so the middleware
    can exercise every dispatch path.
    """

    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        self.responses = responses or [{"output": "Mock LLM response"}]
        self._call_idx = 0

    def _next_response(self) -> dict[str, Any]:
        resp = self.responses[min(self._call_idx, len(self.responses) - 1)]
        self._call_idx += 1
        return resp

    async def ainvoke(self, input_data: dict, **kwargs: Any) -> dict:
        return self._next_response()

    async def astream(self, input_data: dict, **kwargs: Any):
        resp = self._next_response()
        for token in resp.get("output", "").split():
            yield {"token": token}

    def invoke(self, input_data: dict, **kwargs: Any) -> dict:
        return self._next_response()

    def stream(self, input_data: dict, **kwargs: Any):
        resp = self._next_response()
        for token in resp.get("output", "").split():
            yield {"token": token}


# ---------------------------------------------------------------------------
# PRD § LangChain integration pattern
# ---------------------------------------------------------------------------


class TestLangChainIntegration:
    @pytest.mark.asyncio
    async def test_wrap_agent_invoke_with_noop(self):
        """wrap_agent + NoopInterceptor produces correct output from mock LLM."""
        llm = MockLLMAgent(responses=[{"output": "Hello from LLM"}])
        secure = wrap_agent(llm, interceptors=[NoopInterceptor()])
        result = await secure.invoke({"input": "hello"})
        assert result == {"output": "Hello from LLM"}

    @pytest.mark.asyncio
    async def test_wrap_agent_stream_with_noop(self):
        """wrap_agent streaming path collects all tokens from mock LLM."""
        llm = MockLLMAgent(responses=[{"output": "token1 token2 token3"}])
        secure = wrap_agent(llm, interceptors=[NoopInterceptor()])
        tokens = [chunk async for chunk in secure.stream({"input": "hello"})]
        assert tokens == [
            {"token": "token1"},
            {"token": "token2"},
            {"token": "token3"},
        ]


# ---------------------------------------------------------------------------
# PRD § LangGraph integration pattern
# ---------------------------------------------------------------------------


class TestLangGraphIntegration:
    @pytest.mark.asyncio
    async def test_wrap_graph_agent_invoke_with_noop(self):
        """wrap_graph_agent + NoopInterceptor runs mock graph end-to-end."""
        graph = MockLLMAgent(responses=[{"messages": [{"role": "assistant", "content": "Hi!"}]}])
        secure = wrap_graph_agent(graph, interceptors=[NoopInterceptor()])
        result = await secure.invoke({"messages": [{"role": "user", "content": "hello"}]})
        assert result["messages"] == [{"role": "assistant", "content": "Hi!"}]

    @pytest.mark.asyncio
    async def test_wrap_graph_agent_stream_with_noop(self):
        """wrap_graph_agent streaming collects tokens from mock graph."""
        graph = MockLLMAgent(responses=[{"output": "graph stream"}])
        secure = wrap_graph_agent(graph, interceptors=[NoopInterceptor()])
        tokens = [chunk async for chunk in secure.stream({"input": "run"})]
        assert len(tokens) == 2
        assert tokens[0] == {"token": "graph"}


# ---------------------------------------------------------------------------
# PRD § Direct OpenScriptMiddleware usage
# ---------------------------------------------------------------------------


class TestDirectMiddlewareIntegration:
    @pytest.mark.asyncio
    async def test_middleware_invoke_default_noop(self):
        """Middleware with no interceptors defaults to NoopInterceptor."""
        llm = MockLLMAgent(responses=[{"output": "default noop"}])
        mw = OpenScriptMiddleware(agent=llm)
        result = await mw.invoke({"input": "test"})
        assert result["output"] == "default noop"

    @pytest.mark.asyncio
    async def test_middleware_invoke_explicit_noop(self):
        """Mirrors PRD: OpenScriptMiddleware(agent=agent, interceptors=[...])."""
        llm = MockLLMAgent(responses=[{"output": "secured response"}])
        mw = OpenScriptMiddleware(agent=llm, interceptors=[NoopInterceptor()])
        result = await mw.invoke({"input": "user prompt"})
        assert result["output"] == "secured response"

    @pytest.mark.asyncio
    async def test_middleware_multi_turn_conversation(self):
        """Simulates multiple invoke calls (multi-turn) against same agent."""
        llm = MockLLMAgent(
            responses=[
                {"output": "Hello! How can I help?"},
                {"output": "Here is the weather forecast."},
                {"output": "Goodbye!"},
            ]
        )
        mw = OpenScriptMiddleware(agent=llm, interceptors=[NoopInterceptor()])

        r1 = await mw.invoke({"input": "hi"})
        assert r1["output"] == "Hello! How can I help?"

        r2 = await mw.invoke({"input": "what's the weather?"})
        assert r2["output"] == "Here is the weather forecast."

        r3 = await mw.invoke({"input": "bye"})
        assert r3["output"] == "Goodbye!"

    @pytest.mark.asyncio
    async def test_middleware_passes_kwargs(self):
        """Kwargs like agent_id and session_id flow through to the agent."""

        class KwargsCapturingAgent:
            def __init__(self):
                self.captured_kwargs: dict = {}

            async def ainvoke(self, input_data, **kwargs):
                self.captured_kwargs = kwargs
                return {"output": "ok"}

        agent = KwargsCapturingAgent()
        mw = OpenScriptMiddleware(agent=agent, interceptors=[NoopInterceptor()])
        await mw.invoke({"input": "test"}, agent_id="agent-1", session_id="sess-42")
        assert agent.captured_kwargs["agent_id"] == "agent-1"
        assert agent.captured_kwargs["session_id"] == "sess-42"

    @pytest.mark.asyncio
    async def test_sync_only_agent_via_executor(self):
        """Agent with only sync invoke is supported via run_in_executor."""

        class SyncOnlyAgent:
            def invoke(self, input_data, **kwargs):
                return {"output": "sync agent reply"}

        agent = SyncOnlyAgent()
        mw = OpenScriptMiddleware(agent=agent, interceptors=[NoopInterceptor()])
        result = await mw.invoke({"input": "hello"})
        assert result["output"] == "sync agent reply"
