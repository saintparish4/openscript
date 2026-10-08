"""What the wrapped agent is actually handed.

Two things used to be wrong on the one line that calls it. The agent was given
the caller's original input, so a policy that redacted the input had redacted
only its own copy. And it was given the policies' findings as keyword
arguments, because the context's metadata and the call's kwargs were the same
dict.
"""

from __future__ import annotations

from typing import Any

import pytest

from sdk import PromptInjectionPolicy, SecretsPolicy, SecureAgent

KEY = "AKIAIOSFODNN7EXAMPLE"
PROMPT = {"input": f"deploy with {KEY} please"}


class Recording:
    """Writes down what it was called with."""

    def __init__(self) -> None:
        self.inputs: list[dict[str, Any]] = []
        self.kwargs: list[dict[str, Any]] = []

    async def ainvoke(self, input_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        self.inputs.append(dict(input_data))
        self.kwargs.append(dict(kwargs))
        return {"output": "ok"}

    async def astream(self, input_data: dict[str, Any], **kwargs: Any) -> Any:
        self.inputs.append(dict(input_data))
        self.kwargs.append(dict(kwargs))
        yield "ok"


async def test_a_secret_redacted_from_the_input_does_not_reach_the_agent():
    agent = Recording()
    await SecureAgent(agent, policies=[SecretsPolicy(mode="redact")]).invoke(dict(PROMPT))
    assert KEY not in agent.inputs[0]["input"]
    assert agent.inputs[0]["input"].startswith("deploy with AKIA")


@pytest.mark.parametrize("mode", ["buffer", "guarded", "passthrough"])
async def test_nor_when_the_agent_streams(mode: str):
    agent = Recording()
    secure = SecureAgent(agent, policies=[SecretsPolicy(mode="redact")])
    async for _ in secure.stream(dict(PROMPT), stream_output=mode):
        pass
    assert KEY not in agent.inputs[0]["input"]


async def test_the_callers_own_dict_is_left_alone():
    """Redaction is what the agent is given, not a rewrite of the caller's data."""
    sent = dict(PROMPT)
    await SecureAgent(Recording(), policies=[SecretsPolicy(mode="redact")]).invoke(sent)
    assert sent == PROMPT


async def test_input_no_policy_touched_arrives_as_it_was_sent():
    agent = Recording()
    await SecureAgent(agent, policies=[PromptInjectionPolicy()]).invoke({"input": "hello"})
    assert agent.inputs == [{"input": "hello"}]


async def test_findings_are_not_passed_to_the_agent_as_keyword_arguments():
    agent = Recording()
    secure = SecureAgent(agent, policies=[PromptInjectionPolicy(), SecretsPolicy()])
    _, context = await secure.invoke_with_context({"input": "hello"}, session_id="s1", user="jo")

    # The agent gets what the caller passed, and nothing the policies wrote.
    assert agent.kwargs == [{"session_id": "s1", "user": "jo"}]
    # The context has both.
    assert {"threat", "secrets", "session_id", "user"} <= set(context.metadata)


async def test_an_agent_that_takes_no_keyword_arguments_can_be_wrapped():
    """It used to fail with "unexpected keyword argument 'threat'"."""

    class Strict:
        async def ainvoke(self, input_data: dict[str, Any]) -> dict[str, Any]:
            return {"output": input_data["input"].upper()}

    result = await SecureAgent(Strict(), policies=[PromptInjectionPolicy()]).invoke(
        {"input": "hello"}
    )
    assert result == {"output": "HELLO"}


async def test_findings_do_not_reach_a_streaming_agent_either():
    agent = Recording()
    secure = SecureAgent(agent, policies=[PromptInjectionPolicy()])
    async for _ in secure.stream({"input": "hello"}, session_id="s1"):
        pass
    assert agent.kwargs == [{"session_id": "s1"}]
