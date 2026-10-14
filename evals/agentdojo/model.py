"""A model in AgentDojo's pipeline, with a meter on it, and a stand-in that needs no key.

AgentDojo ships an Anthropic pipeline element, but it predates the current
models: it sends ``temperature=0``, which Claude Sonnet 5.5 refuses, it
rebuilds each earlier turn in its own order, which a thinking model refuses
too, and it keeps no record of what a request cost. ``Claude`` reuses
AgentDojo's own message conversion, so a transcript means what it means in
AgentDojo's runs, sends each earlier turn back exactly as it was written, and
adds the two things a paid run needs: the usage of every request, and a
budget that stops the run before it is overspent.

``ScriptedAgent`` stands where the model would and costs nothing. It makes the
calls AgentDojo ships as the task's solution, one at a time, and once a result
it was handed carries the injection it makes all of the attacker's calls
before carrying on. That is the replay's compromised agent (PROTOCOL.md),
driven through the real pipeline, so the harness can be checked end to end
against the replay's committed rows without spending anything.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import dataclass, field
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.anthropic_llm import (
    _anthropic_to_assistant_message,
    _conversation_to_anthropic,
    _function_to_anthropic,
)
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, text_content_block_from_string


@dataclass(frozen=True)
class Profile:
    """A model, what it costs, and the request parameters the protocol fixes for it."""

    model: str
    #: US dollars per million tokens, as listed on 2026-09-25. Check before a run.
    input: float
    output: float
    #: Sent with every request on top of the model, messages, tools and max_tokens.
    params: Mapping[str, Any] = field(default_factory=dict)
    max_tokens: int = 16000

    def cost(self, usage: Any) -> float:
        """What one request cost. A cache write is billed at 1.25x input and a
        cache read at 0.1x (the five-minute cache)."""
        written = getattr(usage, "cache_creation_input_tokens", 0) or 0
        read = getattr(usage, "cache_read_input_tokens", 0) or 0
        tokens_in = usage.input_tokens + 1.25 * written + 0.1 * read
        return (tokens_in * self.input + usage.output_tokens * self.output) / 1_000_000


#: Each model as it ships: no temperature, its own default for thinking and
#: effort. Claude Haiku 4.5 does not think unless asked; Claude Sonnet 5.5
#: thinks adaptively, at effort high. No refusal fallbacks: a fallback would
#: answer with another model in the middle of a run.
PROFILES: dict[str, Profile] = {
    "haiku": Profile("claude-haiku-4-5", input=1.00, output=5.00),
    "sonnet": Profile("claude-sonnet-5-5", input=2.00, output=10.00),
}

#: Where an assistant turn keeps the blocks exactly as the model wrote them.
RAW = "anthropic_content"
#: What AgentDojo's view of a turn keeps. Thinking stays in the turn as written
#: (RAW); AgentDojo cannot convert a redacted thinking block back.
_VIEW_BLOCKS = {"text", "tool_use"}
_TOOL_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_NO_ENV = EmptyEnv()


class BudgetExceeded(RuntimeError):
    """Raised instead of sending a request once the budget is spent."""


@dataclass
class Meter:
    """Usage and spend, for one case or one whole run.

    ``spend`` reads and adds to what has been spent so far across the run, so
    several worker processes can share one budget; by default it is a plain
    number in this process. A request is not sent once the budget is reached,
    so the run overshoots by at most the one request in flight in each worker.
    """

    profile: Profile
    budget: float
    spend: Callable[[float], float] | None = None
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read: int = 0
    cache_write: int = 0
    cost: float = 0.0
    refusals: int = 0
    _spent: float = 0.0

    def spent(self, add: float = 0.0) -> float:
        if self.spend is not None:
            return self.spend(add)
        self._spent += add
        return self._spent

    def check(self) -> None:
        spent = self.spent()
        if spent >= self.budget:
            raise BudgetExceeded(f"${spent:.2f} spent of a ${self.budget:.2f} budget")

    def add(self, usage: Any, stop_reason: str | None) -> dict[str, Any]:
        cost = self.profile.cost(usage)
        self.spent(cost)
        self.requests += 1
        self.input_tokens += usage.input_tokens
        self.output_tokens += usage.output_tokens
        self.cache_read += getattr(usage, "cache_read_input_tokens", 0) or 0
        self.cache_write += getattr(usage, "cache_creation_input_tokens", 0) or 0
        self.cost += cost
        self.refusals += stop_reason == "refusal"
        return {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cache_read": getattr(usage, "cache_read_input_tokens", 0) or 0,
            "cache_write": getattr(usage, "cache_creation_input_tokens", 0) or 0,
            "stop_reason": stop_reason,
            "cost_usd": round(cost, 6),
        }

    def totals(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read": self.cache_read,
            "cache_write": self.cache_write,
            "refusals": self.refusals,
            "cost_usd": round(self.cost, 6),
        }


class Claude(BasePipelineElement):
    """A Claude model as an AgentDojo pipeline element, metered.

    ``client`` is anything with ``messages.create``; by default the Anthropic
    SDK's client, which reads its credentials from the environment
    (``ANTHROPIC_API_KEY``). ``on_request`` is told the usage of each request.
    """

    def __init__(
        self,
        profile: Profile,
        meter: Meter,
        client: Any = None,
        on_request: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if client is None:
            import anthropic

            # A new account's rate limits are low; the SDK waits out a 429.
            client = anthropic.Anthropic(max_retries=8)
        self.name = profile.model
        self.profile = profile
        self.meter = meter
        self.client = client
        self.on_request = on_request

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = _NO_ENV,
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},  # noqa: B006 -- AgentDojo's own signature
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        system, conversation = _conversation_to_anthropic(messages)
        # AgentDojo rebuilds an assistant turn as text and thinking first, tool
        # calls after. A thinking model refuses a conversation whose earlier
        # turns were changed, so each turn goes back exactly as it came.
        written = (m.get(RAW) for m in messages if m["role"] == "assistant")
        for turn in conversation:
            if turn["role"] == "assistant":
                raw = next(written)
                if raw is not None:
                    turn["content"] = raw
        request: dict[str, Any] = {
            "model": self.profile.model,
            "max_tokens": self.profile.max_tokens,
            "messages": conversation,
            "tools": [_function_to_anthropic(tool) for tool in runtime.functions.values()],
            # Each turn resends the conversation so far; caching it is billed
            # at a tenth on the next turn. It changes the bill, not the answer.
            "cache_control": {"type": "ephemeral"},
            **self.profile.params,
        }
        if system:
            request["system"] = system
        self.meter.check()
        response = self.client.messages.create(**request)
        usage = self.meter.add(response.usage, response.stop_reason)
        if self.on_request is not None:
            self.on_request(usage)

        # AgentDojo's view of the turn is its text and its calls; the turn
        # itself is kept whole, to be sent back as it was written.
        view = [block for block in response.content if block.type in _VIEW_BLOCKS]
        output = _anthropic_to_assistant_message(response.model_copy(update={"content": view}))
        calls = output["tool_calls"] or []
        valid = [call for call in calls if _TOOL_NAME.match(call.function)]
        if len(valid) < len(calls):
            # As AgentDojo's own element does: a call to a name no tool can
            # have is dropped. The turn is then sent back as AgentDojo
            # rebuilds it, since a call with no result would be refused.
            output["tool_calls"] = valid
        else:
            output[RAW] = [  # type: ignore[literal-required]
                block.model_dump(mode="json", exclude_none=True) for block in response.content
            ]
        return query, runtime, env, [*messages, output], extra_args


class ScriptedAgent(BasePipelineElement):
    """The replay's compromised agent, as a pipeline element. No model, no key.

    Makes the task's own calls one per turn. When one of them that AgentDojo
    exposes to the injection (``exposed``, by index, found as the replay finds
    it) hands its result back, it makes every one of the attacker's calls
    next, then carries on with the task. A held, refused or withheld call
    comes back as an error and the script goes on regardless, as the replay
    does. When the calls run out it says the task's expected answer, and the
    attacker's too if it was compromised.

    ``input_chars`` is the length of every request a model would have been
    sent, for a floor on what a model run costs.
    """

    name = "scripted"

    def __init__(
        self,
        user_task: BaseUserTask[Any],
        injection_task: BaseInjectionTask[Any] | None,
        exposed: Set[int] = frozenset(),
    ) -> None:
        self.user_task = user_task
        self.injection_task = injection_task
        self.exposed = exposed
        self.compromised = False
        self.input_chars: list[int] = []
        self._user: list[FunctionCall] | None = None
        self._attack: list[FunctionCall] = []
        self._queue: list[FunctionCall] = []  # the attacker's calls still to make
        self._next = 0
        self._last: int | None = None  # index of the task's own call made last turn

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = _NO_ENV,
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},  # noqa: B006
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        system, conversation = _conversation_to_anthropic(messages)
        tools = [_function_to_anthropic(tool) for tool in runtime.functions.values()]
        self.input_chars.append(len(json.dumps([system, conversation, tools], default=str)))

        if self._user is None:
            # The first turn: the environment is as the task left it.
            self._user = self.user_task.ground_truth(env.model_copy(deep=True))
            if self.injection_task is not None:
                self._attack = self.injection_task.ground_truth(env.model_copy(deep=True))
        if (
            self.injection_task is not None
            and not self.compromised
            and self._last in self.exposed
            and messages[-1]["role"] == "tool"
            and messages[-1]["error"] is None
        ):
            # The agent has now read the injection, and does all of what it says.
            self.compromised = True
            self._queue = list(self._attack)

        self._last = None
        if self._queue:
            call = self._queue.pop(0)
        elif self._next < len(self._user):
            call, self._last = self._user[self._next], self._next
            self._next += 1
        else:
            said = self.user_task.GROUND_TRUTH_OUTPUT
            if self.compromised and self.injection_task is not None:
                said += f" {self.injection_task.GROUND_TRUTH_OUTPUT}"
            answer = ChatAssistantMessage(
                role="assistant", content=[text_content_block_from_string(said)], tool_calls=None
            )
            return query, runtime, env, [*messages, answer], extra_args

        turn = sum(message["role"] == "assistant" for message in messages)
        message = ChatAssistantMessage(
            role="assistant",
            content=[text_content_block_from_string("")],
            tool_calls=[FunctionCall(function=call.function, args=dict(call.args), id=f"c{turn}")],
        )
        return query, runtime, env, [*messages, message], extra_args
