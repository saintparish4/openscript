from unittest.mock import MagicMock, patch

import pytest

from contracts.types import ActionContext, FailureMode
from sdk import SecureAgent


class FakeAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": f"echo: {input_data.get('input', '')}"}

    async def astream(self, input_data, **kwargs):
        for word in input_data.get("input", "").split():
            yield {"token": word}


class RecordingPolicy:
    failure_mode = FailureMode.FAIL_OPEN

    def __init__(self):
        self.calls = []

    async def before_action(self, context: ActionContext) -> ActionContext:
        self.calls.append(("before", context.action))
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        self.calls.append(("after", context.action))
        return context


class FailingPolicy:
    def __init__(self, failure_mode: FailureMode):
        self.failure_mode = failure_mode

    async def before_action(self, context: ActionContext) -> ActionContext:
        raise ValueError("interceptor failure")

    async def after_action(self, context: ActionContext) -> ActionContext:
        raise ValueError("interceptor failure")


@pytest.mark.asyncio
async def test_empty_policy_list_passes_through():
    agent = FakeAgent()
    mw = SecureAgent(agent=agent, policies=[])
    result = await mw.invoke({"input": "hello"})
    assert result["output"] == "echo: hello"


@pytest.mark.asyncio
async def test_policies_called_in_order():
    agent = FakeAgent()
    p1 = RecordingPolicy()
    p2 = RecordingPolicy()
    mw = SecureAgent(agent=agent, policies=[p1, p2])
    await mw.invoke({"input": "test"})
    assert p1.calls[0] == ("before", "invoke")
    assert p2.calls[0] == ("before", "invoke")
    assert p1.calls[1] == ("after", "invoke")
    assert p2.calls[1] == ("after", "invoke")


@pytest.mark.asyncio
async def test_fail_closed_blocks_action():
    agent = FakeAgent()
    policy = FailingPolicy(FailureMode.FAIL_CLOSED)
    mw = SecureAgent(agent=agent, policies=[policy])
    with pytest.raises(RuntimeError, match="Action blocked"):
        await mw.invoke({"input": "test"})


@pytest.mark.asyncio
async def test_fail_open_allows_action():
    agent = FakeAgent()
    policy = FailingPolicy(FailureMode.FAIL_OPEN)
    mw = SecureAgent(agent=agent, policies=[policy])
    result = await mw.invoke({"input": "hello"})
    assert result["output"] == "echo: hello"


@pytest.mark.asyncio
async def test_stream_and_invoke_same_interception():
    agent = FakeAgent()
    invoke_rec = RecordingPolicy()
    stream_rec = RecordingPolicy()

    mw_invoke = SecureAgent(agent=agent, policies=[invoke_rec])
    await mw_invoke.invoke({"input": "a b"})

    mw_stream = SecureAgent(agent=agent, policies=[stream_rec])
    chunks = []
    async for chunk in mw_stream.stream({"input": "a b"}):
        chunks.append(chunk)

    assert invoke_rec.calls[0][0] == "before"
    assert invoke_rec.calls[1][0] == "after"
    assert stream_rec.calls[0][0] == "before"
    assert stream_rec.calls[1][0] == "after"


@pytest.mark.asyncio
async def test_custom_third_party_policy():
    """Proves the plugin seam works for third-party policies."""

    class CustomThirdPartyPolicy:
        failure_mode = FailureMode.FAIL_OPEN

        def __init__(self):
            self.seen_actions = []

        async def before_action(self, context: ActionContext) -> ActionContext:
            self.seen_actions.append(context.action)
            context.metadata["custom_tag"] = "third_party"
            return context

        async def after_action(self, context: ActionContext) -> ActionContext:
            return context

    agent = FakeAgent()
    custom = CustomThirdPartyPolicy()
    mw = SecureAgent(agent=agent, policies=[custom])
    await mw.invoke({"input": "test"})
    assert custom.seen_actions == ["invoke"]


# ---------------------------------------------------------------------------
# Log-emission assertions for policy errors
# ---------------------------------------------------------------------------


class TestPolicyErrorLogging:
    """Verify that _handle_failure emits the correct structlog events."""

    @pytest.mark.asyncio
    async def test_fail_open_emits_warning(self):
        mock_bound = MagicMock()
        mock_logger = MagicMock()
        mock_logger.bind.return_value = mock_bound

        with patch("sdk.middleware.middleware.logger", mock_logger):
            agent = FakeAgent()
            policy = FailingPolicy(FailureMode.FAIL_OPEN)
            mw = SecureAgent(agent=agent, policies=[policy])
            await mw.invoke({"input": "hello"})

        mock_logger.bind.assert_any_call(
            interceptor="FailingPolicy",
            phase="before_action",
            error="interceptor failure",
        )
        mock_bound.warning.assert_called_with("interceptor_error_fail_open")

    @pytest.mark.asyncio
    async def test_fail_closed_emits_error(self):
        mock_bound = MagicMock()
        mock_logger = MagicMock()
        mock_logger.bind.return_value = mock_bound

        with patch("sdk.middleware.middleware.logger", mock_logger):
            agent = FakeAgent()
            policy = FailingPolicy(FailureMode.FAIL_CLOSED)
            mw = SecureAgent(agent=agent, policies=[policy])
            with pytest.raises(RuntimeError, match="Action blocked"):
                await mw.invoke({"input": "test"})

        mock_logger.bind.assert_called_once_with(
            interceptor="FailingPolicy",
            phase="before_action",
            error="interceptor failure",
        )
        mock_bound.error.assert_called_once_with("interceptor_error_fail_closed")

    @pytest.mark.asyncio
    async def test_fail_exception_emits_error_and_reraises(self):
        mock_bound = MagicMock()
        mock_logger = MagicMock()
        mock_logger.bind.return_value = mock_bound

        with patch("sdk.middleware.middleware.logger", mock_logger):
            agent = FakeAgent()
            policy = FailingPolicy(FailureMode.FAIL_EXCEPTION)
            mw = SecureAgent(agent=agent, policies=[policy])
            with pytest.raises(ValueError, match="interceptor failure"):
                await mw.invoke({"input": "test"})

        mock_logger.bind.assert_called_once_with(
            interceptor="FailingPolicy",
            phase="before_action",
            error="interceptor failure",
        )
        mock_bound.error.assert_called_once_with("interceptor_error_fail_exception")

    @pytest.mark.asyncio
    async def test_fail_open_logs_both_phases(self):
        """FAIL_OPEN continues execution, so both before and after emit logs."""
        mock_bound = MagicMock()
        mock_logger = MagicMock()
        mock_logger.bind.return_value = mock_bound

        with patch("sdk.middleware.middleware.logger", mock_logger):
            agent = FakeAgent()
            policy = FailingPolicy(FailureMode.FAIL_OPEN)
            mw = SecureAgent(agent=agent, policies=[policy])
            await mw.invoke({"input": "hello"})

        bind_calls = mock_logger.bind.call_args_list
        phases = [c.kwargs["phase"] for c in bind_calls]
        assert "before_action" in phases
        assert "after_action" in phases
        assert mock_bound.warning.call_count == 2
