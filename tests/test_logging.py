from __future__ import annotations

import json
import logging

import pytest
import structlog

import sdk.logging as sdk_logging
from sdk import OpenScriptMiddleware, configure_logging


class FakeAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": "ok"}


@pytest.fixture(autouse=True)
def _reset_logging_state():
    """Reset the module-level guard between tests so each test starts fresh."""
    sdk_logging._configured = False
    yield
    sdk_logging._configured = False


class TestConfigureLogging:
    def test_sets_configured_flag(self):
        assert sdk_logging._configured is False
        configure_logging(json_output=False)
        assert sdk_logging._configured is True

    def test_json_renderer_produces_parseable_json(self, capsys):
        configure_logging(json_output=True)
        log = structlog.get_logger("test_json")
        log.info("hello", key="value")
        captured = capsys.readouterr()
        record = json.loads(captured.err.strip())
        assert record["event"] == "hello"
        assert record["key"] == "value"

    def test_env_override_log_level(self, monkeypatch, capsys):
        monkeypatch.setenv("OPENSCRIPT_LOG_LEVEL", "WARNING")
        configure_logging(json_output=True)

        log = structlog.get_logger("test_level")
        log.info("should_not_appear")
        log.warning("should_appear")

        captured = capsys.readouterr()
        assert "should_not_appear" not in captured.err
        assert "should_appear" in captured.err

    def test_env_override_json_format(self, monkeypatch, capsys):
        monkeypatch.setenv("OPENSCRIPT_LOG_FORMAT", "json")
        configure_logging()

        log = structlog.get_logger("test_env_json")
        log.info("env_json_test")

        captured = capsys.readouterr()
        record = json.loads(captured.err.strip())
        assert record["event"] == "env_json_test"


class TestEnsureConfigured:
    def test_called_once_even_with_multiple_calls(self):
        assert sdk_logging._configured is False
        sdk_logging._ensure_configured()
        assert sdk_logging._configured is True
        sdk_logging._ensure_configured()
        assert sdk_logging._configured is True

    def test_explicit_configure_prevents_auto_configure(self):
        configure_logging(json_output=False)
        assert sdk_logging._configured is True
        sdk_logging._ensure_configured()
        assert sdk_logging._configured is True


class TestMiddlewareAutoConfigures:
    @pytest.mark.asyncio
    async def test_middleware_init_triggers_configure(self):
        assert sdk_logging._configured is False
        agent = FakeAgent()
        OpenScriptMiddleware(agent=agent, interceptors=[])
        assert sdk_logging._configured is True

    @pytest.mark.asyncio
    async def test_middleware_logs_in_json_when_configured(self, capsys):
        configure_logging(json_output=True)
        agent = FakeAgent()
        mw = OpenScriptMiddleware(agent=agent, interceptors=[])
        await mw.invoke({"input": "test"})

        root = logging.getLogger()
        assert any(
            isinstance(h.formatter, structlog.stdlib.ProcessorFormatter)
            for h in root.handlers
        )
