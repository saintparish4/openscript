from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from contracts.types import ActionContext

logger = structlog.get_logger(__name__)

# Feature flag: set OPENSCRIPT_OTEL=1 (or "true") to have SecureAgent open an
# OpenTelemetry span per action without passing tracer= explicitly.
OTEL_ENV_FLAG = "OPENSCRIPT_OTEL"


class ActionTracer:
    """One OpenTelemetry span per SecureAgent action (pip install openscript[otel]).

    Uses the ambient tracer provider — exporter setup (OTLP endpoint, which
    Datadog and friends consume) is the host application's job via the
    standard OTEL_* environment variables or explicit SDK configuration;
    with no provider configured the spans are no-ops.
    """

    def __init__(self, instrumentation_name: str = "openscript") -> None:
        try:
            from opentelemetry import trace
        except ImportError as exc:
            raise ImportError(
                "ActionTracer requires the OpenTelemetry SDK: pip install openscript[otel]"
            ) from exc
        self._tracer = trace.get_tracer(instrumentation_name)

    @contextmanager
    def span(self, context: ActionContext) -> Iterator[Any]:
        with self._tracer.start_as_current_span(f"openscript.{context.action}") as span:
            span.set_attribute("openscript.agent_id", context.agent_id)
            span.set_attribute("openscript.session_id", context.session_id)
            try:
                yield span
            finally:
                # risk/decision are written by SecureAgent before any raise,
                # so blocked actions carry their final values too
                span.set_attribute("openscript.risk_score", context.risk_score)
                span.set_attribute("openscript.decision", context.decision.value)


def tracer_from_env() -> ActionTracer | None:
    """Build an ActionTracer when the OPENSCRIPT_OTEL flag is set.

    Fails open: with the flag set but the otel packages missing, logs a
    warning and returns None rather than breaking the pipeline.
    """
    if os.environ.get(OTEL_ENV_FLAG, "").lower() not in ("1", "true"):
        return None
    try:
        return ActionTracer()
    except ImportError:
        logger.warning(
            "otel_flag_set_but_sdk_missing",
            hint="pip install openscript[otel] to emit spans",
        )
        return None
