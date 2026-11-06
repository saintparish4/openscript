from __future__ import annotations

import logging
import os
import threading

import structlog

_configured = False
_lock = threading.Lock()


def configure_logging(*, json_output: bool | None = None) -> None:
    """Configure structlog for OpenScript.

    Call this explicitly before creating ``OpenScriptMiddleware`` to control
    output format and log level.  If never called, the middleware auto-configures
    with sensible defaults on first use (JSON when not a TTY, console otherwise).

    Args:
        json_output: Force JSON output.  When *None* (default), use JSON if
            ``OPENSCRIPT_LOG_FORMAT=json`` or if stderr is not a TTY.
    """
    global _configured

    if json_output is None:
        env_format = os.environ.get("OPENSCRIPT_LOG_FORMAT", "").lower()
        json_output = env_format == "json" or not _is_tty()

    log_level_name = os.environ.get("OPENSCRIPT_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    _configured = True


def _ensure_configured() -> None:
    """Auto-configure logging once if the caller hasn't done so already.

    Thread-safe: concurrent calls block on the lock, and only the first one
    actually configures.
    """
    global _configured
    if _configured:
        return
    with _lock:
        if _configured:
            return
        configure_logging()


def _is_tty() -> bool:
    import sys

    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
