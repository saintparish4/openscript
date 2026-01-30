"""
Structured logging configuration

Why: Structured logs are machine-readable, enabling better
analysis, alerting, and debugging

Uses structlog for structured logging and JSON output
"""

import structlog
import logging
import sys


def configure_logging(log_level: str = "INFO", json_logs: bool = True):
    """
    Configure structured logging.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        json_logs: Whether to output JSON format (True) or human-readable (False)
    """

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )

    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


# Export commonly used logging functions
def get_logger(name: str = None):
    """Get a structured logger."""
    return structlog.get_logger(name)
