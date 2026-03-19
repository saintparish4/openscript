# Shared contracts package (types, interceptor protocols).

"""OpenScript contract: Public framework types and protocols"""

from contracts.interceptor import Interceptor
from contracts.types import (
    ActionContext,
    AgentCapabilities,
    FailureMode,
    InterceptorDecision,
    InterceptorResult,
)

__all__ = [
    "ActionContext",
    "AgentCapabilities",
    "FailureMode",
    "Interceptor",
    "InterceptorDecision",
    "InterceptorResult",
]
