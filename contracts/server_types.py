from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    TURN_STARTED = "turn_start"
    TURN_END = "turn_end"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    INTERCEPTOR_BEFORE = "interceptor_before"
    INTERCEPTOR_AFTER = "interceptor_after"
    THREAT_DETECTED = "threat_detected"
    POLICY_EVALUATED = "policy_evaluated"
    AGENT_MESSAGE = "agent_message"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_RESOLVED = "approval_resolved"


class Event(BaseModel):
    model_config = {"frozen": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    agent_id: str
    event_type: EventType
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    sequence_num: int


class ThreatScoreRequest(BaseModel):
    session_id: str
    agent_id: str
    text: str
    turn_number: int
    context: dict[str, Any] = Field(default_factory=dict)


class ThreatScoreResponse(BaseModel):
    session_id: str
    score: float
    signals: dict[str, float] = Field(default_factory=dict)
    flagged: bool = False
    reason: str = ""


class PolicyEvalRequest(BaseModel):
    session_id: str
    agent_id: str
    action: str
    capabilities: dict[str, bool] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class PolicyEvalResponse(BaseModel):
    session_id: str
    decision: str
    reason: str = ""
    policies_evaluated: list[str] = Field(default_factory=list)


class DetectionResult(BaseModel):
    regex_score: float = 0.0
    embedding_score: float = 0.0
    final_score: float = 0.0
    method: str = ""


class ToolValidateRequest(BaseModel):
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    role: str | None = None


class ToolValidateResponse(BaseModel):
    allowed: bool
    reason: str
    requires_approval: bool = False
