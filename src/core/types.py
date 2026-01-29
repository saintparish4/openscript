"""
Core type definitions for OpenScript security system

Why: Type safety catches errors at development time, not production
Runtime validation with Pydantic ensures data integrity
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """Attack severity classification"""

    CRITICAL = "critical"  # Immediate threat, block execution
    HIGH = "high"  # Likely attack, strong evidence
    MEDIUM = "medium"  # Suspicious pattern, needs review
    LOW = "low"  # Informational, log only
    INFO = "info"  # Normal behavior, audit trail


class AttackCategory(str, Enum):
    """Types of prompt injection attacks"""

    DIRECT_INJECTION = "direct_injection"  # "Ignore previous instructions"
    ROLE_PLAY_MANIPULATION = "role_play"  # "Pretend you're DAN"
    ENCODED_PAYLOAD = "encoded_payload"  # Base64, ROT13, etc.
    DELIMITER_CONFUSION = "delimiter_confusion"  # Fake XML/JSON boundaries
    CONTEXT_POISONING = "context_poisoning"  # Injecting fake context
    JAILBREAK = "jailbreak"  # Bypassing safety filters
    DATA_EXFILTRATION = "data_exfiltration"  # Extracting system prompts
    CREDENTIAL_LEAK = "credential_leak"  # API keys, passwords, etc.
    PII_EXPOSURE = "pii_exposure"  # SSN, credit cards, etc.
    MULTI_TURN_ATTACK = "multi_turn"  # Attack across conversation
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"  # Print your instructions


class DetectionMethod(str, Enum):
    """How the threat was detected."""

    PATTERN_MATCH = "pattern_match"  # Regex/string matching
    HEURISTIC = "heuristic"  # Rule-based analysis
    SEMANTIC = "semantic"  # Embedding similarity
    STATISTICAL = "statistical"  # Anomaly detection
    COMPOSITE = "composite"  # Multiple methods


class ThreatDetection(BaseModel):
    """Represents a detected security threat."""

    attack_id: str = Field(..., description="Unique identifier for this attack pattern")
    category: AttackCategory
    severity: SeverityLevel
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Detection confidence 0-1"
    )
    detection_method: DetectionMethod
    matched_pattern: str = Field(
        ..., description="The pattern that triggered detection"
    )
    context: str = Field(..., description="Surrounding text context")
    position: int = Field(..., ge=0, description="Character position in input")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("Confidence must be between 0 and 1")
        return v


class SecurityPolicy(BaseModel):
    """Defines security policies for evaluation."""

    policy_id: str
    name: str
    description: str
    enabled: bool = True
    block_on_detection: bool = True  # Whether to block or just alert
    severity_threshold: SeverityLevel = SeverityLevel.MEDIUM
    categories: List[AttackCategory] = Field(default_factory=list)
    custom_patterns: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of scanning input/output."""

    scan_id: str
    input_hash: str  # SHA256 of input for deduplication
    is_safe: bool
    detections: List[ThreatDetection] = Field(default_factory=list)
    scan_duration_ms: float
    policy_applied: Optional[str] = None
    blocked: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def max_severity(self) -> Optional[SeverityLevel]:
        """Get highest severity level detected."""
        if not self.detections:
            return None
        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0,
        }
        return max(self.detections, key=lambda d: severity_order[d.severity]).severity

    @property
    def detection_summary(self) -> Dict[str, int]:
        """Get summary of detections grouped by category."""
        summary: Dict[str, int] = {}
        for detection in self.detections:
            category_name = detection.category.value
            summary[category_name] = summary.get(category_name, 0) + 1
        return summary
