"""
Tests for core type definitions and Pydantic model behavior.

Covers boundary conditions, validation rules, and computed properties
that downstream code relies on.
"""

import pytest
from pydantic import ValidationError

from src.core.types import (
    ThreatDetection,
    ScanResult,
    SeverityLevel,
    AttackCategory,
    DetectionMethod,
    SEVERITY_ORDER,
)


class TestConfidenceBoundaries:
    """Confidence field must be in [0.0, 1.0]."""

    @pytest.mark.parametrize("value", [0.0, 0.5, 1.0])
    def test_confidence_valid(self, value):
        detection = ThreatDetection(
            attack_id="test",
            category=AttackCategory.DIRECT_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=value,
            detection_method=DetectionMethod.PATTERN_MATCH,
            matched_pattern=".*",
            context="ctx",
            position=0,
        )
        assert detection.confidence == value

    @pytest.mark.parametrize("value", [-0.1, 1.1, -1.0, 2.0])
    def test_confidence_out_of_bounds(self, value):
        with pytest.raises(ValidationError):
            ThreatDetection(
                attack_id="test",
                category=AttackCategory.DIRECT_INJECTION,
                severity=SeverityLevel.HIGH,
                confidence=value,
                detection_method=DetectionMethod.PATTERN_MATCH,
                matched_pattern=".*",
                context="ctx",
                position=0,
            )


class TestMaxSeverity:
    """ScanResult.max_severity computed property."""

    def _make_detection(self, severity: SeverityLevel) -> ThreatDetection:
        return ThreatDetection(
            attack_id="test",
            category=AttackCategory.DIRECT_INJECTION,
            severity=severity,
            confidence=0.9,
            detection_method=DetectionMethod.PATTERN_MATCH,
            matched_pattern=".*",
            context="ctx",
            position=0,
        )

    def test_empty_detections(self):
        result = ScanResult(
            scan_id="s1",
            input_hash="h1",
            is_safe=True,
            detections=[],
            scan_duration_ms=1.0,
        )
        assert result.max_severity is None

    def test_single_detection(self):
        result = ScanResult(
            scan_id="s1",
            input_hash="h1",
            is_safe=False,
            detections=[self._make_detection(SeverityLevel.HIGH)],
            scan_duration_ms=1.0,
        )
        assert result.max_severity == SeverityLevel.HIGH

    def test_multiple_severities(self):
        result = ScanResult(
            scan_id="s1",
            input_hash="h1",
            is_safe=False,
            detections=[
                self._make_detection(SeverityLevel.LOW),
                self._make_detection(SeverityLevel.CRITICAL),
                self._make_detection(SeverityLevel.MEDIUM),
            ],
            scan_duration_ms=1.0,
        )
        assert result.max_severity == SeverityLevel.CRITICAL


class TestDetectionSummary:
    """ScanResult.detection_summary computed property."""

    def _make_detection(self, category: AttackCategory) -> ThreatDetection:
        return ThreatDetection(
            attack_id="test",
            category=category,
            severity=SeverityLevel.MEDIUM,
            confidence=0.9,
            detection_method=DetectionMethod.PATTERN_MATCH,
            matched_pattern=".*",
            context="ctx",
            position=0,
        )

    def test_empty(self):
        result = ScanResult(
            scan_id="s1",
            input_hash="h1",
            is_safe=True,
            detections=[],
            scan_duration_ms=1.0,
        )
        assert result.detection_summary == {}

    def test_multiple_categories(self):
        result = ScanResult(
            scan_id="s1",
            input_hash="h1",
            is_safe=False,
            detections=[
                self._make_detection(AttackCategory.DIRECT_INJECTION),
                self._make_detection(AttackCategory.DIRECT_INJECTION),
                self._make_detection(AttackCategory.PII_EXPOSURE),
            ],
            scan_duration_ms=1.0,
        )
        summary = result.detection_summary
        assert summary[AttackCategory.DIRECT_INJECTION.value] == 2
        assert summary[AttackCategory.PII_EXPOSURE.value] == 1


class TestSeverityOrder:
    """Ensure the canonical ordering is correct."""

    def test_order_is_monotonically_increasing(self):
        expected = [
            SeverityLevel.INFO,
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.HIGH,
            SeverityLevel.CRITICAL,
        ]
        for i in range(len(expected) - 1):
            assert SEVERITY_ORDER[expected[i]] < SEVERITY_ORDER[expected[i + 1]]
