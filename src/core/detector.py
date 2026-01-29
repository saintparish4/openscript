"""
Detection engine that orchestrates pattern matching

Why: Seperation between patterns (what to detect) and detection logic (how to detect)
allows independent evolution of each

Design:
- Fail fast: Return immediately on critical detections
- Observable: Log every decision
- Accurate: Minimize false positives while catching attacks
"""

import hashlib
import uuid
from typing import List, Optional, Set
from datetime import datetime, timezone
import structlog

from .types import (
    ThreatDetection,
    ScanResult,
    SecurityPolicy,
    DetectionMethod,
    SeverityLevel,
    AttackCategory,
)
from .patterns import PatternLibrary, AttackPattern

logger = structlog.get_logger()


class DetectionEngine:
    """
    Engine for threat detection

    Responsibilities:
    - Coordinate pattern matching
    - Apply policy rules
    - Make block/allow decisions
    - Generate audit logs
    - Track performance metrics

    Thread Safety: Read-only after initialization, safe for concurrent scans
    """

    def __init__(
        self,
        pattern_library: Optional[PatternLibrary] = None,
        enable_caching: bool = True,
    ):
        """
        Initialize detection engine

        Args:
            pattern_library: Custom pattern library (or use default)
            enable_caching: Whether to cache scan results by input hash
        """
        self.pattern_library = pattern_library or PatternLibrary()
        self.enable_caching = enable_caching
        self.logger = logger.bind(component="detection_engine")

        # Simple in-memory cache for deduplication
        # In prod, use Redis or similar for distributed caching
        self._scan_cache: dict = {} if enable_caching else None

        self.logger.info(
            "detection_engine_initialized",
            pattern_count=len(self.pattern_library.patterns),
            caching_enabled=enable_caching,
        )

    def scan_text(
        self, text: str, policy: SecurityPolicy, metadata: Optional[dict] = None
    ) -> ScanResult:
        """
        Scan text for security threats

        This is the main entry point for threat detection

        Args:
            text: Input text to scan
            policy: Security policy to apply
            metadata: Additional context for logging (user_id, session_id, etc)

        Returns:
            ScanResult with all detections and decision
        """
        start_time = datetime.now(timezone.utc)
        scan_id = str(uuid.uuid4())
        input_hash = self._hash_input(text)

        # Check cache for duplicate scans
        if self._scan_cache is not None and input_hash in self._scan_cache:
            cached_result = self._scan_cache[input_hash]
            self.logger.info(
                "scan_cache_hit",
                scan_id=scan_id,
                input_hash=input_hash,
                cached_scan_id=cached_result.scan_id,
            )
            # Return cached result with new scan_id
            cached_result.scan_id = scan_id
            return cached_result

        self.logger.info(
            "scan_started",
            scan_id=scan_id,
            input_hash=input_hash,
            policy_id=policy.policy_id,
            text_length=len(text),
            metadata=metadata,
        )

        # Fast path: Empty or very short text
        if not text or len(text.strip()) < 3:
            return self._create_clean_result(
                scan_id, input_hash, policy.policy_id, 0.0, metadata
            )

        detections: List[ThreatDetection] = []

        # Get applicable patterns based on policy
        applicable_patterns = self._get_applicable_patterns(policy)

        self.logger.debug(
            "patterns_selected", scan_id=scan_id, pattern_count=len(applicable_patterns)
        )

        # Run pattern matching
        for pattern in applicable_patterns:
            matches = pattern.match(text)

            if not matches:
                continue

            for position, matched_text in matches:
                # Extract context around match for review
                context = self._extract_context(text, position, len(matched_text))

                detection = ThreatDetection(
                    attack_id=pattern.pattern_id,
                    category=pattern.category,
                    severity=pattern.severity,
                    confidence=self._calculate_confidence(pattern, matched_text, text),
                    detection_method=DetectionMethod.PATTERN_MATCH,
                    matched_pattern=pattern.regex.pattern[:100],  # Truncate for logs
                    context=context,
                    position=position,
                    metadata={
                        "pattern_description": pattern.description,
                        "matched_text": matched_text,
                        "false_positive_rate": pattern.false_positive_rate,
                    },
                )

                detections.append(detection)

                self.logger.info(
                    "threat_detected",
                    scan_id=scan_id,
                    attack_id=pattern.pattern_id,
                    category=pattern.category.value,
                    severity=pattern.severity.value,
                    confidence=detection.confidence,
                    position=position,
                )

                # Early exit for critical threats if policy requires blocking
                if (
                    policy.block_on_detection
                    and pattern.severity == SeverityLevel.CRITICAL
                    and detection.confidence > 0.9
                ):

                    self.logger.warning(
                        "critical_threat_early_exit",
                        scan_id=scan_id,
                        attack_id=pattern.pattern_id,
                    )
                    break

        # Calculate scan duration
        duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        # Determine if should block based on policy
        blocked = self._should_block(detections, policy)
        is_safe = len(detections) == 0 or not blocked

        result = ScanResult(
            scan_id=scan_id,
            input_hash=input_hash,
            is_safe=is_safe,
            detections=detections,
            scan_duration_ms=duration_ms,
            policy_applied=policy.policy_id,
            blocked=blocked,
            metadata=metadata or {},
        )

        # Cache result
        if self._scan_cache is not None:
            self._scan_cache[input_hash] = result

        self.logger.info(
            "scan_completed",
            scan_id=scan_id,
            is_safe=is_safe,
            blocked=blocked,
            detection_count=len(detections),
            duration_ms=duration_ms,
            max_severity=result.max_severity.value if result.max_severity else None,
        )

        return result

    def _hash_input(self, text: str) -> str:
        """Create SHA256 hash of input for caching and deduplication"""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _extract_context(
        self, text: str, position: int, match_length: int, context_chars: int = 50
    ) -> str:
        """
        Extract context around a match for review

        Args:
            text: Full text
            position: Match position
            match_length: Length of matched text
            context_chars: Characters to include before/after

        Returns:
            Context string with match highlighted
        """
        start = max(0, position - context_chars)
        end = min(len(text), position + match_length + context_chars)

        context = text[start:end]

        # Add ellipsis if truncated
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."

        return context

    def _calculate_confidence(
        self, pattern: AttackPattern, matched_text: str, full_text: str
    ) -> float:
        """
        Calculate confidence score for a detection.

        Factors:
        - Pattern's inherent false positive rate
        - Length of matched text (longer = more confident)
        - Position in text (attacks often at start)

        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 1.0 - pattern.false_positive_rate

        # Boost confidence for longer matches
        if len(matched_text) > 50:
            base_confidence = min(1.0, base_confidence + 0.1)

        # Boost confidence for attacks near start of text
        # (many attacks try to override initial instructions)
        position_ratio = full_text.find(matched_text) / len(full_text)
        if position_ratio < 0.1:  # First 10% of text
            base_confidence = min(1.0, base_confidence + 0.05)

        return round(base_confidence, 2)

    def _get_applicable_patterns(self, policy: SecurityPolicy) -> List[AttackPattern]:
        """
        Get patterns applicable to this policy.

        Applies policy filters:
        - Category filtering
        - Severity threshold
        - Enabled status

        Returns:
            List of patterns to apply
        """
        patterns = []

        # Filter by category if specified
        if policy.categories:
            for category in policy.categories:
                patterns.extend(self.pattern_library.get_patterns_by_category(category))
        else:
            # Use all patterns
            patterns = self.pattern_library.list_all_patterns()

        # Note: We don't filter by severity_threshold here.
        # All patterns are run for detection visibility and audit trails.
        # severity_threshold is applied in _should_block() to determine blocking.

        # Remove duplicates while preserving order
        seen: Set[str] = set()
        unique_patterns = []
        for p in patterns:
            if p.pattern_id not in seen:
                seen.add(p.pattern_id)
                unique_patterns.append(p)

        return unique_patterns

    def _severity_meets_threshold(
        self, severity: SeverityLevel, threshold: SeverityLevel
    ) -> bool:
        """
        Check if severity meets or exceeds threshold.

        Severity hierarchy: INFO < LOW < MEDIUM < HIGH < CRITICAL
        """
        severity_order = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }
        return severity_order[severity] >= severity_order[threshold]

    def _should_block(
        self, detections: List[ThreatDetection], policy: SecurityPolicy
    ) -> bool:
        """
        Determine if request should be blocked.

        Blocking logic:
        1. If policy doesn't allow blocking, return False
        2. If no detections, return False
        3. If any detection meets severity threshold, return True

        Args:
            detections: List of detected threats
            policy: Applied security policy

        Returns:
            True if should block, False otherwise
        """
        if not policy.block_on_detection:
            return False

        if not detections:
            return False

        # Block if any detection meets severity threshold
        for detection in detections:
            if self._severity_meets_threshold(
                detection.severity, policy.severity_threshold
            ):
                self.logger.warning(
                    "blocking_decision",
                    attack_id=detection.attack_id,
                    severity=detection.severity.value,
                    confidence=detection.confidence,
                )
                return True

        return False

    def _create_clean_result(
        self,
        scan_id: str,
        input_hash: str,
        policy_id: str,
        duration_ms: float,
        metadata: Optional[dict],
    ) -> ScanResult:
        """Create a clean scan result (no threats detected)."""
        return ScanResult(
            scan_id=scan_id,
            input_hash=input_hash,
            is_safe=True,
            detections=[],
            scan_duration_ms=duration_ms,
            policy_applied=policy_id,
            blocked=False,
            metadata=metadata or {},
        )

    def clear_cache(self):
        """Clear the scan cache. Useful for testing."""
        if self._scan_cache is not None:
            self._scan_cache.clear()
            self.logger.info("scan_cache_cleared")
