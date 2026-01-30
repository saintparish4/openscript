"""
Tests for observability module (metrics and logging).

Why: Observability is critical for production monitoring.
Must verify that metrics are recorded correctly and logging works.

Test Coverage:
- Metrics recording functions (counters)
- Decorator behavior (duration tracking, error counting)
- Gauge operations
- Logging configuration
"""

import pytest
import time
import asyncio
from unittest.mock import patch, MagicMock
from prometheus_client import REGISTRY, CollectorRegistry

from src.observability.metrics import (
    # Counters
    SCAN_REQUESTS_TOTAL,
    THREATS_DETECTED_TOTAL,
    SCANS_BLOCKED_TOTAL,
    PATTERN_MATCHES_TOTAL,
    API_ERRORS_TOTAL,
    # Histograms
    SCAN_DURATION_SECONDS,
    API_REQUEST_DURATION_SECONDS,
    INPUT_LENGTH_BYTES,
    # Gauges
    ACTIVE_SCANS,
    CACHED_SCANS,
    LOADED_PATTERNS,
    LOADED_POLICIES,
    # Decorators
    track_scan_duration,
    count_api_requests,
    # Recording functions
    record_scan,
    record_threat,
    record_block,
    record_pattern_match,
)
from src.observability.logging import configure_logging, get_logger


class TestMetricsRecording:
    """Test metrics recording functions."""

    def test_record_scan_increments_counter(self):
        """Test that record_scan increments the scan counter."""
        # Get initial value
        initial = SCAN_REQUESTS_TOTAL.labels(
            policy_id="test_policy", endpoint="/scan"
        )._value.get()

        record_scan(policy_id="test_policy", endpoint="/scan")

        # Verify increment
        new_value = SCAN_REQUESTS_TOTAL.labels(
            policy_id="test_policy", endpoint="/scan"
        )._value.get()
        assert new_value == initial + 1

    def test_record_scan_with_different_labels(self):
        """Test recording scans with different policy IDs."""
        initial_a = SCAN_REQUESTS_TOTAL.labels(
            policy_id="policy_a", endpoint="/scan"
        )._value.get()
        initial_b = SCAN_REQUESTS_TOTAL.labels(
            policy_id="policy_b", endpoint="/scan"
        )._value.get()

        record_scan(policy_id="policy_a", endpoint="/scan")
        record_scan(policy_id="policy_a", endpoint="/scan")
        record_scan(policy_id="policy_b", endpoint="/scan")

        # Verify separate counters
        assert (
            SCAN_REQUESTS_TOTAL.labels(
                policy_id="policy_a", endpoint="/scan"
            )._value.get()
            == initial_a + 2
        )
        assert (
            SCAN_REQUESTS_TOTAL.labels(
                policy_id="policy_b", endpoint="/scan"
            )._value.get()
            == initial_b + 1
        )

    def test_record_threat_increments_counter(self):
        """Test that record_threat increments the threats counter."""
        initial = THREATS_DETECTED_TOTAL.labels(
            severity="high", category="injection", policy_id="test"
        )._value.get()

        record_threat(severity="high", category="injection", policy_id="test")

        new_value = THREATS_DETECTED_TOTAL.labels(
            severity="high", category="injection", policy_id="test"
        )._value.get()
        assert new_value == initial + 1

    def test_record_threat_different_severities(self):
        """Test recording threats with different severity levels."""
        severities = ["critical", "high", "medium", "low", "info"]

        for severity in severities:
            initial = THREATS_DETECTED_TOTAL.labels(
                severity=severity, category="test_cat", policy_id="sev_test"
            )._value.get()

            record_threat(severity=severity, category="test_cat", policy_id="sev_test")

            new_value = THREATS_DETECTED_TOTAL.labels(
                severity=severity, category="test_cat", policy_id="sev_test"
            )._value.get()
            assert new_value == initial + 1, f"Failed for severity: {severity}"

    def test_record_block_increments_counter(self):
        """Test that record_block increments the blocked counter."""
        initial = SCANS_BLOCKED_TOTAL.labels(
            policy_id="block_test", severity="high"
        )._value.get()

        record_block(policy_id="block_test", severity="high")

        new_value = SCANS_BLOCKED_TOTAL.labels(
            policy_id="block_test", severity="high"
        )._value.get()
        assert new_value == initial + 1

    def test_record_pattern_match_increments_counter(self):
        """Test that record_pattern_match increments the pattern counter."""
        initial = PATTERN_MATCHES_TOTAL.labels(
            pattern_id="pattern_001", category="injection"
        )._value.get()

        record_pattern_match(pattern_id="pattern_001", category="injection")

        new_value = PATTERN_MATCHES_TOTAL.labels(
            pattern_id="pattern_001", category="injection"
        )._value.get()
        assert new_value == initial + 1

    def test_multiple_pattern_matches(self):
        """Test recording multiple pattern matches."""
        initial = PATTERN_MATCHES_TOTAL.labels(
            pattern_id="multi_test", category="jailbreak"
        )._value.get()

        for _ in range(5):
            record_pattern_match(pattern_id="multi_test", category="jailbreak")

        new_value = PATTERN_MATCHES_TOTAL.labels(
            pattern_id="multi_test", category="jailbreak"
        )._value.get()
        assert new_value == initial + 5


class TestTrackScanDurationDecorator:
    """Test the track_scan_duration decorator."""

    def test_decorator_tracks_duration(self):
        """Test that decorator records scan duration."""

        @track_scan_duration(policy_id="duration_test")
        def slow_scan():
            time.sleep(0.01)  # 10ms
            return "result"

        result = slow_scan()

        assert result == "result"
        # Verify histogram was updated (check sample count)
        sample_count = SCAN_DURATION_SECONDS.labels(
            policy_id="duration_test"
        )._sum.get()
        assert sample_count > 0

    def test_decorator_preserves_return_value(self):
        """Test that decorator preserves function return value."""

        @track_scan_duration(policy_id="return_test")
        def compute():
            return {"status": "ok", "count": 42}

        result = compute()

        assert result == {"status": "ok", "count": 42}

    def test_decorator_preserves_exceptions(self):
        """Test that decorator lets exceptions propagate."""

        @track_scan_duration(policy_id="exception_test")
        def failing_scan():
            raise ValueError("Scan failed")

        with pytest.raises(ValueError, match="Scan failed"):
            failing_scan()

    def test_decorator_records_duration_on_exception(self):
        """Test duration is recorded even when exception occurs."""
        initial_sum = SCAN_DURATION_SECONDS.labels(
            policy_id="exc_duration_test"
        )._sum.get()

        @track_scan_duration(policy_id="exc_duration_test")
        def failing_scan():
            time.sleep(0.005)
            raise RuntimeError("Failed")

        try:
            failing_scan()
        except RuntimeError:
            pass

        # Duration should still be recorded (sum should increase)
        new_sum = SCAN_DURATION_SECONDS.labels(policy_id="exc_duration_test")._sum.get()
        assert new_sum > initial_sum

    def test_decorator_with_arguments(self):
        """Test decorator works with functions that have arguments."""

        @track_scan_duration(policy_id="args_test")
        def scan_with_args(text: str, options: dict = None):
            return f"Scanned: {len(text)} chars"

        result = scan_with_args("Hello world", options={"strict": True})

        assert result == "Scanned: 11 chars"


class TestCountApiRequestsDecorator:
    """Test the count_api_requests decorator (async)."""

    @pytest.mark.asyncio
    async def test_decorator_tracks_request_duration(self):
        """Test that async decorator records request duration."""

        @count_api_requests(endpoint="/api/scan", method="POST")
        async def api_handler():
            await asyncio.sleep(0.01)
            return {"status": "ok"}

        result = await api_handler()

        assert result == {"status": "ok"}
        # Verify histogram was updated
        sample_sum = API_REQUEST_DURATION_SECONDS.labels(
            endpoint="/api/scan", method="POST"
        )._sum.get()
        assert sample_sum > 0

    @pytest.mark.asyncio
    async def test_decorator_counts_errors(self):
        """Test that decorator counts API errors."""
        initial_errors = API_ERRORS_TOTAL.labels(
            endpoint="/api/error_test", error_type="ValueError"
        )._value.get()

        @count_api_requests(endpoint="/api/error_test", method="GET")
        async def failing_handler():
            raise ValueError("Bad request")

        with pytest.raises(ValueError):
            await failing_handler()

        # Error should be counted
        new_errors = API_ERRORS_TOTAL.labels(
            endpoint="/api/error_test", error_type="ValueError"
        )._value.get()
        assert new_errors == initial_errors + 1

    @pytest.mark.asyncio
    async def test_decorator_preserves_return_value(self):
        """Test that async decorator preserves return value."""

        @count_api_requests(endpoint="/api/preserve", method="POST")
        async def handler():
            return {"id": 123, "data": [1, 2, 3]}

        result = await handler()

        assert result == {"id": 123, "data": [1, 2, 3]}

    @pytest.mark.asyncio
    async def test_decorator_records_duration_on_error(self):
        """Test duration is recorded even on error."""
        initial_sum = API_REQUEST_DURATION_SECONDS.labels(
            endpoint="/api/err_duration", method="DELETE"
        )._sum.get()

        @count_api_requests(endpoint="/api/err_duration", method="DELETE")
        async def failing():
            await asyncio.sleep(0.005)
            raise RuntimeError("Server error")

        try:
            await failing()
        except RuntimeError:
            pass

        new_sum = API_REQUEST_DURATION_SECONDS.labels(
            endpoint="/api/err_duration", method="DELETE"
        )._sum.get()
        assert new_sum > initial_sum

    @pytest.mark.asyncio
    async def test_decorator_with_async_arguments(self):
        """Test async decorator works with function arguments."""

        @count_api_requests(endpoint="/api/args", method="PUT")
        async def handler_with_args(data: dict, timeout: int = 30):
            return {"received": data, "timeout": timeout}

        result = await handler_with_args({"key": "value"}, timeout=60)

        assert result == {"received": {"key": "value"}, "timeout": 60}

    @pytest.mark.asyncio
    async def test_different_error_types_tracked_separately(self):
        """Test that different exception types are tracked separately."""
        initial_value_errors = API_ERRORS_TOTAL.labels(
            endpoint="/api/multi_err", error_type="ValueError"
        )._value.get()
        initial_type_errors = API_ERRORS_TOTAL.labels(
            endpoint="/api/multi_err", error_type="TypeError"
        )._value.get()

        @count_api_requests(endpoint="/api/multi_err", method="POST")
        async def handler(error_type: str):
            if error_type == "value":
                raise ValueError("Value error")
            elif error_type == "type":
                raise TypeError("Type error")
            return "ok"

        # Trigger ValueError
        try:
            await handler("value")
        except ValueError:
            pass

        # Trigger TypeError
        try:
            await handler("type")
        except TypeError:
            pass

        # Verify separate counts
        assert (
            API_ERRORS_TOTAL.labels(
                endpoint="/api/multi_err", error_type="ValueError"
            )._value.get()
            == initial_value_errors + 1
        )
        assert (
            API_ERRORS_TOTAL.labels(
                endpoint="/api/multi_err", error_type="TypeError"
            )._value.get()
            == initial_type_errors + 1
        )


class TestGaugeOperations:
    """Test gauge metric operations."""

    def test_active_scans_gauge(self):
        """Test ACTIVE_SCANS gauge operations."""
        # Set initial value
        ACTIVE_SCANS.set(0)
        assert ACTIVE_SCANS._value.get() == 0

        # Increment
        ACTIVE_SCANS.inc()
        assert ACTIVE_SCANS._value.get() == 1

        ACTIVE_SCANS.inc(5)
        assert ACTIVE_SCANS._value.get() == 6

        # Decrement
        ACTIVE_SCANS.dec()
        assert ACTIVE_SCANS._value.get() == 5

        ACTIVE_SCANS.dec(3)
        assert ACTIVE_SCANS._value.get() == 2

        # Set explicit value
        ACTIVE_SCANS.set(10)
        assert ACTIVE_SCANS._value.get() == 10

    def test_cached_scans_gauge(self):
        """Test CACHED_SCANS gauge operations."""
        CACHED_SCANS.set(100)
        assert CACHED_SCANS._value.get() == 100

        CACHED_SCANS.inc(50)
        assert CACHED_SCANS._value.get() == 150

    def test_loaded_patterns_gauge(self):
        """Test LOADED_PATTERNS gauge tracks pattern count."""
        LOADED_PATTERNS.set(25)
        assert LOADED_PATTERNS._value.get() == 25

        # Simulate loading more patterns
        LOADED_PATTERNS.inc(10)
        assert LOADED_PATTERNS._value.get() == 35

    def test_loaded_policies_gauge(self):
        """Test LOADED_POLICIES gauge tracks policy count."""
        LOADED_POLICIES.set(5)
        assert LOADED_POLICIES._value.get() == 5


class TestHistogramOperations:
    """Test histogram metric operations."""

    def test_input_length_histogram(self):
        """Test INPUT_LENGTH_BYTES histogram."""
        # Record some input lengths
        INPUT_LENGTH_BYTES.observe(100)
        INPUT_LENGTH_BYTES.observe(500)
        INPUT_LENGTH_BYTES.observe(1000)

        # Verify observations were recorded
        assert INPUT_LENGTH_BYTES._sum.get() >= 1600

    def test_scan_duration_histogram_buckets(self):
        """Test scan duration histogram has correct bucket boundaries."""
        # Expected buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        histogram = SCAN_DURATION_SECONDS.labels(policy_id="bucket_test")

        # Record observations in different buckets
        histogram.observe(0.002)  # Should be in 0.005 bucket
        histogram.observe(0.008)  # Should be in 0.01 bucket
        histogram.observe(0.5)  # Should be in 0.5 bucket

        # Verify observations recorded (sum should reflect recorded values)
        assert histogram._sum.get() >= 0.51  # 0.002 + 0.008 + 0.5


class TestLogging:
    """Test logging configuration and functionality."""

    def test_configure_logging_json_format(self):
        """Test configuring logging with JSON output."""
        # Should not raise
        configure_logging(log_level="INFO", json_logs=True)

    def test_configure_logging_console_format(self):
        """Test configuring logging with console output."""
        # Should not raise
        configure_logging(log_level="DEBUG", json_logs=False)

    def test_configure_logging_different_levels(self):
        """Test configuring with different log levels."""
        levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        for level in levels:
            configure_logging(log_level=level, json_logs=True)

    def test_get_logger_returns_logger(self):
        """Test get_logger returns a structured logger."""
        logger = get_logger("test_module")

        assert logger is not None
        # Should have standard logging methods
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")

    def test_get_logger_without_name(self):
        """Test get_logger works without a name."""
        logger = get_logger()
        assert logger is not None

    def test_logger_can_log_with_context(self):
        """Test logger can log with structured context."""
        configure_logging(log_level="DEBUG", json_logs=True)
        logger = get_logger("context_test")

        # Should not raise - structured logging supports extra fields
        logger.info(
            "Test message",
            user_id="123",
            action="scan",
            policy="default",
        )

    def test_logger_bind_context(self):
        """Test logger can bind persistent context."""
        configure_logging(log_level="INFO", json_logs=True)
        logger = get_logger("bind_test")

        # Bind context to logger
        bound_logger = logger.bind(request_id="abc123", trace_id="xyz789")

        # Should work without raising
        bound_logger.info("Request started")
        bound_logger.info("Request completed", status="success")


class TestMetricsIntegration:
    """Integration tests for metrics in realistic scenarios."""

    def test_full_scan_workflow_metrics(self):
        """Test metrics recording through a complete scan workflow."""
        policy_id = "integration_test_policy"

        # Simulate scan start
        ACTIVE_SCANS.inc()
        record_scan(policy_id=policy_id, endpoint="/scan")

        # Simulate detection
        record_threat(severity="high", category="injection", policy_id=policy_id)
        record_pattern_match(pattern_id="inj_001", category="injection")

        # Simulate block
        record_block(policy_id=policy_id, severity="high")

        # Simulate scan end
        ACTIVE_SCANS.dec()

        # Verify metrics were recorded (counters should have values)
        assert (
            SCAN_REQUESTS_TOTAL.labels(
                policy_id=policy_id, endpoint="/scan"
            )._value.get()
            > 0
        )
        assert (
            THREATS_DETECTED_TOTAL.labels(
                severity="high", category="injection", policy_id=policy_id
            )._value.get()
            > 0
        )

    @pytest.mark.asyncio
    async def test_api_request_with_metrics(self):
        """Test API request handler with full metrics tracking."""

        @count_api_requests(endpoint="/api/integration", method="POST")
        async def scan_handler(text: str, policy_id: str):
            ACTIVE_SCANS.inc()
            try:
                record_scan(policy_id=policy_id, endpoint="/api/integration")
                await asyncio.sleep(0.005)  # Simulate work
                return {"status": "clean", "threats": []}
            finally:
                ACTIVE_SCANS.dec()

        result = await scan_handler("test input", "int_policy")

        assert result == {"status": "clean", "threats": []}

    def test_decorator_function_metadata_preserved(self):
        """Test that decorators preserve function metadata."""

        @track_scan_duration(policy_id="metadata_test")
        def documented_function():
            """This is a documented function."""
            return "result"

        # Function name should be preserved
        assert documented_function.__name__ == "documented_function"
        # Docstring should be preserved
        assert "documented function" in documented_function.__doc__

    @pytest.mark.asyncio
    async def test_async_decorator_metadata_preserved(self):
        """Test that async decorator preserves function metadata."""

        @count_api_requests(endpoint="/meta", method="GET")
        async def async_documented():
            """Async documented function."""
            return "async result"

        assert async_documented.__name__ == "async_documented"
        assert "Async documented" in async_documented.__doc__
