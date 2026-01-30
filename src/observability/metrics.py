"""
Prometheus metrics for monitoring

Why: Metrics enable monitoring, alerting, and capacity planning

Key Metrics:
- Request counters (by policy, severity)
- Latency histograms
- Detection rates
- Error rates
"""

from prometheus_client import Counter, Histogram, Gauge, Info
from functools import wraps
import time

# ====================
# COUNTERS
# ====================

SCAN_REQUESTS_TOTAL = Counter(
    "openscript_scan_requests_total",
    "Total number of scan requests",
    ["policy_id", "endpoint"],
)

THREATS_DETECTED_TOTAL = Counter(
    "openscript_threats_detected_total",
    "Total number of threats detected",
    ["severity", "category", "policy_id"],
)

SCANS_BLOCKED_TOTAL = Counter(
    "openscript_scans_blocked_total",
    "Total number of scans that were blocked",
    ["policy_id", "severity"],
)

PATTERN_MATCHES_TOTAL = Counter(
    "openscript_pattern_matches_total",
    "Total number of pattern matches",
    ["pattern_id", "category"],
)

API_ERRORS_TOTAL = Counter(
    "openscript_api_errors_total",
    "Total number of API errors",
    ["endpoint", "error_type"],
)

# ====================
# HISTOGRAMS
# ====================

SCAN_DURATION_SECONDS = Histogram(
    "openscript_scan_duration_seconds",
    "Time taken to complete a scan",
    ["policy_id"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

API_REQUEST_DURATION_SECONDS = Histogram(
    "openscript_api_request_duration_seconds",
    "Time taken to complete an API request",
    ["endpoint", "method"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

INPUT_LENGTH_BYTES = Histogram(
    "openscript_input_length_bytes",
    "Length of input text being scanned",
    buckets=[100, 500, 1000, 5000, 10000, 50000, 100000],
)

# ====================
# GAUGES
# ====================

ACTIVE_SCANS = Gauge("openscript_active_scans", "Number of scans currently in progress")

CACHED_SCANS = Gauge("openscript_cached_scans", "Number of scan results in cache")

LOADED_PATTERNS = Gauge(
    "openscript_loaded_patterns", "Number of patterns currently loaded"
)

LOADED_POLICIES = Gauge(
    "openscript_loaded_policies", "Number of policies currently loaded"
)

# ====================
# INFO
# ====================

BUILD_INFO = Info("openscript_build", "Build information")

# Set build info
BUILD_INFO.info({"version": "1.0.0", "python_version": "3.11+"})


# ====================
# DECORATORS
# ====================


def track_scan_duration(policy_id: str):
    """Decorator to track scan duration."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                duration = time.time() - start_time
                SCAN_DURATION_SECONDS.labels(policy_id=policy_id).observe(duration)

        return wrapper

    return decorator


def count_api_requests(endpoint: str, method: str):
    """Decorator to count API requests."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                API_ERRORS_TOTAL.labels(
                    endpoint=endpoint, error_type=type(e).__name__
                ).inc()
                raise
            finally:
                duration = time.time() - start_time
                API_REQUEST_DURATION_SECONDS.labels(
                    endpoint=endpoint, method=method
                ).observe(duration)

        return wrapper

    return decorator


# ====================
# UTILITY FUNCTIONS
# ====================


def record_scan(policy_id: str, endpoint: str):
    """Record a scan request."""
    SCAN_REQUESTS_TOTAL.labels(policy_id=policy_id, endpoint=endpoint).inc()


def record_threat(severity: str, category: str, policy_id: str):
    """Record a detected threat."""
    THREATS_DETECTED_TOTAL.labels(
        severity=severity, category=category, policy_id=policy_id
    ).inc()


def record_block(policy_id: str, severity: str):
    """Record a blocked scan."""
    SCANS_BLOCKED_TOTAL.labels(policy_id=policy_id, severity=severity).inc()


def record_pattern_match(pattern_id: str, category: str):
    """Record a pattern match."""
    PATTERN_MATCHES_TOTAL.labels(pattern_id=pattern_id, category=category).inc()
