"""
FastAPI server for security service

Why: RESTful API allows integration with any application.
FastAPI provides high performance, async support, and automatic documentation.
"""

import os
from typing import List
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_client import make_asgi_app
import structlog
import time

from ..core.detector import DetectionEngine
from ..core.types import ScanResult, ThreatDetection as DomainThreatDetection, SecurityPolicy
from ..core.policy import PolicyManager
from ..observability.metrics import (
    record_scan,
    record_threat,
    record_block,
    count_api_requests,
    ACTIVE_SCANS,
    LOADED_PATTERNS,
    LOADED_POLICIES,
)

logger = structlog.get_logger()

# ============================================================================
# CONFIGURATION
# ============================================================================

API_KEYS: set = set(
    filter(None, os.environ.get("OPENSCRIPT_API_KEYS", "").split(","))
)
CORS_ORIGINS: list = [
    o.strip()
    for o in os.environ.get("OPENSCRIPT_CORS_ORIGINS", "").split(",")
    if o.strip()
]
RATE_LIMIT: str = os.environ.get("OPENSCRIPT_RATE_LIMIT", "")


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================


class ScanRequest(BaseModel):
    """Request to scan text for threats."""

    text: str = Field(
        ...,
        description="Text to scan for security threats",
        min_length=1,
        max_length=100_000,
    )
    policy_id: str = Field(
        default="balanced", description="Policy ID to apply for scanning"
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Optional metadata (user_id, session_id, etc.)",
    )


class ThreatDetectionResponse(BaseModel):
    """Representation of a detected threat."""

    attack_id: str
    category: str
    severity: str
    confidence: float
    detection_method: str
    context: str
    position: int
    metadata: dict

    @classmethod
    def from_domain(cls, detection: DomainThreatDetection) -> "ThreatDetectionResponse":
        return cls(
            attack_id=detection.attack_id,
            category=detection.category.value,
            severity=detection.severity.value,
            confidence=detection.confidence,
            detection_method=detection.detection_method.value,
            context=detection.context,
            position=detection.position,
            metadata=detection.metadata,
        )


class ScanResponse(BaseModel):
    """Response from a scan operation."""

    scan_id: str
    is_safe: bool
    blocked: bool
    detections: List[ThreatDetectionResponse]
    scan_duration_ms: float
    policy_applied: str
    timestamp: datetime

    @classmethod
    def from_domain(cls, result: ScanResult) -> "ScanResponse":
        return cls(
            scan_id=result.scan_id,
            is_safe=result.is_safe,
            blocked=result.blocked,
            detections=[
                ThreatDetectionResponse.from_domain(d) for d in result.detections
            ],
            scan_duration_ms=result.scan_duration_ms,
            policy_applied=result.policy_applied or "",
            timestamp=result.scanned_at,
        )


class PolicyResponse(BaseModel):
    """Representation of a security policy."""

    policy_id: str
    name: str
    description: str
    enabled: bool
    block_on_detection: bool
    severity_threshold: str
    categories: List[str]

    @classmethod
    def from_domain(cls, policy: SecurityPolicy) -> "PolicyResponse":
        return cls(
            policy_id=policy.policy_id,
            name=policy.name,
            description=policy.description,
            enabled=policy.enabled,
            block_on_detection=policy.block_on_detection,
            severity_threshold=policy.severity_threshold.value,
            categories=[c.value for c in policy.categories],
        )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    timestamp: datetime
    version: str
    pattern_count: int
    policy_count: int


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    detail: str
    timestamp: datetime


# ============================================================================
# DEPENDENCY INJECTION
# ============================================================================


def get_detection_engine(request: Request) -> DetectionEngine:
    return request.app.state.detection_engine


def get_policy_manager(request: Request) -> PolicyManager:
    return request.app.state.policy_manager


# ============================================================================
# APPLICATION SETUP
# ============================================================================

limiter = Limiter(
    key_func=get_remote_address,
    enabled=bool(RATE_LIMIT),
    default_limits=[RATE_LIMIT] if RATE_LIMIT else [],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    engine = DetectionEngine()
    policy_manager = PolicyManager()

    app.state.detection_engine = engine
    app.state.policy_manager = policy_manager

    LOADED_PATTERNS.set(len(engine.pattern_library.patterns))
    LOADED_POLICIES.set(len(policy_manager.policies))

    logger.info(
        "api_server_starting",
        version="1.0.0",
        patterns=len(engine.pattern_library.patterns),
        policies=len(policy_manager.policies),
    )
    yield
    logger.info("api_server_shutting_down")


app = FastAPI(
    title="OpenScript Security API",
    description=(
        "Enterprise prompt security platform for detecting injection attacks, "
        "data leaks, and unsafe LLM outputs."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter

# CORS -- use configured origins or permissive fallback (never wildcard + credentials)
cors_origins = CORS_ORIGINS or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=cors_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# ============================================================================
# MIDDLEWARE
# ============================================================================

OPEN_PATHS = {"/v1/health", "/docs", "/redoc", "/openapi.json"}


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Validate API key for protected endpoints."""
    if API_KEYS and request.url.path not in OPEN_PATHS and not request.url.path.startswith("/metrics"):
        key = request.headers.get("X-API-Key")
        if key not in API_KEYS:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Invalid or missing API key",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
    return await call_next(request)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests and responses."""
    start_time = time.time()

    logger.info(
        "api_request",
        method=request.method,
        path=request.url.path,
        client=request.client.host if request.client else None,
    )

    try:
        response = await call_next(request)
    except Exception as e:
        logger.error(
            "api_error",
            method=request.method,
            path=request.url.path,
            error=str(e),
            error_type=type(e).__name__,
        )
        raise

    duration_ms = (time.time() - start_time) * 1000
    logger.info(
        "api_response",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )

    return response


# ============================================================================
# SCAN HELPER
# ============================================================================


async def _do_scan(
    text: str,
    policy_id: str,
    metadata: dict,
    scan_type: str,
    engine: DetectionEngine,
    pm: PolicyManager,
) -> ScanResponse:
    """Shared scan logic for input and output endpoints."""
    policy = pm.get_policy(policy_id)
    if not policy:
        raise HTTPException(
            status_code=404, detail=f"Policy '{policy_id}' not found"
        )

    record_scan(policy_id=policy_id, endpoint=f"/v1/scan/{scan_type}")
    ACTIVE_SCANS.inc()
    try:
        result = engine.scan_text(text, policy, metadata)
    finally:
        ACTIVE_SCANS.dec()

    for d in result.detections:
        record_threat(
            severity=d.severity.value,
            category=d.category.value,
            policy_id=policy_id,
        )

    if result.blocked:
        max_sev = result.max_severity.value if result.max_severity else "unknown"
        record_block(policy_id=policy_id, severity=max_sev)

    logger.info(
        "scan_completed",
        scan_type=scan_type,
        scan_id=result.scan_id,
        policy_id=policy_id,
        is_safe=result.is_safe,
        blocked=result.blocked,
        detection_count=len(result.detections),
    )

    return ScanResponse.from_domain(result)


# ============================================================================
# ENDPOINTS
# ============================================================================


@app.post(
    "/v1/scan/input",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan user input",
    description=(
        "Scan user input for security threats before sending to LLM. "
        "Returns detections and blocking decision."
    ),
)
@limiter.limit(RATE_LIMIT or "1000/minute")
@count_api_requests("/v1/scan/input", "POST")
async def scan_input(
    request: Request,
    body: ScanRequest,
    engine: DetectionEngine = Depends(get_detection_engine),
    pm: PolicyManager = Depends(get_policy_manager),
) -> ScanResponse:
    """
    Scan user input for security threats.

    Use this endpoint to scan user messages before sending them to your LLM.
    If the response indicates `blocked=true`, you should not process the input.
    """
    try:
        return await _do_scan(body.text, body.policy_id, body.metadata, "input", engine, pm)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("scan_input_failed", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.post(
    "/v1/scan/output",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan LLM output",
    description=(
        "Scan LLM output for security issues before showing to user. "
        "Detects credential leaks, PII exposure, etc."
    ),
)
@limiter.limit(RATE_LIMIT or "1000/minute")
@count_api_requests("/v1/scan/output", "POST")
async def scan_output(
    request: Request,
    body: ScanRequest,
    engine: DetectionEngine = Depends(get_detection_engine),
    pm: PolicyManager = Depends(get_policy_manager),
) -> ScanResponse:
    """
    Scan LLM output for security issues.

    Use this endpoint to scan LLM responses before showing them to users.
    Primarily detects data leaks (credentials, PII) in model outputs.
    """
    policy_id = body.policy_id
    if policy_id == "balanced":
        policy_id = "data_protection"

    try:
        return await _do_scan(body.text, policy_id, body.metadata, "output", engine, pm)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("scan_output_failed", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get(
    "/v1/policies",
    response_model=List[PolicyResponse],
    status_code=status.HTTP_200_OK,
    summary="List policies",
    description="List all available security policies",
)
async def list_policies(
    pm: PolicyManager = Depends(get_policy_manager),
) -> List[PolicyResponse]:
    """Get list of all available security policies."""
    try:
        return [PolicyResponse.from_domain(p) for p in pm.list_policies()]
    except Exception as e:
        logger.error("list_policies_failed", error=str(e), error_type=type(e).__name__)
        raise HTTPException(
            status_code=500, detail=f"Failed to list policies: {str(e)}"
        )


@app.get(
    "/v1/policies/{policy_id}",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Get policy",
    description="Get details of a specific policy",
)
async def get_policy(
    policy_id: str,
    pm: PolicyManager = Depends(get_policy_manager),
) -> PolicyResponse:
    """Get details of a specific policy."""
    try:
        policy = pm.get_policy(policy_id)
        if not policy:
            raise HTTPException(
                status_code=404, detail=f"Policy '{policy_id}' not found"
            )
        return PolicyResponse.from_domain(policy)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "get_policy_failed",
            policy_id=policy_id,
            error=str(e),
            error_type=type(e).__name__,
        )
        raise HTTPException(status_code=500, detail=f"Failed to get policy: {str(e)}")


@app.get(
    "/v1/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check",
    description="Check if the service is running and healthy",
)
async def health_check(
    engine: DetectionEngine = Depends(get_detection_engine),
    pm: PolicyManager = Depends(get_policy_manager),
) -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version="1.0.0",
        pattern_count=len(engine.pattern_library.patterns),
        policy_count=len(pm.policies),
    )


@app.get(
    "/v1/stats",
    summary="Get statistics",
    description="Get usage statistics (if implemented)",
)
async def get_stats():
    """Get usage statistics."""
    return {
        "total_scans": "not_implemented",
        "threats_detected": "not_implemented",
        "uptime": "not_implemented",
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate Limit Exceeded",
            "detail": str(exc.detail),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP Error",
            "detail": exc.detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        error=str(exc),
        error_type=type(exc).__name__,
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected error occurred",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )
