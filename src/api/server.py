"""
FastAPI server for security service

Why: RESTful API allows integration with any application.
FastAPI provides high performance, async support, and automatic documentation.
"""

from typing import List
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import structlog
import time

from ..core.detector import DetectionEngine
from ..core.policy import PolicyManager

logger = structlog.get_logger()

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================


class ScanRequest(BaseModel):
    """Request to scan text for threats."""

    text: str = Field(
        ...,
        description="Text to scan for security threats",
        min_length=1,
        max_length=100_000,  # 100KB limit
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


class ScanResponse(BaseModel):
    """Response from a scan operation."""

    scan_id: str
    is_safe: bool
    blocked: bool
    detections: List[ThreatDetectionResponse]
    scan_duration_ms: float
    policy_applied: str
    timestamp: datetime


class PolicyResponse(BaseModel):
    """Representation of a security policy."""

    policy_id: str
    name: str
    description: str
    enabled: bool
    block_on_detection: bool
    severity_threshold: str
    categories: List[str]


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
# APPLICATION SETUP
# ============================================================================

# Initialize core components (before app creation)
detection_engine = DetectionEngine()
policy_manager = PolicyManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    # Startup
    logger.info(
        "api_server_starting",
        version="1.0.0",
        patterns=len(detection_engine.pattern_library.patterns),
        policies=len(policy_manager.policies),
    )
    yield
    # Shutdown
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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# MIDDLEWARE
# ============================================================================


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests and responses."""
    start_time = time.time()

    # Log request
    logger.info(
        "api_request",
        method=request.method,
        path=request.url.path,
        client=request.client.host if request.client else None,
    )

    # Process request
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

    # Log response
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
async def scan_input(request: ScanRequest) -> ScanResponse:
    """
    Scan user input for security threats.

    Use this endpoint to scan user messages before sending them to your LLM.
    If the response indicates `blocked=true`, you should not process the input.
    """
    try:
        # Get policy
        policy = policy_manager.get_policy(request.policy_id)
        if not policy:
            raise HTTPException(
                status_code=404, detail=f"Policy '{request.policy_id}' not found"
            )

        # Run scan
        result = detection_engine.scan_text(request.text, policy, request.metadata)

        # Convert to response format
        return ScanResponse(
            scan_id=result.scan_id,
            is_safe=result.is_safe,
            blocked=result.blocked,
            detections=[
                ThreatDetectionResponse(
                    attack_id=d.attack_id,
                    category=d.category.value,
                    severity=d.severity.value,
                    confidence=d.confidence,
                    detection_method=d.detection_method.value,
                    context=d.context,
                    position=d.position,
                    metadata=d.metadata,
                )
                for d in result.detections
            ],
            scan_duration_ms=result.scan_duration_ms,
            policy_applied=result.policy_applied or request.policy_id,
            timestamp=result.scanned_at,
        )

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
async def scan_output(request: ScanRequest) -> ScanResponse:
    """
    Scan LLM output for security issues.

    Use this endpoint to scan LLM responses before showing them to users.
    Primarily detects data leaks (credentials, PII) in model outputs.
    """
    # Use data protection policy by default for output scanning
    if request.policy_id == "balanced":
        request.policy_id = "data_protection"

    # Same logic as input scanning
    return await scan_input(request)


@app.get(
    "/v1/policies",
    response_model=List[PolicyResponse],
    status_code=status.HTTP_200_OK,
    summary="List policies",
    description="List all available security policies",
)
async def list_policies() -> List[PolicyResponse]:
    """Get list of all available security policies."""
    try:
        policies = policy_manager.list_policies()

        return [
            PolicyResponse(
                policy_id=p.policy_id,
                name=p.name,
                description=p.description,
                enabled=p.enabled,
                block_on_detection=p.block_on_detection,
                severity_threshold=p.severity_threshold.value,
                categories=[c.value for c in p.categories],
            )
            for p in policies
        ]

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
async def get_policy(policy_id: str) -> PolicyResponse:
    """Get details of a specific policy."""
    try:
        policy = policy_manager.get_policy(policy_id)

        if not policy:
            raise HTTPException(
                status_code=404, detail=f"Policy '{policy_id}' not found"
            )

        return PolicyResponse(
            policy_id=policy.policy_id,
            name=policy.name,
            description=policy.description,
            enabled=policy.enabled,
            block_on_detection=policy.block_on_detection,
            severity_threshold=policy.severity_threshold.value,
            categories=[c.value for c in policy.categories],
        )

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
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version="1.0.0",
        pattern_count=len(detection_engine.pattern_library.patterns),
        policy_count=len(policy_manager.policies),
    )


@app.get(
    "/v1/stats",
    summary="Get statistics",
    description="Get usage statistics (if implemented)",
)
async def get_stats():
    """Get usage statistics."""
    # Placeholder for future statistics endpoint
    return {
        "total_scans": "not_implemented",
        "threats_detected": "not_implemented",
        "uptime": "not_implemented",
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================


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


# ============================================================================
# STARTUP/SHUTDOWN
# ============================================================================
# Lifecycle events are now handled via the lifespan context manager above
