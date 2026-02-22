---
name: OpenScript Feature Iteration
overview: Final iteration guide for OpenScript -- 15 features across API completeness, persistence/compliance, detection intelligence, and operations, plus a 5-item future roadmap. All decisions confirmed interactively.
todos:
  - id: feat-config
    content: "Feature 3: Create pydantic-settings Settings class + .env.example"
    status: pending
  - id: feat-docker
    content: "Feature 13: Dockerfile (multi-stage) + docker-compose (app + Prometheus + Grafana)"
    status: pending
  - id: feat-ci
    content: "Feature 14: GitHub Actions CI -- lint (black + ruff) + test (pytest + coverage) + build (Docker)"
    status: pending
  - id: feat-crud
    content: "Feature 1: Policy CRUD API -- POST, PUT, DELETE endpoints with validation"
    status: pending
  - id: feat-errors
    content: "Feature 4: Error response consistency + X-Request-ID middleware"
    status: pending
  - id: feat-health
    content: "Feature 15: Split /v1/health (liveness) and /v1/ready (readiness with canary scan)"
    status: pending
  - id: feat-audit
    content: "Feature 5: AuditStore protocol + FileAuditStore (JSONL, append-only, daily rotation)"
    status: pending
  - id: feat-stats
    content: "Feature 2: Implement stats endpoint from Prometheus metric aggregation"
    status: pending
  - id: feat-custom-patterns
    content: "Feature 9: Activate custom_patterns in detection pipeline with ReDoS protection"
    status: pending
  - id: feat-output-patterns
    content: "Feature 10: Add output-specific patterns (email, phone, IP, AWS keys, passwords)"
    status: pending
  - id: feat-remediation
    content: "Feature 11: Add remediation suggestions to AttackPattern and ThreatDetectionResponse"
    status: pending
  - id: feat-feedback
    content: "Feature 6: POST /v1/feedback endpoint for false positive/negative reporting"
    status: pending
  - id: feat-tenant
    content: "Feature 7: Multi-tenant API key isolation with tenant_id in audit/metrics/logs"
    status: pending
  - id: feat-export
    content: "Feature 8: GET /v1/audit/export with date/severity/tenant filters, JSON + CSV"
    status: pending
  - id: feat-webhook
    content: "Feature 12: WebhookManager -- async POST on critical threats, fire-and-forget"
    status: pending
isProject: false
---

# OpenScript Final Iteration Guide -- Feature Plan

This plan covers 15 features and a 5-item future roadmap. It is a **separate plan** from the [code review plan](openscript_code_review_bdfbdfdf.plan.md) and should be executed after those 16 code quality fixes are complete.

**Dependency note**: Several features here depend on code review fixes. Feature 2 depends on Issue 5 (metrics wiring), Features 6/8 depend on Feature 5 (audit store), and Feature 7 depends on Issue 2 (API key auth). The execution order below respects these dependencies.

---

## Recommended Execution Order

Build in layers, not in section order:

1. **Foundation layer** (Features 3, 13, 14) -- config, Docker, CI
2. **API layer** (Features 1, 4, 15) -- CRUD, error polish, health probes
3. **Persistence layer** (Features 5, 2) -- audit store, stats
4. **Intelligence layer** (Features 9, 10, 11) -- custom patterns, output patterns, remediation
5. **Platform layer** (Features 6, 7, 8, 12) -- feedback, tenants, export, webhooks

---

## Section 1: API Completeness & Developer Experience

### Feature 1: Policy CRUD API (1A -- Full CRUD)

**Files**: `[src/api/server.py](src/api/server.py)`

- Add `POST /v1/policies` -- accepts `SecurityPolicy` fields, validates via `PolicyManager.validate_policy()`, returns created policy
- Add `PUT /v1/policies/{policy_id}` -- full replacement update, validate before saving
- Add `DELETE /v1/policies/{policy_id}` -- protect default policies (`balanced`, `maximum_security`, etc.) from deletion, return 400 if attempted
- Add request models: `CreatePolicyRequest`, `UpdatePolicyRequest` with field validation
- Handle concurrency: log warning if policy changes mid-scan (acceptable for v1, scans use snapshot of policy at scan start)
- Tests: CRUD success paths, validation errors, default policy protection, overwrite behavior

### Feature 2: Implement Stats Endpoint (2A -- In-Memory from Prometheus)

**Files**: `[src/api/server.py](src/api/server.py)`, `[src/observability/metrics.py](src/observability/metrics.py)`
**Depends on**: Code review Issue 5 (wire metrics)

- Replace placeholder in `get_stats()` with real aggregation from Prometheus metric objects
- Return: `total_scans`, `threats_by_severity` (dict), `block_rate` (float), `avg_scan_duration_ms`, `cache_hit_rate`, `uptime_seconds`, `patterns_loaded`, `policies_loaded`
- Use `SCAN_REQUESTS_TOTAL._metrics` to sum across label combinations
- Add `app_start_time` in lifespan for uptime calculation
- Tests: verify stats structure, verify counters increment after scans

### Feature 3: Configuration Management (3A -- pydantic-settings)

**New file**: `src/config.py`
**Files to update**: `[src/api/server.py](src/api/server.py)`, `[src/core/detector.py](src/core/detector.py)`, `[src/observability/logging.py](src/observability/logging.py)`

- Create `Settings(BaseSettings)` class with:
  - `app_version: str = "1.0.0"`
  - `cors_origins: list[str] = ["*"]`
  - `api_key: Optional[str] = None` (None = no auth)
  - `cache_max_size: int = 10000`
  - `cache_ttl_seconds: int = 300`
  - `log_level: str = "INFO"`
  - `log_json: bool = True`
  - `max_input_length: int = 100_000`
  - `audit_store_path: Optional[str] = None`
- Use `model_config = SettingsConfigDict(env_prefix="OPENSCRIPT_", env_file=".env")`
- Add `pydantic-settings` to `[requirements.txt](requirements.txt)`
- Replace all hardcoded values with settings references
- Create `.env.example` with documented defaults
- Tests: verify defaults, verify env var override

### Feature 4: SDK-Friendly Error Responses + Request IDs (4A)

**Files**: `[src/api/server.py](src/api/server.py)`

- Update `http_exception_handler` and `general_exception_handler` to return `ErrorResponse` model (not raw dicts) with `response_model=ErrorResponse` for proper OpenAPI docs
- Add request ID middleware: generate `X-Request-ID` (UUID) per request, include in all log entries and error responses
- Add `request_id` field to `ErrorResponse` model
- Include `request_id` in `ScanResponse` for correlation
- Tests: verify error responses match ErrorResponse schema, verify X-Request-ID header present

---

## Section 2: Persistence & Compliance

### Feature 5: Scan Audit Trail (5A -- AuditStore Protocol + JSONL)

**New files**: `src/audit/store.py`, `src/audit/file_store.py`
**Files to update**: `[src/core/detector.py](src/core/detector.py)` or `[src/api/server.py](src/api/server.py)`

- Define `AuditStore` protocol:

```python
  class AuditStore(Protocol):
      def save_scan(self, result: ScanResult, metadata: dict) -> None: ...
      def query_scans(self, filters: dict) -> List[dict]: ...
  

```

- Implement `FileAuditStore`:
  - Append-only JSONL (one JSON line per scan)
  - Configurable file path via Settings (Feature 3)
  - Include: scan_id, timestamp, input_hash, is_safe, blocked, detection_count, policy_applied, tenant_id, scan_duration_ms
  - Do NOT store raw input text (security: avoid persisting potentially sensitive user content)
  - Rotate files by date (one file per day)
- Wire into server: after scan completes, call `audit_store.save_scan()` (fire-and-forget, don't block response)
- Tests: write + read round-trip, file rotation, query with filters

### Feature 6: Detection Feedback API (6A -- Collection Only)

**Files**: `[src/api/server.py](src/api/server.py)`, `src/audit/store.py`
**Depends on**: Feature 5

- Add `POST /v1/feedback` endpoint:

```python
  class FeedbackRequest(BaseModel):
      scan_id: str
      detection_id: Optional[str] = None
      feedback_type: Literal["false_positive", "false_negative", "confirmed"]
      notes: Optional[str] = None
  

```

- Store feedback in audit trail (separate JSONL file or same file with `type: "feedback"` prefix)
- Return `202 Accepted` (async processing in future)
- Tests: submit feedback, verify persisted, verify invalid scan_id handling

### Feature 7: Multi-Tenant API Key Isolation (7A -- Lightweight)

**Files**: `[src/api/server.py](src/api/server.py)`, `src/config.py`
**Depends on**: Code review Issue 2 (API key auth)

- Extend API key config to map keys to tenant_ids:

```
  OPENSCRIPT_API_KEYS={"key1": "tenant_acme", "key2": "tenant_globex"}
  

```

- Add `tenant_id` to request context (via middleware or dependency)
- Include `tenant_id` in: audit records, metrics labels, log entries
- Custom policies get `tenant_id` prefix (e.g., `tenant_acme:custom_policy_1`)
- Tenants can see only their own custom policies (default policies visible to all)
- Tests: tenant isolation on policies, audit records include tenant_id

### Feature 8: Compliance Export Endpoint (8A -- API with Filters)

**Files**: `[src/api/server.py](src/api/server.py)`
**Depends on**: Feature 5

- Add `GET /v1/audit/export`:
  - Query params: `start_date`, `end_date`, `severity`, `category`, `blocked_only`, `tenant_id`, `format` (json/csv), `limit`, `offset`
  - Read from `AuditStore.query_scans()` with filters
  - Support CSV format via `text/csv` Accept header or `?format=csv`
  - Paginate with `limit`/`offset` (default limit: 1000)
- Streaming response for large exports (use FastAPI `StreamingResponse`)
- Tests: filter combinations, CSV format, pagination, empty results

---

## Section 3: Detection & Intelligence

### Feature 9: Activate Custom Patterns (9A -- Full Regex with ReDoS Protection)

**Files**: `[src/core/detector.py](src/core/detector.py)`, `[src/core/patterns.py](src/core/patterns.py)`

- In `_get_applicable_patterns()`, after loading library patterns, compile `policy.custom_patterns` into temporary `AttackPattern` objects:
  - Pattern ID: `custom_{index}`
  - Category: `AttackCategory.CUSTOM` (add to enum in `types.py` if needed, or use a configurable default)
  - Severity: configurable per custom pattern (or default to MEDIUM)
- **ReDoS protection**: wrap regex compilation in a timeout check. Use `re.compile()` with a max pattern length (e.g., 500 chars). Consider using the `regex` library's timeout support or a simple string-length heuristic.
- Cache compiled custom patterns per policy_id to avoid re-compiling on every scan
- Tests: custom pattern matches, ReDoS rejection, cache behavior, invalid regex handling

### Feature 10: Output-Specific Detection Patterns (10A)

**Files**: `[src/core/patterns.py](src/core/patterns.py)`

- Add new patterns to `_initialize_core_patterns()`:
  - `pii_003`: Email addresses (`\b[\w.+-]+@[\w-]+\.[\w.-]+\b`)
  - `pii_004`: Phone numbers (US format: `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
  - `credential_002`: Internal URLs / IP addresses (`\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`)
  - `credential_003`: AWS access keys (`AKIA[0-9A-Z]{16}`)
  - `credential_004`: Generic password-in-output (`(?i)password\s*[:=]\s*\S+`)
- Tag all with appropriate categories, tune `false_positive_rate` conservatively
- Include in `data_protection` policy categories
- Tests: true positive + false positive for each new pattern

### Feature 11: Remediation Suggestions (11A)

**Files**: `[src/core/patterns.py](src/core/patterns.py)`, `[src/core/types.py](src/core/types.py)`, `[src/api/server.py](src/api/server.py)`

- Add `remediation: str` field to `AttackPattern` dataclass
- Add pre-written suggestions per existing pattern:
  - `direct_injection_001`: "Input contains an instruction override attempt. Reject the input and prompt the user to rephrase without referencing AI instructions."
  - `credential_001`: "Output contains a potential API key or token. Mask or redact the credential before displaying to the user."
  - (Similar for all 9+ patterns)
- Add `remediation: str` field to `ThreatDetectionResponse`
- Populate from pattern metadata in scan flow
- Tests: verify remediation field present in responses, verify not empty

### Feature 12: Webhook Notifications (12A)

**New file**: `src/notifications/webhook.py`
**Files to update**: `[src/api/server.py](src/api/server.py)`, `src/config.py`

- Create `WebhookManager` class:
  - `async def notify(self, scan_result: ScanResult)` -- sends POST to configured URLs
  - Uses `httpx.AsyncClient` (already a dependency) with 5-second timeout
  - Fire-and-forget (don't await in scan response path -- use `asyncio.create_task`)
  - Retry: 1 retry with exponential backoff on failure
  - Payload: `{scan_id, timestamp, max_severity, detection_count, blocked, policy_applied}`
- Settings: `webhook_urls: list[str] = []`, `webhook_severity_threshold: str = "high"`
- Wire into scan flow: after scan, if any detection meets threshold, notify
- Tests: mock httpx, verify webhook called on critical, not called on clean

---

## Section 4: Operations & Deployment

### Feature 13: Docker Containerization (13A -- Multi-Stage + Compose)

**New files**: `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `prometheus.yml`

- **Dockerfile**: Multi-stage build
  - Stage 1: `python:3.11-slim` builder, install deps
  - Stage 2: slim runtime, copy deps + source, non-root user, healthcheck
  - Expose port 8000, CMD: `uvicorn src.api.server:app --host 0.0.0.0 --port 8000`
- **docker-compose.yml**: 3 services
  - `openscript`: the app (port 8000)
  - `prometheus`: scrapes `/metrics` from openscript (port 9090)
  - `grafana`: pre-configured dashboard (port 3000)
- **prometheus.yml**: scrape config for openscript
- **.dockerignore**: `.git`, `__pycache`__, `.env`, `tests/`, `.cursor/`
- Tests: `docker build` succeeds, health check passes

### Feature 14: CI/CD Pipeline (14A -- Lint + Test + Build)

**New file**: `.github/workflows/ci.yml`

- **lint** job: `black --check .`, `ruff check .` (add `ruff` to requirements.txt)
- **test** job: `pytest --cov=src --cov-report=xml`, upload coverage report, fail if coverage < 80%
- **build** job: `docker build .`, runs only on main branch
- Trigger: push to main, PRs
- Matrix: Python 3.11 (can expand later)
- Add `ruff` and `ruff.toml` with sensible defaults

### Feature 15: Enhanced Health & Readiness Probes (15A)

**Files**: `[src/api/server.py](src/api/server.py)`

- Keep `/v1/health` as lightweight liveness probe (current behavior, fast)
- Add `/v1/ready` readiness endpoint:
  - Check: `pattern_count > 0`
  - Check: `policy_count > 0`
  - Check: run a canary scan (`"test"` with `balanced` policy, verify no crash)
  - Return: `{"ready": true/false, "checks": {"patterns": "ok", "policies": "ok", "scan_engine": "ok"}}`
  - If any check fails: return 503 with failing check details
- Docker healthcheck uses `/v1/ready`
- Tests: healthy state, degraded state (empty patterns)

---

## Future Roadmap (Post-Iteration)

Documented for planning purposes. Priority order based on user signal:

### Priority 1: Semantic Detection

- Embedding-based detection using sentence-transformers or OpenAI embeddings
- Compare input embeddings against known attack embedding clusters
- Enables detection of novel attacks that regex can't catch
- Activates the unused `DetectionMethod.SEMANTIC` enum value
- **Estimated effort**: 2-3 weeks. Requires ML infrastructure decisions.

### Priority 2: LLM Provider SDK Wrappers

- LangChain callback handler that auto-scans input/output
- OpenAI SDK wrapper: `openscript.wrap(openai.ChatCompletion.create)`
- Anthropic SDK wrapper
- Generic middleware pattern for any LLM API
- **Estimated effort**: 1-2 weeks. High distribution impact (makes adoption frictionless).

### Priority 3: Distributed Deployment

- Redis cache backend (replace in-memory cache)
- Message queue for async scanning (Celery/RQ)
- Horizontal scaling with shared state
- Database-backed audit store (PostgreSQL)
- **Estimated effort**: 3-4 weeks. Required for high-throughput production deployments.

### Priority 4: Admin Dashboard Web UI

- React/Next.js frontend
- Policy management (visual CRUD)
- Scan history with search/filter
- Threat visualization (timeline, heatmaps)
- Real-time scan monitoring
- **Estimated effort**: 4-6 weeks. High value for enterprise sales demos.

### Priority 5: Pattern Marketplace

- Community-contributed patterns with quality scoring
- Pattern sharing/importing via API
- Automated testing of contributed patterns against red team suite
- Versioned pattern sets
- **Estimated effort**: 6-8 weeks. Network effect growth driver.

