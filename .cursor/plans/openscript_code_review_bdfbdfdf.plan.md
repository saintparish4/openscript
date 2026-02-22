---
name: OpenScript Code Review
overview: Comprehensive code review of OpenScript with 16 issues identified across Architecture, Code Quality, Tests, and Performance. All decisions confirmed interactively.
todos:
  - id: arch-cache-bug
    content: "Issue 1: Fix policy-blind cache key + deep copy of cached results in detector.py"
    status: pending
  - id: arch-auth
    content: "Issue 2: Add API key middleware, rate limiting, fix CORS in server.py"
    status: pending
  - id: arch-di
    content: "Issue 3: Refactor to FastAPI Depends() DI, move globals to app.state"
    status: pending
  - id: arch-lru-cache
    content: "Issue 4: Replace bare dict cache with cachetools.TTLCache"
    status: pending
  - id: quality-wire-metrics
    content: "Issue 5: Wire metrics module into server.py and detector.py, expose /metrics"
    status: pending
  - id: quality-severity-order
    content: "Issue 6: Extract SEVERITY_ORDER constant to types.py, remove 3 duplicates"
    status: pending
  - id: quality-from-domain
    content: "Issue 7: Add .from_domain() class methods to response models"
    status: pending
  - id: quality-do-scan
    content: "Issue 8: Extract _do_scan() helper, separate input/output scan paths"
    status: pending
  - id: test-false-positive
    content: "Issue 9: Replace assert True with real false positive assertions in test_patterns.py"
    status: pending
  - id: test-whitespace
    content: "Issue 10: Parametrize whitespace test with expected outcomes in test_detector.py"
    status: pending
  - id: test-cross-policy-cache
    content: "Issue 11: Add cross-policy cache test + mutation test in test_detector.py"
    status: pending
  - id: test-types
    content: "Issue 12: Create test_types.py with boundary tests for Pydantic models"
    status: pending
  - id: perf-scaling-test
    content: "Issue 13: Add scaling-aware pattern count regression test"
    status: pending
  - id: perf-confidence
    content: "Issue 14: Fix _calculate_confidence to use position param, add zero-div guard"
    status: pending
  - id: perf-timer
    content: "Issue 15: Switch scan_text timing to time.perf_counter()"
    status: pending
  - id: perf-delimiters
    content: "Issue 16: Fix duplicate delimiter variants in generator.py, update tests"
    status: pending
isProject: false
---

# OpenScript Code Review -- Implementation Plan

All 16 issues were reviewed interactively. The user confirmed the recommended option for every issue. This plan captures the agreed-upon changes.

---

## Architecture Fixes

### Issue 1: Cache Bug -- Policy-Blind Caching + Shared Mutable State (1A)

- In `[src/core/detector.py](src/core/detector.py)`, change cache key from `input_hash` to `f"{input_hash}:{policy.policy_id}"` (line 93)
- Return a deep copy of cached results (use `model_copy(deep=True)` on the Pydantic model) instead of mutating `cached_result.scan_id` in place (line 102)

### Issue 2: API Key Middleware + Rate Limiting + CORS Fix (2A)

- In `[src/api/server.py](src/api/server.py)`, add API key validation middleware (check `X-API-Key` header against configured keys, skip for `/v1/health` and `/docs`)
- Add basic rate limiting (use `slowapi` or simple in-memory token bucket)
- Fix CORS: replace `allow_origins=["*"]` with configurable origins; remove `allow_credentials=True` when using wildcard (lines 139-145)
- Add `API_KEY` and `CORS_ORIGINS` to a settings/config pattern

### Issue 3: FastAPI Dependency Injection (3A)

- Move `DetectionEngine` and `PolicyManager` instantiation into the `lifespan` context manager, store on `app.state`
- Create `Depends()` functions: `get_detection_engine(request)` and `get_policy_manager(request)` that read from `request.app.state`
- Update all endpoints to inject dependencies via `Depends()`
- Remove module-level globals (lines 107-108)

### Issue 4: LRU/TTL Cache (4A)

- Replace bare `dict` in `[src/core/detector.py](src/core/detector.py)` line 64 with `cachetools.TTLCache(maxsize=10000, ttl=300)` (10K entries, 5-min TTL)
- Add `cachetools` to `[requirements.txt](requirements.txt)`
- Make `maxsize` and `ttl` constructor parameters with sensible defaults

---

## Code Quality Fixes

### Issue 5: Wire Metrics Into Server + Detector (5A)

- In `[src/api/server.py](src/api/server.py)`: import metrics, call `record_scan()` in scan endpoints, `record_threat()` for each detection, `record_block()` on block decisions
- Apply `count_api_requests` decorator to scan endpoints
- Update `ACTIVE_SCANS`, `LOADED_PATTERNS`, `LOADED_POLICIES` gauges during lifespan
- Expose `/metrics` endpoint (or add Prometheus ASGI middleware)
- In `[src/core/detector.py](src/core/detector.py)`: call `record_pattern_match()` on matches, observe `SCAN_DURATION_SECONDS` and `INPUT_LENGTH_BYTES`

### Issue 6: Extract SEVERITY_ORDER Constant (6A)

- In `[src/core/types.py](src/core/types.py)`, add a module-level constant:

```python
SEVERITY_ORDER: Dict[SeverityLevel, int] = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}
```

- Import and use in `[src/core/detector.py](src/core/detector.py)` (lines 320-326), `[src/core/patterns.py](src/core/patterns.py)` (lines 231-237), and `[src/core/types.py](src/core/types.py)` `max_severity` property (lines 108-114)
- Remove all three local copies

### Issue 7: Add `.from_domain()` Class Methods (7A)

- In `[src/api/server.py](src/api/server.py)`, add `@classmethod from_domain(cls, ...)` to `PolicyResponse`, `ThreatDetectionResponse`, and `ScanResponse`
- Replace inline conversions in `list_policies` (lines 292-301), `get_policy` (lines 329-337), and `scan_input` (lines 226-246)

### Issue 8: Extract `_do_scan()` Helper, Separate Input/Output (8A)

- In `[src/api/server.py](src/api/server.py)`, extract shared scan logic into `async def _do_scan(text, policy_id, metadata, scan_type)` 
- `scan_input` calls `_do_scan(..., scan_type="input")`
- `scan_output` determines its own default policy (without mutating request), calls `_do_scan(..., scan_type="output")`
- Include `scan_type` in logging and metrics

---

## Test Fixes

### Issue 9: Real False Positive Assertions (9A)

- In `[tests/test_patterns.py](tests/test_patterns.py)`, replace `assert True` (line 48) with actual assertions: `assert len(matches) == 0` for benign text
- Add more benign examples that exercise the regex boundary (e.g., "Please ignore the previous noise" -- contains trigger words but in benign context)
- If any benign text triggers a match, either fix the regex or document the known FP rate

### Issue 10: Parametrize Whitespace Test (10A)

- In `[tests/test_detector.py](tests/test_detector.py)`, convert `test_whitespace_variations` (lines 318-332) to use `@pytest.mark.parametrize` with expected outcomes
- Mark known-failing variants with `pytest.mark.xfail(reason="regex doesn't match across newlines/tabs")`
- Remove `print()` statements

### Issue 11: Cross-Policy Cache Test + Mutation Test (11A)

- In `[tests/test_detector.py](tests/test_detector.py)`, add:
  - `test_cache_respects_policy_differences`: scan same text with `balanced` vs `maximum_security`, assert results may differ in `blocked`/`policy_applied`
  - `test_cache_does_not_mutate_results`: scan twice, verify first result's `scan_id` was not changed by second scan

### Issue 12: Create `test_types.py` (12A)

- Create `[tests/test_types.py](tests/test_types.py)` with:
  - `test_confidence_at_boundaries` (0.0, 1.0 valid)
  - `test_confidence_out_of_bounds` (-0.1, 1.1 raise `ValidationError`)
  - `test_max_severity_empty_detections` (returns `None`)
  - `test_max_severity_single_detection` 
  - `test_max_severity_multiple_severities`
  - `test_detection_summary_empty`
  - `test_detection_summary_multiple_categories`

---

## Performance Fixes

### Issue 13: Scaling-Aware Regression Test (13A)

- In `[tests/test_detector.py](tests/test_detector.py)`, add a test that asserts `len(engine.pattern_library.patterns) < 25` with a message like "Pattern count exceeds threshold -- consider implementing pre-filtering scan strategy"
- No architectural change now

### Issue 14: Fix `_calculate_confidence` (14A)

- In `[src/core/detector.py](src/core/detector.py)`, change `_calculate_confidence` signature to accept `position: int` parameter
- Replace `full_text.find(matched_text) / len(full_text)` with `position / len(full_text)` 
- Add guard: `if len(full_text) == 0: return base_confidence`
- Update call site (line 144) to pass `position`

### Issue 15: Switch to `time.perf_counter()` (15A)

- In `[src/core/detector.py](src/core/detector.py)`, replace `datetime.now(timezone.utc)` for timing (lines 88, 183) with `time.perf_counter()`
- Keep `datetime.now(timezone.utc)` for `scanned_at` timestamp fields

### Issue 16: Fix Duplicate Delimiter Variants (16A)

- In `[src/redteam/generator.py](src/redteam/generator.py)`, fix lines 43 and 48 to produce real delimiter variants (e.g., `<system>{attack}</system>` and `</end>\n{attack}`)
- Update `[tests/test_redteam.py](tests/test_redteam.py)` to assert all 5 variants are unique, add tests for the new delimiter types

