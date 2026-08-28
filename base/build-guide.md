# OpenScript Interactive Demo — Build Guide

**Status:** Draft
**Owner:** Saint Parish / BlueSky Labs
**Related:** OpenScript (security-gateway SDK, Jan–Apr 2026, code-complete)
**See also:** `openscript-demo-prd.md` for the full requirements and rationale

---

## Recommendation this guide builds toward

**Pure client-side, decided.** Run the actual OpenScript package compiled to WASM via **Pyodide**, entirely in the visitor's browser. There is no backend and no API endpoint of any kind. See the PRD, Section 2, for the full reasoning — the short version is that the Phase 0 audit came back all-local, so a backend would be infrastructure serving no policy, and "every check runs in your browser, nothing leaves the tab" is a stronger, simpler claim than any hybrid could make.

**Phase 0 is complete** — its outcome is recorded below and it is what deleted the backend phase. Full audit, evidence, and the Phase 1 proof harness: `base/directive/p0-1.md`.

---

## Phase 0 — Policy audit ✅ DONE

Audited against `b29fbc9`. The 8 built-in policies are exactly the 8 non-`noop` entries in
the registry at `sdk/policies/config.py`.

| Policy | Class | Pure local (regex/heuristic)? | External call required? | Notes |
|---|---|---|---|---|
| PII redaction | `PIIPolicy` | **Yes** — 5 regexes + Luhn | **No** | Email, phone, SSN, API-key shapes, IPv4; cards Luhn-validated. |
| Secrets detection | `SecretsPolicy` | **Yes** — 8 credential + 6 internal-URL regexes | **No** | AWS, GitHub, Slack, JWT, PEM blocks, generic `sk-`. Runs on input *and* output. |
| Prompt injection (pattern) | `PromptInjectionPolicy` | **Yes** — 38 weighted regexes, 6 categories | **No** | Additive weights, per-category cap 0.7, threshold 0.5. |
| Prompt injection (semantic/LLM) | — | **N/A — not implemented** | **N/A** | No such policy exists. `contracts/server_types.py` declares an unused `embedding_score` field; the server's `/v1/threat/score` calls the same `score_text()` as the pattern policy. |
| Tool-call firewall | `ToolFirewallPolicy` | **Yes** — declarative rule match | **No** | Deny / RBAC / `requires_approval` / `max_<field>` arg bounds, from YAML or in-process. |
| Compliance | `CompliancePolicy` | **Yes** — 5 PHI regexes + secrets bank | **No** | `phi_detection`, `credential_output_guard`, `data_access_audit`. |
| Toxicity | `ToxicityPolicy` | **Yes** — 15 structural regexes | **No** | Violence, hate speech, harassment, self-harm. |
| Output schema / hallucination | `OutputSchemaPolicy` | **Yes** in default `keyword` mode | **No** | Pydantic validation + dangerous-content scan + keyword grounding. The optional `embedding` mode uses a **local** model and auto-falls back; never used here. |
| Audit logging | `AuditPolicy` | **Yes** — pure serialization | **No** | Drains into any sink; the browser supplies an in-memory one. The Postgres sink is never imported by `import sdk`. |

**Outcome: 0 of 8 need `requires-backend`. Phase 3 deleted; shipping pure client-side.**

Supporting evidence: no outbound HTTP anywhere in `sdk/`, no policy reads an API key, and the
whole `import sdk` graph needs exactly three third-party packages (`pydantic`, `structlog`,
`pyyaml`) — verified by importing `sdk` with `sqlalchemy`, `redis`, `sentence_transformers`,
`prometheus_client`, `opentelemetry`, `fastapi`, `asyncpg` and `httpx` all forcibly blocked.

This verdict is enforced in CI by `tests/test_audit.py`: if a policy ever grows a
network call, those tests fail and the backend phase comes back onto the roadmap.

---

## Phase 1 — Prove Pyodide can run the package ✅ DONE

Proven against Pyodide **0.28.3** (Python 3.13.2, abi `2025_0`). All 8 policies — plus the
full `SecureAgent` pipeline, the deny path, risk aggregation and YAML config loading — run
in WASM. `make probe` is the repeatable gate.

**Two blockers were found and fixed** (both in `pyproject.toml`, both invisible to a normal
`pytest` run, which imports from the repo root rather than an installed wheel):

- `include = ["sdk", ...]` shipped a wheel with only `sdk/__init__.py` and `sdk/logging.py` —
  every policy subpackage was missing. Fixed with `sdk*`; the wheel now carries 19 `sdk/` modules.
- `pydantic>=2.12` is unsatisfiable in the browser: Pyodide bundles 2.10.6 and no pydantic-core
  between 2.28 and 2.46 publishes a WASM wheel, so micropip aborts. Floor relaxed to
  `>=2.10,<3`; the whole suite still passes.

**Step 1 — C extensions:** `make wasm-deps`. Two dependencies carry native code
(`pydantic-core`, `pyyaml`); Pyodide ships a prebuilt WASM wheel for both. Nothing needed
swapping, so the original step 3 ("swap it for a pure-Python equivalent") was a no-op.

**Step 2 — the proof:** `make probe-serve` and open `http://localhost:8080`. The page loads
Pyodide from the CDN, installs the self-hosted wheels from `./wheels/` (never PyPI), and runs
`web/smoke.py`. `make probe` runs the identical `smoke.py` headless in Node over the same HTTP
install path, so the page and CI can never disagree about what "it works" means.

**Measured:** ~7.2 MB cold load (brotli), ~5.4 s install-to-ready with a warm cache, and a
5-policy pipeline over 1.1 KB of text at **4.4 ms p50 / 6.0 ms p95**. The load budget is why
Phase 2 step 2's lazy-load is mandatory rather than a nicety, and why the loading state needs
real progress text.

**Enforced in CI** by `tests/test_pyodide_compat.py` (wheel completeness, pure-Python wheel,
dependency floors vs. the Pyodide lockfile) and by `node web/probe.mjs`. Both blockers above
were re-introduced deliberately to confirm the tests fail on them.

---

## Phase 2 — Client-side demo shell

1. Build the demo as a Next.js client component (`"use client"`) — Pyodide and the WASM package only run in the browser, so this section gets no benefit from SSR. Keep it isolated from server components so the Pyodide bundle doesn't leak into unrelated route bundles.
2. Lazy-load Pyodide + the package via `next/dynamic` with `ssr: false`, triggered when the demo section scrolls into view or on an explicit "load demo" button — don't tax the initial page load or attempt to load Pyodide during SSR (it will fail, since it depends on browser globals).
3. Build the gallery: hardcode the 6–8 example prompts and their expected policy, wire each chip to run the client-side pipeline and render the result component (per-policy verdict, before/after diff, plain-English explanation — see PRD Section 4.3).
4. Build the free-text path using the same pipeline, client-side policies only for now.
5. Ship this. Phase 0 came back all-local, so this *is* the demo — there is no second half waiting behind it.

---

## Phase 3 — ~~Backend for server-side-only policies~~ (deleted)

**Deleted by the Phase 0 audit.** All 8 policies are pure-local, so there is nothing for a
backend to run. No FastAPI service, no endpoint, no rate limiting, no spend cap, no deploy
target — none of it has a job to do.

Phase 4 keeps its number so existing references stay valid. Do not re-add this phase without
first re-running `make audit`; if a future policy needs a network call, that is the signal.

---

## Phase 4 — Polish & ship

1. Add the privacy statement next to the free-text box. It is now a structural fact, not a retention promise: **the text never leaves your browser.** There is no server to send it to, and the network tab proves it. Say that, not "we don't log it."
2. Add one global "every check ran locally in your browser" line above the results. Not a per-result badge — with no server-side path there is nothing to contrast it against, and a badge on every row implies a distinction that no longer exists.
3. Test cold-load on mobile.
4. Link it from the portfolio and the OpenScript README.

---

## Open Questions Before Starting

- ~~Does any of the 8 policies actually require an external LLM call today?~~ **Answered: no. All 8 are local heuristics.** See Phase 0 above.
- ~~Is there an existing wheel/build pipeline for the package?~~ **Answered: yes, but it was broken** — `include = ["sdk", ...]` shipped a wheel containing only `sdk/__init__.py` and `sdk/logging.py`, and `pydantic>=2.12` is unsatisfiable under Pyodide. Both fixed in Phase 1; see `base/directive/p0-1.md` §1.1.