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

## Phase 2 — Client-side demo shell ✅ DONE

The demo lives in `site/` — a Next.js 16 app with `output: "export"`, so `npm run build`
emits a directory of static files. There is no server, no API route and nothing to keep
running, which is the Phase 0 verdict made concrete rather than merely claimed.

**Structure.** `app/page.tsx` is a server component that renders `DemoSection`, the only
client component in the tree. It holds the runtime download until the demo is on screen —
`IntersectionObserver` with a 200 px margin, falling back to a "Load the demo" button where
the observer is unavailable — then pulls `DemoPanel` in through `next/dynamic` with
`ssr: false`. That flag is load-bearing, not stylistic: the panel boots a WebAssembly
interpreter against browser globals that do not exist during a build. Keeping the boundary
here is also what stops the Pyodide import from leaking into unrelated route bundles.

**One pipeline, one entry point.** `site/public/pipeline.py` exposes a single
`run_pipeline(payload_json)`. The example chips and the free-text box call it with the same
arguments, so there is no "demo mode" that behaves differently from the box a visitor types
into. Policy objects are built once at module scope: rebuilding them per submission would
show up in the latency number the page advertises.

**What it shows per run:** a verdict for each of the six policies exercised (prompt
injection, toxicity, secrets, PII, compliance, tool firewall) with a plain-English
explanation, a before/after diff of the response when a policy rewrote it, the aggregated
risk score, and the number of audit events written. `flag` is kept distinct from `allow` on
purpose — a policy in annotate mode records a finding and deliberately does not act on it,
and collapsing that into "nothing fired" would hide the policy that did the noticing.

**The gallery is asserted, not decorative.** The 8 examples live in `lib/examples.json`,
read by both the page and `site/verify.mjs`. Each entry names the policy it advertises, and
the gate fails if that policy stops firing — so a pattern drifting under a chip is a build
failure rather than a visitor seeing a chip that does nothing. The benign example asserts
the converse: that the pipeline is not simply blocking everything.

**Enforced in CI** by the `demo` job: it builds the wheel bundle, exports the app, and runs
`verify.mjs` against the export over HTTP — the same install path the browser takes, so a
broken manifest, a missing wheel or a stale `pipeline.py` fails in CI rather than in front
of a visitor. `make demo-verify` is the local equivalent.

**Measured:** 8/8 examples behave as advertised, pipeline time **1.5 ms p50 / 3.3 ms max**
across the gallery. That is the policy pipeline only; the ~7 MB runtime boot is separate and
happens once.

## Phase 3 — ~~Backend for server-side-only policies~~ (deleted)

**Deleted by the Phase 0 audit.** All 8 policies are pure-local, so there is nothing for a
backend to run. No FastAPI service, no endpoint, no rate limiting, no spend cap, no deploy
target — none of it has a job to do.

Phase 4 keeps its number so existing references stay valid. Do not re-add this phase without
first re-running `make audit`; if a future policy needs a network call, that is the signal.

---

## Phase 4 — Polish & ship — partially done

- [x] **Privacy statement next to the free-text box.** Phrased as the structural fact it is,
      not a retention promise: "Your text never leaves this browser. There is no server to
      send it to — open the network tab and watch."
- [x] **One global "ran locally" line above the results**, not a per-result badge. With no
      server-side path there is nothing to contrast against, and a badge on every row would
      imply a distinction that no longer exists.
- [ ] **Cold-load on mobile.** Not yet tested on a real device. The ~7 MB runtime download is
      the whole risk here, and it is the one number that a desktop measurement does not
      predict. `DemoSection` already defers the download until the demo scrolls into view, so
      a visitor who never reaches it pays nothing.
- [x] **Linked from the OpenScript README** — "Try It in Your Browser", above the install
      instructions.
- [ ] **Linked from the portfolio**, and deployed. The export is a directory of static files
      (`make demo-build` → `site/out/`), so any static host will serve it; no host has been
      chosen yet, so there is no public URL to link.

## Open Questions Before Starting

- ~~Does any of the 8 policies actually require an external LLM call today?~~ **Answered: no. All 8 are local heuristics.** See Phase 0 above.
- ~~Is there an existing wheel/build pipeline for the package?~~ **Answered: yes, but it was broken** — `include = ["sdk", ...]` shipped a wheel containing only `sdk/__init__.py` and `sdk/logging.py`, and `pydantic>=2.12` is unsatisfiable under Pyodide. Both fixed in Phase 1; see `base/directive/p0-1.md` §1.1.