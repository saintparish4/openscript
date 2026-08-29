"""The demo may ship client-side only for as long as every built-in policy
stays free of network calls and heavy runtime dependencies.

If a policy ever grows an LLM call, these tests fail and a backend comes back
onto the roadmap. That is the point: shipping without one is only safe while
its premise holds, so the premise is enforced rather than assumed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from policy_audit import ALLOWED_RUNTIME_DEPS, audit  # noqa: E402

# The exact set of policies the demo claims to run in the browser.
EXPECTED_POLICIES = {
    "prompt_injection",
    "toxicity",
    "harmful_request",
    "pii",
    "secrets",
    "compliance",
    "tool_firewall",
    "output_schema",
    "audit",
}

# Everything `import sdk` must survive without. If one of these becomes a real
# import-time dependency, the Pyodide build breaks.
FORBIDDEN_AT_IMPORT = [
    "sqlalchemy",
    "redis",
    "sentence_transformers",
    "prometheus_client",
    "opentelemetry",
    "fastapi",
    "asyncpg",
    "httpx",
    "uvicorn",
    "alembic",
]


def test_registry_has_exactly_the_nine_audited_policies():
    found = {r["policy"] for r in audit()}
    assert found == EXPECTED_POLICIES, (
        f"policy registry changed: added={found - EXPECTED_POLICIES}, "
        f"removed={EXPECTED_POLICIES - found}. Re-run the policy audit."
    )


@pytest.mark.parametrize("row", audit(), ids=lambda r: r["policy"])
def test_policy_makes_no_network_call(row):
    assert not row["network_markers"], (
        f"{row['policy']} ({row['module']}) references {row['network_markers']}. "
        "A policy that reaches the network cannot run client-side."
    )


@pytest.mark.parametrize("row", audit(), ids=lambda r: r["policy"])
def test_policy_imports_only_pyodide_available_deps(row):
    assert not row["disallowed_top_level"], (
        f"{row['policy']} imports {row['disallowed_top_level']} at module scope. "
        f"Only {sorted(ALLOWED_RUNTIME_DEPS)} are available in the browser build. "
        "Move it inside the function that needs it, or drop it."
    )


def test_import_sdk_without_any_heavy_dependency():
    """Runs in a subprocess so the guard applies to a cold interpreter."""
    blocked = repr(set(FORBIDDEN_AT_IMPORT))
    script = f"""
import builtins, sys
blocked = {blocked}
_real = builtins.__import__
def guard(name, *a, **k):
    if name.split(".")[0] in blocked:
        raise ImportError("BLOCKED at import time: " + name)
    return _real(name, *a, **k)
builtins.__import__ = guard

import sdk
required = [
    "PIIPolicy", "SecretsPolicy", "PromptInjectionPolicy", "ToxicityPolicy",
    "HarmfulRequestPolicy", "CompliancePolicy", "ToolFirewallPolicy",
    "OutputSchemaPolicy", "AuditPolicy", "SecureAgent", "RiskScorer", "load_policies",
]
missing = [n for n in required if not hasattr(sdk, n)]
assert not missing, missing
print("OK")
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "`import sdk` pulled in a dependency Pyodide cannot provide:\n" + proc.stderr
    )
    assert "OK" in proc.stdout
