"""Regenerate the policy audit table.

Usage:  python tools/policy_audit.py            # markdown table to stdout
        python tools/policy_audit.py --json     # machine-readable

Reports, per registered policy: the module it lives in, whether importing it
pulls in anything outside the pure-local dependency set, and whether its module
source mentions a network client.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sdk.policies.config import _REGISTRY  # noqa: E402

# Third-party packages a pure local policy is allowed to import at module scope
ALLOWED_RUNTIME_DEPS = {"pydantic", "structlog", "yaml", "annotated_types", "typing_extensions"}

# Anything that could reach the network. A hit here means the policy is no
# longer pure-local and the demo needs a backend after all.
NETWORK_MARKERS = {
    "httpx",
    "requests",
    "aiohttp",
    "urllib",
    "urllib3",
    "http",
    "socket",
    "openai",
    "anthropic",
    "cohere",
    "google",
    "boto3",
    "botocore",
}

# Optional heavyweights that are legal ONLY behind a function-local import.
LAZY_ONLY = {"sentence_transformers", "prometheus_client", "opentelemetry", "redis", "sqlalchemy"}

# The concrete module each registry entry's policy class lives in.
_POLICY_MODULES = {
    "prompt_injection": "sdk/interceptors/threat.py",
    "toxicity": "sdk/policies/toxicity.py",
    "pii": "sdk/interceptors/pii.py",
    "secrets": "sdk/policies/secrets.py",
    "compliance": "sdk/policies/compliance.py",
    "tool_firewall": "sdk/policies/tool_firewall.py",
    "output_schema": "sdk/policies/output_schema.py",
    "audit": "sdk/interceptors/event_writer.py",
}


def top_level_imports(path: Path) -> set[str]:
    """Roots of every import at module scope (function-local imports excluded)."""
    tree = ast.parse(path.read_text())
    roots: set[str] = set()
    for node in tree.body:  # module scope only
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
        elif isinstance(node, ast.If):  # `if TYPE_CHECKING:` blocks
            for sub in ast.walk(node):
                if isinstance(sub, ast.ImportFrom) and sub.module:
                    roots.add(sub.module.split(".")[0])
    return roots


def lazy_imports(path: Path) -> set[str]:
    """Roots of imports nested inside a function or class body."""
    tree = ast.parse(path.read_text())
    roots: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Import):
                roots.update(a.name.split(".")[0] for a in sub.names)
            elif isinstance(sub, ast.ImportFrom) and sub.module:
                roots.add(sub.module.split(".")[0])
    return roots


def audit() -> list[dict]:
    rows = []
    first_party = {"sdk", "contracts", "events"}
    for name in sorted(_REGISTRY):
        if name == "noop":
            continue
        target = _POLICY_MODULES[name]
        path = REPO_ROOT / target
        top = top_level_imports(path)
        lazy = lazy_imports(path)
        external_top = {m for m in top if m not in sys.stdlib_module_names and m not in first_party}
        rows.append(
            {
                "policy": name,
                "module": target,
                "top_level_third_party": sorted(external_top),
                "disallowed_top_level": sorted(external_top - ALLOWED_RUNTIME_DEPS),
                "network_markers": sorted((top | lazy) & NETWORK_MARKERS),
                "lazy_heavy": sorted(lazy & LAZY_ONLY),
                "pure_local": not (external_top - ALLOWED_RUNTIME_DEPS)
                and not ((top | lazy) & NETWORK_MARKERS),
            }
        )
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rows = audit()

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0 if all(r["pure_local"] for r in rows) else 1

    print(
        "| Policy | Module | Pure local? | External call? | Third-party imports | Lazy heavy deps |"
    )
    print("|---|---|---|---|---|---|")
    for r in rows:
        print(
            f"| `{r['policy']}` | `{r['module']}` | "
            f"{'**Yes**' if r['pure_local'] else '**NO**'} | "
            f"{'No' if not r['network_markers'] else '**YES: ' + ', '.join(r['network_markers']) + '**'} | "
            f"{', '.join(r['top_level_third_party']) or '—'} | "
            f"{', '.join(r['lazy_heavy']) or '—'} |"
        )
    impure = [r["policy"] for r in rows if not r["pure_local"]]
    print()
    if impure:
        print(
            f"**{len(impure)} policy/policies are NOT pure-local: {impure}. Phase 3 is required.**"
        )
        return 1
    print(f"**All {len(rows)} policies are pure-local. Phase 3 is not required.**")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
