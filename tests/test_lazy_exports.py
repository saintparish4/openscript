"""sdk and contracts export lazily: a name's module is imported when the name is.

So `import sdk` is nearly free, and `from sdk import ToolFirewallPolicy` costs
that policy and what it imports, not all ten. What has to hold: every exported
name still resolves, to the same object as before, and asking for nothing
imports nothing heavy.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import contracts
import sdk

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("package", [sdk, contracts], ids=lambda p: p.__name__)
def test_every_exported_name_resolves(package):
    for name in package.__all__:
        assert getattr(package, name) is not None, name
    assert set(package.__all__) <= set(dir(package))


def test_a_name_resolves_to_the_object_in_its_module():
    from sdk.policies.session_taint import SessionTaintPolicy
    from sdk.policies.tool_firewall import validate_tool_call

    assert sdk.SessionTaintPolicy is SessionTaintPolicy
    assert sdk.validate_tool_call is validate_tool_call
    from contracts.session_graph import NodeType

    assert contracts.NodeType is NodeType, "listed in __all__, and now importable too"


def test_a_name_it_does_not_export_is_an_attribute_error():
    with pytest.raises(AttributeError, match="no attribute 'NoSuchPolicy'"):
        sdk.NoSuchPolicy  # noqa: B018
    with pytest.raises(ImportError):
        from sdk import NoSuchPolicy  # noqa: F401


def test_importing_the_packages_alone_imports_nothing_heavy():
    script = (
        "import sys, sdk, contracts\n"
        "heavy = sorted(m for m in ('pydantic', 'structlog', 'yaml') if m in sys.modules)\n"
        "print(heavy)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "[]"
