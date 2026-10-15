"""The redaction helpers, held to what SecretsPolicy and PIIPolicy do with the same text.

They are the same code the policies run, moved where something with a string
and no pipeline can call it. These tests pin that the move changed nothing
and that the module keeps to the standard library.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from contracts.types import ActionContext
from sdk import find_pii, find_secrets, redact_data, redact_pii, redact_secrets
from sdk.interceptors.pii import PIIMode, PIIPolicy
from sdk.policies.secrets import SecretsPolicy

AWS = "AKIAIOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
SECRET_TEXT = f"deploy with {AWS} and {GITHUB}\n{PEM}\nthen ping localhost:8080"
PII_TEXT = "Mail bob@test.org or call 555-867-5309; SSN 987-65-4321; card 4111 1111 1111 1111"


def _ctx(output: str) -> ActionContext:
    return ActionContext(
        action="invoke",
        agent_id="agent",
        session_id="s1",
        input_data={"input": ""},
        output_data={"output": output},
    )


async def test_redact_secrets_masks_as_the_secrets_policy_does():
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    done = await policy.after_action(_ctx(SECRET_TEXT))
    text, labels = redact_secrets(SECRET_TEXT)
    assert text == done.output_data["output"]
    assert AWS not in text and GITHUB not in text and "MIIEow" not in text
    assert labels == ["private_key", "aws_access_key", "github_token"]


async def test_redact_pii_replaces_as_the_pii_policy_does():
    policy = PIIPolicy(mode=PIIMode.REDACT)
    done = await policy.after_action(_ctx(PII_TEXT))
    text, labels = redact_pii(PII_TEXT)
    assert text == done.output_data["output"]
    assert set(labels) == {"email", "phone", "ssn", "credit_card"}


def test_internal_urls_are_left_alone_unless_asked_for():
    assert "localhost:8080" in redact_secrets(SECRET_TEXT)[0]
    text, labels = redact_secrets(SECRET_TEXT, internal_urls=True)
    assert "localhost" not in text and "internal_url" in labels


def test_an_allowlisted_match_is_left_as_it_is():
    text, labels = redact_secrets(f"key {AWS}", allowlist=["iosfodnn7example"])
    assert AWS in text and labels == []


def test_redact_data_keeps_the_shape_and_reports_each_label_once():
    before = {
        "stdout": f"{AWS}\n{AWS}",
        "stderr": "",
        "interrupted": False,
        "lines": [f"token {GITHUB}", 3, None],
        "nested": {"mail": "bob@test.org"},
    }
    after, labels = redact_data(before)
    assert set(after) == set(before) and len(after["lines"]) == 3
    assert after["interrupted"] is False and after["lines"][1:] == [3, None]
    assert AWS not in after["stdout"] and GITHUB not in after["lines"][0]
    assert after["nested"]["mail"] == "bob@test.org", "PII is off unless asked for"
    assert labels == ["aws_access_key", "github_token"]
    after, labels = redact_data(before, pii=True)
    assert after["nested"]["mail"] == "[REDACTED:email]" and "email" in labels


def test_nothing_found_comes_back_unchanged():
    data = {"stdout": "all clean", "n": 1}
    assert redact_data(data) == (data, [])
    assert redact_secrets("plain prose") == ("plain prose", [])


def test_the_finders_report_what_the_redactors_remove():
    assert {label for _, label in find_secrets(SECRET_TEXT)} >= {"aws_access_key", "github_token"}
    assert ("4111 1111 1111 1111", "credit_card") in find_pii(PII_TEXT)
    assert not any(label == "credit_card" for _, label in find_pii("card 1234 5678 9012 3456"))


@pytest.mark.parametrize("path", ["sdk/policies/redaction.py"])
def test_the_module_imports_nothing_outside_the_standard_library(path):
    """Cheap to import on purpose: a hook pays for it on every tool call."""
    tree = ast.parse((Path(__file__).resolve().parents[1] / path).read_text())
    imported = {
        (node.module or "").split(".")[0] if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    assert imported <= {"__future__", "re", "collections", "dataclasses", "typing"}, imported
