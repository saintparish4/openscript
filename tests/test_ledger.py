"""The effect side: a token from a person's approval, checked where the effect happens.

PROTOCOL-ledger.md under evals/agentdojo froze the design. These tests are its
evidence. Each one counts what the ledger applied, not what the wrapper says
it let run.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import urllib.error
import urllib.request
from typing import Any

import pytest

from contracts.types import ActionBlockedError
from evals.ledger import (
    DOMAIN,
    Ledger,
    LedgerRefused,
    ServiceProcess,
    TokenClass,
    call_hash,
)
from events.approvals import InMemoryApprovalStore
from sdk import SecureTool, ToolFirewallPolicy, ToolRules

PAY = {"recipient": "acct-7", "amount": 500}


def test_a_token_buys_its_own_call_once():
    ledger = Ledger()
    token = ledger.mint("a1", call_hash("send_money", PAY))
    assert ledger.check("send_money", PAY, token).applied
    again = ledger.check("send_money", PAY, token)
    assert (again.token, again.applied) == (TokenClass.SPENT, False)


@pytest.mark.parametrize(
    ("args", "kind"),
    [
        ({"recipient": "acct-7", "amount": 5000}, TokenClass.OTHER_CALL),
        ({"recipient": "attacker", "amount": 500}, TokenClass.OTHER_CALL),
        ({"recipient": "acct-7", "amount": "500"}, TokenClass.OTHER_CALL),
    ],
)
def test_a_token_for_one_call_does_not_buy_another(args: dict[str, Any], kind: TokenClass):
    ledger = Ledger()
    token = ledger.mint("a1", call_hash("send_money", PAY))
    entry = ledger.check("send_money", args, token)
    assert (entry.token, entry.applied) == (kind, False)
    # Nor another tool with the same arguments.
    assert ledger.check("schedule_transaction", PAY, token).token is TokenClass.OTHER_CALL


def test_no_token_and_a_forged_token_are_refused_and_written_down():
    ledger = Ledger()
    ledger.mint("a1", call_hash("send_money", PAY))
    guessed = hmac.new(secrets.token_bytes(32), DOMAIN + b"a1|x", hashlib.sha256).hexdigest()
    for token, kind in (
        (None, TokenClass.NONE),
        (f"a1.{guessed}", TokenClass.FORGED),
        ("never-minted.00", TokenClass.FORGED),
        ("garbage", TokenClass.FORGED),
    ):
        entry = ledger.check("send_money", PAY, token)
        assert (entry.token, entry.applied) == (kind, False)
    assert [e.applied for e in ledger.entries] == [False] * 4


def test_record_mode_applies_everything_and_still_says_what_came_with_it():
    ledger = Ledger(mode="record")
    entry = ledger.check("send_money", PAY, None, origin="injection")
    assert (entry.token, entry.applied, entry.origin) == (TokenClass.NONE, True, "injection")


def test_the_authority_mints_once_per_approval():
    ledger = Ledger()
    ledger.mint("a1", call_hash("send_money", PAY))
    with pytest.raises(ValueError, match="already minted"):
        ledger.mint("a1", call_hash("send_money", {**PAY, "amount": 1}))


# -- with SecureTool in front: the person's yes reaches the effect, nothing else does ----


def _guarded_bank(
    ledger: Ledger,
) -> tuple[SecureTool, InMemoryApprovalStore, dict[str, str], list[Any]]:
    """A send_money whose effect is behind the ledger, wrapped as an agent gets it.

    *tokens* is where the person's side leaves a token for the call it
    approved. The tool looks up its own call there, which is harmless for an
    agent to read: a token buys only the call a person approved, once.
    """
    store = InMemoryApprovalStore()
    tokens: dict[str, str] = {}
    applied: list[Any] = []

    def send_money(recipient: str, amount: int) -> str:
        args = {"recipient": recipient, "amount": amount}
        entry = ledger.check("send_money", args, tokens.pop(call_hash("send_money", args), None))
        if not entry.applied:
            raise LedgerRefused(entry)
        applied.append(args)
        return "sent"

    rules = ToolRules.model_validate({"rules": {"send_money": {"requires_approval": True}}})
    tool = SecureTool(send_money, [ToolFirewallPolicy(rules=rules)], approval_store=store)
    return tool, store, tokens, applied


async def _approve(
    store: InMemoryApprovalStore, ledger: Ledger, tokens: dict[str, str], approval_id: str
) -> None:
    """What a person's yes does: decide the record, and have the authority mint."""
    record = await store.get(approval_id)
    assert record is not None
    await store.decide(approval_id, approved=True, decided_by="dana")
    tokens[record.action_hash] = ledger.mint(approval_id, record.action_hash)


async def test_an_approved_call_through_the_wrapper_is_applied_once():
    ledger = Ledger()
    send, store, tokens, applied = _guarded_bank(ledger)
    with pytest.raises(ActionBlockedError) as held:
        await send.call(PAY)
    await _approve(store, ledger, tokens, held.value.approval_id)
    assert await send.call(PAY, approval_id=held.value.approval_id) == "sent"
    assert applied == [PAY]
    assert [(e.token, e.applied) for e in ledger.entries] == [(TokenClass.VALID, True)]


async def test_going_round_the_wrapper_reaches_the_effect_side_and_is_refused():
    """Row S2 of the threat model: the function under the wrapper is one
    attribute away. The effect side refuses it, and the ledger says so."""
    ledger = Ledger()
    send, _store, _tokens, applied = _guarded_bank(ledger)
    with pytest.raises(LedgerRefused):
        send.__wrapped__(**PAY)
    assert applied == []
    assert [(e.token, e.applied) for e in ledger.entries] == [(TokenClass.NONE, False)]


async def test_a_token_lifted_for_an_approved_call_cannot_pay_more_or_elsewhere():
    ledger = Ledger()
    send, store, tokens, applied = _guarded_bank(ledger)
    with pytest.raises(ActionBlockedError) as held:
        await send.call(PAY)
    await _approve(store, ledger, tokens, held.value.approval_id)
    stolen = next(iter(tokens.values()))
    for args in ({**PAY, "amount": 5000}, {**PAY, "recipient": "attacker"}):
        entry = ledger.check("send_money", args, stolen)
        assert (entry.token, entry.applied) == (TokenClass.OTHER_CALL, False)
    # The approved call still goes through once, and then the token is spent.
    assert await send.call(PAY, approval_id=held.value.approval_id) == "sent"
    assert ledger.check("send_money", PAY, stolen).token is TokenClass.SPENT
    assert applied == [PAY]


# -- across a process boundary: the agent's process never holds the secret ------------


def test_a_separate_service_applies_only_what_its_person_approved():
    with ServiceProcess() as service:
        token = service.approve("a1", call_hash("send_money", PAY))
        assert service.effect("send_money", PAY, token).applied
        assert service.effect("send_money", PAY, token).token is TokenClass.SPENT
        assert service.effect("send_money", PAY).token is TokenClass.NONE
        # A token made with any key but the child's own is forged.
        mac = hmac.new(
            secrets.token_bytes(32),
            DOMAIN + b"a2|" + call_hash("send_money", PAY).encode(),
            hashlib.sha256,
        ).hexdigest()
        assert service.effect("send_money", PAY, f"a2.{mac}").token is TokenClass.FORGED
        listed = service.entries()
    assert [(e["token"], e["applied"]) for e in listed] == [
        ("valid", True),
        ("spent", False),
        ("none", False),
        ("forged", False),
    ]


def test_the_agents_side_of_the_service_has_no_way_to_mint():
    with ServiceProcess() as service:
        for path in ("/approve", "/mint", "/token"):
            request = urllib.request.Request(
                service.url + path,
                data=json.dumps({"approve": "a1", "hash": call_hash("send_money", PAY)}).encode(),
            )
            with pytest.raises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(request, timeout=10)
            assert refused.value.code == 404
        assert service.entries() == []
