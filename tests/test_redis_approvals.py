"""RedisApprovalStore, against a real Redis.

This is the store the README says is required once approvals are decided
somewhere other than the process that asked for them — and until this file it
was the one approval store with no test at all. A fake would not do: the claims
worth checking are about what happens when two clients reach the same record at
the same moment, and only a real server on the other end of real connections
makes that happen.

    docker compose up -d redis
    OPENSCRIPT_TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/test_redis_approvals.py

Without that variable the tests skip. In CI they must not: see the first test.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timedelta
from typing import Any

import pytest

from contracts.types import ActionBlockedError
from events.approvals import ApprovalRecord, ApprovalStatus, RedisApprovalStore, action_hash
from sdk import SecureTool, ToolFirewallPolicy, ToolRules

URL = os.environ.get("OPENSCRIPT_TEST_REDIS_URL", "")
HASH = action_hash("tool_call", {"name": "send", "args": {"to": "alice"}})


def test_ci_does_not_skip_this_file():
    """A skipped test proves nothing, and a skip is easy to miss in a green run."""
    if os.environ.get("CI") and not URL:
        pytest.fail("CI has no OPENSCRIPT_TEST_REDIS_URL, so the Redis store is not being tested")


@pytest.fixture
async def connect() -> AsyncIterator[Callable[[], RedisApprovalStore]]:
    """Hands out stores that share a key prefix and nothing else.

    Each has its own client and its own connections, which is what two
    processes look like from Redis's side.
    """
    if not URL:
        pytest.skip("set OPENSCRIPT_TEST_REDIS_URL to run against a real Redis")
    prefix = f"openscript:test:{uuid.uuid4().hex}"
    made: list[RedisApprovalStore] = []

    def make() -> RedisApprovalStore:
        store = RedisApprovalStore(URL, key_prefix=prefix)
        made.append(store)
        return store

    janitor = make()
    try:
        await janitor._redis.ping()
    except Exception as exc:  # the variable was set, so this is a failure, not a skip
        pytest.fail(f"OPENSCRIPT_TEST_REDIS_URL={URL!r} but Redis did not answer: {exc}")

    yield make

    async for key in janitor._redis.scan_iter(f"{prefix}:*"):
        await janitor._redis.delete(key)
    for store in made:
        await store._redis.aclose()


def _record(**overrides: Any) -> ApprovalRecord:
    fields: dict[str, Any] = {
        "session_id": "s1",
        "agent_id": "agent",
        "action": "tool_call",
        "reason": "tool 'send' requires manual review",
        "action_hash": HASH,
    }
    return ApprovalRecord(**{**fields, **overrides})


def _in(seconds: float) -> datetime:
    # Aware, in whatever zone this machine is in: the store compares instants,
    # so the zone does not matter and the test should not care which it is.
    return datetime.now().astimezone() + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# One client
# ---------------------------------------------------------------------------


async def test_a_record_written_by_one_client_is_read_by_another(connect):
    writer, reader = connect(), connect()
    record = _record()
    await writer.create(record)

    seen = await reader.get(record.approval_id)
    assert seen is not None
    assert seen.to_dict() == record.to_dict()
    assert [r.approval_id for r in await reader.list_pending()] == [record.approval_id]


async def test_unknown_ids(connect):
    store = connect()
    assert await store.get("nope") is None
    assert await store.decide("nope", approved=True) is None
    assert await store.consume("nope", HASH) is False


async def test_a_decided_record_leaves_the_pending_list(connect):
    store = connect()
    waiting, approved, denied = _record(), _record(), _record()
    for record in (waiting, approved, denied):
        await store.create(record)
    await store.decide(approved.approval_id, approved=True, decided_by="ops")
    await store.decide(denied.approval_id, approved=False, decided_by="ops")

    assert [r.approval_id for r in await store.list_pending()] == [waiting.approval_id]
    decided = await store.get(approved.approval_id)
    assert decided is not None
    assert (decided.status, decided.decided_by) == (ApprovalStatus.APPROVED, "ops")


async def test_a_decision_cannot_be_made_twice(connect):
    store = connect()
    record = _record()
    await store.create(record)
    await store.decide(record.approval_id, approved=False)
    with pytest.raises(ValueError, match="not pending"):
        await store.decide(record.approval_id, approved=True)
    still = await store.get(record.approval_id)
    assert still is not None and still.status == ApprovalStatus.DENIED


async def test_redis_itself_drops_the_record_when_it_expires(connect):
    """The TTL is on the key, so nothing has to remember to clean up."""
    store = connect()
    record = _record(expires_at=_in(1))
    await store.create(record)
    assert await store.get(record.approval_id) is not None

    await asyncio.sleep(1.5)
    assert await store.get(record.approval_id) is None
    assert await store.list_pending() == []
    assert await store._redis.smembers(f"{store._prefix}:pending") == set()
    assert await store.decide(record.approval_id, approved=True) is None


async def test_an_expired_record_is_refused_even_while_its_key_still_exists(connect):
    store = connect()
    record = _record(expires_at=_in(-5), status=ApprovalStatus.APPROVED)
    await store.create(record)
    assert await store.get(record.approval_id) is not None  # the key outlives it by a second
    assert await store.consume(record.approval_id, HASH) is False

    late = _record(expires_at=_in(-5))
    await store.create(late)
    with pytest.raises(ValueError, match="not pending"):
        await store.decide(late.approval_id, approved=True)


# ---------------------------------------------------------------------------
# Redeeming
# ---------------------------------------------------------------------------


async def test_only_an_approved_record_redeems_and_only_once(connect):
    store = connect()
    record = _record()
    await store.create(record)
    assert await store.consume(record.approval_id, HASH) is False  # still pending

    await store.decide(record.approval_id, approved=True)
    assert await store.consume(record.approval_id, HASH) is True
    assert await store.consume(record.approval_id, HASH) is False
    assert await store.get(record.approval_id) is None


async def test_a_denied_record_never_redeems(connect):
    store = connect()
    record = _record()
    await store.create(record)
    await store.decide(record.approval_id, approved=False)
    assert await store.consume(record.approval_id, HASH) is False


async def test_the_wrong_call_does_not_redeem_and_does_not_spend_it(connect):
    store = connect()
    record = _record()
    await store.create(record)
    await store.decide(record.approval_id, approved=True)

    other = action_hash("tool_call", {"name": "send", "args": {"to": "mallory"}})
    assert await store.consume(record.approval_id, other) is False
    assert await store.consume(record.approval_id, HASH) is True


# ---------------------------------------------------------------------------
# Two clients at once
# ---------------------------------------------------------------------------


async def test_twenty_clients_redeeming_at_once_spend_it_once(connect):
    record = _record()
    first = connect()
    await first.create(record)
    await first.decide(record.approval_id, approved=True)

    clients = [connect() for _ in range(20)]
    results = await asyncio.gather(*(c.consume(record.approval_id, HASH) for c in clients))
    assert results.count(True) == 1


async def test_two_people_deciding_at_once_do_not_both_succeed(connect):
    """Ten approvers, half saying yes and half saying no, on separate connections."""
    record = _record()
    await connect().create(record)

    async def decide(store: RedisApprovalStore, approved: bool) -> bool | None:
        try:
            await store.decide(record.approval_id, approved=approved, decided_by=str(approved))
        except ValueError:
            return None
        return approved

    clients = [connect() for _ in range(10)]
    outcomes = await asyncio.gather(*(decide(c, i % 2 == 0) for i, c in enumerate(clients)))
    winners = [o for o in outcomes if o is not None]

    assert len(winners) == 1, f"{len(winners)} approvers were each told their decision stood"
    final = await clients[0].get(record.approval_id)
    assert final is not None
    assert final.status == (ApprovalStatus.APPROVED if winners[0] else ApprovalStatus.DENIED)
    assert final.decided_by == str(winners[0])


# ---------------------------------------------------------------------------
# The reason the store exists: asked for in one place, decided in another
# ---------------------------------------------------------------------------


async def test_a_tool_held_in_one_process_is_released_by_a_decision_in_another(connect):
    agent_side, server_side = connect(), connect()
    sent: list[str] = []

    async def send(to: str) -> str:
        sent.append(to)
        return f"sent to {to}"

    rules = ToolRules.model_validate({"rules": {"send": {"requires_approval": True}}})
    tool = SecureTool(send, [ToolFirewallPolicy(rules=rules)], approval_store=agent_side)

    with pytest.raises(ActionBlockedError) as held:
        await tool.call({"to": "alice"})
    approval_id = held.value.approval_id
    assert sent == []

    # The server sees it in its own queue and a person approves it there.
    [pending] = await server_side.list_pending()
    assert pending.approval_id == approval_id
    await server_side.decide(approval_id, approved=True, decided_by="ops")

    # Not for a different recipient, and the attempt costs the approval nothing.
    with pytest.raises(ActionBlockedError):
        await tool.call({"to": "mallory"}, approval_id=approval_id)
    assert sent == []

    assert await tool.call({"to": "alice"}, approval_id=approval_id) == "sent to alice"
    with pytest.raises(ActionBlockedError):
        await tool.call({"to": "alice"}, approval_id=approval_id)
    assert sent == ["alice"]
