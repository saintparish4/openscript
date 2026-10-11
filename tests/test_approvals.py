from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionBlockedError, ActionContext, InterceptorDecision
from events.approvals import (
    ApprovalRecord,
    ApprovalStatus,
    InMemoryApprovalStore,
    action_hash,
)
from sdk.middleware.middleware import SecureAgent
from server.routers import approvals as approvals_router

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _record(**overrides: Any) -> ApprovalRecord:
    defaults: dict[str, Any] = {
        "session_id": "s1",
        "agent_id": "agent",
        "action": "invoke",
        "reason": "manual review required",
        "action_hash": action_hash("invoke", {"input": "hi"}),
    }
    defaults.update(overrides)
    return ApprovalRecord(**defaults)


class CountingAgent:
    def __init__(self) -> None:
        self.calls = 0

    async def ainvoke(self, input_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return {"output": "done"}


class BeforeGatePolicy(BasePolicy):
    """Requires approval for every action in before_action."""

    async def before_action(self, context: ActionContext) -> ActionContext:
        context.decision = InterceptorDecision.REQUIRE_APPROVAL
        context.decision_reason = "manual review required"
        return context


class AfterGatePolicy(BasePolicy):
    """Requires approval for every action in after_action."""

    async def after_action(self, context: ActionContext) -> ActionContext:
        context.decision = InterceptorDecision.REQUIRE_APPROVAL
        context.decision_reason = "output review required"
        return context


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def write(self, event: Event) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# action_hash
# ---------------------------------------------------------------------------


def test_action_hash_is_deterministic():
    assert action_hash("invoke", {"a": 1, "b": 2}) == action_hash("invoke", {"b": 2, "a": 1})


def test_action_hash_differs_on_args_and_action():
    base = action_hash("invoke", {"amount": 100})
    assert action_hash("invoke", {"amount": 999}) != base
    assert action_hash("stream", {"amount": 100}) != base


# ---------------------------------------------------------------------------
# InMemoryApprovalStore
# ---------------------------------------------------------------------------


async def test_create_get_roundtrip():
    store = InMemoryApprovalStore()
    record = _record()
    await store.create(record)

    fetched = await store.get(record.approval_id)

    assert fetched is not None
    assert fetched.status == ApprovalStatus.PENDING
    assert fetched.action_hash == record.action_hash
    assert await store.get("nope") is None


async def test_list_pending_excludes_decided_and_expired():
    store = InMemoryApprovalStore()
    pending = _record()
    decided = _record()
    expired = _record(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    for r in (pending, decided, expired):
        await store.create(r)
    await store.decide(decided.approval_id, approved=True)

    listed = await store.list_pending()

    assert [r.approval_id for r in listed] == [pending.approval_id]


async def test_decide_unknown_returns_none():
    store = InMemoryApprovalStore()
    assert await store.decide("nope", approved=True) is None


async def test_decide_twice_raises():
    store = InMemoryApprovalStore()
    record = _record()
    await store.create(record)
    await store.decide(record.approval_id, approved=True)

    with pytest.raises(ValueError, match="not pending"):
        await store.decide(record.approval_id, approved=False)


async def test_decide_expired_raises():
    store = InMemoryApprovalStore()
    record = _record(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    await store.create(record)

    with pytest.raises(ValueError, match="not pending"):
        await store.decide(record.approval_id, approved=True)


async def test_consume_requires_approved_status():
    store = InMemoryApprovalStore()
    record = _record()
    await store.create(record)

    assert await store.consume(record.approval_id, record.action_hash) is False  # pending

    await store.decide(record.approval_id, approved=True)
    assert await store.consume(record.approval_id, record.action_hash) is True
    assert await store.consume(record.approval_id, record.action_hash) is False  # single-use


async def test_consume_rejects_wrong_hash_without_burning_record():
    store = InMemoryApprovalStore()
    record = _record()
    await store.create(record)
    await store.decide(record.approval_id, approved=True)

    assert await store.consume(record.approval_id, "wrong-hash") is False
    # record survives a mismatched attempt and still redeems for the right hash
    assert await store.consume(record.approval_id, record.action_hash) is True


async def test_consume_rejects_expired_approval():
    store = InMemoryApprovalStore()
    record = _record(expires_at=datetime.now(UTC) + timedelta(seconds=60))
    await store.create(record)
    await store.decide(record.approval_id, approved=True)
    store._records[record.approval_id].expires_at = datetime.now(UTC) - timedelta(seconds=1)

    assert await store.consume(record.approval_id, record.action_hash) is False


def test_record_dict_roundtrip():
    record = _record()
    assert ApprovalRecord.from_dict(record.to_dict()) == record


# ---------------------------------------------------------------------------
# SecureAgent — request / retry flow
# ---------------------------------------------------------------------------


async def test_require_approval_raises_with_approval_id():
    store = InMemoryApprovalStore()
    sa = SecureAgent(CountingAgent(), policies=[BeforeGatePolicy()], approval_store=store)

    with pytest.raises(ActionBlockedError) as excinfo:
        await sa.invoke({"input": "hi"})

    err = excinfo.value
    assert err.approval_id != ""
    assert err.interceptor == "BeforeGatePolicy"
    pending = await store.list_pending()
    assert [r.approval_id for r in pending] == [err.approval_id]
    assert pending[0].reason == "manual review required"


async def test_approved_retry_executes_action():
    store = InMemoryApprovalStore()
    agent = CountingAgent()
    sa = SecureAgent(agent, policies=[BeforeGatePolicy()], approval_store=store)

    with pytest.raises(ActionBlockedError) as excinfo:
        await sa.invoke({"input": "hi"})
    assert agent.calls == 0  # blocked before the agent ran

    await store.decide(excinfo.value.approval_id, approved=True, decided_by="alice")
    result = await sa.invoke({"input": "hi"}, approval_id=excinfo.value.approval_id)

    assert result == {"output": "done"}
    assert agent.calls == 1


async def test_approval_is_single_use():
    store = InMemoryApprovalStore()
    sa = SecureAgent(CountingAgent(), policies=[BeforeGatePolicy()], approval_store=store)

    with pytest.raises(ActionBlockedError) as first:
        await sa.invoke({"input": "hi"})
    await store.decide(first.value.approval_id, approved=True)
    await sa.invoke({"input": "hi"}, approval_id=first.value.approval_id)

    with pytest.raises(ActionBlockedError) as second:
        await sa.invoke({"input": "hi"}, approval_id=first.value.approval_id)

    assert second.value.approval_id != first.value.approval_id  # a fresh request


async def test_denied_approval_blocks_again():
    store = InMemoryApprovalStore()
    sa = SecureAgent(CountingAgent(), policies=[BeforeGatePolicy()], approval_store=store)

    with pytest.raises(ActionBlockedError) as excinfo:
        await sa.invoke({"input": "hi"})
    await store.decide(excinfo.value.approval_id, approved=False)

    with pytest.raises(ActionBlockedError):
        await sa.invoke({"input": "hi"}, approval_id=excinfo.value.approval_id)


async def test_approval_is_bound_to_the_exact_action():
    store = InMemoryApprovalStore()
    agent = CountingAgent()
    sa = SecureAgent(agent, policies=[BeforeGatePolicy()], approval_store=store)

    with pytest.raises(ActionBlockedError) as excinfo:
        await sa.invoke({"input": "transfer $100"})
    await store.decide(excinfo.value.approval_id, approved=True)

    # different input under the same approval id: blocked, record not burned
    with pytest.raises(ActionBlockedError):
        await sa.invoke({"input": "transfer $99999"}, approval_id=excinfo.value.approval_id)
    assert agent.calls == 0

    # the approved action itself still goes through
    await sa.invoke({"input": "transfer $100"}, approval_id=excinfo.value.approval_id)
    assert agent.calls == 1


async def test_approval_requested_event_emitted():
    writer = FakeWriter()
    sa = SecureAgent(CountingAgent(), policies=[BeforeGatePolicy()], writer=writer)

    with pytest.raises(ActionBlockedError) as excinfo:
        await sa.invoke({"input": "hi"}, session_id="s9")

    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.event_type == EventType.APPROVAL_REQUESTED
    assert event.session_id == "s9"
    assert event.payload["approval_id"] == excinfo.value.approval_id
    assert event.payload["interceptor"] == "BeforeGatePolicy"


async def test_after_phase_gate_blocks_and_retries():
    store = InMemoryApprovalStore()
    agent = CountingAgent()
    sa = SecureAgent(agent, policies=[AfterGatePolicy()], approval_store=store)

    with pytest.raises(ActionBlockedError) as excinfo:
        await sa.invoke({"input": "hi"})
    assert agent.calls == 1  # output-side gate: the agent had already run

    await store.decide(excinfo.value.approval_id, approved=True)
    result = await sa.invoke({"input": "hi"}, approval_id=excinfo.value.approval_id)

    assert result == {"output": "done"}
    assert agent.calls == 2  # retry re-executes the agent


async def test_single_approval_covers_before_and_after_gates():
    store = InMemoryApprovalStore()
    sa = SecureAgent(
        CountingAgent(),
        policies=[BeforeGatePolicy(), AfterGatePolicy()],
        approval_store=store,
    )

    with pytest.raises(ActionBlockedError) as excinfo:
        await sa.invoke({"input": "hi"})
    await store.decide(excinfo.value.approval_id, approved=True)

    result = await sa.invoke({"input": "hi"}, approval_id=excinfo.value.approval_id)

    assert result == {"output": "done"}


# ---------------------------------------------------------------------------
# /v1/approvals endpoints
# ---------------------------------------------------------------------------


class FakeEventStore:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def insert_events(self, events: list[Event]) -> None:
        self.events.extend(events)


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("OPENSCRIPT_API_KEY", "test-api-key")
    app = FastAPI()
    app.include_router(approvals_router.router)
    app.state.approval_store = InMemoryApprovalStore()
    app.state.event_store = FakeEventStore()
    client = TestClient(app)
    client.headers["X-API-KEY"] = "test-api-key"
    return client


def _seed(api: TestClient, record: ApprovalRecord) -> None:
    # direct dict insert — sync test, in-memory store
    api.app.state.approval_store._records[record.approval_id] = record


def test_endpoints_require_auth(api):
    assert api.get("/v1/approvals", headers={"X-API-KEY": "wrong"}).status_code == 401


def test_list_pending_endpoint(api):
    record = _record()
    _seed(api, record)

    resp = api.get("/v1/approvals")

    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["approvals"][0]["approval_id"] == record.approval_id


def test_decide_endpoint_resolves_and_emits_event(api):
    record = _record()
    _seed(api, record)

    resp = api.post(
        f"/v1/approvals/{record.approval_id}/decide",
        json={"approved": True, "decided_by": "alice"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    assert resp.json()["decided_by"] == "alice"
    events = api.app.state.event_store.events
    assert len(events) == 1
    assert events[0].event_type == EventType.APPROVAL_RESOLVED
    assert events[0].payload["approval_id"] == record.approval_id


def test_decide_unknown_returns_404(api):
    resp = api.post("/v1/approvals/nope/decide", json={"approved": True})
    assert resp.status_code == 404


def test_decide_twice_returns_409(api):
    record = _record()
    _seed(api, record)
    first = api.post(f"/v1/approvals/{record.approval_id}/decide", json={"approved": True})
    assert first.status_code == 200

    second = api.post(f"/v1/approvals/{record.approval_id}/decide", json={"approved": False})
    assert second.status_code == 409
