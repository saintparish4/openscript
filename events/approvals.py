from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Protocol

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_TTL_SECONDS = 3600  # approvals expire back to blocked after 1h


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


def action_hash(action: str, input_data: dict[str, Any]) -> str:
    """Canonical fingerprint of (action, input) for approval binding.

    An approval is redeemable only against the exact action it was requested
    for — a matching hash proves the retried call carries the same action
    name and input/args, so a granted approval can't be replayed against a
    different tool call.
    """
    canonical = json.dumps(
        {"action": action, "input_data": input_data}, sort_keys=True, default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _new_expiry(ttl_seconds: int = DEFAULT_TTL_SECONDS) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=ttl_seconds)


@dataclass
class ApprovalRecord:
    session_id: str
    agent_id: str
    action: str
    reason: str
    action_hash: str
    approval_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = field(default_factory=_new_expiry)
    decided_by: str = ""

    @property
    def expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["expires_at"] = self.expires_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalRecord:
        return cls(
            session_id=data["session_id"],
            agent_id=data["agent_id"],
            action=data["action"],
            reason=data["reason"],
            action_hash=data["action_hash"],
            approval_id=data["approval_id"],
            status=ApprovalStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            decided_by=data.get("decided_by", ""),
        )


class ApprovalStore(Protocol):
    """Storage for pending/decided approval records.

    Expired records behave as denied everywhere: they drop out of
    list_pending, can no longer be decided, and never redeem.
    """

    async def create(self, record: ApprovalRecord) -> None: ...

    async def get(self, approval_id: str) -> ApprovalRecord | None: ...

    async def list_pending(self) -> list[ApprovalRecord]: ...

    async def decide(
        self, approval_id: str, approved: bool, decided_by: str = ""
    ) -> ApprovalRecord | None:
        """Resolve a pending record. Returns the updated record, or None when
        the id is unknown. Raises ValueError when the record is no longer
        pending (already decided or expired)."""
        ...

    async def consume(self, approval_id: str, expected_hash: str) -> bool:
        """Single-use redemption: True iff the record exists, is approved,
        is not expired, and its action_hash matches — the record is deleted
        so it can never redeem twice."""
        ...


class InMemoryApprovalStore:
    """Dict-backed store for SINGLE-PROCESS use and tests only.

    SecureAgent runs in the caller's process while /v1/approvals runs in the
    server — an in-memory store is never visible to both. Use
    RedisApprovalStore whenever approvals are decided over the HTTP API.
    """

    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}

    async def create(self, record: ApprovalRecord) -> None:
        self._records[record.approval_id] = replace(record)

    async def get(self, approval_id: str) -> ApprovalRecord | None:
        record = self._records.get(approval_id)
        return replace(record) if record is not None else None

    async def list_pending(self) -> list[ApprovalRecord]:
        self._purge_expired()
        return [replace(r) for r in self._records.values() if r.status == ApprovalStatus.PENDING]

    async def decide(
        self, approval_id: str, approved: bool, decided_by: str = ""
    ) -> ApprovalRecord | None:
        record = self._records.get(approval_id)
        if record is None:
            return None
        if record.status != ApprovalStatus.PENDING or record.expired:
            raise ValueError(f"approval '{approval_id}' is not pending")
        record.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        record.decided_by = decided_by
        return replace(record)

    async def consume(self, approval_id: str, expected_hash: str) -> bool:
        record = self._records.get(approval_id)
        if (
            record is None
            or record.status != ApprovalStatus.APPROVED
            or record.expired
            or record.action_hash != expected_hash
        ):
            return False
        del self._records[approval_id]
        return True

    def _purge_expired(self) -> None:
        expired = [aid for aid, r in self._records.items() if r.expired]
        for aid in expired:
            del self._records[aid]


class RedisApprovalStore:
    """Redis-backed store — required whenever SecureAgent and the server run
    in separate processes (i.e. any real deployment of the approvals API).

    Records live at {prefix}:{approval_id} as JSON with a Redis TTL matching
    expires_at; pending ids are tracked in the {prefix}:pending set. Single-use
    redemption relies on DELETE's atomicity: only the caller whose DELETE
    returns 1 wins a concurrent redeem race.
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        *,
        key_prefix: str = "openscript:approval",
    ) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(url, decode_responses=True)
        self._prefix = key_prefix
        self._pending_key = f"{key_prefix}:pending"

    def _key(self, approval_id: str) -> str:
        return f"{self._prefix}:{approval_id}"

    @staticmethod
    def _ttl_seconds(record: ApprovalRecord) -> int:
        return max(1, int((record.expires_at - datetime.now(UTC)).total_seconds()))

    async def create(self, record: ApprovalRecord) -> None:
        await self._redis.set(
            self._key(record.approval_id),
            json.dumps(record.to_dict()),
            ex=self._ttl_seconds(record),
        )
        await self._redis.sadd(self._pending_key, record.approval_id)

    async def get(self, approval_id: str) -> ApprovalRecord | None:
        raw = await self._redis.get(self._key(approval_id))
        return ApprovalRecord.from_dict(json.loads(raw)) if raw else None

    async def list_pending(self) -> list[ApprovalRecord]:
        pending: list[ApprovalRecord] = []
        for approval_id in await self._redis.smembers(self._pending_key):
            record = await self.get(approval_id)
            if record is None or record.status != ApprovalStatus.PENDING:
                # expired (key TTL fired) or already decided — clean the set
                await self._redis.srem(self._pending_key, approval_id)
                continue
            pending.append(record)
        return pending

    async def decide(
        self, approval_id: str, approved: bool, decided_by: str = ""
    ) -> ApprovalRecord | None:
        record = await self.get(approval_id)
        if record is None:
            return None
        if record.status != ApprovalStatus.PENDING or record.expired:
            raise ValueError(f"approval '{approval_id}' is not pending")
        record.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        record.decided_by = decided_by
        await self._redis.set(
            self._key(approval_id),
            json.dumps(record.to_dict()),
            ex=self._ttl_seconds(record),
        )
        await self._redis.srem(self._pending_key, approval_id)
        return record

    async def consume(self, approval_id: str, expected_hash: str) -> bool:
        record = await self.get(approval_id)
        if (
            record is None
            or record.status != ApprovalStatus.APPROVED
            or record.expired
            or record.action_hash != expected_hash
        ):
            return False
        # DELETE returning 1 is the atomic single-use gate under concurrency
        return await self._redis.delete(self._key(approval_id)) == 1
