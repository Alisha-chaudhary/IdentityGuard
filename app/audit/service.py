import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.db.models import AuditEvent


GENESIS_HASH = "0" * 64  # "previous hash" of the very first event


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def _compute_hash(
    prev_hash: str,
    *,
    timestamp: datetime,
    actor: str,
    event_type: str,
    target: str,
    action: str,
    result: str,
    reason: str,
    correlation_id: str,
) -> str:
    payload = json.dumps(
        {
            "timestamp": timestamp.isoformat(),
            "actor": actor,
            "event_type": event_type,
            "target": target,
            "action": action,
            "result": result,
            "reason": reason,
            "correlation_id": correlation_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(
        (prev_hash + payload).encode("utf-8")
    ).hexdigest()


def record_event(
    db: Session,
    *,
    actor: str,
    event_type: EventType | str,
    target: str,
    action: str,
    result: Result | str,
    reason: str = "",
    correlation_id: str | None = None,
) -> AuditEvent:
    """Append an audit event. Flushes but does NOT commit: the caller commits
    so the event lands in the same transaction as the change it describes."""
    event_type = getattr(event_type, "value", event_type)
    result = getattr(result, "value", result)

    prev_hash = (
        db.scalar(
            select(AuditEvent.event_hash)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        or GENESIS_HASH
    )

    timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
    correlation_id = correlation_id or new_correlation_id()

    event_hash = _compute_hash(
        prev_hash,
        timestamp=timestamp,
        actor=actor,
        event_type=event_type,
        target=target,
        action=action,
        result=result,
        reason=reason,
        correlation_id=correlation_id,
    )

    audit_event = AuditEvent(
        timestamp=timestamp,
        actor=actor,
        event_type=event_type,
        target=target,
        action=action,
        result=result,
        reason=reason,
        correlation_id=correlation_id,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )

    db.add(audit_event)
    db.flush()  # so the next event sees this one as "latest"

    return audit_event


@dataclass
class ChainVerification:
    ok: bool
    checked: int
    first_bad_id: int | None


def verify_chain(db: Session) -> ChainVerification:
    """Recompute every hash from the database and compare."""
    prev = GENESIS_HASH
    checked = 0

    rows = db.scalars(
        select(AuditEvent)
        .order_by(AuditEvent.id)
        .execution_options(populate_existing=True)
    )

    for ev in rows:
        expected = _compute_hash(
            prev,
            timestamp=ev.timestamp,
            actor=ev.actor,
            event_type=ev.event_type,
            target=ev.target,
            action=ev.action,
            result=ev.result,
            reason=ev.reason,
            correlation_id=ev.correlation_id,
        )

        if ev.prev_hash != prev or ev.event_hash != expected:
            return ChainVerification(False, checked, ev.id)

        prev = ev.event_hash
        checked += 1

    return ChainVerification(True, checked, None)


def list_events(
    db: Session,
    *,
    event_type: EventType | str | None = None,
    actor: str | None = None,
    target: str | None = None,
    correlation_id: str | None = None,
    limit: int = 100,
) -> list[AuditEvent]:
    """Newest first."""
    stmt = (
        select(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
    )

    if event_type is not None:
        stmt = stmt.where(
            AuditEvent.event_type
            == getattr(event_type, "value", event_type)
        )

    if actor is not None:
        stmt = stmt.where(AuditEvent.actor == actor)

    if target is not None:
        stmt = stmt.where(AuditEvent.target == target)

    if correlation_id is not None:
        stmt = stmt.where(
            AuditEvent.correlation_id == correlation_id
        )

    return list(db.scalars(stmt))