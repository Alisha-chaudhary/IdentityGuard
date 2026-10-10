from datetime import datetime

from sqlalchemy.orm import Session

from app.audit.service import list_events, verify_chain


def get_audit_trail(
    db: Session,
    *,
    event_type: str | None = None,
    actor: str | None = None,
    target: str | None = None,
    correlation_id: str | None = None,
    limit: int = 100,
) -> dict:
    """Return filtered audit events and whole-chain integrity status."""

    events = list_events(
        db,
        event_type=event_type,
        actor=actor,
        target=target,
        correlation_id=correlation_id,
        limit=limit,
    )

    integrity = verify_chain(db)

    items = [
        {
            "event_id": event.id,
            "timestamp": event.timestamp,
            "actor": event.actor,
            "event_type": event.event_type,
            "target": event.target,
            "action": event.action,
            "result": event.result,
            "reason": event.reason,
            "correlation_id": event.correlation_id,
        }
        for event in events
    ]

    result_counts = {
        result: sum(item["result"] == result for item in items)
        for result in ("SUCCESS", "DENIED", "FAILURE")
    }

    return {
        "total_count": len(items),
        "success_count": result_counts["SUCCESS"],
        "denied_count": result_counts["DENIED"],
        "failure_count": result_counts["FAILURE"],
        "integrity": {
            "ok": integrity.ok,
            "checked": integrity.checked,
            "first_bad_id": integrity.first_bad_id,
        },
        "items": items,
    }