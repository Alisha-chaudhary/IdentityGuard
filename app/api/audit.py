from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission
from app.db.models import AuditEvent, User

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events")
def list_audit_events(
    current_user: User = Depends(
        require_permission("IdentityGuard:audit.read")
    ),
    db: Session = Depends(get_db),
) -> list[dict]:
    events = db.scalars(
        select(AuditEvent).order_by(AuditEvent.id.desc())
    ).all()

    return [
        {
            "id": event.id,
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