from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from app.db.models import AccessRequest, Role, User


def get_access_request_history(db: Session) -> dict:
    """Return access request history with requester, target, and role context."""

    requester = aliased(User)
    target_user = aliased(User)

    statement = (
        select(
            AccessRequest,
            requester.username.label("requester_username"),
            target_user.username.label("target_username"),
            Role.name.label("role_name"),
            Role.is_privileged.label("is_privileged"),
        )
        .join(
            requester,
            AccessRequest.requester_id == requester.id,
        )
        .join(
            target_user,
            AccessRequest.target_user_id == target_user.id,
        )
        .join(
            Role,
            AccessRequest.role_id == Role.id,
        )
        .order_by(
            AccessRequest.requested_at.desc(),
            AccessRequest.id.desc(),
        )
    )

    rows = db.execute(statement).all()

    items = [
        {
            "request_id": request.id,
            "requester_id": request.requester_id,
            "requester_username": requester_username,
            "target_user_id": request.target_user_id,
            "target_username": target_username,
            "role_id": request.role_id,
            "role_name": role_name,
            "is_privileged": is_privileged,
            "justification": request.justification,
            "status": request.status,
            "decision_by": request.decision_by,
            "decision_reason": request.decision_reason,
            "requested_at": request.requested_at,
            "decided_at": request.decided_at,
            "provisioned_at": request.provisioned_at,
            "expires_at": request.expires_at,
        }
        for (
            request,
            requester_username,
            target_username,
            role_name,
            is_privileged,
        ) in rows
    ]

    status_counts = {
        status: sum(item["status"] == status for item in items)
        for status in (
            "REQUESTED",
            "APPROVED",
            "REJECTED",
            "PROVISIONED",
        )
    }

    return {
        "total_count": len(items),
        "requested_count": status_counts["REQUESTED"],
        "approved_count": status_counts["APPROVED"],
        "rejected_count": status_counts["REJECTED"],
        "provisioned_count": status_counts["PROVISIONED"],
        "items": items,
    }