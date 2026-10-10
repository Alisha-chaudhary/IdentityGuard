from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import User
from app.pam.models import (
    PamAccessRequest,
    PamAccount,
    PamCheckout,
    PamSafe,
    PamSession,
)


def get_pam_activity_report(db: Session) -> dict:
    """Return PAM request activity with checkout and session metadata."""

    statement = (
        select(
            PamAccessRequest,
            PamAccount,
            PamSafe,
            User.username.label("requester_username"),
        )
        .join(
            PamAccount,
            PamAccessRequest.account_id == PamAccount.id,
        )
        .join(
            PamSafe,
            PamAccount.safe_id == PamSafe.id,
        )
        .join(
            User,
            PamAccessRequest.requester_id == User.id,
        )
        .order_by(PamAccessRequest.id)
    )

    rows = db.execute(statement).all()
    items = []

    for request, account, safe, requester_username in rows:
        checkout = db.scalar(
            select(PamCheckout).where(
                PamCheckout.access_request_id == request.id
            )
        )

        sessions = []
        if checkout is not None:
            session_rows = db.scalars(
                select(PamSession)
                .where(PamSession.checkout_id == checkout.id)
                .order_by(PamSession.id)
            ).all()

            sessions = [
                {
                    "session_id": session.id,
                    "status": session.status,
                    "started_at": session.started_at,
                    "ended_at": session.ended_at,
                    "source_ip": session.source_ip,
                    "session_reference": session.session_reference,
                }
                for session in session_rows
            ]

        items.append(
            {
                "request_id": request.id,
                "requester_username": requester_username,
                "account_name": account.name,
                "system_name": account.system_name,
                "safe_name": safe.name,
                "justification": request.justification,
                "requested_duration_minutes": (
                    request.requested_duration_minutes
                ),
                "request_status": request.status,
                "requested_at": request.requested_at,
                "approver_id": request.approver_id,
                "decision_reason": request.decision_reason,
                "decided_at": request.decided_at,
                "checkout_id": checkout.id if checkout else None,
                "checkout_status": checkout.status if checkout else None,
                "checked_out_at": (
                    checkout.checked_out_at if checkout else None
                ),
                "expires_at": checkout.expires_at if checkout else None,
                "checkout_ended_at": checkout.ended_at if checkout else None,
                "sessions": sessions,
            }
        )

    return {
        "total_count": len(items),
        "items": items,
    }
