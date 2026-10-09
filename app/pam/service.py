
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.db.models import User
from app.pam.models import (
    PamAccessRequest,
    PamAccount,
    PamCheckout,
    PamSafe,
)


MAX_CHECKOUT_MINUTES = 60


class PamServiceError(Exception):
    """Base exception for PAM workflow errors."""


class PamValidationError(PamServiceError):
    """Raised when PAM request input is invalid."""


class PamNotFoundError(PamServiceError):
    """Raised when a requested PAM resource does not exist."""


class PamAuthorizationError(PamServiceError):
    """Raised when a PAM operation is not permitted."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_active_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None or user.status != "ACTIVE":
        raise PamAuthorizationError("An active user is required.")
    return user


def request_privileged_access(
    db: Session,
    *,
    requester_id: int,
    account_id: int,
    justification: str,
    duration_minutes: int,
) -> PamAccessRequest:
    """Create a pending request; this does not grant privileged access."""
    requester = _require_active_user(db, requester_id)

    if not isinstance(justification, str) or not justification.strip():
        raise PamValidationError("A justification is required.")

    justification = justification.strip()
    if len(justification) > 500:
        raise PamValidationError("Justification must be 500 characters or fewer.")

    if (
        isinstance(duration_minutes, bool)
        or not isinstance(duration_minutes, int)
        or not 1 <= duration_minutes <= MAX_CHECKOUT_MINUTES
    ):
        raise PamValidationError(
            f"Duration must be between 1 and {MAX_CHECKOUT_MINUTES} minutes."
        )

    account = db.get(PamAccount, account_id)
    if account is None:
        raise PamNotFoundError("PAM account not found.")

    safe = db.get(PamSafe, account.safe_id)
    if (
        account.status != "ACTIVE"
        or safe is None
        or safe.status != "ACTIVE"
    ):
        raise PamAuthorizationError(
            "The PAM account and its Safe must both be active."
        )

    request = PamAccessRequest(
        requester_id=requester.id,
        account_id=account.id,
        justification=justification,
        requested_duration_minutes=duration_minutes,
        status="REQUESTED",
    )

    try:
        db.add(request)
        db.flush()
        record_event(
            db,
            actor=requester.username,
            event_type=EventType.ACCESS_REQUESTED,
            target=f"pam_access_request:{request.id}",
            action="REQUEST_PRIVILEGED_ACCESS",
            result=Result.SUCCESS,
            reason=justification,
        )
        db.commit()
        db.refresh(request)
        return request
    except Exception:
        db.rollback()
        raise


def decide_privileged_access(
    db: Session,
    *,
    request_id: int,
    approver_id: int,
    decision: str,
    reason: str,
) -> PamAccessRequest:
    """Approve or reject a pending request without creating a checkout."""
    approver = _require_active_user(db, approver_id)

    if decision not in {"APPROVED", "REJECTED"}:
        raise PamValidationError("Decision must be APPROVED or REJECTED.")

    if not isinstance(reason, str) or not reason.strip():
        raise PamValidationError("A decision reason is required.")

    reason = reason.strip()
    if len(reason) > 500:
        raise PamValidationError("Decision reason must be 500 characters or fewer.")

    request = db.get(PamAccessRequest, request_id)
    if request is None:
        raise PamNotFoundError("PAM access request not found.")

    if request.requester_id == approver.id:
        raise PamAuthorizationError("Users cannot approve their own requests.")

    if request.status != "REQUESTED":
        raise PamAuthorizationError(
            "Only pending requests can receive a decision."
        )

    try:
        request.status = decision
        request.approver_id = approver.id
        request.decision_reason = reason
        request.decided_at = _utcnow()

        db.flush()
        record_event(
            db,
            actor=approver.username,
            event_type=(
                EventType.ACCESS_APPROVED
                if decision == "APPROVED"
                else EventType.ACCESS_REJECTED
            ),
            target=f"pam_access_request:{request.id}",
            action=f"{decision}_PRIVILEGED_ACCESS",
            result=Result.SUCCESS,
            reason=reason,
        )
        db.commit()
        db.refresh(request)
        return request
    except Exception:
        db.rollback()
        raise


def checkout_privileged_access(
    db: Session,
    *,
    request_id: int,
    user_id: int,
) -> PamCheckout:
    """Create a time-limited checkout for the requester of an approved request."""
    user = _require_active_user(db, user_id)

    request = db.get(PamAccessRequest, request_id)
    if request is None:
        raise PamNotFoundError("PAM access request not found.")

    if request.requester_id != user.id:
        raise PamAuthorizationError(
            "Only the requester can check out their approved request."
        )

    if request.status != "APPROVED":
        raise PamAuthorizationError(
            "Only approved requests can be checked out."
        )

    account = db.get(PamAccount, request.account_id)
    if account is None:
        raise PamNotFoundError("PAM account not found.")

    safe = db.get(PamSafe, account.safe_id)
    if (
        account.status != "ACTIVE"
        or safe is None
        or safe.status != "ACTIVE"
    ):
        raise PamAuthorizationError(
            "The PAM account and its Safe must both be active."
        )

    existing_checkout = db.scalar(
        select(PamCheckout).where(
            PamCheckout.access_request_id == request.id
    )
)

    if existing_checkout is not None:
        raise PamAuthorizationError(
            "This access request has already been checked out."
    )

    duration = request.requested_duration_minutes
    if (
        isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 1 <= duration <= MAX_CHECKOUT_MINUTES
    ):
        raise PamValidationError(
            f"Approved duration must be between 1 and {MAX_CHECKOUT_MINUTES} minutes."
        )

    checked_out_at = _utcnow()
    checkout = PamCheckout(
        access_request_id=request.id,
        checked_out_by_id=user.id,
        checked_out_at=checked_out_at,
        expires_at=checked_out_at + timedelta(minutes=duration),
        status="ACTIVE",
    )

    try:
        db.add(checkout)
        db.flush()
        record_event(
            db,
            actor=user.username,
            event_type=EventType.PRIVILEGED_CHECKOUT,
            target=f"pam_checkout:{checkout.id}",
            action="CHECKOUT_PRIVILEGED_ACCESS",
            result=Result.SUCCESS,
            reason=request.justification,
        )
        db.commit()
        db.refresh(checkout)
        return checkout
    except Exception:
        db.rollback()
        raise