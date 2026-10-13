
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.core.clock import now
from app.db.models import (
    AccessReviewCycle,
    AccessReviewItem,
    Role,
    User,
    UserRole,
)


class AccessReviewError(Exception):
    """Base exception for access review operations."""


class AccessReviewNotFoundError(AccessReviewError):
    pass


class AccessReviewInvalidError(AccessReviewError):
    pass


class AccessReviewAlreadyCompletedError(AccessReviewError):
    pass


class AccessReviewDecisionError(AccessReviewError):
    pass


class AccessReviewSelfReviewError(AccessReviewError):
    pass


def create_access_review_cycle(
    db: Session,
    *,
    creator: User,
    name: str,
) -> AccessReviewCycle:
    name = name.strip()

    if not name:
        raise AccessReviewInvalidError(
            "Access review cycle name cannot be empty"
        )

    if len(name) > 150:
        raise AccessReviewInvalidError(
            "Access review cycle name cannot exceed 150 characters"
        )

    current_time = now()

    cycle = AccessReviewCycle(
        name=name,
        status="OPEN",
        created_by_id=creator.id,
        created_at=current_time,
    )
    db.add(cycle)
    db.flush()

    # Snapshot assignments so later changes do not rewrite review history.
    assignments = db.scalars(
        select(UserRole)
        .join(User, User.id == UserRole.user_id)
        .where(
            User.status == "ACTIVE",
            or_(
                UserRole.expires_at.is_(None),
                UserRole.expires_at > current_time,
            ),
        )
        .order_by(UserRole.user_id, UserRole.role_id)
    ).all()

    if not assignments:
        db.rollback()
        raise AccessReviewInvalidError(
            "Cannot create an access review cycle without active role assignments"
    )

    for assignment in assignments:
        db.add(
            AccessReviewItem(
                cycle_id=cycle.id,
                user_id=assignment.user_id,
                role_id=assignment.role_id,
                assignment_assigned_at=assignment.assigned_at,
                decision="PENDING",
            )
        )

    record_event(
        db,
        actor=creator.username,
        event_type=EventType.ACCESS_REVIEW_CREATED,
        target=f"access_review:{cycle.id}",
        action="create_access_review",
        result=Result.SUCCESS,
        reason=(
            f"Created access review cycle '{name}' "
            f"with {len(assignments)} assignment(s)"
        ),
    )

    db.commit()
    db.refresh(cycle)

    return cycle


def record_access_review_decision(
    db: Session,
    *,
    cycle_id: int,
    item_id: int,
    reviewer: User,
    decision: str,
    reason: str,
) -> AccessReviewItem:
    cycle = db.get(AccessReviewCycle, cycle_id)

    if cycle is None:
        raise AccessReviewNotFoundError(
            f"Access review cycle {cycle_id} not found"
        )

    if cycle.status != "OPEN":
        raise AccessReviewAlreadyCompletedError(
            "Cannot decide an item in a completed review cycle"
        )

    item = db.get(AccessReviewItem, item_id)

    if item is None or item.cycle_id != cycle_id:
        raise AccessReviewNotFoundError(
            f"Review item {item_id} not found in cycle {cycle_id}"
        )

    if item.decision != "PENDING":
        raise AccessReviewDecisionError(
            "This review item already has a decision"
        )

    if reviewer.id == item.user_id:
        record_event(
            db,
            actor=reviewer.username,
            event_type=EventType.ACCESS_DENIED,
            target=f"access_review_item:{item.id}",
            action="access_review_self_review",
            result=Result.DENIED,
            reason="Reviewer attempted to review their own role assignment",
           )
        db.commit()
        raise AccessReviewSelfReviewError(
            "Users cannot review their own role assignments"
        )

    decision = decision.strip().upper()
    if decision not in {"RETAIN", "REVOKE"}:
        raise AccessReviewInvalidError(
            "Decision must be RETAIN or REVOKE"
        )

    reason = reason.strip()
    if not reason:
        raise AccessReviewInvalidError(
            "A decision reason is required"
        )

    if len(reason) > 500:
        raise AccessReviewInvalidError(
            "Decision reason cannot exceed 500 characters"
        )

    item.decision = decision
    item.reviewer_id = reviewer.id
    item.decision_reason = reason
    item.decided_at = now()

    record_event(
        db,
        actor=reviewer.username,
        event_type=EventType.ACCESS_REVIEW_DECISION_RECORDED,
        target=f"access_review_item:{item.id}",
        action=f"access_review_{decision.lower()}",
        result=Result.SUCCESS,
        reason=reason,
    )

    db.commit()
    db.refresh(item)

    return item


def complete_access_review_cycle(
    db: Session,
    *,
    cycle_id: int,
    actor: User,
) -> AccessReviewCycle:
    cycle = db.get(AccessReviewCycle, cycle_id)

    if cycle is None:
        raise AccessReviewNotFoundError(
            f"Access review cycle {cycle_id} not found"
        )

    if cycle.status != "OPEN":
        raise AccessReviewAlreadyCompletedError(
            "Access review cycle is already completed"
        )

    items = db.scalars(
        select(AccessReviewItem)
        .where(AccessReviewItem.cycle_id == cycle_id)
        .order_by(AccessReviewItem.id)
    ).all()

    if not items:
        raise AccessReviewInvalidError(
            "Cannot complete a review cycle without review items"
        )

    pending_items = [
        item for item in items if item.decision == "PENDING"
    ]

    if pending_items:
        raise AccessReviewInvalidError(
            f"Cannot complete review: {len(pending_items)} decision(s) pending"
        )

    try:
        for item in items:
            if item.decision != "REVOKE":
                continue

            assignment = db.get(
                UserRole,
                (item.user_id, item.role_id),
            )

            # If the original assignment no longer exists, there is
            # nothing left to revoke.
            if assignment is None:
                continue

            # Do not revoke a role that was removed and reassigned
            # after this review item was created.
            if assignment.assigned_at != item.assignment_assigned_at:
                raise AccessReviewInvalidError(
                    "Role assignment changed after the review began; "
                    "resolve the assignment conflict before completing"
                )

            target_user = db.get(User, item.user_id)
            role = db.get(Role, item.role_id)

            if target_user is None or role is None:
                raise AccessReviewInvalidError(
                    "Review references a missing user or role"
                )

            db.delete(assignment)

            record_event(
                db,
                actor=actor.username,
                event_type=EventType.ACCESS_REVOKED,
                target=target_user.username,
                action=f"access_review_revoke:{role.name}",
                result=Result.SUCCESS,
                reason=item.decision_reason or "Access review revocation",
            )

        cycle.status = "COMPLETED"
        cycle.completed_at = now()

        record_event(
            db,
            actor=actor.username,
            event_type=EventType.ACCESS_REVIEW_COMPLETED,
            target=f"access_review:{cycle.id}",
            action="complete_access_review",
            result=Result.SUCCESS,
            reason=f"Completed access review cycle '{cycle.name}'",
        )

        db.commit()
        db.refresh(cycle)
        return cycle

    except Exception:
        db.rollback()
        raise

def _fit_reason(text: str, limit: int = 500) -> str:
    """Audit reasons are limited to 500 characters."""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def correct_access_review_reason(
    db: Session,
    *,
    cycle_id: int,
    item_id: int,
    corrector: User,
    new_reason: str,
) -> AccessReviewItem:
    """
    Correct only the reason text of an existing decision.

    The decision, reviewer and decision time are not changed. The previous
    reason is preserved in a separate audit event, so each correction leaves
    a record of what was replaced.
    """
    cycle = db.get(AccessReviewCycle, cycle_id)

    if cycle is None:
        raise AccessReviewNotFoundError(
            f"Access review cycle {cycle_id} not found"
        )

    if cycle.status != "OPEN":
        raise AccessReviewAlreadyCompletedError(
            "Cannot correct an item in a completed review cycle"
        )

    item = db.get(AccessReviewItem, item_id)

    if item is None or item.cycle_id != cycle_id:
        raise AccessReviewNotFoundError(
            f"Review item {item_id} not found in cycle {cycle_id}"
        )

    if item.decision == "PENDING":
        raise AccessReviewDecisionError(
            "This review item has no decision to correct"
        )

    if corrector.id == item.user_id:
        record_event(
            db,
            actor=corrector.username,
            event_type=EventType.ACCESS_DENIED,
            target=f"access_review_item:{item.id}",
            action="access_review_self_correction",
            result=Result.DENIED,
            reason=(
                "User attempted to correct a decision about their own "
                "role assignment"
            ),
        )
        db.commit()

        raise AccessReviewSelfReviewError(
            "Users cannot correct decisions about their own role assignments"
        )

    new_reason = new_reason.strip()

    if not new_reason:
        raise AccessReviewInvalidError("A corrected reason is required")

    if len(new_reason) > 500:
        raise AccessReviewInvalidError(
            "Decision reason cannot exceed 500 characters"
        )

    previous_reason = item.decision_reason or ""

    if new_reason == previous_reason:
        raise AccessReviewInvalidError(
            "The corrected reason matches the current reason"
        )

    try:
        item.decision_reason = new_reason

        record_event(
            db,
            actor=corrector.username,
            event_type=EventType.ACCESS_REVIEW_REASON_CORRECTED,
            target=f"access_review_item:{item.id}",
            action="correct_access_review_reason",
            result=Result.SUCCESS,
            reason=_fit_reason(f"Previous reason: {previous_reason}"),
        )

        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise