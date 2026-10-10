from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from app.db.models import AccessReviewCycle, AccessReviewItem, Role, User


def get_access_review_summary(db: Session) -> dict:
    """Return access review cycles, decisions, and reviewer context."""

    creator = aliased(User)
    reviewed_user = aliased(User)
    reviewer = aliased(User)

    statement = (
        select(
            AccessReviewCycle,
            creator.username.label("creator_username"),
            AccessReviewItem,
            reviewed_user.username.label("reviewed_username"),
            Role.name.label("role_name"),
            reviewer.username.label("reviewer_username"),
        )
        .join(
            creator,
            AccessReviewCycle.created_by_id == creator.id,
        )
        .outerjoin(
            AccessReviewItem,
            AccessReviewItem.cycle_id == AccessReviewCycle.id,
        )
        .outerjoin(
            reviewed_user,
            AccessReviewItem.user_id == reviewed_user.id,
        )
        .outerjoin(
            Role,
            AccessReviewItem.role_id == Role.id,
        )
        .outerjoin(
            reviewer,
            AccessReviewItem.reviewer_id == reviewer.id,
        )
        .order_by(
            AccessReviewCycle.created_at.desc(),
            AccessReviewCycle.id.desc(),
            AccessReviewItem.id,
        )
    )

    rows = db.execute(statement).all()

    cycles_by_id = {}

    for (
        cycle,
        creator_username,
        review_item,
        reviewed_username,
        role_name,
        reviewer_username,
    ) in rows:
        if cycle.id not in cycles_by_id:
            cycles_by_id[cycle.id] = {
                "cycle_id": cycle.id,
                "name": cycle.name,
                "status": cycle.status,
                "created_by_id": cycle.created_by_id,
                "creator_username": creator_username,
                "created_at": cycle.created_at,
                "completed_at": cycle.completed_at,
                "total_count": 0,
                "pending_count": 0,
                "retain_count": 0,
                "revoke_decision_count": 0,
                "decided_count": 0,
                "completion_percentage": 0.0,
                "items": [],
            }

        if review_item is None:
            continue

        cycle_summary = cycles_by_id[cycle.id]
        decision = review_item.decision

        cycle_summary["total_count"] += 1

        if decision == "PENDING":
            cycle_summary["pending_count"] += 1
        elif decision == "RETAIN":
            cycle_summary["retain_count"] += 1
        elif decision == "REVOKE":
            cycle_summary["revoke_decision_count"] += 1

        if decision != "PENDING":
            cycle_summary["decided_count"] += 1

        cycle_summary["items"].append(
            {
                "item_id": review_item.id,
                "user_id": review_item.user_id,
                "username": reviewed_username,
                "role_id": review_item.role_id,
                "role_name": role_name,
                "assignment_assigned_at": (
                    review_item.assignment_assigned_at
                ),
                "decision": decision,
                "reviewer_id": review_item.reviewer_id,
                "reviewer_username": reviewer_username,
                "decision_reason": review_item.decision_reason,
                "decided_at": review_item.decided_at,
            }
        )

    items = list(cycles_by_id.values())

    for cycle_summary in items:
        total = cycle_summary["total_count"]

        if total:
            cycle_summary["completion_percentage"] = round(
                cycle_summary["decided_count"] / total * 100,
                2,
            )

    return {
        "total_cycles": len(items),
        "open_cycles": sum(
            cycle["status"] == "OPEN" for cycle in items
        ),
        "completed_cycles": sum(
            cycle["status"] == "COMPLETED" for cycle in items
        ),
        "total_review_items": sum(
            cycle["total_count"] for cycle in items
        ),
        "pending_decisions": sum(
            cycle["pending_count"] for cycle in items
        ),
        "items": items,
    }