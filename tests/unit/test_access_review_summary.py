from datetime import datetime

from app.db.models import (
    AccessReviewCycle,
    AccessReviewItem,
    Department,
    Role,
    User,
)
from app.reports.access_review_summary import (
    get_access_review_summary,
)


def create_user(db, username, employee_id):
    department = Department(name=f"Department {employee_id}")
    db.add(department)
    db.flush()

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        password_hash="test-password-hash",
        status="ACTIVE",
        department_id=department.id,
    )
    db.add(user)
    db.flush()
    return user


def create_role(db, name):
    role = Role(
        name=name,
        description="Test role",
        is_privileged=False,
    )
    db.add(role)
    db.flush()
    return role


def create_cycle(db, creator, name, status="OPEN", cycle_id=None):
    cycle = AccessReviewCycle(
        name=name,
        status=status,
        created_by_id=creator.id,
        created_at=datetime(2026, 1, 1, 10, 0, 0),
        completed_at=(
            datetime(2026, 1, 2, 10, 0, 0)
            if status == "COMPLETED"
            else None
        ),
    )
    db.add(cycle)
    db.flush()
    return cycle


def create_review_item(
    db,
    cycle,
    user,
    role,
    decision="PENDING",
    reviewer=None,
    reason=None,
):
    item = AccessReviewItem(
        cycle_id=cycle.id,
        user_id=user.id,
        role_id=role.id,
        assignment_assigned_at=datetime(2025, 12, 1, 9, 0, 0),
        decision=decision,
        reviewer_id=reviewer.id if reviewer else None,
        decision_reason=reason,
        decided_at=(
            datetime(2026, 1, 2, 9, 0, 0)
            if decision != "PENDING"
            else None
        ),
    )
    db.add(item)
    db.flush()
    return item


def test_access_review_summary_returns_empty_report(db):
    report = get_access_review_summary(db)

    assert report == {
        "total_cycles": 0,
        "open_cycles": 0,
        "completed_cycles": 0,
        "total_review_items": 0,
        "pending_decisions": 0,
        "items": [],
    }


def test_access_review_summary_counts_cycles_and_decisions(db):
    creator = create_user(db, "review.creator", "ARS001")
    target = create_user(db, "review.target", "ARS002")
    reviewer = create_user(db, "review.approver", "ARS003")
    role = create_role(db, "Review Analyst")

    # Use a distinct user-role assignment for each item in this cycle.
    second_target = create_user(db, "review.target2", "ARS008")
    second_role = create_role(db, "Review Auditor")

    open_cycle = create_cycle(db, creator, "January Review")
    completed_cycle = create_cycle(
        db, creator, "December Review", status="COMPLETED"
    )

    create_review_item(db, open_cycle, target, role, "PENDING")
    create_review_item(
        db,
        open_cycle,
        second_target,
        second_role,
        "RETAIN",
        reviewer,
        "Access required",
    )
    create_review_item(
        db,
        completed_cycle,
        target,
        role,
        "REVOKE",
        reviewer,
        "No longer needed",
    )

    report = get_access_review_summary(db)

    assert report["total_cycles"] == 2
    assert report["open_cycles"] == 1
    assert report["completed_cycles"] == 1
    assert report["total_review_items"] == 3
    assert report["pending_decisions"] == 1

    cycles = {cycle["name"]: cycle for cycle in report["items"]}

    january = cycles["January Review"]
    assert january["total_count"] == 2
    assert january["pending_count"] == 1
    assert january["retain_count"] == 1
    assert january["revoke_decision_count"] == 0
    assert january["decided_count"] == 1
    assert january["completion_percentage"] == 50.0

    december = cycles["December Review"]
    assert december["total_count"] == 1
    assert december["revoke_decision_count"] == 1
    assert december["completion_percentage"] == 100.0


def test_access_review_summary_includes_identity_and_reviewer_details(db):
    creator = create_user(db, "review.creator", "ARS004")
    target = create_user(db, "review.target", "ARS005")
    reviewer = create_user(db, "review.approver", "ARS006")
    role = create_role(db, "Privileged Reviewer")
    cycle = create_cycle(db, creator, "Identity Review")

    create_review_item(
        db,
        cycle,
        target,
        role,
        decision="RETAIN",
        reviewer=reviewer,
        reason="Access remains necessary",
    )

    report = get_access_review_summary(db)

    item = report["items"][0]["items"][0]

    assert item["username"] == "review.target"
    assert item["role_name"] == "Privileged Reviewer"
    assert item["decision"] == "RETAIN"
    assert item["reviewer_username"] == "review.approver"
    assert item["decision_reason"] == "Access remains necessary"
    assert item["decided_at"] == datetime(2026, 1, 2, 9, 0, 0)

    assert "password_hash" not in item
    assert "email" not in item


def test_access_review_summary_handles_cycle_without_review_items(db):
    creator = create_user(db, "review.creator", "ARS007")
    create_cycle(db, creator, "Empty Review")

    report = get_access_review_summary(db)

    assert report["total_cycles"] == 1
    assert report["total_review_items"] == 0
    assert report["items"][0]["items"] == []
    assert report["items"][0]["completion_percentage"] == 0.0