
import pytest

from app.audit.events import EventType
from app.core.clock import FrozenClock, set_clock
from app.db.models import (
    AccessReviewCycle,
    AccessReviewItem,
    AuditEvent,
    Department,
    Role,
    User,
    UserRole,
)
from app.iam.access_reviews import (
    AccessReviewAlreadyCompletedError,
    AccessReviewDecisionError,
    AccessReviewInvalidError,
    AccessReviewSelfReviewError,
    create_access_review_cycle,
    record_access_review_decision,
    complete_access_review_cycle,
    AccessReviewNotFoundError,
)


@pytest.fixture(autouse=True)
def reset_clock():
    from datetime import datetime

    set_clock(FrozenClock(datetime(2026, 1, 1, 12, 0, 0)))
    yield
    set_clock(FrozenClock(datetime(2026, 1, 1, 12, 0, 0)))


def create_department(db):
    department = Department(name="Finance")
    db.add(department)
    db.flush()
    return department


def create_user(db, department, username, employee_id, status="ACTIVE"):
    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.title(),
        email=f"{username}@example.test",
        department_id=department.id,
        status=status,
    )
    db.add(user)
    db.flush()
    return user


def create_role(db, name="Finance Analyst"):
    role = Role(
        name=name,
        description="Test role",
        is_privileged=False,
    )
    db.add(role)
    db.flush()
    return role


def test_create_cycle_snapshots_active_role_assignments(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR001")
    target = create_user(db, department, "target", "AR002")
    role = create_role(db)

    assignment = UserRole(user_id=target.id, role_id=role.id)
    db.add(assignment)
    db.commit()
    db.refresh(assignment)

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Q1 Finance Access Review",
    )

    items = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .all()
    )

    assert cycle.status == "OPEN"
    assert cycle.created_by_id == creator.id
    assert len(items) == 1
    assert items[0].user_id == target.id
    assert items[0].role_id == role.id
    assert items[0].assignment_assigned_at == assignment.assigned_at
    assert items[0].decision == "PENDING"


def test_create_cycle_rejects_empty_name(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR003")
    target = create_user(db, department, "target", "AR004")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    with pytest.raises(AccessReviewInvalidError, match="name"):
        create_access_review_cycle(
            db,
            creator=creator,
            name="   ",
        )


def test_create_cycle_rejects_when_no_active_assignments(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR005")

    with pytest.raises(AccessReviewInvalidError, match="without active"):
        create_access_review_cycle(
            db,
            creator=creator,
            name="Empty Review",
        )


def test_record_retain_decision_and_audit(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR006")
    target = create_user(db, department, "target", "AR007")
    reviewer = create_user(db, department, "reviewer", "AR008")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Quarterly Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    result = record_access_review_decision(
        db,
        cycle_id=cycle.id,
        item_id=item.id,
        reviewer=reviewer,
        decision="RETAIN",
        reason="Access is required for current duties",
    )

    assert result.decision == "RETAIN"
    assert result.reviewer_id == reviewer.id
    assert result.decision_reason == "Access is required for current duties"
    assert result.decided_at is not None

    event = (
        db.query(AuditEvent)
        .filter_by(
            event_type=EventType.ACCESS_REVIEW_DECISION_RECORDED
        )
        .one()
    )
    assert event.actor == reviewer.username
    assert event.result == "SUCCESS"


def test_record_decision_rejects_invalid_decision(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR009")
    target = create_user(db, department, "target", "AR010")
    reviewer = create_user(db, department, "reviewer", "AR011")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Quarterly Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    with pytest.raises(AccessReviewInvalidError, match="RETAIN or REVOKE"):
        record_access_review_decision(
            db,
            cycle_id=cycle.id,
            item_id=item.id,
            reviewer=reviewer,
            decision="APPROVE",
            reason="Test reason",
        )


def test_record_decision_requires_reason(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR012")
    target = create_user(db, department, "target", "AR013")
    reviewer = create_user(db, department, "reviewer", "AR014")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Quarterly Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    with pytest.raises(AccessReviewInvalidError, match="reason"):
        record_access_review_decision(
            db,
            cycle_id=cycle.id,
            item_id=item.id,
            reviewer=reviewer,
            decision="REVOKE",
            reason="  ",
        )


def test_user_cannot_review_own_assignment(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR015")
    target = create_user(db, department, "target", "AR016")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Quarterly Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    with pytest.raises(AccessReviewSelfReviewError):
        record_access_review_decision(
            db,
            cycle_id=cycle.id,
            item_id=item.id,
            reviewer=target,
            decision="RETAIN",
            reason="I need this access",
        )


def test_review_item_cannot_be_decided_twice(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR017")
    target = create_user(db, department, "target", "AR018")
    reviewer = create_user(db, department, "reviewer", "AR019")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Quarterly Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    record_access_review_decision(
        db,
        cycle_id=cycle.id,
        item_id=item.id,
        reviewer=reviewer,
        decision="RETAIN",
        reason="Required",
    )

    with pytest.raises(AccessReviewDecisionError):
        record_access_review_decision(
            db,
            cycle_id=cycle.id,
            item_id=item.id,
            reviewer=reviewer,
            decision="REVOKE",
            reason="Changed my mind",
        )


def test_cannot_complete_cycle_with_pending_decisions(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR020")
    target = create_user(db, department, "target", "AR021")
    reviewer = create_user(db, department, "reviewer", "AR022")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Pending Review",
    )

    with pytest.raises(
        AccessReviewInvalidError,
        match="decision",
    ):
        complete_access_review_cycle(
            db,
            cycle_id=cycle.id,
            actor=reviewer,
        )

    assert cycle.status == "OPEN"


def test_revoke_decision_removes_assignment_and_audits(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR023")
    target = create_user(db, department, "target", "AR024")
    reviewer = create_user(db, department, "reviewer", "AR025")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Revocation Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    record_access_review_decision(
        db,
        cycle_id=cycle.id,
        item_id=item.id,
        reviewer=reviewer,
        decision="REVOKE",
        reason="Role no longer required",
    )

    completed = complete_access_review_cycle(
        db,
        cycle_id=cycle.id,
        actor=reviewer,
    )

    assignment = db.get(UserRole, (target.id, role.id))
    assert assignment is None
    assert completed.status == "COMPLETED"
    assert completed.completed_at is not None

    event_types = [
        event.event_type
        for event in db.query(AuditEvent).all()
    ]
    assert EventType.ACCESS_REVOKED in event_types
    assert EventType.ACCESS_REVIEW_COMPLETED in event_types


def test_retain_decision_preserves_assignment(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR026")
    target = create_user(db, department, "target", "AR027")
    reviewer = create_user(db, department, "reviewer", "AR028")
    role = create_role(db)

    db.add(UserRole(user_id=target.id, role_id=role.id))
    db.commit()

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Retention Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    record_access_review_decision(
        db,
        cycle_id=cycle.id,
        item_id=item.id,
        reviewer=reviewer,
        decision="RETAIN",
        reason="Still needed",
    )

    complete_access_review_cycle(
        db,
        cycle_id=cycle.id,
        actor=reviewer,
    )

    assert db.get(UserRole, (target.id, role.id)) is not None


def test_cannot_complete_nonexistent_cycle(db):
    department = create_department(db)
    actor = create_user(db, department, "actor", "AR029")

    with pytest.raises(AccessReviewNotFoundError):
        complete_access_review_cycle(
            db,
            cycle_id=9999,
            actor=actor,
        )


def test_stale_review_does_not_revoke_reassigned_role(db):
    department = create_department(db)
    creator = create_user(db, department, "creator", "AR030")
    target = create_user(db, department, "target", "AR031")
    reviewer = create_user(db, department, "reviewer", "AR032")
    role = create_role(db)

    original = UserRole(user_id=target.id, role_id=role.id)
    db.add(original)
    db.commit()
    db.refresh(original)
    original_assigned_at = original.assigned_at

    cycle = create_access_review_cycle(
        db,
        creator=creator,
        name="Stale Assignment Review",
    )
    item = (
        db.query(AccessReviewItem)
        .filter_by(cycle_id=cycle.id)
        .one()
    )

    record_access_review_decision(
        db,
        cycle_id=cycle.id,
        item_id=item.id,
        reviewer=reviewer,
        decision="REVOKE",
        reason="Original access no longer required",
    )

    # Simulate removal and a later reassignment.
    db.delete(original)
    db.flush()

    replacement = UserRole(
        user_id=target.id,
        role_id=role.id,
        assigned_at=original_assigned_at.replace(
            microsecond=(original_assigned_at.microsecond + 1) % 1_000_000
        ),
    )
    db.add(replacement)
    db.commit()
    db.refresh(replacement)

    with pytest.raises(AccessReviewInvalidError, match="changed"):
        complete_access_review_cycle(
            db,
            cycle_id=cycle.id,
            actor=reviewer,
        )

    current = db.get(UserRole, (target.id, role.id))
    assert current is not None
    assert current.assigned_at == replacement.assigned_at
    assert cycle.status == "OPEN"