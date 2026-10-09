
from datetime import timedelta

from app.core.clock import now
from app.db.models import Department, Role, User, UserRole
from app.governance.sod import (
    evaluate_user_sod,
    find_role_conflicts,
)


def test_detects_payment_initiator_and_approver_conflict():
    conflicts = find_role_conflicts(
        {"Payment Initiator", "Payment Approver"}
    )

    assert len(conflicts) == 1
    assert set(conflicts[0]) == {
        "Payment Initiator",
        "Payment Approver",
    }


def test_no_conflict_for_unrelated_roles():
    conflicts = find_role_conflicts(
        {"Finance Analyst", "SOC Analyst"}
    )

    assert conflicts == []


def test_proposed_role_creates_conflict(db):
    department = Department(name="Finance")
    initiator = Role(name="Payment Initiator")
    approver = Role(name="Payment Approver")

    db.add_all([department, initiator, approver])
    db.flush()

    user = User(
        employee_id="SOD001",
        username="sod.user",
        full_name="SoD Test User",
        email="sod.user@example.test",
        department_id=department.id,
        status="ACTIVE",
    )
    db.add(user)
    db.flush()

    db.add(
        UserRole(
            user_id=user.id,
            role_id=initiator.id,
        )
    )
    db.commit()

    conflicts = evaluate_user_sod(
        db,
        user.id,
        additional_role_id=approver.id,
    )

    assert len(conflicts) == 1
    assert conflicts[0].username == "sod.user"
    assert set(conflicts[0].conflicting_roles) == {
        "Payment Initiator",
        "Payment Approver",
    }

    # Evaluating a proposed role must not provision it.
    assigned_role_ids = {
        assignment.role_id
        for assignment in db.query(UserRole)
        .filter_by(user_id=user.id)
        .all()
    }
    assert assigned_role_ids == {initiator.id}


def test_expired_role_does_not_create_conflict(db):
    department = Department(name="Finance")
    initiator = Role(name="Payment Initiator")
    approver = Role(name="Payment Approver")

    db.add_all([department, initiator, approver])
    db.flush()

    user = User(
        employee_id="SOD002",
        username="sod.expired",
        full_name="Expired Role Test",
        email="sod.expired@example.test",
        department_id=department.id,
        status="ACTIVE",
    )
    db.add(user)
    db.flush()

    db.add_all([
        UserRole(
            user_id=user.id,
            role_id=initiator.id,
            expires_at=now() - timedelta(minutes=1),
        ),
        UserRole(
            user_id=user.id,
            role_id=approver.id,
        ),
    ])
    db.commit()

    conflicts = evaluate_user_sod(db, user.id)

    assert conflicts == []