
from datetime import datetime, timedelta

from app.core.clock import FrozenClock, set_clock
from app.db.models import Department, Role, User, UserRole
from app.reports.role_access_assignment import (
    get_role_access_assignments,
)


def test_role_access_report_includes_assignment_details(db):
    department = Department(name="Security")
    db.add(department)
    db.flush()

    user = User(
        employee_id="RA001",
        username="report.user",
        full_name="Report User",
        email="report.user@example.test",
        password_hash="must-not-appear",
        status="ACTIVE",
        department_id=department.id,
    )
    role = Role(
        name="Security Analyst",
        description="Reviews security events",
        is_privileged=False,
    )
    db.add_all([user, role])
    db.flush()

    assigned_at = datetime(2026, 1, 1, 10, 0, 0)
    expires_at = datetime(2026, 12, 1, 10, 0, 0)

    db.add(
        UserRole(
            user_id=user.id,
            role_id=role.id,
            assigned_at=assigned_at,
            expires_at=expires_at,
        )
    )
    db.flush()

    original_time = datetime(2026, 10, 1, 10, 0, 0)
    set_clock(FrozenClock(original_time))

    try:
        report = get_role_access_assignments(db)
    finally:
        from app.core.clock import SystemClock
        set_clock(SystemClock())

    assert report["total_count"] == 1
    assert report["active_count"] == 1
    assert report["expired_count"] == 0
    assert report["privileged_assignment_count"] == 0

    item = report["items"][0]
    assert item["username"] == "report.user"
    assert item["department"] == "Security"
    assert item["role_name"] == "Security Analyst"
    assert item["assigned_at"] == assigned_at
    assert item["expires_at"] == expires_at
    assert item["assignment_status"] == "ACTIVE"

    assert "password_hash" not in item
    assert "email" not in item


def test_role_access_report_marks_expired_assignment(db):
    department = Department(name="Finance")
    db.add(department)
    db.flush()

    user = User(
        employee_id="RA002",
        username="expired.user",
        full_name="Expired User",
        email="expired.user@example.test",
        status="ACTIVE",
        department_id=department.id,
    )
    role = Role(
        name="Finance Reviewer",
        description="Reviews finance records",
        is_privileged=False,
    )
    db.add_all([user, role])
    db.flush()

    current_time = datetime(2026, 10, 1, 10, 0, 0)

    db.add(
        UserRole(
            user_id=user.id,
            role_id=role.id,
            assigned_at=current_time - timedelta(days=30),
            expires_at=current_time - timedelta(seconds=1),
        )
    )
    db.flush()

    from app.core.clock import SystemClock

    set_clock(FrozenClock(current_time))
    try:
        report = get_role_access_assignments(db)
    finally:
        set_clock(SystemClock())

    assert report["total_count"] == 1
    assert report["expired_count"] == 1
    assert report["active_count"] == 0
    assert report["items"][0]["assignment_status"] == "EXPIRED"


def test_role_access_report_includes_users_without_assignments(db):
    department = Department(name="Operations")
    db.add(department)
    db.flush()

    db.add(
        User(
            employee_id="RA003",
            username="no.roles",
            full_name="No Roles",
            email="no.roles@example.test",
            status="ACTIVE",
            department_id=department.id,
        )
    )
    db.flush()

    report = get_role_access_assignments(db)

    assert report["total_count"] == 0
    assert report["active_count"] == 0
    assert report["items"] == []
