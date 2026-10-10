from datetime import datetime

from app.db.models import Department, Role, User, UserRole
from app.reports.identity_inventory import get_identity_inventory


def create_department(db, name="Engineering"):
    department = Department(name=name)
    db.add(department)
    db.flush()
    return department


def create_user(
    db,
    department,
    username,
    employee_id,
    status="ACTIVE",
    manager_id=None,
    terminated_at=None,
):
    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        password_hash="must-not-appear-in-report",
        status=status,
        department_id=department.id,
        manager_id=manager_id,
        created_at=datetime(2026, 1, 1, 12, 0, 0),
        terminated_at=terminated_at,
    )
    db.add(user)
    db.flush()
    return user


def create_role(db, name):
    role = Role(name=name, description="Test role")
    db.add(role)
    db.flush()
    return role


def assign_role(db, user, role):
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.flush()


def test_identity_inventory_returns_identity_details(db):
    department = create_department(db)
    user = create_user(
        db,
        department,
        username="priya.nair",
        employee_id="EMP001",
    )

    report = get_identity_inventory(db)

    assert report["total_count"] == 1
    assert len(report["items"]) == 1

    item = report["items"][0]
    assert item["user_id"] == user.id
    assert item["employee_id"] == "EMP001"
    assert item["username"] == "priya.nair"
    assert item["department"] == "Engineering"
    assert item["status"] == "ACTIVE"
    assert item["manager_id"] is None
    assert item["role_assignment_count"] == 0


def test_identity_inventory_counts_role_assignments(db):
    department = create_department(db)
    user = create_user(
        db,
        department,
        username="rahul.mehta",
        employee_id="EMP002",
    )
    first_role = create_role(db, "Analyst")
    second_role = create_role(db, "Reviewer")

    assign_role(db, user, first_role)
    assign_role(db, user, second_role)

    report = get_identity_inventory(db)

    assert report["total_count"] == 1
    assert report["items"][0]["role_assignment_count"] == 2


def test_identity_inventory_includes_terminated_users(db):
    department = create_department(db)
    termination_time = datetime(2026, 2, 1, 12, 0, 0)

    create_user(
        db,
        department,
        username="former.employee",
        employee_id="EMP003",
        status="TERMINATED",
        terminated_at=termination_time,
    )

    report = get_identity_inventory(db)

    assert report["total_count"] == 1
    item = report["items"][0]
    assert item["status"] == "TERMINATED"
    assert item["terminated_at"] == termination_time


def test_identity_inventory_returns_empty_report_when_no_users_exist(db):
    report = get_identity_inventory(db)

    assert report == {
        "total_count": 0,
        "items": [],
    }


def test_identity_inventory_does_not_expose_authentication_secrets(db):
    department = create_department(db)
    create_user(
        db,
        department,
        username="sneha.rao",
        employee_id="EMP004",
    )

    report = get_identity_inventory(db)

    for item in report["items"]:
        assert "password_hash" not in item
        assert "failed_attempts" not in item
        assert "locked_until" not in item
