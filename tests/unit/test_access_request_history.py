from datetime import datetime

from app.db.models import AccessRequest, Department, Role, User
from app.reports.access_request_history import (
    get_access_request_history,
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
        password_hash="must-not-appear-in-report",
        status="ACTIVE",
        department_id=department.id,
    )
    db.add(user)
    db.flush()
    return user


def create_role(db, name, is_privileged=False):
    role = Role(
        name=name,
        description="Test role",
        is_privileged=is_privileged,
    )
    db.add(role)
    db.flush()
    return role


def create_request(
    db,
    requester,
    target_user,
    role,
    request_id,
    status,
    requested_at,
):
    request = AccessRequest(
        requester_id=requester.id,
        target_user_id=target_user.id,
        role_id=role.id,
        justification=f"Test justification {request_id}",
        status=status,
        decision_by=(
            "test.approver"
            if status in ("APPROVED", "REJECTED", "PROVISIONED")
            else None
        ),
        decision_reason=(
            f"Test decision {request_id}"
            if status in ("APPROVED", "REJECTED", "PROVISIONED")
            else None
        ),
        requested_at=requested_at,
        decided_at=(
            requested_at
            if status in ("APPROVED", "REJECTED", "PROVISIONED")
            else None
        ),
        provisioned_at=(
            requested_at if status == "PROVISIONED" else None
        ),
    )
    db.add(request)
    db.flush()
    return request


def test_access_request_history_returns_empty_report(db):
    report = get_access_request_history(db)

    assert report == {
        "total_count": 0,
        "requested_count": 0,
        "approved_count": 0,
        "rejected_count": 0,
        "provisioned_count": 0,
        "items": [],
    }


def test_access_request_history_counts_all_statuses(db):
    requester = create_user(db, "history.requester", "ARH001")
    target = create_user(db, "history.target", "ARH002")
    role = create_role(db, "History Reviewer")

    statuses = [
        "REQUESTED",
        "APPROVED",
        "REJECTED",
        "PROVISIONED",
    ]

    for index, status in enumerate(statuses, start=1):
        create_request(
            db,
            requester,
            target,
            role,
            request_id=index,
            status=status,
            requested_at=datetime(2026, 1, index, 10, 0, 0),
        )

    report = get_access_request_history(db)

    assert report["total_count"] == 4
    assert report["requested_count"] == 1
    assert report["approved_count"] == 1
    assert report["rejected_count"] == 1
    assert report["provisioned_count"] == 1


def test_access_request_history_returns_request_and_identity_details(db):
    requester = create_user(db, "history.requester", "ARH003")
    target = create_user(db, "history.target", "ARH004")
    role = create_role(db, "Privileged Operator", is_privileged=True)

    requested_at = datetime(2026, 5, 12, 9, 30, 0)

    create_request(
        db,
        requester,
        target,
        role,
        request_id=1,
        status="APPROVED",
        requested_at=requested_at,
    )

    report = get_access_request_history(db)

    assert report["total_count"] == 1

    item = report["items"][0]
    assert item["requester_username"] == "history.requester"
    assert item["target_username"] == "history.target"
    assert item["role_name"] == "Privileged Operator"
    assert item["is_privileged"] is True
    assert item["status"] == "APPROVED"
    assert item["justification"] == "Test justification 1"
    assert item["requested_at"] == requested_at
    assert item["decision_by"] == "test.approver"

    assert "password_hash" not in item
    assert "email" not in item


def test_access_request_history_orders_newest_first(db):
    requester = create_user(db, "history.requester", "ARH005")
    target = create_user(db, "history.target", "ARH006")
    role = create_role(db, "History Analyst")

    create_request(
        db, requester, target, role, 1, "REQUESTED",
        datetime(2026, 1, 1, 10, 0, 0),
    )
    create_request(
        db, requester, target, role, 2, "REQUESTED",
        datetime(2026, 1, 3, 10, 0, 0),
    )
    create_request(
        db, requester, target, role, 3, "REQUESTED",
        datetime(2026, 1, 2, 10, 0, 0),
    )

    report = get_access_request_history(db)

    assert [
        item["requested_at"] for item in report["items"]
    ] == [
        datetime(2026, 1, 3, 10, 0, 0),
        datetime(2026, 1, 2, 10, 0, 0),
        datetime(2026, 1, 1, 10, 0, 0),
    ]