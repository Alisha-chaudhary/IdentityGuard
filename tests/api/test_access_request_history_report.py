from datetime import datetime
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.security import create_access_token
from app.db.models import AccessRequest, Department, Role, User
from app.main import app


def create_user(db, username, employee_id):
    department = Department(name=f"Department-{employee_id}")
    db.add(department)
    db.flush()

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        password_hash="test-password-hash",
        status="ACTIVE",
        failed_attempts=0,
        locked_until=None,
        department_id=department.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def grant_reports_read(db, user):
    from tests.api.test_reports import (
        grant_reports_read as grant_permission,
    )

    grant_permission(db, user)


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def test_access_request_history_requires_authentication(db):
    client = make_client(db)

    try:
        response = client.get("/reports/access-request-history")

        assert response.status_code == 401
    finally:
        teardown_client()


def test_access_request_history_requires_reports_read_permission(db):
    user = create_user(db, "history.report.denied", "ARHA001")
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/access-request-history",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"
    finally:
        teardown_client()


def test_access_request_history_returns_empty_report_for_authorized_user(db):
    user = create_user(db, "history.report.reader", "ARHA002")
    grant_reports_read(db, user)
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/access-request-history",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.json() == {
            "total_count": 0,
            "requested_count": 0,
            "approved_count": 0,
            "rejected_count": 0,
            "provisioned_count": 0,
            "items": [],
        }
    finally:
        teardown_client()

def test_access_request_history_returns_populated_report_for_authorized_user(db):
    requester = create_user(db, "history.requester", "ARHA003")
    target = create_user(db, "history.target", "ARHA004")

    role = Role(
        name="History Reviewer",
        description="Reviews access requests",
        is_privileged=True,
    )
    db.add(role)
    db.flush()

    requested_at = datetime(2026, 5, 12, 9, 30, 0)

    db.add(
        AccessRequest(
            requester_id=requester.id,
            target_user_id=target.id,
            role_id=role.id,
            justification="Investigate a production alert",
            status="APPROVED",
            decision_by="history.approver",
            decision_reason="Approved for investigation",
            requested_at=requested_at,
            decided_at=requested_at,
        )
    )
    db.flush()

    grant_reports_read(db, requester)
    token = create_access_token(requester.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/access-request-history",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 1
        assert data["requested_count"] == 0
        assert data["approved_count"] == 1
        assert data["rejected_count"] == 0
        assert data["provisioned_count"] == 0
        assert len(data["items"]) == 1

        item = data["items"][0]
        assert item["requester_username"] == "history.requester"
        assert item["target_username"] == "history.target"
        assert item["role_name"] == "History Reviewer"
        assert item["is_privileged"] is True
        assert item["status"] == "APPROVED"
        assert item["justification"] == "Investigate a production alert"
        assert item["decision_by"] == "history.approver"
        assert item["decision_reason"] == "Approved for investigation"

        assert "password_hash" not in item
        assert "failed_attempts" not in item
        assert "locked_until" not in item
    finally:
        teardown_client()