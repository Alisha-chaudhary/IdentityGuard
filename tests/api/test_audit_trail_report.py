from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.audit.service import record_event
from app.core.security import create_access_token
from app.db.models import Department, User
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
    from tests.api.test_reports import grant_reports_read as grant_permission

    grant_permission(db, user)


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def test_audit_trail_report_requires_authentication(db):
    client = make_client(db)

    try:
        response = client.get("/reports/audit-trail")
        assert response.status_code == 401
    finally:
        teardown_client()


def test_audit_trail_report_requires_reports_read_permission(db):
    user = create_user(db, "audit.report.denied", "ATR001")
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/audit-trail",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"
    finally:
        teardown_client()


def test_audit_trail_report_returns_empty_report_for_authorized_user(db):
    user = create_user(db, "audit.report.reader", "ATR002")
    grant_reports_read(db, user)
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/audit-trail",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        body = response.json()

        assert body["total_count"] == 0
        assert body["success_count"] == 0
        assert body["denied_count"] == 0
        assert body["failure_count"] == 0
        assert body["integrity"]["ok"] is True
        assert body["items"] == []
    finally:
        teardown_client()


def test_audit_trail_report_rejects_invalid_limit(db):
    user = create_user(db, "audit.report.limit", "ATR003")
    grant_reports_read(db, user)
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        for limit in ("0", "501"):
            response = client.get(
                "/reports/audit-trail",
                params={"limit": limit},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
    finally:
        teardown_client()

def test_audit_trail_report_filters_events_and_checks_full_chain(db):
    user = create_user(db, "audit.report.filter", "ATR004")
    grant_reports_read(db, user)

    record_event(
        db,
        actor=user.username,
        event_type="ACCESS_REQUESTED",
        target="request:101",
        action="REQUEST_ACCESS",
        result="SUCCESS",
        reason="Test access request",
        correlation_id="audit-filter-test",
    )
    record_event(
        db,
        actor=user.username,
        event_type="ACCESS_REJECTED",
        target="request:102",
        action="REJECT_ACCESS",
        result="DENIED",
        reason="Test rejection",
        correlation_id="audit-filter-test",
    )
    db.commit()

    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/audit-trail",
            params={"event_type": "ACCESS_REQUESTED"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        body = response.json()

        assert body["total_count"] == 1
        assert body["success_count"] == 1
        assert body["denied_count"] == 0
        assert body["failure_count"] == 0
        assert body["integrity"]["ok"] is True
        assert body["integrity"]["checked"] == 2
        assert len(body["items"]) == 1
        assert body["items"][0]["event_type"] == "ACCESS_REQUESTED"
        assert body["items"][0]["target"] == "request:101"
    finally:
        teardown_client()
