from fastapi.testclient import TestClient

from app.api.deps import get_db
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


def test_pam_activity_report_requires_authentication(db):
    client = make_client(db)

    try:
        response = client.get("/reports/pam-activity")
        assert response.status_code == 401
    finally:
        teardown_client()


def test_pam_activity_report_requires_reports_read_permission(db):
    user = create_user(db, "pam.report.denied", "PAMR001")
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/pam-activity",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"
    finally:
        teardown_client()


def test_pam_activity_report_returns_empty_report_for_authorized_user(db):
    user = create_user(db, "pam.report.reader", "PAMR002")
    grant_reports_read(db, user)
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/pam-activity",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.json() == {
            "total_count": 0,
            "items": [],
        }
    finally:
        teardown_client()