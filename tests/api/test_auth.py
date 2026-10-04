from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.deps import get_db
from app.audit.events import EventType
from app.audit.service import verify_chain
from app.db.models import AuditEvent, Department, User
from app.main import app
from app.core.security import create_access_token, hash_password


def create_test_user(
    db,
    *,
    username="test.user",
    password="StrongPassword!2026",
    status="ACTIVE",
):
    department = Department(name="Test")
    db.add(department)
    db.flush()

    user = User(
        employee_id="TEST001",
        username=username,
        full_name="Test User",
        email=f"{username}@example.test",
        password_hash=hash_password(password),
        status=status,
        failed_attempts=0,
        locked_until=None,
        department_id=department.id,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def test_login_returns_access_token(db):
    create_test_user(db)
    client = make_client(db)

    try:
        response = client.post(
            "/auth/login",
            json={
                "username": "test.user",
                "password": "StrongPassword!2026",
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["token_type"] == "bearer"
        assert data["access_token"]
    finally:
        teardown_client()


def test_login_wrong_password_returns_generic_401(db):
    create_test_user(db)
    client = make_client(db)

    try:
        response = client.post(
            "/auth/login",
            json={
                "username": "test.user",
                "password": "WrongPassword!2026",
            },
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"
    finally:
        teardown_client()


def test_unknown_user_returns_same_generic_401(db):
    create_test_user(db)
    client = make_client(db)

    try:
        response = client.post(
            "/auth/login",
            json={
                "username": "unknown.user",
                "password": "WrongPassword!2026",
            },
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"
    finally:
        teardown_client()


def test_disabled_user_cannot_login(db):
    create_test_user(
        db,
        status="DISABLED",
    )
    client = make_client(db)

    try:
        response = client.post(
            "/auth/login",
            json={
                "username": "test.user",
                "password": "StrongPassword!2026",
            },
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"
    finally:
        teardown_client()


def test_account_locks_after_five_failed_attempts(db):
    user = create_test_user(db)
    client = make_client(db)

    try:
        for _ in range(5):
            response = client.post(
                "/auth/login",
                json={
                    "username": "test.user",
                    "password": "WrongPassword!2026",
                },
            )

            assert response.status_code == 401

        db.refresh(user)

        assert user.status == "LOCKED"
        assert user.failed_attempts == 5
        assert user.locked_until is not None
        assert user.locked_until > datetime.now(timezone.utc).replace(
            tzinfo=None
        )
    finally:
        teardown_client()


def test_locked_user_cannot_login(db):
    user = create_test_user(db)

    user.status = "LOCKED"
    user.locked_until = datetime.now(timezone.utc).replace(
        tzinfo=None
    ) + timedelta(minutes=15)

    db.commit()

    client = make_client(db)

    try:
        response = client.post(
            "/auth/login",
            json={
                "username": "test.user",
                "password": "StrongPassword!2026",
            },
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"
    finally:
        teardown_client()


def test_auth_me_requires_token(db):
    create_test_user(db)
    client = make_client(db)

    try:
        response = client.get("/auth/me")

        assert response.status_code == 401
    finally:
        teardown_client()


def test_auth_me_returns_current_user(db):
    create_test_user(db)
    client = make_client(db)

    try:
        login = client.post(
            "/auth/login",
            json={
                "username": "test.user",
                "password": "StrongPassword!2026",
            },
        )

        token = login.json()["access_token"]

        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

        data = response.json()

        assert data["username"] == "test.user"
        assert data["employee_id"] == "TEST001"
        assert data["status"] == "ACTIVE"
    finally:
        teardown_client()


def test_invalid_token_returns_401(db):
    create_test_user(db)
    client = make_client(db)

    try:
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid-token"},
        )

        assert response.status_code == 401
    finally:
        teardown_client()


def test_login_events_are_audited_and_chain_verifies(db):
    create_test_user(db)
    client = make_client(db)

    try:
        response = client.post(
            "/auth/login",
            json={
                "username": "test.user",
                "password": "StrongPassword!2026",
            },
        )

        assert response.status_code == 200

        events = db.scalars(
            select(AuditEvent)
            .order_by(AuditEvent.id)
        ).all()

        assert len(events) == 1
        assert events[0].event_type == EventType.LOGIN_SUCCEEDED.value
        assert events[0].result == "SUCCESS"

        verification = verify_chain(db)

        assert verification.ok is True
        assert verification.checked == 1
    finally:
        teardown_client()