"""Login rate limiting on /auth/login.

Verifies that repeated login attempts from the same client IP are throttled
and that the limiter is resettable for tests. Limits are in-memory and
single-process only (see README limitations).
"""

from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.security import hash_password
from app.core.rate_limit import login_rate_limiter
from app.db.models import Department, User
from app.main import app


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def _add_user(db):
    dept = Department(name="RateLimit Dept")
    db.add(dept)
    db.flush()
    user = User(
        employee_id="RL001",
        username="ratelimit.user",
        full_name="Rate Limit User",
        email="ratelimit@example.test",
        password_hash=hash_password("StrongPassword!2026"),
        status="ACTIVE",
        failed_attempts=0,
        locked_until=None,
        department_id=dept.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_login_rate_limits_repeated_attempts(db, monkeypatch):
    _add_user(db)
    # Use a small limit for this test only; monkeypatch restores it after.
    monkeypatch.setattr(login_rate_limiter, "max_requests", 3)
    login_rate_limiter.reset()

    client = make_client(db)
    try:
        # No platform permission, so every attempt that passes rate limiting
        # is rejected with 401 by authentication.
        statuses = []
        for _ in range(4):
            response = client.post(
                "/auth/login",
                json={"username": "ratelimit.user", "password": "StrongPassword!2026"},
            )
            statuses.append(response.status_code)

        assert statuses[:3] == [401, 401, 401], statuses
        assert statuses[3] == 429, statuses
    finally:
        teardown_client()
        login_rate_limiter.reset()


def test_login_allowed_after_reset(db, monkeypatch):
    _add_user(db)
    monkeypatch.setattr(login_rate_limiter, "max_requests", 1)
    login_rate_limiter.reset()

    client = make_client(db)
    try:
        # First attempt passes rate limiting (then 401 on auth).
        assert client.post(
            "/auth/login",
            json={"username": "ratelimit.user", "password": "StrongPassword!2026"},
        ).status_code == 401

        # Second attempt is rate limited.
        assert client.post(
            "/auth/login",
            json={"username": "ratelimit.user", "password": "StrongPassword!2026"},
        ).status_code == 429

        # After reset, allowed again.
        login_rate_limiter.reset()
        assert client.post(
            "/auth/login",
            json={"username": "ratelimit.user", "password": "StrongPassword!2026"},
        ).status_code == 401
    finally:
        teardown_client()
        login_rate_limiter.reset()
