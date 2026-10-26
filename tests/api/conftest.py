"""Shared fixtures that exercise the *real* seed data and the real login."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.deps import get_db
from app.core.clock import SystemClock, set_clock
from app.db.models import Permission, Resource, Role, RolePermission, User, UserRole
from app.db.seed import seed, seed_demo_platform
from app.main import app

SEED_PASSWORD = "Str0ng-Demo-Passw0rd"


@pytest.fixture()
def seeded(db, monkeypatch):
    """A database seeded exactly like `python -m app.db.seed`."""
    # Cheap Argon2 parameters keep the suite fast (production uses defaults).
    from argon2 import PasswordHasher
    import app.core.security as security

    monkeypatch.setattr(
        security, "_hasher", PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    )
    monkeypatch.setenv("IDENTITYGUARD_SEED_PASSWORD", SEED_PASSWORD)
    seed(db)
    seed_demo_platform(db, SEED_PASSWORD)
    return db


@pytest.fixture()
def api(seeded):
    """TestClient wired to the seeded DB, with a login() helper."""

    def override_get_db():
        yield seeded

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    def login(username: str, password: str = SEED_PASSWORD) -> dict:
        response = client.post(
            "/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    client.login = login
    yield client
    app.dependency_overrides.clear()
    set_clock(SystemClock())


def user_by_name(db, username: str) -> User:
    return db.scalar(select(User).where(User.username == username))


def role_by_name(db, name: str) -> Role:
    return db.scalar(select(Role).where(Role.name == name))


def make_role_with_permissions(db, name: str, actions: list[str], privileged=False) -> Role:
    resource = db.scalar(select(Resource).where(Resource.name == "IdentityGuard"))
    role = Role(name=name, description=name, is_privileged=privileged)
    db.add(role)
    db.flush()
    for action in actions:
        permission = db.scalar(
            select(Permission).where(
                Permission.resource_id == resource.id, Permission.action == action
            )
        )
        db.add(RolePermission(role_id=role.id, permission_id=permission.id))
    db.commit()
    return role


def grant(db, username: str, role: Role) -> None:
    db.add(UserRole(user_id=user_by_name(db, username).id, role_id=role.id))
    db.commit()


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter():
    """Reset the in-memory login rate limiter around every API test so
    one test's login attempts cannot rate-limit another test."""
    from app.core.rate_limit import login_rate_limiter

    login_rate_limiter.reset()
    yield
    login_rate_limiter.reset()
