"""Tests for the extended GET /roles endpoint that now exposes the
permissions associated with each role."""

from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.security import create_access_token
from app.db.models import (
    Department,
    Permission,
    Resource,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.main import app


def _make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _teardown():
    app.dependency_overrides.clear()


def test_roles_include_permissions(db):
    department = Department(name="Roles Department")
    db.add(department)
    db.flush()

    user = User(
        employee_id="RL001",
        username="role.reader",
        full_name="Role Reader",
        email="role.reader@example.test",
        password_hash="x",
        status="ACTIVE",
        failed_attempts=0,
        department_id=department.id,
    )
    db.add(user)
    db.flush()

    resource = Resource(name="IdentityGuard", resource_type="platform")
    db.add(resource)
    db.flush()

    read_perm = Permission(resource_id=resource.id, action="user.read")
    approve_perm = Permission(resource_id=resource.id, action="access.approve")
    db.add_all([read_perm, approve_perm])
    db.flush()

    role = Role(
        name="Role Viewer",
        description="Can read roles",
        is_privileged=False,
    )
    db.add(role)
    db.flush()
    db.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
    db.add(RolePermission(role_id=role.id, permission_id=approve_perm.id))
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()

    token = create_access_token(user.username)
    headers = {"Authorization": f"Bearer {token}"}
    client = _make_client(db)
    try:
        response = client.get("/roles", headers=headers)
        assert response.status_code == 200, response.text
        roles = response.json()
        viewer = next(r for r in roles if r["name"] == "Role Viewer")
        assert viewer["is_privileged"] is False
        assert set(viewer["permissions"]) == {
            "IdentityGuard:user.read",
            "IdentityGuard:access.approve",
        }
    finally:
        _teardown()


def test_roles_require_user_read_permission(db):
    department = Department(name="Roles Department")
    db.add(department)
    db.flush()

    user = User(
        employee_id="RL002",
        username="role.nope",
        full_name="Role Nope",
        email="role.nope@example.test",
        password_hash="x",
        status="ACTIVE",
        failed_attempts=0,
        department_id=department.id,
    )
    db.add(user)
    db.flush()

    resource = Resource(name="IdentityGuard", resource_type="platform")
    db.add(resource)
    db.flush()

    # Any platform permission other than user.read.
    perm = Permission(resource_id=resource.id, action="audit.read")
    db.add(perm)
    db.flush()

    role = Role(name="No Roles Read", description="no user.read", is_privileged=False)
    db.add(role)
    db.flush()
    db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()

    token = create_access_token(user.username)
    headers = {"Authorization": f"Bearer {token}"}
    client = _make_client(db)
    try:
        response = client.get("/roles", headers=headers)
        assert response.status_code == 403, response.text
    finally:
        _teardown()


def test_roles_read_on_seeded_database(seeded, api):
    headers = {"Authorization": api.login("identityguard.admin")["Authorization"]}
    response = api.get("/roles", headers=headers)
    assert response.status_code == 200, response.text
    roles = response.json()
    names = {role["name"] for role in roles}
    assert "IAM Administrator" in names
    assert "Security Auditor" in names
    assert "PAM Operator" in names

    iam_admin = next(r for r in roles if r["name"] == "IAM Administrator")
    assert iam_admin["is_privileged"] is True
    assert "IdentityGuard:reports.read" in iam_admin["permissions"]

    help_desk = next(r for r in roles if r["name"] == "Help Desk")
    assert help_desk["permissions"] == []
