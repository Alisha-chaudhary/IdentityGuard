"""Tests for the PAM read endpoints (GET /pam/safes, /pam/requests,
/pam/checkouts) added to surface privileged-access data on the frontend."""

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


def _grant(db, username, role):
    user = db.execute(
        __import__("sqlalchemy").select(User).where(User.username == username)
    ).scalar()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()


def test_pam_reads_require_authentication(db):
    department = Department(name="PAM Reads Department")
    db.add(department)
    db.flush()

    user = User(
        employee_id="PAMR001",
        username="pam.reader",
        full_name="PAM Reader",
        email="pam.reader@example.test",
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

    perm = Permission(resource_id=resource.id, action="pam.request")
    db.add(perm)
    db.flush()

    role = Role(name="PAM Reader", description="reads pam", is_privileged=False)
    db.add(role)
    db.flush()
    db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()

    token = create_access_token(user.username)
    client = _make_client(db)
    try:
        for path in ("/pam/safes", "/pam/requests", "/pam/checkouts"):
            response = client.get(path)
            assert response.status_code == 401, path
    finally:
        _teardown()


def test_pam_reads_require_pam_request_permission(db):
    department = Department(name="PAM Reads Department")
    db.add(department)
    db.flush()

    user = User(
        employee_id="PAMR002",
        username="pam.nope",
        full_name="PAM Nope",
        email="pam.nope@example.test",
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

    # Any platform permission other than pam.request.
    perm = Permission(resource_id=resource.id, action="audit.read")
    db.add(perm)
    db.flush()

    role = Role(
        name="No PAM", description="no pam perms", is_privileged=False
    )
    db.add(role)
    db.flush()
    db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()

    token = create_access_token(user.username)
    headers = {"Authorization": f"Bearer {token}"}
    client = _make_client(db)
    try:
        for path in ("/pam/safes", "/pam/requests", "/pam/checkouts"):
            response = client.get(path, headers=headers)
            assert response.status_code == 403, path
    finally:
        _teardown()


def test_pam_safes_return_accounts_without_credentials(seeded, api):
    admin_token = api.login("identityguard.admin")
    headers = {"Authorization": admin_token["Authorization"]}

    response = api.get("/pam/safes", headers=headers)
    assert response.status_code == 200, response.text
    safes = response.json()
    assert len(safes) == 2
    for safe in safes:
        assert set(["id", "name", "description", "status", "accounts"]) <= set(
            safe.keys()
        )
        assert safe["status"] == "ACTIVE"
        for account in safe["accounts"]:
            # No credentials are ever exposed.
            assert "password" not in account
            assert "secret" not in account
            assert set(
                ["id", "safe_id", "name", "system_name", "account_type", "status"]
            ) <= set(account.keys())


def test_pam_requests_and_checkouts_list(seeded, api):
    headers = {"Authorization": api.login("identityguard.admin")["Authorization"]}

    response = api.get("/pam/requests", headers=headers)
    assert response.status_code == 200, response.text
    requests_payload = response.json()
    assert isinstance(requests_payload, list)

    response = api.get("/pam/checkouts", headers=headers)
    assert response.status_code == 200, response.text
    checkouts_payload = response.json()
    assert isinstance(checkouts_payload, list)


def test_pam_safe_shape_matches_frontend_expectations(seeded, api):
    headers = {"Authorization": api.login("identityguard.admin")["Authorization"]}
    response = api.get("/pam/safes", headers=headers)
    safes = response.json()

    servers = next(s for s in safes if s["name"] == "Production Servers")
    account_names = {a["name"] for a in servers["accounts"]}
    assert "root-PROD-LINUX-01" in account_names
    assert "administrator-PROD-WIN-01" in account_names
