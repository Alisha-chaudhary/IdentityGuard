from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.security import create_access_token, hash_password
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


def create_user(db, *, username, employee_id):
    department = Department(name=f"Department-{employee_id}")
    db.add(department)
    db.flush()

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        password_hash=hash_password("StrongPassword!2026"),
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
    resource = db.query(Resource).filter_by(
        name="IdentityGuard"
    ).first()

    if resource is None:
        resource = Resource(
            name="IdentityGuard",
            resource_type="platform",
            description="IdentityGuard resource",
        )
        db.add(resource)
        db.flush()

    permission = db.query(Permission).filter_by(
        resource_id=resource.id,
        action="reports.read",
    ).first()

    if permission is None:
        permission = Permission(
            resource_id=resource.id,
            action="reports.read",
        )
        db.add(permission)
        db.flush()

    role = Role(
        name=f"{user.username}-reports-role",
        description="Test reports role",
        is_privileged=False,
    )
    db.add(role)
    db.flush()

    db.add(
        RolePermission(
            role_id=role.id,
            permission_id=permission.id,
        )
    )
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def test_identity_inventory_requires_authentication(db):
    client = make_client(db)

    try:
        response = client.get("/reports/identity-inventory")

        assert response.status_code == 401
    finally:
        teardown_client()


def test_identity_inventory_requires_reports_read_permission(db):
    user = create_user(
        db,
        username="report.denied",
        employee_id="RPT001",
    )
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/identity-inventory",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"
    finally:
        teardown_client()


def test_identity_inventory_returns_report_for_authorized_user(db):
    user = create_user(
        db,
        username="report.reader",
        employee_id="RPT002",
    )
    grant_reports_read(db, user)
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/identity-inventory",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 1
        assert len(data["items"]) == 1

        item = data["items"][0]
        assert item["username"] == "report.reader"
        assert item["employee_id"] == "RPT002"
        assert item["status"] == "ACTIVE"
        assert item["role_assignment_count"] == 1

        assert "password_hash" not in item
        assert "failed_attempts" not in item
        assert "locked_until" not in item
    finally:
        teardown_client()
