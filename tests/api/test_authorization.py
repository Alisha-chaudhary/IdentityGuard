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


def create_user(
    db,
    *,
    username,
    employee_id,
    password="StrongPassword!2026",
):
    department = Department(name=f"Department-{employee_id}")
    db.add(department)
    db.flush()

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        password_hash=hash_password(password),
        status="ACTIVE",
        failed_attempts=0,
        locked_until=None,
        department_id=department.id,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def grant_permission(
    db,
    user,
    *,
    resource_name,
    action,
):
    resource = db.query(Resource).filter(
        Resource.name == resource_name
    ).first()

    if resource is None:
        resource = Resource(
            name=resource_name,
            resource_type="platform",
            description=f"{resource_name} resource",
        )
        db.add(resource)
        db.flush()

    permission = db.query(Permission).filter(
        Permission.resource_id == resource.id,
        Permission.action == action,
    ).first()

    if permission is None:
        permission = Permission(
            resource_id=resource.id,
            action=action,
        )
        db.add(permission)
        db.flush()

    role = Role(
        name=f"{user.username}-{action}-role",
        description="Test authorization role",
        is_privileged=False,
    )
    db.add(role)
    db.flush()

    role_permission = RolePermission(
        role_id=role.id,
        permission_id=permission.id,
    )
    db.add(role_permission)

    assignment = UserRole(
        user_id=user.id,
        role_id=role.id,
    )
    db.add(assignment)

    db.commit()

    return role


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def test_users_requires_authentication(db):
    client = make_client(db)

    try:
        response = client.get("/users")

        assert response.status_code == 401
    finally:
        teardown_client()


def test_users_requires_user_read_permission(db):
    user = create_user(
        db,
        username="no.permission",
        employee_id="AUTH001",
    )

    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"
    finally:
        teardown_client()


def test_users_allows_user_read_permission(db):
    user = create_user(
        db,
        username="reader.user",
        employee_id="AUTH002",
    )

    grant_permission(
        db,
        user,
        resource_name="IdentityGuard",
        action="user.read",
    )

    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

        data = response.json()

        assert isinstance(data, list)
        assert any(
            item["username"] == "reader.user"
            for item in data
        )
    finally:
        teardown_client()


def test_audit_requires_audit_read_permission(db):
    user = create_user(
        db,
        username="audit.denied",
        employee_id="AUTH003",
    )

    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/audit/events",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"
    finally:
        teardown_client()


def test_audit_allows_audit_read_permission(db):
    user = create_user(
        db,
        username="audit.reader",
        employee_id="AUTH004",
    )

    grant_permission(
        db,
        user,
        resource_name="IdentityGuard",
        action="audit.read",
    )

    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/audit/events",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert isinstance(response.json(), list)
    finally:
        teardown_client()