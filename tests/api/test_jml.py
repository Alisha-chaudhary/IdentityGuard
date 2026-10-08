from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.security import create_access_token
from app.db.models import Department, Role, User, UserRole
from app.main import app


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def create_department(db, name):
    department = Department(name=name)
    db.add(department)
    db.flush()
    return department


def create_admin_user(db, department):
    user = User(
        employee_id="ADMIN001",
        username="admin.user",
        full_name="Admin User",
        email="admin@example.test",
        password_hash="existing-hash",
        status="ACTIVE",
        department_id=department.id,
    )

    db.add(user)
    db.flush()

    return user


def create_regular_user(db, department):
    user = User(
        employee_id="USER001",
        username="regular.user",
        full_name="Regular User",
        email="regular@example.test",
        password_hash="existing-hash",
        status="ACTIVE",
        department_id=department.id,
    )

    db.add(user)
    db.flush()

    return user


def create_identityguard_admin_role(db):
    role = Role(
        name="IAM API Test Administrator",
        description="Test administrator for JML API tests",
        is_privileged=True,
    )

    db.add(role)
    db.flush()

    return role


def create_permission(db):
    from app.db.models import Permission, Resource

    resource = Resource(
        name="IdentityGuard",
        resource_type="platform",
        description="IdentityGuard platform administration",
    )

    db.add(resource)
    db.flush()

    permission = Permission(
        resource_id=resource.id,
        action="user.create",
    )

    db.add(permission)
    db.flush()

    return permission


def assign_permission(db, user, role, permission):
    from app.db.models import RolePermission

    db.add(
        RolePermission(
            role_id=role.id,
            permission_id=permission.id,
        )
    )

    db.add(
        UserRole(
            user_id=user.id,
            role_id=role.id,
        )
    )

    db.commit()


def auth_headers(user):
    token = create_access_token(user.username)

    return {
        "Authorization": f"Bearer {token}",
    }


def test_jml_joiner_api_creates_user(db):
    department = create_department(db, "IT")
    admin = create_admin_user(db, department)

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        response = client.post(
            "/jml/users",
            headers=auth_headers(admin),
            json={
                "employee_id": "EMP200",
                "username": "api.joiner",
                "full_name": "API Joiner",
                "email": "api.joiner@example.test",
                "department_id": department.id,
                "password": "StrongPassword123!",
            },
        )

        assert response.status_code == 201

        data = response.json()

        assert data["username"] == "api.joiner"
        assert data["status"] == "ACTIVE"
        assert data["department_id"] == department.id

    finally:
        teardown_client()


def test_jml_joiner_api_requires_permission(db):
    department = create_department(db, "IT")
    user = create_regular_user(db, department)

    client = make_client(db)

    try:
        response = client.post(
            "/jml/users",
            headers=auth_headers(user),
            json={
                "employee_id": "EMP201",
                "username": "unauthorized.joiner",
                "full_name": "Unauthorized Joiner",
                "email": "unauthorized@example.test",
                "department_id": department.id,
                "password": "StrongPassword123!",
            },
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"

    finally:
        teardown_client()


def test_jml_joiner_api_rejects_duplicate_identity(db):
    department = create_department(db, "IT")
    admin = create_admin_user(db, department)

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        payload = {
            "employee_id": "EMP202",
            "username": "duplicate.api",
            "full_name": "Duplicate API User",
            "email": "duplicate.api@example.test",
            "department_id": department.id,
            "password": "StrongPassword123!",
        }

        first = client.post(
            "/jml/users",
            headers=auth_headers(admin),
            json=payload,
        )

        second = client.post(
            "/jml/users",
            headers=auth_headers(admin),
            json=payload,
        )

        assert first.status_code == 201
        assert second.status_code == 409

    finally:
        teardown_client()


def test_jml_mover_api_changes_department(db):
    old_department = create_department(db, "IT")
    new_department = create_department(db, "Finance")

    admin = create_admin_user(db, old_department)

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        response = client.patch(
            f"/jml/users/{admin.id}/move",
            headers=auth_headers(admin),
            json={
                "department_id": new_department.id,
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["department_id"] == new_department.id

    finally:
        teardown_client()


def test_jml_mover_api_requires_a_change(db):
    department = create_department(db, "IT")
    admin = create_admin_user(db, department)

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        response = client.patch(
            f"/jml/users/{admin.id}/move",
            headers=auth_headers(admin),
            json={},
        )

        assert response.status_code == 422
        assert response.json()["detail"] == (
            "At least one mover field must be provided"
        )

    finally:
        teardown_client()


def test_jml_mover_api_rejects_unknown_user(db):
    department = create_department(db, "IT")
    admin = create_admin_user(db, department)

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        response = client.patch(
            "/jml/users/99999/move",
            headers=auth_headers(admin),
            json={
                "department_id": department.id,
            },
        )

        assert response.status_code == 404

    finally:
        teardown_client()


def test_jml_leaver_api_terminates_user(db):
    department = create_department(db, "IT")
    admin = create_admin_user(db, department)

    target = User(
        employee_id="EMP203",
        username="api.leaver",
        full_name="API Leaver",
        email="api.leaver@example.test",
        password_hash="existing-hash",
        status="ACTIVE",
        department_id=department.id,
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        response = client.post(
            f"/jml/users/{target.id}/terminate",
            headers=auth_headers(admin),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["username"] == "api.leaver"
        assert data["status"] == "TERMINATED"
        assert data["terminated_at"] is not None

    finally:
        teardown_client()


def test_jml_leaver_api_expires_role_assignments(db):
    department = create_department(db, "IT")
    admin = create_admin_user(db, department)

    target = User(
        employee_id="EMP204",
        username="role.leaver.api",
        full_name="Role Leaver API",
        email="role.leaver.api@example.test",
        password_hash="existing-hash",
        status="ACTIVE",
        department_id=department.id,
    )

    db.add(target)
    db.flush()

    target_role = Role(
        name="Temporary API Role",
        description="Temporary role for API leaver test",
        is_privileged=False,
    )

    db.add(target_role)
    db.flush()

    assignment = UserRole(
        user_id=target.id,
        role_id=target_role.id,
    )

    db.add(assignment)
    db.flush()

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        response = client.post(
            f"/jml/users/{target.id}/terminate",
            headers=auth_headers(admin),
        )

        assert response.status_code == 200

        db.refresh(assignment)

        assert assignment.expires_at is not None

    finally:
        teardown_client()


def test_jml_leaver_api_rejects_unknown_user(db):
    department = create_department(db, "IT")
    admin = create_admin_user(db, department)

    role = create_identityguard_admin_role(db)
    permission = create_permission(db)

    assign_permission(
        db,
        admin,
        role,
        permission,
    )

    client = make_client(db)

    try:
        response = client.post(
            "/jml/users/99999/terminate",
            headers=auth_headers(admin),
        )

        assert response.status_code == 404

    finally:
        teardown_client()


def test_jml_api_rejects_missing_authentication(db):
    department = create_department(db, "IT")
    create_admin_user(db, department)

    client = make_client(db)

    try:
        response = client.post(
            "/jml/users",
            json={
                "employee_id": "EMP205",
                "username": "no.auth",
                "full_name": "No Authentication",
                "email": "no.auth@example.test",
                "department_id": department.id,
                "password": "StrongPassword123!",
            },
        )

        assert response.status_code == 401

    finally:
        teardown_client()