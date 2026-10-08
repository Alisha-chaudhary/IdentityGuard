import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_current_user, get_db
from app.db.models import (
    Department,
    Permission,
    Resource,
    Role,
    RolePermission,
    User,
    UserRole,
)


@pytest.fixture()
def api_setup(db):
    department = Department(name="Finance")
    db.add(department)
    db.flush()

    requester = User(
        employee_id="EMP001",
        username="requester",
        full_name="Requester User",
        email="requester@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    approver = User(
        employee_id="EMP002",
        username="approver",
        full_name="Approver User",
        email="approver@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    target = User(
        employee_id="EMP003",
        username="target",
        full_name="Target User",
        email="target@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add_all([requester, approver, target])
    db.flush()

    resource = Resource(
        name="IdentityGuard",
        resource_type="platform",
        description="Test platform",
    )
    db.add(resource)
    db.flush()

    permissions = {}

    for action in [
        "access.request",
        "access.approve",
        "access.provision",
    ]:
        permission = Permission(
            resource_id=resource.id,
            action=action,
        )
        db.add(permission)
        db.flush()
        permissions[action] = permission

    requester_role = Role(
        name="Access Requester",
        description="Test access requester role",
        is_privileged=False,
    )
    db.add(requester_role)
    db.flush()

    db.add(
        RolePermission(
            role_id=requester_role.id,
            permission_id=permissions["access.request"].id,
        )
    )

    approver_role = Role(
        name="IAM Administrator",
        description="Test IAM administrator",
        is_privileged=True,
    )
    db.add(approver_role)
    db.flush()

    for action in [
        "access.approve",
        "access.provision",
    ]:
        db.add(
            RolePermission(
                role_id=approver_role.id,
                permission_id=permissions[action].id,
            )
        )

    db.add(
        UserRole(
            user_id=requester.id,
            role_id=requester_role.id,
        )
    )

    db.add(
        UserRole(
            user_id=approver.id,
            role_id=approver_role.id,
        )
    )

    db.commit()

    return {
        "requester": requester,
        "approver": approver,
        "target": target,
        "role": approver_role,
    }


@pytest.fixture()
def client(db, api_setup):
    from app.main import app

    current_user = {"user": api_setup["requester"]}

    def override_current_user():
        return current_user["user"]

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db] = override_db

    test_client = TestClient(app)
    test_client.current_user = current_user

    yield test_client

    app.dependency_overrides.clear()


def test_create_access_request_returns_201(client, api_setup):
    response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
        },
    )

    assert response.status_code == 201

    body = response.json()

    assert body["status"] == "REQUESTED"
    assert body["requester_id"] == api_setup["requester"].id
    assert body["target_user_id"] == api_setup["target"].id
    assert body["role_id"] == api_setup["role"].id


def test_create_access_request_requires_permission(client, api_setup):
    client.current_user["user"] = api_setup["target"]

    response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Request access",
        },
    )

    assert response.status_code == 403


def test_list_access_requests_requires_approval_permission(
    client,
    api_setup,
):
    client.current_user["user"] = api_setup["approver"]

    response = client.get("/access-requests")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_approve_access_request(client, api_setup):
    create_response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
        },
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    client.current_user["user"] = api_setup["approver"]

    response = client.post(
        f"/access-requests/{request_id}/approve",
        json={
            "reason": "Business requirement confirmed",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"
    assert response.json()["decision_by"] == "approver"


def test_requester_cannot_approve_own_request(client, api_setup):
    create_response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
        },
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    response = client.post(
        f"/access-requests/{request_id}/approve",
        json={
            "reason": "I approve this",
        },
    )

    assert response.status_code == 403


def test_reject_access_request(client, api_setup):
    create_response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
        },
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    client.current_user["user"] = api_setup["approver"]

    response = client.post(
        f"/access-requests/{request_id}/reject",
        json={
            "reason": "Insufficient business justification",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"


def test_provision_requires_provision_permission(
    client,
    api_setup,
):
    create_response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
        },
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    client.current_user["user"] = api_setup["target"]

    response = client.post(
        f"/access-requests/{request_id}/provision",
    )

    assert response.status_code == 403


def test_provision_before_approval_returns_409(
    client,
    api_setup,
):
    create_response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
        },
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    client.current_user["user"] = api_setup["approver"]

    response = client.post(
        f"/access-requests/{request_id}/provision",
    )

    assert response.status_code == 409


def test_approved_request_can_be_provisioned(
    client,
    api_setup,
):
    create_response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
            "expires_at": "2027-01-02T12:00:00",
        },
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    client.current_user["user"] = api_setup["approver"]

    approve_response = client.post(
        f"/access-requests/{request_id}/approve",
        json={
            "reason": "Business requirement confirmed",
        },
    )

    assert approve_response.status_code == 200

    response = client.post(
        f"/access-requests/{request_id}/provision",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "PROVISIONED"
    assert response.json()["provisioned_at"] is not None


def test_unknown_request_returns_404(client, api_setup):
    client.current_user["user"] = api_setup["approver"]

    response = client.post(
        "/access-requests/9999/approve",
        json={
            "reason": "Approved",
        },
    )

    assert response.status_code == 404


def test_second_approval_returns_409(
    client,
    api_setup,
):
    create_response = client.post(
        "/access-requests",
        json={
            "target_user_id": api_setup["target"].id,
            "role_id": api_setup["role"].id,
            "justification": "Temporary finance access",
        },
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    client.current_user["user"] = api_setup["approver"]

    first_response = client.post(
        f"/access-requests/{request_id}/approve",
        json={
            "reason": "Approved",
        },
    )

    assert first_response.status_code == 200

    second_response = client.post(
        f"/access-requests/{request_id}/approve",
        json={
            "reason": "Approved again",
        },
    )

    assert second_response.status_code == 409