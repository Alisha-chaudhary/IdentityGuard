
import pytest
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
from app.pam.models import PamAccount, PamSafe
from app.main import app


PAM_PERMISSIONS = [
    "pam.request",
    "pam.approve",
    "pam.checkout",
    "pam.revoke",
]


@pytest.fixture()
def pam_api_setup(db):
    department = Department(name="PAM Test Department")
    db.add(department)
    db.flush()

    users = {}
    for username, employee_id in [
        ("pam.requester", "PAM001"),
        ("pam.approver", "PAM002"),
        ("pam.outsider", "PAM003"),
    ]:
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
        users[username] = user

    db.flush()

    resource = Resource(
        name="IdentityGuard",
        resource_type="platform",
        description="IdentityGuard platform",
    )
    db.add(resource)
    db.flush()

    permissions = {}
    for action in PAM_PERMISSIONS:
        permission = Permission(
            resource_id=resource.id,
            action=action,
        )
        db.add(permission)
        db.flush()
        permissions[action] = permission

    roles = {}
    for username, actions in [
        ("pam.requester", ["pam.request", "pam.checkout"]),
        ("pam.approver", ["pam.approve", "pam.revoke"]),
    ]:
        role = Role(
            name=f"{username}-test-role",
            description="PAM API test role",
            is_privileged=True,
        )
        db.add(role)
        db.flush()
        roles[username] = role

        for action in actions:
            db.add(
                RolePermission(
                    role_id=role.id,
                    permission_id=permissions[action].id,
                )
            )

        db.add(
            UserRole(
                user_id=users[username].id,
                role_id=role.id,
            )
        )

    safe = PamSafe(
        name="Test Safe",
        description="Safe for PAM API tests",
        status="ACTIVE",
    )
    db.add(safe)
    db.flush()

    account = PamAccount(
        safe_id=safe.id,
        name="test-admin",
        system_name="test-server",
        account_type="administrator",
        description="Test privileged account",
        status="ACTIVE",
    )
    db.add(account)
    db.commit()

    return {
        **users,
        "safe": safe,
        "account": account,
    }


@pytest.fixture()
def client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)

    yield test_client

    app.dependency_overrides.clear()


def authenticate(client, user):
    token = create_access_token(user.username)
    client.headers.update(
        {"Authorization": f"Bearer {token}"}
    )


def create_approved_request(client, setup):
    authenticate(client, setup["pam.requester"])

    response = client.post(
        "/pam/requests",
        json={
            "account_id": setup["account"].id,
            "justification": "Approved administrative maintenance",
            "duration_minutes": 30,
        },
    )
    assert response.status_code == 201
    request_id = response.json()["id"]

    authenticate(client, setup["pam.approver"])
    response = client.post(
        f"/pam/requests/{request_id}/decision",
        json={
            "decision": "APPROVED",
            "reason": "Maintenance requirement confirmed",
        },
    )
    assert response.status_code == 200

    return request_id


def test_create_pam_request_returns_201(
    client,
    db,
    pam_api_setup,
):
    authenticate(client, pam_api_setup["pam.requester"])

    response = client.post(
        "/pam/requests",
        json={
            "account_id": pam_api_setup["account"].id,
            "justification": "Investigate server alerts",
            "duration_minutes": 30,
        },
    )

    assert response.status_code == 201
    assert response.json()["status"] == "REQUESTED"
    assert response.json()["requester_id"] == (
        pam_api_setup["pam.requester"].id
    )


def test_request_requires_authentication(client):
    response = client.post(
        "/pam/requests",
        json={
            "account_id": 1,
            "justification": "Maintenance",
            "duration_minutes": 30,
        },
    )

    assert response.status_code == 401


def test_request_requires_permission(
    client,
    pam_api_setup,
):
    authenticate(client, pam_api_setup["pam.outsider"])

    response = client.post(
        "/pam/requests",
        json={
            "account_id": pam_api_setup["account"].id,
            "justification": "Maintenance",
            "duration_minutes": 30,
        },
    )

    assert response.status_code == 403


def test_invalid_request_data_returns_422(
    client,
    pam_api_setup,
):
    authenticate(client, pam_api_setup["pam.requester"])

    response = client.post(
        "/pam/requests",
        json={
            "account_id": pam_api_setup["account"].id,
            "justification": "   ",
            "duration_minutes": 61,
        },
    )

    assert response.status_code == 422


def test_unknown_request_returns_404(
    client,
    pam_api_setup,
):
    authenticate(client, pam_api_setup["pam.approver"])

    response = client.post(
        "/pam/requests/99999/decision",
        json={
            "decision": "APPROVED",
            "reason": "Approved",
        },
    )

    assert response.status_code == 404


def test_approve_request_and_checkout(
    client,
    pam_api_setup,
):
    request_id = create_approved_request(
        client,
        pam_api_setup,
    )

    authenticate(client, pam_api_setup["pam.requester"])

    response = client.post(
        f"/pam/requests/{request_id}/checkout",
    )

    assert response.status_code == 201
    assert response.json()["status"] == "ACTIVE"
    assert response.json()["checked_out_by_id"] == (
        pam_api_setup["pam.requester"].id
    )
    assert response.json()["expires_at"] is not None


def test_reject_request(
    client,
    pam_api_setup,
):
    authenticate(client, pam_api_setup["pam.requester"])

    created = client.post(
        "/pam/requests",
        json={
            "account_id": pam_api_setup["account"].id,
            "justification": "Temporary investigation",
            "duration_minutes": 20,
        },
    )
    assert created.status_code == 201

    authenticate(client, pam_api_setup["pam.approver"])
    response = client.post(
        f"/pam/requests/{created.json()['id']}/decision",
        json={
            "decision": "REJECTED",
            "reason": "Request not justified",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"


def test_revoke_checkout(
    client,
    pam_api_setup,
):
    request_id = create_approved_request(
        client,
        pam_api_setup,
    )

    authenticate(client, pam_api_setup["pam.requester"])
    checkout = client.post(
        f"/pam/requests/{request_id}/checkout",
    )
    assert checkout.status_code == 201

    authenticate(client, pam_api_setup["pam.approver"])
    response = client.post(
        f"/pam/checkouts/{checkout.json()['id']}/revoke",
        json={"reason": "Maintenance completed"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "REVOKED"
    assert response.json()["ended_at"] is not None