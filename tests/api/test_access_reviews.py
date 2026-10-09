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
def review_api_setup(db):
    department = Department(name="Finance")
    db.add(department)
    db.flush()

    admin = User(
        employee_id="AR001",
        username="review_admin",
        full_name="Review Administrator",
        email="review_admin@example.test",
        department_id=department.id,
        status="ACTIVE",
    )
    reviewer1 = User(
        employee_id="AR002",
        username="reviewer_one",
        full_name="Security Reviewer One",
        email="reviewer_one@example.test",
        department_id=department.id,
        status="ACTIVE",
    )
    reviewer2 = User(
        employee_id="AR003",
        username="reviewer_two",
        full_name="Security Reviewer Two",
        email="reviewer_two@example.test",
        department_id=department.id,
        status="ACTIVE",
    )
    target = User(
        employee_id="AR004",
        username="review_target",
        full_name="Review Target",
        email="review_target@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add_all([admin, reviewer1, reviewer2, target])
    db.flush()

    resource = Resource(
        name="IdentityGuard",
        resource_type="platform",
        description="Test platform",
    )
    db.add(resource)
    db.flush()

    actions = [
        "access_review.create",
        "access_review.view",
        "access_review.decide",
        "access_review.complete",
    ]
    permissions = {}

    for action in actions:
        permission = Permission(resource_id=resource.id, action=action)
        db.add(permission)
        db.flush()
        permissions[action] = permission

    admin_role = Role(
        name="Review Administrator",
        description="Creates and completes access reviews",
        is_privileged=True,
    )
    auditor_role = Role(
        name="Review Auditor",
        description="Reviews access assignments",
        is_privileged=False,
    )
    business_role = Role(
        name="Finance User",
        description="Finance business access",
        is_privileged=False,
    )
    db.add_all([admin_role, auditor_role, business_role])
    db.flush()

    # Administrators can create, view, and complete cycles.
    for action in [
        "access_review.create",
        "access_review.view",
        "access_review.complete",
    ]:
        db.add(
            RolePermission(
                role_id=admin_role.id,
                permission_id=permissions[action].id,
            )
        )

    # Auditors can view cycles and record decisions.
    for action in ["access_review.view", "access_review.decide"]:
        db.add(
            RolePermission(
                role_id=auditor_role.id,
                permission_id=permissions[action].id,
            )
        )

    db.add_all(
        [
            UserRole(user_id=admin.id, role_id=admin_role.id),
            UserRole(user_id=reviewer1.id, role_id=auditor_role.id),
            UserRole(user_id=reviewer2.id, role_id=auditor_role.id),
            UserRole(user_id=target.id, role_id=business_role.id),
        ]
    )
    db.commit()

    return {
        "admin": admin,
        "reviewer1": reviewer1,
        "reviewer2": reviewer2,
        "target": target,
        "business_role": business_role,
    }


@pytest.fixture()
def client(db, review_api_setup):
    from app.main import app

    current_user = {"user": review_api_setup["admin"]}

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


def create_cycle(client):
    response = client.post(
        "/access-reviews",
        json={"name": "Quarterly Access Review"},
    )
    assert response.status_code == 201
    return response.json()


def test_create_and_list_access_review_cycles(client):
    created = create_cycle(client)

    assert created["status"] == "OPEN"
    assert created["name"] == "Quarterly Access Review"

    response = client.get("/access-reviews")
    assert response.status_code == 200
    assert any(cycle["id"] == created["id"] for cycle in response.json())


def test_get_access_review_cycle_includes_assignment_snapshot(
    client,
    review_api_setup,
):
    created = create_cycle(client)

    response = client.get(f"/access-reviews/{created['id']}")

    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 4
    assert all(item["decision"] == "PENDING" for item in body["items"])
    assert any(
        item["user_id"] == review_api_setup["target"].id
        and item["role_id"] == review_api_setup["business_role"].id
        for item in body["items"]
    )


def test_create_access_review_requires_permission(client, review_api_setup):
    client.current_user["user"] = review_api_setup["target"]

    response = client.post(
        "/access-reviews",
        json={"name": "Unauthorized Review"},
    )

    assert response.status_code == 403


def test_unknown_access_review_returns_404(client, review_api_setup):
    client.current_user["user"] = review_api_setup["admin"]

    response = client.get("/access-reviews/9999")
    assert response.status_code == 404


def test_record_retain_decision_through_api(client, review_api_setup):
    created = create_cycle(client)
    detail = client.get(f"/access-reviews/{created['id']}").json()

    item = next(
        item
        for item in detail["items"]
        if item["user_id"] == review_api_setup["target"].id
    )

    client.current_user["user"] = review_api_setup["reviewer1"]
    response = client.post(
        f"/access-reviews/{created['id']}/decisions",
        json={
            "item_id": item["id"],
            "decision": "RETAIN",
            "reason": "Access remains necessary for current duties",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "RETAIN"
    assert response.json()["reviewer_id"] == review_api_setup["reviewer1"].id


def test_decision_requires_permission(client, review_api_setup):
    created = create_cycle(client)
    detail = client.get(f"/access-reviews/{created['id']}").json()
    item = detail["items"][0]

    client.current_user["user"] = review_api_setup["target"]
    response = client.post(
        f"/access-reviews/{created['id']}/decisions",
        json={
            "item_id": item["id"],
            "decision": "RETAIN",
            "reason": "Reviewed",
        },
    )

    assert response.status_code == 403


def test_decision_rejects_blank_reason(client, review_api_setup):
    created = create_cycle(client)
    detail = client.get(f"/access-reviews/{created['id']}").json()
    item = next(
        item
        for item in detail["items"]
        if item["user_id"] == review_api_setup["target"].id
    )

    client.current_user["user"] = review_api_setup["reviewer1"]
    response = client.post(
        f"/access-reviews/{created['id']}/decisions",
        json={
            "item_id": item["id"],
            "decision": "RETAIN",
            "reason": "   ",
        },
    )

    assert response.status_code == 422


def test_cannot_complete_cycle_with_pending_decisions(
    client,
    review_api_setup,
):
    created = create_cycle(client)

    response = client.post(f"/access-reviews/{created['id']}/complete")

    assert response.status_code == 422


def test_complete_cycle_after_all_items_are_decided(
    client,
    review_api_setup,
):
    created = create_cycle(client)
    detail = client.get(f"/access-reviews/{created['id']}").json()

    for item in detail["items"]:
        reviewer = (
            review_api_setup["reviewer2"]
            if item["user_id"] == review_api_setup["reviewer1"].id
            else review_api_setup["reviewer1"]
        )
        client.current_user["user"] = reviewer

        response = client.post(
            f"/access-reviews/{created['id']}/decisions",
            json={
                "item_id": item["id"],
                "decision": "RETAIN",
                "reason": "Assignment reviewed and justified",
            },
        )
        assert response.status_code == 200

    client.current_user["user"] = review_api_setup["admin"]
    response = client.post(f"/access-reviews/{created['id']}/complete")

    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"
    assert response.json()["completed_at"] is not None


def test_cannot_complete_cycle_without_permission(
    client,
    review_api_setup,
):
    created = create_cycle(client)
    client.current_user["user"] = review_api_setup["reviewer1"]

    response = client.post(f"/access-reviews/{created['id']}/complete")

    assert response.status_code == 403