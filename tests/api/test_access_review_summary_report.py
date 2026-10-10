from datetime import datetime

from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.security import create_access_token
from app.db.models import (
    AccessReviewCycle,
    AccessReviewItem,
    Department,
    Role,
    User,
)
from app.main import app


def create_user(db, username, employee_id):
    department = Department(name=f"Department-{employee_id}")
    db.add(department)
    db.flush()

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        password_hash="test-password-hash",
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
    from tests.api.test_reports import (
        grant_reports_read as grant_permission,
    )

    grant_permission(db, user)


def make_client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def teardown_client():
    app.dependency_overrides.clear()


def test_access_review_summary_requires_authentication(db):
    client = make_client(db)

    try:
        response = client.get("/reports/access-review-summary")

        assert response.status_code == 401
    finally:
        teardown_client()


def test_access_review_summary_requires_reports_read_permission(db):
    user = create_user(db, "review.summary.denied", "ARSA001")
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/access-review-summary",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden"
    finally:
        teardown_client()


def test_access_review_summary_returns_empty_report_for_authorized_user(db):
    user = create_user(db, "review.summary.reader", "ARSA002")
    grant_reports_read(db, user)
    token = create_access_token(user.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/access-review-summary",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.json() == {
            "total_cycles": 0,
            "open_cycles": 0,
            "completed_cycles": 0,
            "total_review_items": 0,
            "pending_decisions": 0,
            "items": [],
        }
    finally:
        teardown_client()


def test_access_review_summary_returns_populated_report_for_authorized_user(
    db,
):
    creator = create_user(db, "review.summary.creator", "ARSA003")
    target = create_user(db, "review.summary.target", "ARSA004")
    reviewer = create_user(db, "review.summary.reviewer", "ARSA005")

    role = Role(
        name="Review Analyst",
        description="Reviews assigned access",
        is_privileged=False,
    )
    db.add(role)
    db.flush()

    created_at = datetime(2026, 5, 12, 9, 0, 0)
    assigned_at = datetime(2026, 5, 12, 9, 30, 0)
    decided_at = datetime(2026, 5, 12, 10, 0, 0)

    cycle = AccessReviewCycle(
        name="May Access Review",
        status="OPEN",
        created_by_id=creator.id,
        created_at=created_at,
        completed_at=None,
    )
    db.add(cycle)
    db.flush()

    db.add(
        AccessReviewItem(
            cycle_id=cycle.id,
            user_id=target.id,
            role_id=role.id,
            assignment_assigned_at=assigned_at,
            decision="RETAIN",
            reviewer_id=reviewer.id,
            decision_reason="Access remains required",
            decided_at=decided_at,
        )
    )

    grant_reports_read(db, creator)
    token = create_access_token(creator.username)
    client = make_client(db)

    try:
        response = client.get(
            "/reports/access-review-summary",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["total_cycles"] == 1
        assert data["open_cycles"] == 1
        assert data["completed_cycles"] == 0
        assert data["total_review_items"] == 1
        assert data["pending_decisions"] == 0
        assert len(data["items"]) == 1

        cycle_data = data["items"][0]
        assert cycle_data["name"] == "May Access Review"
        assert cycle_data["status"] == "OPEN"
        assert cycle_data["creator_username"] == "review.summary.creator"
        assert cycle_data["total_count"] == 1
        assert cycle_data["pending_count"] == 0
        assert cycle_data["retain_count"] == 1
        assert cycle_data["revoke_decision_count"] == 0
        assert cycle_data["decided_count"] == 1
        assert cycle_data["completion_percentage"] == 100.0

        assert len(cycle_data["items"]) == 1
        item = cycle_data["items"][0]

        assert item["username"] == "review.summary.target"
        assert item["role_name"] == "Review Analyst"
        assert item["decision"] == "RETAIN"
        assert item["reviewer_username"] == "review.summary.reviewer"
        assert item["decision_reason"] == "Access remains required"

        assert "password_hash" not in item
        assert "failed_attempts" not in item
        assert "locked_until" not in item
    finally:
        teardown_client()