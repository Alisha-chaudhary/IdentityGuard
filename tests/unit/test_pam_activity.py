from datetime import datetime, timedelta

from app.db.models import Department, User
from app.pam.models import (
    PamAccessRequest,
    PamAccount,
    PamCheckout,
    PamSafe,
    PamSession,
)
from app.reports.pam_activity import get_pam_activity_report


def create_user(db, username, employee_id):
    department = Department(name=f"Department-{employee_id}")
    db.add(department)
    db.flush()

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        password_hash="must-not-appear-in-report",
        status="ACTIVE",
        department_id=department.id,
    )
    db.add(user)
    db.flush()
    return user


def create_pam_account(db):
    safe = PamSafe(name="Production-Safe")
    db.add(safe)
    db.flush()

    account = PamAccount(
        safe_id=safe.id,
        name="database-admin",
        system_name="production-db",
        account_type="DATABASE",
        description="Production database administrator account",
    )
    db.add(account)
    db.flush()
    return account


def create_request(db, requester, account):
    request = PamAccessRequest(
        requester_id=requester.id,
        account_id=account.id,
        justification="Investigate a production alert",
        requested_duration_minutes=30,
        status="APPROVED",
        requested_at=datetime(2026, 1, 1, 10, 0, 0),
    )
    db.add(request)
    db.flush()
    return request


def test_pam_activity_includes_request_without_checkout(db):
    requester = create_user(db, "pam.requester", "PAM001")
    account = create_pam_account(db)
    create_request(db, requester, account)

    report = get_pam_activity_report(db)

    assert report["total_count"] == 1
    item = report["items"][0]
    assert item["requester_username"] == "pam.requester"
    assert item["account_name"] == "database-admin"
    assert item["request_status"] == "APPROVED"
    assert item["checkout_id"] is None
    assert item["sessions"] == []


def test_pam_activity_includes_checkout_and_session_metadata(db):
    requester = create_user(db, "pam.checkout-user", "PAM002")
    account = create_pam_account(db)
    request = create_request(db, requester, account)

    checked_out_at = datetime(2026, 1, 1, 10, 5, 0)
    checkout = PamCheckout(
        access_request_id=request.id,
        checked_out_by_id=requester.id,
        checked_out_at=checked_out_at,
        expires_at=checked_out_at + timedelta(minutes=30),
        status="ACTIVE",
    )
    db.add(checkout)
    db.flush()

    session = PamSession(
        checkout_id=checkout.id,
        started_at=checked_out_at,
        status="ACTIVE",
        source_ip="192.0.2.10",
        session_reference="session-test-001",
    )
    db.add(session)
    db.flush()

    report = get_pam_activity_report(db)

    assert report["total_count"] == 1
    item = report["items"][0]
    assert item["checkout_id"] == checkout.id
    assert item["checkout_status"] == "ACTIVE"
    assert len(item["sessions"]) == 1
    assert item["sessions"][0]["session_id"] == session.id
    assert item["sessions"][0]["source_ip"] == "192.0.2.10"
    assert item["sessions"][0]["session_reference"] == "session-test-001"


def test_pam_activity_counts_requests_not_sessions(db):
    requester = create_user(db, "pam.multisession", "PAM003")
    account = create_pam_account(db)
    request = create_request(db, requester, account)

    checked_out_at = datetime(2026, 1, 1, 10, 5, 0)
    checkout = PamCheckout(
        access_request_id=request.id,
        checked_out_by_id=requester.id,
        checked_out_at=checked_out_at,
        expires_at=checked_out_at + timedelta(minutes=30),
        status="ACTIVE",
    )
    db.add(checkout)
    db.flush()

    db.add_all(
        [
            PamSession(
                checkout_id=checkout.id,
                started_at=checked_out_at,
                status="ENDED",
                ended_at=checked_out_at + timedelta(minutes=5),
            ),
            PamSession(
                checkout_id=checkout.id,
                started_at=checked_out_at + timedelta(minutes=10),
                status="ACTIVE",
            ),
        ]
    )
    db.flush()

    report = get_pam_activity_report(db)

    assert report["total_count"] == 1
    assert len(report["items"]) == 1
    assert len(report["items"][0]["sessions"]) == 2


def test_pam_activity_returns_empty_report_when_no_requests_exist(db):
    report = get_pam_activity_report(db)

    assert report == {"total_count": 0, "items": []}


def test_pam_activity_does_not_expose_password_hash(db):
    requester = create_user(db, "pam.private", "PAM004")
    account = create_pam_account(db)
    create_request(db, requester, account)

    report = get_pam_activity_report(db)

    for item in report["items"]:
        assert "password_hash" not in item
        assert "failed_attempts" not in item
        assert "locked_until" not in item
