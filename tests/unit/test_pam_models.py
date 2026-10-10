
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.db.models import Department, User
from app.pam.models import (
    PamAccessRequest,
    PamAccount,
    PamCheckout,
    PamSafe,
    PamSession,
)


def create_user(db, username: str) -> User:
    department = Department(name=f"{username}-department")
    db.add(department)
    db.flush()

    user = User(
        employee_id=f"EMP-{username}",
        username=username,
        full_name=username.title(),
        email=f"{username}@example.test",
        department_id=department.id,
    )
    db.add(user)
    db.flush()
    return user


def create_account(db):
    safe = PamSafe(name="Infrastructure Safe")
    db.add(safe)
    db.flush()

    account = PamAccount(
        safe_id=safe.id,
        name="Linux Admin",
        system_name="linux-lab-01",
        account_type="SYSTEM_ADMIN",
    )
    db.add(account)
    db.flush()
    return safe, account


def test_pam_tables_are_registered(db):
    expected = {
        "pam_safes",
        "pam_accounts",
        "pam_access_requests",
        "pam_checkouts",
        "pam_sessions",
    }
    assert expected.issubset(db.get_bind().dialect.get_table_names(db.get_bind().connect()))


def test_safe_and_account_can_be_created(db):
    safe, account = create_account(db)

    assert account.safe_id == safe.id
    assert account.safe.name == "Infrastructure Safe"


def test_duplicate_account_name_in_same_safe_is_rejected(db):
    safe, _ = create_account(db)
    db.add(
        PamAccount(
            safe_id=safe.id,
            name="Linux Admin",
            system_name="linux-lab-02",
            account_type="SYSTEM_ADMIN",
        )
    )

    with pytest.raises(IntegrityError):
        db.flush()

    db.rollback()


def test_checkout_requires_expiry_after_checkout_time(db):
    requester = create_user(db, "pam-requester")
    _, account = create_account(db)

    request = PamAccessRequest(
        requester_id=requester.id,
        account_id=account.id,
        justification="Investigate a lab server alert",
        requested_duration_minutes=30,
        status="APPROVED",
    )
    db.add(request)
    db.flush()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    checkout = PamCheckout(
        access_request_id=request.id,
        checked_out_by_id=requester.id,
        checked_out_at=now,
        expires_at=now - timedelta(minutes=1),
    )
    db.add(checkout)

    with pytest.raises(IntegrityError):
        db.flush()

    db.rollback()


def test_access_request_cannot_have_two_checkouts(db):
    requester = create_user(db, "pam-checkout-user")
    _, account = create_account(db)

    request = PamAccessRequest(
        requester_id=requester.id,
        account_id=account.id,
        justification="Approved maintenance task",
        requested_duration_minutes=20,
        status="APPROVED",
    )
    db.add(request)
    db.flush()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    first_checkout = PamCheckout(
        access_request_id=request.id,
        checked_out_by_id=requester.id,
        checked_out_at=now,
        expires_at=now + timedelta(minutes=20),
    )
    db.add(first_checkout)
    db.flush()

    second_checkout = PamCheckout(
        access_request_id=request.id,
        checked_out_by_id=requester.id,
        checked_out_at=now,
        expires_at=now + timedelta(minutes=20),
    )
    db.add(second_checkout)

    with pytest.raises(IntegrityError):
        db.flush()

    db.rollback()


def test_session_can_reference_checkout(db):
    requester = create_user(db, "pam-session-user")
    _, account = create_account(db)

    request = PamAccessRequest(
        requester_id=requester.id,
        account_id=account.id,
        justification="Test session metadata",
        requested_duration_minutes=15,
        status="APPROVED",
    )
    db.add(request)
    db.flush()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    checkout = PamCheckout(
        access_request_id=request.id,
        checked_out_by_id=requester.id,
        checked_out_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    db.add(checkout)
    db.flush()

    session = PamSession(
        checkout_id=checkout.id,
        source_ip="192.0.2.10",
        session_reference="LAB-SESSION-001",
    )
    db.add(session)
    db.flush()

    assert session.checkout_id == checkout.id
    assert session.checkout.access_request_id == request.id