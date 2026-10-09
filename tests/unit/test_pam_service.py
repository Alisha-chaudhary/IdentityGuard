import pytest
from sqlalchemy import select

from app.db.models import Department, User, AuditEvent
from app.pam.models import PamAccessRequest, PamAccount, PamCheckout, PamSafe
from app.pam.service import (
    PamAuthorizationError,
    PamValidationError,
    checkout_privileged_access,
    decide_privileged_access,
    request_privileged_access,
)


def create_user(db, username: str, status: str = "ACTIVE") -> User:
    department = Department(name=f"{username}-department")
    db.add(department)
    db.flush()

    user = User(
        employee_id=f"EMP-{username}",
        username=username,
        full_name=username.title(),
        email=f"{username}@example.test",
        department_id=department.id,
        status=status,
    )
    db.add(user)
    db.flush()
    return user


def create_account(db, status: str = "ACTIVE", safe_status: str = "ACTIVE"):
    safe = PamSafe(name=f"Safe-{status}-{safe_status}", status=safe_status)
    db.add(safe)
    db.flush()

    account = PamAccount(
        safe_id=safe.id,
        name=f"Account-{status}-{safe_status}",
        system_name="lab-server-01",
        account_type="SYSTEM_ADMIN",
        status=status,
    )
    db.add(account)
    db.flush()
    return account


def create_request(db, requester: User, account: PamAccount) -> PamAccessRequest:
    request = PamAccessRequest(
        requester_id=requester.id,
        account_id=account.id,
        justification="Investigate a lab server alert",
        requested_duration_minutes=30,
        status="REQUESTED",
    )
    db.add(request)
    db.flush()
    return request


def test_active_user_can_request_access(db):
    requester = create_user(db, "pam-requester")
    account = create_account(db)

    request = request_privileged_access(
        db,
        requester_id=requester.id,
        account_id=account.id,
        justification="Investigate a lab server alert",
        duration_minutes=30,
    )

    assert request.id is not None
    assert request.status == "REQUESTED"
    assert request.requester_id == requester.id
    assert request.account_id == account.id
    assert request.requested_duration_minutes == 30
    assert request.checkout is None


def test_inactive_user_cannot_request_access(db):
    requester = create_user(db, "inactive-requester", status="DISABLED")
    account = create_account(db)

    with pytest.raises(PamAuthorizationError):
        request_privileged_access(
            db,
            requester_id=requester.id,
            account_id=account.id,
            justification="Approved lab task",
            duration_minutes=30,
        )


@pytest.mark.parametrize("duration", [0, -1, 61, True, 1.5])
def test_invalid_duration_is_rejected(db, duration):
    requester = create_user(
        db, f"duration-user-{str(duration).replace('.', '-')}"
    )
    account = create_account(db)

    with pytest.raises(PamValidationError):
        request_privileged_access(
            db,
            requester_id=requester.id,
            account_id=account.id,
            justification="Test duration validation",
            duration_minutes=duration,
        )


@pytest.mark.parametrize("justification", ["", "   ", None])
def test_blank_justification_is_rejected(db, justification):
    requester = create_user(db, "blank-justification-user")
    account = create_account(db)

    with pytest.raises(PamValidationError):
        request_privileged_access(
            db,
            requester_id=requester.id,
            account_id=account.id,
            justification=justification,
            duration_minutes=15,
        )


@pytest.mark.parametrize(
    ("account_status", "safe_status"),
    [("DISABLED", "ACTIVE"), ("ACTIVE", "DISABLED")],
)
def test_inactive_account_or_safe_cannot_be_requested(
    db, account_status, safe_status
):
    requester = create_user(db, "inactive-target-user")
    account = create_account(
        db, status=account_status, safe_status=safe_status
    )

    with pytest.raises(PamAuthorizationError):
        request_privileged_access(
            db,
            requester_id=requester.id,
            account_id=account.id,
            justification="Test inactive target",
            duration_minutes=15,
        )


def test_requester_cannot_approve_own_request(db):
    requester = create_user(db, "self-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    with pytest.raises(PamAuthorizationError):
        decide_privileged_access(
            db,
            request_id=request.id,
            approver_id=requester.id,
            decision="APPROVED",
            reason="Trying self-approval",
        )

    db.refresh(request)
    assert request.status == "REQUESTED"
    assert request.approver_id is None


def test_another_active_user_can_approve_without_creating_checkout(db):
    requester = create_user(db, "access-requester")
    approver = create_user(db, "access-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decided = decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for scheduled maintenance",
    )

    assert decided.status == "APPROVED"
    assert decided.approver_id == approver.id
    assert decided.decided_at is not None
    assert decided.checkout is None


def test_rejected_request_cannot_receive_another_decision(db):
    requester = create_user(db, "rejected-requester")
    approver = create_user(db, "rejected-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="REJECTED",
        reason="Request does not meet policy",
    )

    with pytest.raises(PamAuthorizationError):
        decide_privileged_access(
            db,
            request_id=request.id,
            approver_id=approver.id,
            decision="APPROVED",
            reason="Attempt to change a final decision",
        )

    db.refresh(request)
    assert request.status == "REJECTED"


def test_invalid_decision_is_rejected(db):
    requester = create_user(db, "invalid-decision-requester")
    approver = create_user(db, "invalid-decision-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    with pytest.raises(PamValidationError):
        decide_privileged_access(
            db,
            request_id=request.id,
            approver_id=approver.id,
            decision="PENDING",
            reason="Invalid decision test",
        )

    db.refresh(request)
    assert request.status == "REQUESTED"


def test_request_privileged_access_records_audit_event(db):
    requester = create_user(db, "audit-requester")
    account = create_account(db)

    request = request_privileged_access(
        db,
        requester_id=requester.id,
        account_id=account.id,
        justification="Investigate a production alert",
        duration_minutes=30,
    )

    events = db.scalars(
        select(AuditEvent).where(
            AuditEvent.target == f"pam_access_request:{request.id}",
            AuditEvent.event_type == "ACCESS_REQUESTED",
        )
    ).all()

    assert len(events) == 1
    assert events[0].action == "REQUEST_PRIVILEGED_ACCESS"
    assert events[0].result == "SUCCESS"
    assert events[0].actor == requester.username


def test_approval_records_audit_event(db):
    requester = create_user(db, "audit-approval-requester")
    approver = create_user(db, "audit-approval-approver")
    account = create_account(db)

    request = request_privileged_access(
        db,
        requester_id=requester.id,
        account_id=account.id,
        justification="Investigate a production alert",
        duration_minutes=30,
    )

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for investigation",
    )

    events = db.scalars(
        select(AuditEvent).where(
            AuditEvent.target == f"pam_access_request:{request.id}",
            AuditEvent.event_type == "ACCESS_APPROVED",
        )
    ).all()

    assert len(events) == 1
    assert events[0].actor == approver.username
    assert events[0].action == "APPROVED_PRIVILEGED_ACCESS"
    assert events[0].result == "SUCCESS"


def test_rejection_records_audit_event(db):
    requester = create_user(db, "audit-rejection-requester")
    approver = create_user(db, "audit-rejection-approver")
    account = create_account(db)

    request = request_privileged_access(
        db,
        requester_id=requester.id,
        account_id=account.id,
        justification="Investigate a production alert",
        duration_minutes=30,
    )

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="REJECTED",
        reason="Business justification is insufficient",
    )

    events = db.scalars(
        select(AuditEvent).where(
            AuditEvent.target == f"pam_access_request:{request.id}",
            AuditEvent.event_type == "ACCESS_REJECTED",
        )
    ).all()

    assert len(events) == 1
    assert events[0].actor == approver.username
    assert events[0].action == "REJECTED_PRIVILEGED_ACCESS"
    assert events[0].result == "SUCCESS"


def test_approved_request_can_be_checked_out(db):
    requester = create_user(db, "checkout-requester")
    approver = create_user(db, "checkout-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for maintenance",
    )

    checkout = checkout_privileged_access(
        db,
        request_id=request.id,
        user_id=requester.id,
    )

    assert checkout.id is not None
    assert checkout.access_request_id == request.id
    assert checkout.checked_out_by_id == requester.id
    assert checkout.status == "ACTIVE"
    assert checkout.expires_at > checkout.checked_out_at
    assert (
        checkout.expires_at - checkout.checked_out_at
    ).total_seconds() == 30 * 60


def test_pending_request_cannot_be_checked_out(db):
    requester = create_user(db, "pending-checkout-user")
    account = create_account(db)
    request = create_request(db, requester, account)

    with pytest.raises(PamAuthorizationError):
        checkout_privileged_access(
            db,
            request_id=request.id,
            user_id=requester.id,
        )

    assert request.checkout is None


def test_only_requester_can_check_out_approved_request(db):
    requester = create_user(db, "checkout-owner")
    other_user = create_user(db, "checkout-other-user")
    approver = create_user(db, "checkout-owner-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for maintenance",
    )

    with pytest.raises(PamAuthorizationError):
        checkout_privileged_access(
            db,
            request_id=request.id,
            user_id=other_user.id,
        )

    assert request.checkout is None


def test_inactive_user_cannot_check_out_access(db):
    requester = create_user(db, "disabled-checkout-user")
    approver = create_user(db, "disabled-checkout-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for maintenance",
    )

    requester.status = "DISABLED"
    db.flush()

    with pytest.raises(PamAuthorizationError):
        checkout_privileged_access(
            db,
            request_id=request.id,
            user_id=requester.id,
        )

    assert request.checkout is None


def test_inactive_account_cannot_be_checked_out(db):
    requester = create_user(db, "inactive-target-checkout-user")
    approver = create_user(db, "inactive-target-checkout-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for maintenance",
    )

    account.status = "DISABLED"
    db.flush()

    with pytest.raises(PamAuthorizationError):
        checkout_privileged_access(
            db,
            request_id=request.id,
            user_id=requester.id,
        )

    assert request.checkout is None


def test_duplicate_checkout_is_rejected(db):
    requester = create_user(db, "duplicate-checkout-user")
    approver = create_user(db, "duplicate-checkout-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for maintenance",
    )

    first_checkout = checkout_privileged_access(
        db,
        request_id=request.id,
        user_id=requester.id,
    )

    with pytest.raises(PamAuthorizationError):
        checkout_privileged_access(
            db,
            request_id=request.id,
            user_id=requester.id,
        )

    assert first_checkout.id is not None


def test_checkout_records_audit_event(db):
    requester = create_user(db, "checkout-audit-user")
    approver = create_user(db, "checkout-audit-approver")
    account = create_account(db)
    request = create_request(db, requester, account)

    decide_privileged_access(
        db,
        request_id=request.id,
        approver_id=approver.id,
        decision="APPROVED",
        reason="Approved for maintenance",
    )

    checkout = checkout_privileged_access(
        db,
        request_id=request.id,
        user_id=requester.id,
    )

    events = db.scalars(
        select(AuditEvent).where(
            AuditEvent.target == f"pam_checkout:{checkout.id}",
            AuditEvent.event_type == "PRIVILEGED_CHECKOUT",
        )
    ).all()

    assert len(events) == 1
    assert events[0].actor == requester.username
    assert events[0].action == "CHECKOUT_PRIVILEGED_ACCESS"
    assert events[0].result == "SUCCESS"