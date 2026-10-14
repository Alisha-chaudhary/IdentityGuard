"""Regression tests for the audit findings (H1, H2, M1-M4, M7, SoD report)."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.clock import FrozenClock, now, set_clock
from app.db.models import AuditEvent, UserRole
from app.iam.jml import (
    LastAdministratorError,
    SelfTerminationError,
    create_user,
    terminate_user,
)
from app.pam.models import PamAccessRequest, PamAccount, PamCheckout
from app.pam.service import (
    checkout_privileged_access,
    decide_privileged_access,
    end_privileged_checkout,
    expire_due_checkouts,
    request_privileged_access,
)
from app.core.security import WeakPasswordError
from tests.api.conftest import (
    SEED_PASSWORD,
    grant,
    make_role_with_permissions,
    role_by_name,
    user_by_name,
)


def events(db, event_type):
    return db.scalars(
        select(AuditEvent).where(AuditEvent.event_type == event_type)
    ).all()


def file_request(api, who, target, role_name, **extra):
    headers = api.login(who)
    response = api.post(
        "/access-requests",
        headers=headers,
        json={
            "target_user_id": user_by_name(api.app_db, target).id,
            "role_id": role_by_name(api.app_db, role_name).id,
            "justification": "Test justification",
            **extra,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


@pytest.fixture(autouse=True)
def _expose_db(api, seeded):
    api.app_db = seeded


# ---------------------------------------------------------------- H1 bootstrap
@pytest.mark.parametrize(
    "username",
    ["identityguard.admin", "identityguard.admin2", "auditor", "reviewer", "lisa"],
)
def test_fresh_seed_can_log_in(api, username):
    assert "Authorization" in api.login(username)


def test_seed_is_idempotent(seeded):
    from app.db.seed import seed, seed_demo_platform

    seed(seeded)
    seed_demo_platform(seeded, SEED_PASSWORD)
    assert user_by_name(seeded, "identityguard.admin") is not None


# ----------------------------------------------------------------- H2 PAM expiry
def _approved_request(db, requester="lisa", approver="identityguard.admin"):
    account = db.scalar(select(PamAccount))
    req = request_privileged_access(
        db,
        requester_id=user_by_name(db, requester).id,
        account_id=account.id,
        justification="Patch window",
        duration_minutes=30,
    )
    decide_privileged_access(
        db,
        request_id=req.id,
        approver_id=user_by_name(db, approver).id,
        decision="APPROVED",
        reason="Change ticket CHG-1",
    )
    return req


def test_pam_checkout_expires_and_is_audited(seeded):
    start = now()
    set_clock(FrozenClock(start))
    req = _approved_request(seeded)
    checkout = checkout_privileged_access(
        seeded, request_id=req.id, user_id=user_by_name(seeded, "lisa").id
    )

    # Still inside the window: nothing happens.
    set_clock(FrozenClock(start + timedelta(minutes=29)))
    assert expire_due_checkouts(seeded) == []
    seeded.refresh(checkout)
    assert checkout.status == "ACTIVE"

    # Past the limit: the sweeper expires it and writes PRIVILEGE_EXPIRED.
    set_clock(FrozenClock(start + timedelta(minutes=31)))
    expired = expire_due_checkouts(seeded)
    assert [c.id for c in expired] == [checkout.id]
    seeded.refresh(checkout)
    assert checkout.status == "EXPIRED"
    assert checkout.ended_at is not None
    assert len(events(seeded, "PRIVILEGE_EXPIRED")) == 1

    # Idempotent.
    assert expire_due_checkouts(seeded) == []


def test_pam_expire_endpoint_and_end_early(api, seeded):
    start = now()
    set_clock(FrozenClock(start))
    req = _approved_request(seeded)
    lisa = user_by_name(seeded, "lisa")
    checkout = checkout_privileged_access(seeded, request_id=req.id, user_id=lisa.id)

    # Another operator cannot end lisa's checkout.
    kiran = api.login("kiran.reddy")
    assert api.post(f"/pam/checkouts/{checkout.id}/end", headers=kiran).status_code == 409

    # Lisa ends it herself.
    response = api.post(f"/pam/checkouts/{checkout.id}/end", headers=api.login("lisa"))
    assert response.status_code == 200
    assert response.json()["status"] == "ENDED"
    assert len(events(seeded, "PRIVILEGED_SESSION_ENDED")) == 1

    # Admin-triggered sweep after expiry returns nothing new for an ended one.
    set_clock(FrozenClock(start + timedelta(hours=3)))
    admin = api.login("identityguard.admin")
    assert api.post("/pam/checkouts/expire-due", headers=admin).json() == []


# --------------------------------------------------------- M1 proxy self-approval
def test_target_cannot_approve_access_filed_for_them(api, seeded):
    request_id = file_request(
        api, "identityguard.admin", "identityguard.admin2", "Finance Analyst"
    )
    response = api.post(
        f"/access-requests/{request_id}/approve",
        headers=api.login("identityguard.admin2"),
        json={"reason": "approving myself"},
    )
    assert response.status_code == 403
    assert any(
        e.actor == "identityguard.admin2" for e in events(seeded, "ACCESS_DENIED")
    )


# ------------------------------------------------ M2 privileged role + four-eyes
def test_privileged_role_needs_assign_privileged_to_approve(api, seeded):
    approver_only = make_role_with_permissions(
        seeded, "Access Approver", ["access.approve", "access.provision"]
    )
    grant(seeded, "reviewer", approver_only)

    privileged_id = file_request(api, "identityguard.admin", "arjun.verma", "Database Administrator")
    plain_id = file_request(api, "identityguard.admin", "arjun.verma", "HR Analyst")

    headers = api.login("reviewer")
    denied = api.post(
        f"/access-requests/{privileged_id}/approve", headers=headers, json={"reason": "ok"}
    )
    assert denied.status_code == 403
    allowed = api.post(
        f"/access-requests/{plain_id}/approve", headers=headers, json={"reason": "ok"}
    )
    assert allowed.status_code == 200


def test_privileged_role_approver_cannot_also_provision(api, seeded):
    request_id = file_request(
        api, "identityguard.admin2", "arjun.verma", "Database Administrator"
    )
    admin = api.login("identityguard.admin")
    assert api.post(
        f"/access-requests/{request_id}/approve", headers=admin, json={"reason": "ok"}
    ).status_code == 200

    # Same person approving and provisioning a privileged role is refused.
    assert api.post(f"/access-requests/{request_id}/provision", headers=admin).status_code == 403

    # A second administrator can provision it.
    admin2 = api.login("identityguard.admin2")
    response = api.post(f"/access-requests/{request_id}/provision", headers=admin2)
    assert response.status_code == 200
    assert response.json()["status"] == "PROVISIONED"


def test_sod_conflict_is_still_blocked_end_to_end(api, seeded):
    request_id = file_request(api, "identityguard.admin2", "rahul.mehta", "Payment Approver")
    assert api.post(
        f"/access-requests/{request_id}/approve",
        headers=api.login("identityguard.admin"),
        json={"reason": "ok"},
    ).status_code == 200
    response = api.post(
        f"/access-requests/{request_id}/provision", headers=api.login("identityguard.admin2")
    )
    assert response.status_code == 409
    assert len(events(seeded, "SOD_VIOLATION")) == 1


# -------------------------------------------------------------- M3 expired re-grant
def test_expired_role_can_be_regranted(api, seeded):
    start = now()
    set_clock(FrozenClock(start))
    expires = (start + timedelta(hours=1)).isoformat()

    first = file_request(api, "identityguard.admin2", "arjun.verma", "HR Analyst", expires_at=expires)
    admin, admin2 = api.login("identityguard.admin"), api.login("identityguard.admin2")
    api.post(f"/access-requests/{first}/approve", headers=admin, json={"reason": "ok"})
    assert api.post(f"/access-requests/{first}/provision", headers=admin2).status_code == 200

    # While active, a duplicate is refused.
    dup = file_request(api, "identityguard.admin2", "arjun.verma", "HR Analyst")
    api.post(f"/access-requests/{dup}/approve", headers=admin, json={"reason": "ok"})
    assert api.post(f"/access-requests/{dup}/provision", headers=admin2).status_code == 409

    # After expiry the same role can be granted again.
    set_clock(FrozenClock(start + timedelta(hours=2)))
    again = file_request(api, "identityguard.admin2", "arjun.verma", "HR Analyst")
    api.post(f"/access-requests/{again}/approve", headers=admin, json={"reason": "ok"})
    assert api.post(f"/access-requests/{again}/provision", headers=admin2).status_code == 200
    assignment = seeded.scalar(
        select(UserRole).where(
            UserRole.user_id == user_by_name(seeded, "arjun.verma").id,
            UserRole.role_id == role_by_name(seeded, "HR Analyst").id,
        )
    )
    assert assignment.expires_at is None


# ------------------------------------------------------------ M4 leaver completeness
def test_terminate_revokes_pam_and_closes_open_requests(api, seeded):
    lisa = user_by_name(seeded, "lisa")
    req = _approved_request(seeded)
    checkout = checkout_privileged_access(seeded, request_id=req.id, user_id=lisa.id)
    pending_pam = request_privileged_access(
        seeded,
        requester_id=lisa.id,
        account_id=seeded.scalar(select(PamAccount)).id,
        justification="Another job",
        duration_minutes=10,
    )
    request_id = file_request(api, "identityguard.admin", "lisa", "HR Analyst")

    terminate_user(seeded, user_id=lisa.id, actor="identityguard.admin")

    seeded.refresh(checkout)
    seeded.refresh(pending_pam)
    assert checkout.status == "REVOKED"
    assert pending_pam.status == "CANCELLED"
    from app.db.models import AccessRequest

    assert seeded.get(AccessRequest, request_id).status == "REJECTED"
    assert len(events(seeded, "PRIVILEGED_CHECKOUT_REVOKED")) == 1


def test_cannot_terminate_self_or_last_admin(seeded):
    admin = user_by_name(seeded, "identityguard.admin")
    admin2 = user_by_name(seeded, "identityguard.admin2")

    with pytest.raises(SelfTerminationError):
        terminate_user(seeded, user_id=admin.id, actor="identityguard.admin")

    terminate_user(seeded, user_id=admin2.id, actor="identityguard.admin")  # fine: admin remains
    with pytest.raises(LastAdministratorError):
        terminate_user(seeded, user_id=admin.id, actor="someone.else")


def test_move_and_terminate_have_separate_permissions(api, seeded):
    creator = make_role_with_permissions(seeded, "User Creator", ["user.create"])
    grant(seeded, "reviewer", creator)
    headers = api.login("reviewer")
    target = user_by_name(seeded, "arjun.verma")
    assert api.patch(
        f"/jml/users/{target.id}/move", headers=headers, json={"manager_id": 1}
    ).status_code == 403
    assert api.post(f"/jml/users/{target.id}/terminate", headers=headers).status_code == 403


def test_terminate_endpoint_blocks_self(api, seeded):
    admin = user_by_name(seeded, "identityguard.admin")
    response = api.post(f"/jml/users/{admin.id}/terminate", headers=api.login("identityguard.admin"))
    assert response.status_code == 409


# --------------------------------------------------------------- M7 password policy
def test_joiner_rejects_weak_password_service_and_api(api, seeded):
    with pytest.raises(WeakPasswordError):
        create_user(
            seeded,
            employee_id="X1",
            username="weak.user",
            full_name="Weak User",
            email="weak@example.test",
            department_id=1,
            password="aaaaaaaaaaaa",
            actor="identityguard.admin",
        )
    response = api.post(
        "/jml/users",
        headers=api.login("identityguard.admin"),
        json={
            "employee_id": "X2",
            "username": "weak.api",
            "full_name": "Weak Api",
            "email": "weak.api@example.test",
            "department_id": 1,
            "password": "aaaaaaaaaaaa",
        },
    )
    assert response.status_code == 422


def test_change_password_flow(api, seeded):
    headers = api.login("auditor")
    url = "/auth/change-password"
    assert api.post(url, headers=headers, json={"current_password": "wrong-password-1A", "new_password": "An0ther-Good-Pass"}).status_code == 403
    assert api.post(url, headers=headers, json={"current_password": SEED_PASSWORD, "new_password": "weak"}).status_code == 422
    assert api.post(url, headers=headers, json={"current_password": SEED_PASSWORD, "new_password": "An0ther-Good-Pass"}).status_code == 204
    api.login("auditor", "An0ther-Good-Pass")  # new password works


# ----------------------------------------------------------- SoD violation report
def test_sod_report_lists_existing_conflicts(api, seeded):
    headers = api.login("auditor")
    clean = api.get("/reports/sod-violations", headers=headers).json()
    assert clean["total_count"] == 0
    assert ["Payment Approver", "Payment Initiator"] in clean["rules"]

    # Create a conflict behind the workflow's back (e.g. legacy data).
    grant(seeded, "rahul.mehta", role_by_name(seeded, "Payment Approver"))
    report = api.get("/reports/sod-violations", headers=headers).json()
    assert report["total_count"] == 1
    assert report["items"][0]["username"] == "rahul.mehta"


def test_audit_events_are_paginated(api, seeded):
    api.login("auditor")
    api.login("reviewer")  # generate a few audit events
    headers = api.login("auditor")
    response = api.get("/audit/events?limit=2", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 2
    assert api.get("/audit/events?limit=0", headers=headers).status_code == 422
