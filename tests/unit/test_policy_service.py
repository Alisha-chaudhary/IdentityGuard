"""Tests for the policy-driven role assignment service.

Covers: valid audit result values (allow -> SUCCESS, deny -> DENIED) and
fail-closed behaviour when the policy engine or the audit write fails.
"""

from app.authz.policy_engine import Decision
from app.authz.policy_service import _audit_result_for, can_assign_role_with_policy
from sqlalchemy import select

from app.iam.access_requests import PrivilegedRoleAuthorizationError
from app.iam.access_requests import provision_access_request
from app.db.models import AccessRequest, Department, Role, User, UserRole


def _make_user(db, username):
    dept = db.scalar(select(Department).where(Department.name == "Test Dept"))
    if dept is None:
        dept = Department(name="Test Dept")
        db.add(dept)
        db.flush()
    user = User(
        employee_id=f"E-{username}",
        username=username,
        full_name=username,
        email=f"{username}@example.test",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$x$y",
        status="ACTIVE",
        failed_attempts=0,
        locked_until=None,
        department_id=dept.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_role(db, name, privileged=False):
    role = Role(name=name, is_privileged=privileged)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


def _make_approved_request(db, target, role, provisioner):
    access_request = AccessRequest(
        requester_id=provisioner.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Justification",
        status="APPROVED",
        decision_by="someone.else",
    )
    db.add(access_request)
    db.commit()
    db.refresh(access_request)
    return access_request


def test_audit_result_mapping():
    assert _audit_result_for("allow") == "SUCCESS"
    assert _audit_result_for("deny") == "DENIED"


def test_allow_records_success_and_grants(db, monkeypatch):
    captured = {}

    def fake_record(db, *, actor, event_type, target, action, result, reason, correlation_id=None):
        captured["result"] = result
        captured["reason"] = reason

    monkeypatch.setattr("app.audit.service.record_event", fake_record)

    import app.authz.policy_service as ps

    monkeypatch.setattr(
        ps,
        "evaluate_policy",
        lambda *a, **k: Decision(decision="allow", matched_rules=["r1"], reason="ok"),
    )

    actor = _make_user(db, "actor")
    target = _make_user(db, "target")
    role = _make_role(db, "Super Role", privileged=True)

    assert can_assign_role_with_policy(db, actor, target, role) is True
    assert captured["result"] == "SUCCESS"


def test_deny_records_denied_and_refuses(db, monkeypatch):
    captured = {}

    def fake_record(db, *, actor, event_type, target, action, result, reason, correlation_id=None):
        captured["result"] = result

    monkeypatch.setattr("app.audit.service.record_event", fake_record)

    import app.authz.policy_service as ps

    monkeypatch.setattr(
        ps,
        "evaluate_policy",
        lambda *a, **k: Decision(decision="deny", matched_rules=["r1"], reason="denied"),
    )

    actor = _make_user(db, "actor")
    target = _make_user(db, "target")
    role = _make_role(db, "Super Role", privileged=True)

    assert can_assign_role_with_policy(db, actor, target, role) is False
    assert captured["result"] == "DENIED"


def test_policy_engine_error_propagates_fail_closed(db, monkeypatch):
    import app.authz.policy_service as ps

    monkeypatch.setattr(
        ps,
        "evaluate_policy",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("policy engine down")),
    )

    actor = _make_user(db, "actor")
    target = _make_user(db, "target")
    role = _make_role(db, "Super Role", privileged=True)

    try:
        can_assign_role_with_policy(db, actor, target, role)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected RuntimeError to propagate")


def test_audit_write_failure_rolls_back_and_denies(db, monkeypatch):
    import app.authz.policy_service as ps

    monkeypatch.setattr(
        ps,
        "evaluate_policy",
        lambda *a, **k: Decision(decision="allow", matched_rules=[], reason="ok"),
    )
    monkeypatch.setattr(
        "app.audit.service.record_event",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit write down")),
    )

    actor = _make_user(db, "actor")
    target = _make_user(db, "target")
    role = _make_role(db, "Super Role", privileged=True)

    try:
        can_assign_role_with_policy(db, actor, target, role)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected RuntimeError to propagate")


def test_provisioning_denied_when_policy_engine_errors(db, monkeypatch):
    import app.authz.policy_service as ps

    monkeypatch.setattr(
        ps,
        "evaluate_policy",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("policy engine down")),
    )

    provisioner = _make_user(db, "provisioner")
    target = _make_user(db, "target")
    role = _make_role(db, "Database Administrator", privileged=True)
    access_request = _make_approved_request(db, target, role, provisioner)

    try:
        provision_access_request(db, access_request.id, provisioner)
    except PrivilegedRoleAuthorizationError:
        pass
    else:
        raise AssertionError("expected PrivilegedRoleAuthorizationError")

    # No role assignment must have been created.
    assignment = db.scalar(
        select(UserRole).where(
            UserRole.user_id == target.id,
            UserRole.role_id == role.id,
        )
    )
    assert assignment is None
