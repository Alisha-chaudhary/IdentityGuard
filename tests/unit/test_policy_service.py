from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.authz.policy_engine import Decision
from app.authz.policy_service import (
    _audit_result,
    can_assign_role_with_policy,
)
from app.db.models import Department, Role, User


def _create_department(db, name="Finance"):
    department = Department(name=name)
    db.add(department)
    db.flush()
    return department


def _create_user(db, department, username, employee_id):
    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.title(),
        email=f"{username}@example.test",
        department_id=department.id,
        status="ACTIVE",
    )
    db.add(user)
    db.flush()
    return user


def _create_role(db, name="Privileged Role", is_privileged=True):
    role = Role(name=name, description="Test", is_privileged=is_privileged)
    db.add(role)
    db.flush()
    return role


def test_audit_result_maps_policy_decision_to_db_allowed_values():
    assert _audit_result("deny") == "DENIED"
    assert _audit_result("allow") == "SUCCESS"
    # An unexpected engine decision must not be recorded as allow or deny.
    assert _audit_result("indeterminate") == "FAILURE"


def test_policy_denial_records_denied_audit_and_denies(db):
    department = _create_department(db)
    actor = _create_user(db, department, "actor", "EMP300")
    target = _create_user(db, department, "target", "EMP301")
    role = _create_role(db)

    decision = Decision(
        decision="deny",
        matched_rules=["deny-privileged-without-legacy-permission"],
        reason="No matching allow rule",
    )

    captured = {}

    def fake_record_event(
        db,
        *,
        actor,
        event_type,
        target,
        action,
        result,
        reason,
        correlation_id=None,
    ):
        captured["result"] = result
        captured["event_type"] = event_type

    with patch(
        "app.authz.policy_service.evaluate_policy", return_value=decision
    ), patch("app.audit.service.record_event", side_effect=fake_record_event):
        allowed = can_assign_role_with_policy(db, actor, target, role)

    assert allowed is False
    assert captured["result"] == "DENIED"


def test_policy_allowance_records_success_audit_and_allows(db):
    department = _create_department(db)
    actor = _create_user(db, department, "actor", "EMP302")
    target = _create_user(db, department, "target", "EMP303")
    role = _create_role(db)

    decision = Decision(
        decision="allow",
        matched_rules=["allow-privileged-with-legacy-permission"],
        reason="Allow rule matched",
    )

    captured = {}

    def fake_record_event(
        db,
        *,
        actor,
        event_type,
        target,
        action,
        result,
        reason,
        correlation_id=None,
    ):
        captured["result"] = result

    with patch(
        "app.authz.policy_service.evaluate_policy", return_value=decision
    ), patch("app.audit.service.record_event", side_effect=fake_record_event):
        allowed = can_assign_role_with_policy(db, actor, target, role)

    assert allowed is True
    assert captured["result"] == "SUCCESS"


def test_policy_engine_failure_propagates_and_is_not_swallowed(db):
    department = _create_department(db)
    actor = _create_user(db, department, "actor", "EMP304")
    target = _create_user(db, department, "target", "EMP305")
    role = _create_role(db)

    with patch(
        "app.authz.policy_service.evaluate_policy",
        side_effect=RuntimeError("policy engine down"),
    ):
        with pytest.raises(RuntimeError, match="policy engine down"):
            can_assign_role_with_policy(db, actor, target, role)


def test_policy_audit_write_failure_fails_closed_and_keeps_session_usable(db):
    department = _create_department(db)
    actor = _create_user(db, department, "actor", "EMP306")
    target = _create_user(db, department, "target", "EMP307")
    role = _create_role(db)

    decision = Decision(decision="allow", matched_rules=[], reason="ok")

    with patch(
        "app.authz.policy_service.evaluate_policy", return_value=decision
    ), patch(
        "app.audit.service.record_event",
        side_effect=Exception("audit database unavailable"),
    ):
        with pytest.raises(Exception, match="audit database unavailable"):
            can_assign_role_with_policy(db, actor, target, role)

    # After the rollback inside the failure handler, the session must still be
    # usable for subsequent work (it is not left in a failed transaction state).
    # Note: rollback undoes this test's own uncommitted setup rows, so we only
    # assert a simple query executes without error.
    assert db.scalar(select(1)) == 1
