import pytest
from sqlalchemy import select

from app.audit.events import EventType
from app.audit.service import list_events, verify_chain
from app.db.models import User, UserRole
from app.db.seed import seed
from app.iam.service import (
    ConflictError,
    NotFoundError,
    assign_role,
    create_user,
    remove_role,
)


@pytest.fixture()
def seeded(db):
    seed(db)
    return db


def _roles(db, username):
    user = db.scalar(
        select(User).where(User.username == username)
    )
    return {ur.role.name for ur in user.user_roles}


def test_create_user_is_audited(seeded):
    create_user(
        seeded,
        actor="sneha.rao",
        employee_id="EMP100",
        username="new.joiner",
        full_name="New Joiner",
        email="new.joiner@example.test",
        department_name="Finance",
        manager_username="priya.nair",
    )

    events = list_events(
        seeded,
        event_type=EventType.USER_CREATED,
    )

    assert len(events) == 1
    assert events[0].actor == "sneha.rao"
    assert events[0].target == "user:new.joiner"
    assert events[0].result == "SUCCESS"


def test_create_user_duplicate_username_rejected_and_audited(seeded):
    with pytest.raises(ConflictError):
        create_user(
            seeded,
            actor="sneha.rao",
            employee_id="EMP101",
            username="rahul.mehta",
            full_name="Dup",
            email="dup@example.test",
            department_name="Finance",
        )

    events = list_events(
        seeded,
        event_type=EventType.USER_CREATED,
    )

    assert events[0].result == "FAILURE"


def test_assign_role_is_audited(seeded):
    assign_role(
        seeded,
        actor="priya.nair",
        username="sneha.rao",
        role_name="SOC Analyst",
    )

    assert "SOC Analyst" in _roles(
        seeded,
        "sneha.rao",
    )

    event = list_events(
        seeded,
        event_type=EventType.ROLE_ASSIGNED,
    )[0]

    assert event.action == "assign_role:SOC Analyst"
    assert event.result == "SUCCESS"


def test_remove_role_is_audited(seeded):
    remove_role(
        seeded,
        actor="priya.nair",
        username="meera.iyer",
        role_name="Finance Analyst",
    )

    assert "Finance Analyst" not in _roles(
        seeded,
        "meera.iyer",
    )

    event = list_events(
        seeded,
        event_type=EventType.ROLE_REMOVED,
    )[0]

    assert event.result == "SUCCESS"


def test_duplicate_assignment_rejected_and_audited(seeded):
    with pytest.raises(ConflictError):
        assign_role(
            seeded,
            actor="priya.nair",
            username="meera.iyer",
            role_name="HR Analyst",
        )

    event = list_events(
        seeded,
        event_type=EventType.ROLE_ASSIGNED,
    )[0]

    assert event.result == "FAILURE"
    assert event.reason == "role already assigned"


def test_remove_unassigned_role_fails_and_is_audited(seeded):
    with pytest.raises(NotFoundError):
        remove_role(
            seeded,
            actor="priya.nair",
            username="alisha.c",
            role_name="HR Analyst",
        )

    event = list_events(
        seeded,
        event_type=EventType.ROLE_REMOVED,
    )[0]

    assert event.result == "FAILURE"


def test_audit_chain_is_valid_after_operations(seeded):
    assign_role(
        seeded,
        actor="priya.nair",
        username="sneha.rao",
        role_name="SOC Analyst",
    )

    remove_role(
        seeded,
        actor="priya.nair",
        username="sneha.rao",
        role_name="SOC Analyst",
    )

    result = verify_chain(seeded)

    assert result.ok is True
    assert result.checked == 2