import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.audit.events import EventType, Result
from app.audit.service import (
    GENESIS_HASH,
    list_events,
    record_event,
    verify_chain,
)


def _record(
    db,
    result=Result.SUCCESS,
    event_type=EventType.USER_CREATED,
):
    ev = record_event(
        db,
        actor="admin",
        event_type=event_type,
        target="user:test",
        action="test_action",
        result=result,
        reason="unit test",
    )
    db.commit()
    return ev


def test_record_event_stores_all_fields(db):
    ev = _record(db)

    assert ev.actor == "admin"
    assert ev.event_type == "USER_CREATED"
    assert ev.target == "user:test"
    assert ev.action == "test_action"
    assert ev.result == "SUCCESS"
    assert ev.reason == "unit test"
    assert ev.correlation_id
    assert ev.timestamp is not None


def test_events_are_hash_chained(db):
    first = _record(db)
    second = _record(db)

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.event_hash
    assert first.event_hash != second.event_hash


def test_verify_chain_passes_on_clean_log(db):
    for _ in range(3):
        _record(db)

    result = verify_chain(db)

    assert result.ok is True
    assert result.checked == 3


def test_audit_events_cannot_be_updated(db):
    _record(db)

    with pytest.raises(DBAPIError):
        db.execute(
            text(
                "UPDATE audit_events "
                "SET result = 'SUCCESS' WHERE id = 1"
            )
        )


def test_audit_events_cannot_be_deleted(db):
    _record(db)

    with pytest.raises(DBAPIError):
        db.execute(
            text("DELETE FROM audit_events WHERE id = 1")
        )


def test_tampering_is_detected_even_if_triggers_are_bypassed(db):
    """Simulates a database admin hiding a denial. The triggers are dropped on
    purpose to show the hash chain is a second, independent control."""
    _record(db)
    _record(
        db,
        result=Result.DENIED,
        event_type=EventType.ACCESS_DENIED,
    )
    _record(db)

    db.execute(text("DROP TRIGGER audit_events_no_update"))
    db.execute(
        text(
            "UPDATE audit_events "
            "SET result = 'SUCCESS' WHERE id = 2"
        )
    )
    db.commit()

    result = verify_chain(db)

    assert result.ok is False
    assert result.first_bad_id == 2


def test_list_events_filters(db):
    _record(db, event_type=EventType.USER_CREATED)
    _record(db, event_type=EventType.ROLE_ASSIGNED)

    events = list_events(
        db,
        event_type=EventType.ROLE_ASSIGNED,
    )

    assert len(events) == 1
    assert events[0].event_type == "ROLE_ASSIGNED"