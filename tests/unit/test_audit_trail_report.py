from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.reports.audit_trail import get_audit_trail


def add_event(
    db,
    *,
    actor="audit.user",
    event_type=EventType.USER_CREATED,
    target="user:report-test",
    result=Result.SUCCESS,
    correlation_id=None,
):
    return record_event(
        db,
        actor=actor,
        event_type=event_type,
        target=target,
        action="test_action",
        result=result,
        reason="Audit trail report test",
        correlation_id=correlation_id,
    )


def test_audit_trail_returns_empty_report_with_valid_integrity(db):
    report = get_audit_trail(db)

    assert report["total_count"] == 0
    assert report["success_count"] == 0
    assert report["denied_count"] == 0
    assert report["failure_count"] == 0
    assert report["integrity"] == {
        "ok": True,
        "checked": 0,
        "first_bad_id": None,
    }
    assert report["items"] == []


def test_audit_trail_counts_results_and_reports_integrity(db):
    add_event(db, result=Result.SUCCESS)
    add_event(db, result=Result.DENIED)
    add_event(db, result=Result.FAILURE)
    db.commit()

    report = get_audit_trail(db)

    assert report["total_count"] == 3
    assert report["success_count"] == 1
    assert report["denied_count"] == 1
    assert report["failure_count"] == 1
    assert report["integrity"]["ok"] is True
    assert report["integrity"]["checked"] == 3


def test_audit_trail_filters_events(db):
    add_event(
        db,
        actor="alice",
        event_type=EventType.USER_CREATED,
        target="user:alice",
        correlation_id="correlation-a",
    )
    add_event(
        db,
        actor="bob",
        event_type=EventType.ROLE_ASSIGNED,
        target="user:bob",
        correlation_id="correlation-b",
    )
    db.commit()

    report = get_audit_trail(
        db,
        actor="alice",
        target="user:alice",
        correlation_id="correlation-a",
    )

    assert report["total_count"] == 1
    assert report["items"][0]["actor"] == "alice"
    assert report["items"][0]["target"] == "user:alice"
    assert report["items"][0]["correlation_id"] == "correlation-a"
    assert report["integrity"]["ok"] is True
    assert report["integrity"]["checked"] == 2


def test_audit_trail_returns_newest_events_first(db):
    add_event(db, actor="first")
    add_event(db, actor="second")
    db.commit()

    report = get_audit_trail(db)

    assert [item["actor"] for item in report["items"]] == [
        "second",
        "first",
    ]


def test_audit_trail_respects_limit(db):
    add_event(db, actor="first")
    add_event(db, actor="second")
    add_event(db, actor="third")
    db.commit()

    report = get_audit_trail(db, limit=2)

    assert report["total_count"] == 2
    assert [item["actor"] for item in report["items"]] == [
        "third",
        "second",
    ]
    assert report["integrity"]["checked"] == 3