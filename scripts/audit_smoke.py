from app.audit.service import list_events, verify_chain
from app.db.init_db import init_db
from app.db.seed import seed
from app.db.session import SessionLocal
from app.iam.service import assign_role, remove_role


init_db()

with SessionLocal() as db:
    seed(db)

    assign_role(
        db,
        actor="priya.nair",
        username="sneha.rao",
        role_name="SOC Analyst",
    )

    remove_role(
        db,
        actor="priya.nair",
        username="sneha.rao",
        role_name="SOC Analyst",
    )

    for event in reversed(list_events(db)):
        print(
            event.id,
            event.timestamp,
            event.actor,
            event.event_type,
            event.target,
            event.action,
            event.result,
        )

    print(verify_chain(db))