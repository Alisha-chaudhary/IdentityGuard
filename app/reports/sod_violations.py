"""Report of segregation-of-duties conflicts that exist *right now*.

Provisioning blocks new conflicts (app/iam/access_requests.py), but conflicts
can still exist from before a rule was added or from direct database changes.
This report scans every ACTIVE user against every rule in app/governance/sod.py.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import User
from app.governance.sod import SOD_CONFLICT_RULES, evaluate_user_sod


def get_sod_violations(db: Session) -> dict:
    users = db.scalars(
        select(User).where(User.status == "ACTIVE").order_by(User.username)
    ).all()

    items = []
    for user in users:
        for conflict in evaluate_user_sod(db, user.id):
            items.append(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "department": user.department.name,
                    "conflicting_roles": list(conflict.conflicting_roles),
                    "description": conflict.description,
                }
            )

    return {
        "rules": [sorted(rule) for rule in SOD_CONFLICT_RULES],
        "total_count": len(items),
        "items": items,
    }
