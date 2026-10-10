from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Department, User, UserRole


def get_identity_inventory(db: Session) -> dict:
    """Return an identity inventory without exposing authentication secrets."""

    role_counts = (
        select(
            UserRole.user_id.label("user_id"),
            func.count(UserRole.role_id).label("role_assignment_count"),
        )
        .group_by(UserRole.user_id)
        .subquery()
    )

    statement = (
        select(
            User.id,
            User.employee_id,
            User.username,
            User.full_name,
            Department.name.label("department"),
            User.status,
            User.created_at,
            User.terminated_at,
            User.manager_id,
            role_counts.c.role_assignment_count,
        )
        .join(Department, User.department_id == Department.id)
        .outerjoin(role_counts, User.id == role_counts.c.user_id)
        .order_by(User.id)
    )

    rows = db.execute(statement).all()

    items = [
        {
            "user_id": row.id,
            "employee_id": row.employee_id,
            "username": row.username,
            "full_name": row.full_name,
            "department": row.department,
            "manager_id": row.manager_id,
            "status": row.status,
            "created_at": row.created_at,
            "terminated_at": row.terminated_at,
            "role_assignment_count": row.role_assignment_count or 0,
        }
        for row in rows
    ]

    return {
        "total_count": len(items),
        "items": items,
    }
