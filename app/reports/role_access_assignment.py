
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import now
from app.db.models import Department, Role, User, UserRole


def get_role_access_assignments(db: Session) -> dict:
    """Return role assignments with identity context and expiry status."""

    current_time = now()

    statement = (
        select(
            UserRole.user_id,
            UserRole.role_id,
            UserRole.assigned_at,
            UserRole.expires_at,
            User.username,
            User.employee_id,
            User.full_name,
            User.status.label("user_status"),
            Department.name.label("department"),
            Role.name.label("role_name"),
            Role.description.label("role_description"),
            Role.is_privileged,
        )
        .join(User, UserRole.user_id == User.id)
        .join(Department, User.department_id == Department.id)
        .join(Role, UserRole.role_id == Role.id)
        .order_by(UserRole.user_id, UserRole.role_id)
    )

    rows = db.execute(statement).all()

    items = [
        {
            "user_id": row.user_id,
            "username": row.username,
            "employee_id": row.employee_id,
            "full_name": row.full_name,
            "department": row.department,
            "user_status": row.user_status,
            "role_id": row.role_id,
            "role_name": row.role_name,
            "role_description": row.role_description,
            "is_privileged": row.is_privileged,
            "assigned_at": row.assigned_at,
            "expires_at": row.expires_at,
            "assignment_status": (
                "EXPIRED"
                if (
                    row.expires_at is not None
                    and row.expires_at <= current_time
                )
                else (
                    "DISABLED_USER"
                    if row.user_status != "ACTIVE"
                    else "ACTIVE"
                )
            ),
        }
        for row in rows
    ]

    return {
        "total_count": len(items),
        "active_count": sum(
            item["assignment_status"] == "ACTIVE"
            for item in items
        ),
        "expired_count": sum(
            item["assignment_status"] == "EXPIRED"
            for item in items
        ),
        "disabled_user_count": sum(
            item["assignment_status"] == "DISABLED_USER"
            for item in items
        ),
        "privileged_assignment_count": sum(
            item["is_privileged"] for item in items
        ),
        "items": items,
    }
