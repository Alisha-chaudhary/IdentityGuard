from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import now
from app.db.models import Permission, Role, User, UserRole


def get_active_permissions(db: Session, user: User) -> set[str]:
    current_time = now()

    assignments = db.scalars(
        select(UserRole).where(UserRole.user_id == user.id)
    ).all()

    permissions: set[str] = set()

    for assignment in assignments:
        if (
            assignment.expires_at is not None
            and assignment.expires_at <= current_time
        ):
            continue

        for role_permission in assignment.role.role_permissions:
            permission: Permission = role_permission.permission
            permissions.add(
                f"{permission.resource.name}:{permission.action}"
            )

    return permissions


def has_permission(
    db: Session,
    user: User,
    permission: str,
) -> bool:
    return permission in get_active_permissions(db, user)


def can_assign_role(
    db: Session,
    actor: User,
    target: User,
    role: Role,
) -> bool:
    """Return whether actor may assign role to target."""

    # A user cannot assign a role to themselves.
    if actor.id == target.id:
        return False

    # Privileged roles require the stronger permission.
    if role.is_privileged:
        return has_permission(
            db,
            actor,
            "IdentityGuard:role.assign_privileged",
        )

    return has_permission(
        db,
        actor,
        "IdentityGuard:role.assign",
    )


def can_approve_access(
    actor: User,
    target: User,
) -> bool:
    """Return whether actor may approve access for target."""

    # A user cannot approve their own access request.
    return actor.id != target.id