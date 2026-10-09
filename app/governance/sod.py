
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import now
from app.db.models import Role, User, UserRole


# Each pair represents roles that must not be held together.
SOD_CONFLICT_RULES: tuple[frozenset[str], ...] = (
    frozenset({"Payment Initiator", "Payment Approver"}),
)


@dataclass(frozen=True)
class SodConflict:
    """A detected segregation-of-duties conflict."""

    user_id: int
    username: str
    conflicting_roles: tuple[str, ...]
    description: str


def find_role_conflicts(
    role_names: set[str],
) -> list[tuple[str, ...]]:
    """Return conflicting role combinations from a set of role names."""
    conflicts = []

    for rule in SOD_CONFLICT_RULES:
        if rule.issubset(role_names):
            conflicts.append(tuple(sorted(rule)))

    return conflicts


def get_active_role_names(
    db: Session,
    user_id: int,
) -> set[str]:
    """Get roles assigned to a user that have not expired."""
    user = db.get(User, user_id)

    if user is None or user.status != "ACTIVE":
        return set()

    current_time = now()

    assignments = db.scalars(
        select(UserRole).where(UserRole.user_id == user_id)
    ).all()

    return {
        assignment.role.name
        for assignment in assignments
        if (
            assignment.expires_at is None
            or assignment.expires_at > current_time
        )
    }


def evaluate_user_sod(
    db: Session,
    user_id: int,
    additional_role_id: int | None = None,
) -> list[SodConflict]:
    """
    Evaluate existing role assignments and, optionally,
    a proposed additional role without changing the database.
    """
    user = db.get(User, user_id)

    if user is None or user.status != "ACTIVE":
        return []

    role_names = get_active_role_names(db, user_id)

    if additional_role_id is not None:
        proposed_role = db.get(Role, additional_role_id)

        if proposed_role is None:
            raise ValueError(
                f"Role {additional_role_id} not found"
            )

        role_names.add(proposed_role.name)

    conflicts = find_role_conflicts(role_names)

    return [
        SodConflict(
            user_id=user.id,
            username=user.username,
            conflicting_roles=conflicting_roles,
            description=(
                "User holds incompatible roles: "
                + " and ".join(conflicting_roles)
            ),
        )
        for conflicting_roles in conflicts
    ]