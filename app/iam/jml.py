from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.authz.service import get_active_permissions
from app.core.clock import now
from app.core.security import check_password_strength, hash_password
from app.db.models import AccessRequest, Department, User, UserRole
from app.pam.service import revoke_all_for_user


class JMLError(Exception):
    """Base exception for JML service errors."""


class UserAlreadyExistsError(JMLError):
    """Raised when a user with the same unique identity already exists."""


class DepartmentNotFoundError(JMLError):
    """Raised when the requested department does not exist."""


class ManagerNotFoundError(JMLError):
    """Raised when the requested manager does not exist."""


class UserNotFoundError(JMLError):
    """Raised when the requested user does not exist."""


class InvalidManagerError(JMLError):
    """Raised when an invalid manager relationship is requested."""


class SelfTerminationError(JMLError):
    """Raised when an administrator tries to terminate their own account."""


class LastAdministratorError(JMLError):
    """Raised when terminating the last user able to administer privileged access."""


ADMIN_PERMISSION = "IdentityGuard:role.assign_privileged"


def create_user(
    db: Session,
    *,
    employee_id: str,
    username: str,
    full_name: str,
    email: str,
    department_id: int,
    password: str,
    manager_id: int | None = None,
    actor: str,
) -> User:
    """Create an active user and record the JML joiner event."""

    # Enforce the password policy (raises WeakPasswordError, a ValueError).
    check_password_strength(password, username)

    existing_user = db.scalar(
        select(User).where(
            (User.employee_id == employee_id)
            | (User.username == username)
            | (User.email == email)
        )
    )

    if existing_user is not None:
        raise UserAlreadyExistsError(
            "A user with the supplied employee ID, username, or email already exists."
        )

    department = db.get(Department, department_id)

    if department is None:
        raise DepartmentNotFoundError(
            f"Department {department_id} does not exist."
        )

    if manager_id is not None:
        manager = db.get(User, manager_id)

        if manager is None:
            raise ManagerNotFoundError(
                f"Manager {manager_id} does not exist."
            )

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=full_name,
        email=email,
        password_hash=hash_password(password),
        status="ACTIVE",
        failed_attempts=0,
        locked_until=None,
        department_id=department_id,
        manager_id=manager_id,
    )

    db.add(user)

    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise UserAlreadyExistsError(
            "A user with the supplied identity already exists."
        ) from exc

    record_event(
        db,
        actor=actor,
        event_type=EventType.USER_CREATED,
        target=user.username,
        action="create_user",
        result=Result.SUCCESS,
        reason="JML joiner created user account",
    )

    db.commit()
    db.refresh(user)

    return user


def move_user(
    db: Session,
    *,
    user_id: int,
    department_id: int | None = None,
    manager_id: int | None = None,
    actor: str,
) -> User:
    """Move an existing user to a new department and/or manager."""

    user = db.get(User, user_id)

    if user is None:
        raise UserNotFoundError(
            f"User {user_id} does not exist."
        )

    if department_id is None and manager_id is None:
        raise JMLError(
            "At least one of department_id or manager_id must be provided."
        )

    if department_id is not None:
        department = db.get(Department, department_id)

        if department is None:
            raise DepartmentNotFoundError(
                f"Department {department_id} does not exist."
            )

    if manager_id is not None:
        if manager_id == user.id:
            raise InvalidManagerError(
                "A user cannot be their own manager."
            )

        manager = db.get(User, manager_id)

        if manager is None:
            raise ManagerNotFoundError(
                f"Manager {manager_id} does not exist."
            )

    old_department_id = user.department_id
    old_manager_id = user.manager_id

    if department_id is not None:
        user.department_id = department_id

    if manager_id is not None:
        user.manager_id = manager_id

    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise JMLError(
            "The user move could not be completed."
        ) from exc

    changes = []

    if department_id is not None and department_id != old_department_id:
        changes.append(
            f"department {old_department_id} -> {department_id}"
        )

    if manager_id is not None and manager_id != old_manager_id:
        changes.append(
            f"manager {old_manager_id} -> {manager_id}"
        )

    if changes:
        reason = "JML mover updated " + ", ".join(changes)

        if department_id is not None and department_id != old_department_id:
            # Movers keep their existing roles; the compensating control is
            # the access review. Make that visible in the audit trail.
            retained = [
                a for a in user.user_roles
                if a.expires_at is None or a.expires_at > now()
            ]
            if retained:
                reason += (
                    f"; {len(retained)} active role(s) retained pending "
                    "access review"
                )

        record_event(
            db,
            actor=actor,
            event_type=EventType.USER_MOVED,
            target=user.username,
            action="move_user",
            result=Result.SUCCESS,
            reason=reason,
        )

    db.commit()
    db.refresh(user)

    return user

def terminate_user(
    db: Session,
    *,
    user_id: int,
    actor: str,
) -> User:
    """Terminate a user and expire all active role assignments."""

    user = db.get(User, user_id)

    if user is None:
        raise UserNotFoundError(
            f"User {user_id} does not exist."
        )

    if user.username == actor:
        raise SelfTerminationError(
            "Administrators cannot terminate their own account."
        )

    if user.status == "ACTIVE" and ADMIN_PERMISSION in get_active_permissions(
        db, user
    ):
        other_admins = [
            other
            for other in db.scalars(
                select(User).where(
                    User.status == "ACTIVE", User.id != user.id
                )
            ).all()
            if ADMIN_PERMISSION in get_active_permissions(db, other)
        ]
        if not other_admins:
            raise LastAdministratorError(
                "Cannot terminate the last active privileged administrator."
            )

    termination_time = now()

    user.status = "TERMINATED"
    user.terminated_at = termination_time

    active_role_assignments = db.scalars(
        select(UserRole).where(
            UserRole.user_id == user.id,
            (UserRole.expires_at.is_(None))
            | (UserRole.expires_at > termination_time),
        )
    ).all()

    for assignment in active_role_assignments:
        assignment.expires_at = termination_time

    # Leaver clean-up: close anything that could still act for this user.
    pam = revoke_all_for_user(
        db,
        user_id=user.id,
        actor=actor,
        reason="JML leaver: user terminated",
    )

    open_requests = db.scalars(
        select(AccessRequest).where(
            AccessRequest.status.in_(("REQUESTED", "APPROVED")),
            (AccessRequest.requester_id == user.id)
            | (AccessRequest.target_user_id == user.id),
        )
    ).all()
    for access_request in open_requests:
        access_request.status = "REJECTED"
        access_request.decision_by = "system"
        access_request.decision_reason = "Auto-rejected: JML leaver terminated"
        access_request.decided_at = termination_time
        record_event(
            db,
            actor=actor,
            event_type=EventType.ACCESS_REJECTED,
            target=str(access_request.id),
            action="auto_reject_on_termination",
            result=Result.SUCCESS,
            reason=f"Open request closed because {user.username} was terminated",
        )

    record_event(
        db,
        actor=actor,
        event_type=EventType.USER_TERMINATED,
        target=user.username,
        action="terminate_user",
        result=Result.SUCCESS,
        reason=(
            "JML leaver terminated user account and expired active role "
            f"assignments; revoked {pam['revoked_checkouts']} PAM checkout(s), "
            f"cancelled {pam['cancelled_requests']} PAM request(s), "
            f"closed {len(open_requests)} access request(s)"
        ),
    )

    db.commit()
    db.refresh(user)

    return user