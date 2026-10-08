from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.clock import now
from app.db.models import UserRole
from app.db.models import Department, User
from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.core.security import hash_password


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

    record_event(
        db,
        actor=actor,
        event_type=EventType.USER_TERMINATED,
        target=user.username,
        action="terminate_user",
        result=Result.SUCCESS,
        reason="JML leaver terminated user account and expired active role assignments",
    )

    db.commit()
    db.refresh(user)

    return user