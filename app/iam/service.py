from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.db.models import Department, Role, User, UserRole


class IAMError(Exception):
    pass


class NotFoundError(IAMError):
    pass


class ConflictError(IAMError):
    pass


def _fail(
    db: Session,
    *,
    exc: type[IAMError],
    actor: str,
    event_type: EventType,
    target: str,
    action: str,
    reason: str,
    correlation_id: str | None,
):
    """Record a FAILURE event, commit it on its own, then raise the error."""
    record_event(
        db,
        actor=actor,
        event_type=event_type,
        target=target,
        action=action,
        result=Result.FAILURE,
        reason=reason,
        correlation_id=correlation_id,
    )
    db.commit()
    raise exc(reason)


def _get_user(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def create_user(
    db: Session,
    *,
    actor: str,
    employee_id: str,
    username: str,
    full_name: str,
    email: str,
    department_name: str,
    manager_username: str | None = None,
    correlation_id: str | None = None,
) -> User:
    target = f"user:{username}"

    fail = dict(
        actor=actor,
        event_type=EventType.USER_CREATED,
        target=target,
        action="create_user",
        correlation_id=correlation_id,
    )

    department = db.scalar(
        select(Department).where(Department.name == department_name)
    )

    if department is None:
        _fail(
            db,
            exc=NotFoundError,
            reason=f"department '{department_name}' not found",
            **fail,
        )

    manager = None

    if manager_username:
        manager = _get_user(db, manager_username)

        if manager is None:
            _fail(
                db,
                exc=NotFoundError,
                reason=f"manager '{manager_username}' not found",
                **fail,
            )

    clash = db.scalar(
        select(User).where(
            (User.username == username)
            | (User.employee_id == employee_id)
            | (User.email == email)
        )
    )

    if clash is not None:
        _fail(
            db,
            exc=ConflictError,
            reason="username, employee_id or email already exists",
            **fail,
        )

    user = User(
        employee_id=employee_id,
        username=username,
        full_name=full_name,
        email=email,
        department_id=department.id,
        manager_id=manager.id if manager else None,
    )

    db.add(user)

    record_event(
        db,
        actor=actor,
        event_type=EventType.USER_CREATED,
        target=target,
        action="create_user",
        result=Result.SUCCESS,
        reason=f"department={department_name}",
        correlation_id=correlation_id,
    )

    db.commit()

    return user


def assign_role(
    db: Session,
    *,
    actor: str,
    username: str,
    role_name: str,
    correlation_id: str | None = None,
) -> UserRole:
    target = f"user:{username}"
    action = f"assign_role:{role_name}"

    fail = dict(
        actor=actor,
        event_type=EventType.ROLE_ASSIGNED,
        target=target,
        action=action,
        correlation_id=correlation_id,
    )

    user = _get_user(db, username)

    if user is None:
        _fail(
            db,
            exc=NotFoundError,
            reason=f"user '{username}' not found",
            **fail,
        )

    role = db.scalar(
        select(Role).where(Role.name == role_name)
    )

    if role is None:
        _fail(
            db,
            exc=NotFoundError,
            reason=f"role '{role_name}' not found",
            **fail,
        )

    if db.get(UserRole, (user.id, role.id)) is not None:
        _fail(
            db,
            exc=ConflictError,
            reason="role already assigned",
            **fail,
        )

    assignment = UserRole(
        user_id=user.id,
        role_id=role.id,
    )

    db.add(assignment)

    record_event(
        db,
        actor=actor,
        event_type=EventType.ROLE_ASSIGNED,
        target=target,
        action=action,
        result=Result.SUCCESS,
        correlation_id=correlation_id,
    )

    db.commit()

    return assignment


def remove_role(
    db: Session,
    *,
    actor: str,
    username: str,
    role_name: str,
    correlation_id: str | None = None,
) -> None:
    target = f"user:{username}"
    action = f"remove_role:{role_name}"

    fail = dict(
        actor=actor,
        event_type=EventType.ROLE_REMOVED,
        target=target,
        action=action,
        correlation_id=correlation_id,
    )

    user = _get_user(db, username)

    if user is None:
        _fail(
            db,
            exc=NotFoundError,
            reason=f"user '{username}' not found",
            **fail,
        )

    role = db.scalar(
        select(Role).where(Role.name == role_name)
    )

    if role is None:
        _fail(
            db,
            exc=NotFoundError,
            reason=f"role '{role_name}' not found",
            **fail,
        )

    assignment = db.get(UserRole, (user.id, role.id))

    if assignment is None:
        _fail(
            db,
            exc=NotFoundError,
            reason="role is not assigned to user",
            **fail,
        )

    db.delete(assignment)

    record_event(
        db,
        actor=actor,
        event_type=EventType.ROLE_REMOVED,
        target=target,
        action=action,
        result=Result.SUCCESS,
        correlation_id=correlation_id,
    )

    db.commit()