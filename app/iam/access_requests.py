from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.core.clock import now
from app.db.models import AccessRequest, Role, User, UserRole


class AccessRequestError(Exception):
    """Base exception for access request operations."""


class AccessRequestNotFoundError(AccessRequestError):
    pass


class UserNotFoundError(AccessRequestError):
    pass


class RoleNotFoundError(AccessRequestError):
    pass


class InvalidAccessRequestError(AccessRequestError):
    pass


class SelfApprovalError(AccessRequestError):
    pass


class AccessRequestAlreadyDecidedError(AccessRequestError):
    pass


class AccessRequestNotApprovedError(AccessRequestError):
    pass


class AccessRequestAlreadyProvisionedError(AccessRequestError):
    pass


def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)

    if user is None:
        raise UserNotFoundError(f"User {user_id} not found")

    return user


def _get_role(db: Session, role_id: int) -> Role:
    role = db.get(Role, role_id)

    if role is None:
        raise RoleNotFoundError(f"Role {role_id} not found")

    return role


def _get_access_request(db: Session, request_id: int) -> AccessRequest:
    access_request = db.get(AccessRequest, request_id)

    if access_request is None:
        raise AccessRequestNotFoundError(
            f"Access request {request_id} not found"
        )

    return access_request


def create_access_request(
    db: Session,
    requester_id: int,
    target_user_id: int,
    role_id: int,
    justification: str,
    expires_at=None,
) -> AccessRequest:
    requester = _get_user(db, requester_id)
    target_user = _get_user(db, target_user_id)
    role = _get_role(db, role_id)

    justification = justification.strip()

    if not justification:
        raise InvalidAccessRequestError(
            "Justification cannot be empty"
        )

    if target_user.status != "ACTIVE":
        raise InvalidAccessRequestError(
            "Access can only be requested for an active user"
        )

    if expires_at is not None and expires_at <= now():
        raise InvalidAccessRequestError(
            "Expiration time must be in the future"
        )

    access_request = AccessRequest(
        requester_id=requester.id,
        target_user_id=target_user.id,
        role_id=role.id,
        justification=justification,
        status="REQUESTED",
        expires_at=expires_at,
    )

    db.add(access_request)
    db.flush()

    record_event(
        db,
        actor=requester.username,
        event_type=EventType.ACCESS_REQUESTED,
        target=target_user.username,
        action="request_access",
        result=Result.SUCCESS,
        reason=(
            f"Requested role '{role.name}' "
            f"for user '{target_user.username}'"
        ),
    )

    db.commit()
    db.refresh(access_request)

    return access_request


def approve_access_request(
    db: Session,
    request_id: int,
    approver: User,
    reason: str,
) -> AccessRequest:
    access_request = _get_access_request(db, request_id)

    if access_request.status != "REQUESTED":
        raise AccessRequestAlreadyDecidedError(
            "Access request has already been decided"
        )

    if approver.id == access_request.requester_id:
        raise SelfApprovalError(
            "Requester cannot approve their own access request"
        )

    reason = reason.strip()

    if not reason:
        raise InvalidAccessRequestError(
            "Approval reason cannot be empty"
        )

    access_request.status = "APPROVED"
    access_request.decision_by = approver.username
    access_request.decision_reason = reason
    access_request.decided_at = now()

    record_event(
        db,
        actor=approver.username,
        event_type=EventType.ACCESS_APPROVED,
        target=str(access_request.id),
        action="approve_access_request",
        result=Result.SUCCESS,
        reason=reason,
    )

    db.commit()
    db.refresh(access_request)

    return access_request


def reject_access_request(
    db: Session,
    request_id: int,
    approver: User,
    reason: str,
) -> AccessRequest:
    access_request = _get_access_request(db, request_id)

    if access_request.status != "REQUESTED":
        raise AccessRequestAlreadyDecidedError(
            "Access request has already been decided"
        )

    if approver.id == access_request.requester_id:
        raise SelfApprovalError(
            "Requester cannot reject their own access request"
        )

    reason = reason.strip()

    if not reason:
        raise InvalidAccessRequestError(
            "Rejection reason cannot be empty"
        )

    access_request.status = "REJECTED"
    access_request.decision_by = approver.username
    access_request.decision_reason = reason
    access_request.decided_at = now()

    record_event(
        db,
        actor=approver.username,
        event_type=EventType.ACCESS_REJECTED,
        target=str(access_request.id),
        action="reject_access_request",
        result=Result.SUCCESS,
        reason=reason,
    )

    db.commit()
    db.refresh(access_request)

    return access_request


def provision_access_request(
    db: Session,
    request_id: int,
    provisioner: User,
) -> AccessRequest:
    access_request = _get_access_request(db, request_id)

    if access_request.status != "APPROVED":
        raise AccessRequestNotApprovedError(
            "Only approved access requests can be provisioned"
        )

    target_user = access_request.target_user
    role = access_request.role

    if target_user.status != "ACTIVE":
        raise InvalidAccessRequestError(
            "Access can only be provisioned for an active user"
        )

    existing_assignment = db.scalar(
        select(UserRole).where(
            UserRole.user_id == target_user.id,
            UserRole.role_id == role.id,
        )
    )

    if existing_assignment is not None:
        raise AccessRequestAlreadyProvisionedError(
            "User already has this role"
        )

    assignment = UserRole(
        user_id=target_user.id,
        role_id=role.id,
        expires_at=access_request.expires_at,
    )

    db.add(assignment)

    access_request.status = "PROVISIONED"
    access_request.provisioned_at = now()

    record_event(
        db,
        actor=provisioner.username,
        event_type=EventType.ACCESS_PROVISIONED,
        target=target_user.username,
        action="provision_access",
        result=Result.SUCCESS,
        reason=f"Provisioned role '{role.name}'",
    )

    db.commit()
    db.refresh(access_request)

    return access_request


def list_access_requests(db: Session) -> list[AccessRequest]:
    statement = select(AccessRequest).order_by(
        AccessRequest.requested_at.desc()
    )

    return list(db.scalars(statement).all())