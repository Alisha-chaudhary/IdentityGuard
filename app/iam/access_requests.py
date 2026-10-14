from sqlalchemy import select
from sqlalchemy.orm import Session
from app.governance.sod import evaluate_user_sod
from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.authz.service import has_permission
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


class SodConflictError(AccessRequestError):
    """Raised when provisioning would violate an SoD policy."""


class PrivilegedRoleAuthorizationError(AccessRequestError):
    """Raised when an actor lacks role.assign_privileged for a privileged role."""


class FourEyesViolationError(AccessRequestError):
    """Raised when one person would cover two steps that need separate people
    (target approving own access, self-provisioning, or approver == provisioner
    for a privileged role)."""


PRIVILEGED_ASSIGN_PERMISSION = "IdentityGuard:role.assign_privileged"


def _deny(db: Session, *, actor: str, target: str, action: str, reason: str) -> None:
    """Audit a denial. Committed immediately because the caller raises."""
    record_event(
        db,
        actor=actor,
        event_type=EventType.ACCESS_DENIED,
        target=target,
        action=action,
        result=Result.DENIED,
        reason=reason,
    )
    db.commit()


def _require_privileged_authority(
    db: Session, actor: User, role: Role, action: str
) -> None:
    if role.is_privileged and not has_permission(
        db, actor, PRIVILEGED_ASSIGN_PERMISSION
    ):
        reason = (
            f"'{role.name}' is a privileged role; {action} requires "
            "role.assign_privileged"
        )
        _deny(db, actor=actor.username, target=role.name, action=action, reason=reason)
        raise PrivilegedRoleAuthorizationError(reason)


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

    # Close the proxy loophole: someone else files the request *for* the
    # approver, and the approver then approves access to themselves.
    if approver.id == access_request.target_user_id:
        _deny(
            db,
            actor=approver.username,
            target=str(access_request.id),
            action="approve_access_request",
            reason="Target user attempted to approve access for themselves",
        )
        raise SelfApprovalError(
            "Target user cannot approve access for themselves"
        )

    _require_privileged_authority(
        db, approver, access_request.role, "approve_access_request"
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

    if provisioner.id == target_user.id:
        reason = "Users cannot provision access to themselves"
        _deny(
            db,
            actor=provisioner.username,
            target=target_user.username,
            action="provision_access",
            reason=reason,
        )
        raise FourEyesViolationError(reason)

    _require_privileged_authority(
        db, provisioner, role, "provision_access"
    )

    # Four-eyes for privileged roles: approving and provisioning must be
    # done by two different people.
    if role.is_privileged and provisioner.username == access_request.decision_by:
        reason = (
            f"Four-eyes rule: the approver of privileged role '{role.name}' "
            "cannot also provision it"
        )
        _deny(
            db,
            actor=provisioner.username,
            target=target_user.username,
            action="provision_access",
            reason=reason,
        )
        raise FourEyesViolationError(reason)

    existing_assignment = db.scalar(
        select(UserRole).where(
            UserRole.user_id == target_user.id,
            UserRole.role_id == role.id,
        )
    )

    # An expired (or terminated-out) assignment may be re-granted; only a
    # still-active one is a duplicate.
    reactivating = False
    if existing_assignment is not None:
        still_active = (
            existing_assignment.expires_at is None
            or existing_assignment.expires_at > now()
        )
        if still_active:
            raise AccessRequestAlreadyProvisionedError(
                "User already has this role"
            )
        reactivating = True


    conflicts = evaluate_user_sod(
        db,
        target_user.id,
        additional_role_id=role.id,
    )

    if conflicts:
        reason = "; ".join(
            conflict.description for conflict in conflicts
        )

        record_event(
            db,
            actor=provisioner.username,
            event_type=EventType.SOD_VIOLATION,
            target=target_user.username,
            action="provision_access",
            result=Result.DENIED,
            reason=reason,
        )

        db.commit()

        raise SodConflictError(
            f"Provisioning blocked by SoD policy: {reason}"
        )

    if reactivating:
        existing_assignment.assigned_at = now()
        existing_assignment.expires_at = access_request.expires_at
    else:
        db.add(
            UserRole(
                user_id=target_user.id,
                role_id=role.id,
                expires_at=access_request.expires_at,
            )
        )

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