from datetime import timedelta

import pytest
from app.iam.access_requests import SodConflictError
from app.audit.events import EventType
from app.db.models import AuditEvent
from app.core.clock import FrozenClock, set_clock
from app.iam.access_requests import (
    AccessRequestAlreadyDecidedError,
    AccessRequestAlreadyProvisionedError,
    AccessRequestNotApprovedError,
    SelfApprovalError,
    approve_access_request,
    create_access_request,
    provision_access_request,
    reject_access_request,
)
from app.db.models import (
    Department,
    Role,
    User,
    UserRole,
)


@pytest.fixture(autouse=True)
def reset_clock():
    from datetime import datetime

    clock = FrozenClock(datetime(2026, 1, 1, 12, 0, 0))
    set_clock(clock)

    yield

    set_clock(FrozenClock(datetime(2026, 1, 1, 12, 0, 0)))


def create_department(db, name="Finance"):
    department = Department(name=name)
    db.add(department)
    db.flush()
    return department


def create_user(
    db,
    department,
    username,
    employee_id,
    status="ACTIVE",
):
    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.title(),
        email=f"{username}@example.test",
        department_id=department.id,
        status=status,
    )
    db.add(user)
    db.flush()
    return user


def create_role(db, name="Finance Analyst"):
    role = Role(
        name=name,
        description="Test role",
        is_privileged=False,
    )
    db.add(role)
    db.flush()
    return role


def test_create_access_request_creates_requested_request_and_audit(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP002",
    )
    role = create_role(db)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Finance reporting access",
    )

    assert request.id is not None
    assert request.requester_id == requester.id
    assert request.target_user_id == target.id
    assert request.role_id == role.id
    assert request.status == "REQUESTED"
    assert request.justification == "Finance reporting access"

    event = db.query(AuditEvent).filter(
        AuditEvent.event_type == EventType.ACCESS_REQUESTED
    ).one()

    assert event.actor == requester.username
    assert event.result == "SUCCESS"


def test_cannot_create_request_for_inactive_user(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP002",
        status="DISABLED",
    )
    role = create_role(db)

    with pytest.raises(Exception, match="active user"):
        create_access_request(
            db=db,
            requester_id=requester.id,
            target_user_id=target.id,
            role_id=role.id,
            justification="Need access",
        )


def test_request_expiry_must_be_in_future(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP002",
    )
    role = create_role(db)

    from app.core.clock import now

    with pytest.raises(Exception, match="future"):
        create_access_request(
            db=db,
            requester_id=requester.id,
            target_user_id=target.id,
            role_id=role.id,
            justification="Need temporary access",
            expires_at=now(),
        )


def test_requester_cannot_approve_own_request(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP002",
    )
    role = create_role(db)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Need access",
    )

    with pytest.raises(SelfApprovalError):
        approve_access_request(
            db=db,
            request_id=request.id,
            approver=requester,
            reason="Approved",
        )


def test_approved_request_can_be_provisioned(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    approver = create_user(
        db,
        department,
        "approver",
        "EMP002",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP003",
    )
    role = create_role(db)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Finance reporting access",
    )

    approve_access_request(
        db=db,
        request_id=request.id,
        approver=approver,
        reason="Business need confirmed",
    )

    provision_access_request(
        db=db,
        request_id=request.id,
        provisioner=approver,
    )

    assignment = db.query(UserRole).filter(
        UserRole.user_id == target.id,
        UserRole.role_id == role.id,
    ).one()

    assert assignment.user_id == target.id
    assert assignment.role_id == role.id
    assert request.status == "PROVISIONED"
    assert request.provisioned_at is not None

    events = db.query(AuditEvent).order_by(AuditEvent.id).all()

    event_types = [event.event_type for event in events]

    assert EventType.ACCESS_REQUESTED in event_types
    assert EventType.ACCESS_APPROVED in event_types
    assert EventType.ACCESS_PROVISIONED in event_types


def test_expiry_is_copied_to_role_assignment(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    approver = create_user(
        db,
        department,
        "approver",
        "EMP002",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP003",
    )
    role = create_role(db)

    from app.core.clock import now

    expiry = now() + timedelta(hours=4)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Temporary elevated access",
        expires_at=expiry,
    )

    approve_access_request(
        db=db,
        request_id=request.id,
        approver=approver,
        reason="Approved for temporary work",
    )

    provision_access_request(
        db=db,
        request_id=request.id,
        provisioner=approver,
    )

    assignment = db.query(UserRole).filter(
        UserRole.user_id == target.id,
        UserRole.role_id == role.id,
    ).one()

    assert assignment.expires_at == expiry


def test_rejected_request_cannot_be_provisioned(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    approver = create_user(
        db,
        department,
        "approver",
        "EMP002",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP003",
    )
    role = create_role(db)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Need access",
    )

    reject_access_request(
        db=db,
        request_id=request.id,
        approver=approver,
        reason="Business justification insufficient",
    )

    assert request.status == "REJECTED"

    with pytest.raises(AccessRequestNotApprovedError):
        provision_access_request(
            db=db,
            request_id=request.id,
            provisioner=approver,
        )


def test_cannot_approve_request_twice(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    approver = create_user(
        db,
        department,
        "approver",
        "EMP002",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP003",
    )
    role = create_role(db)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Need access",
    )

    approve_access_request(
        db=db,
        request_id=request.id,
        approver=approver,
        reason="Approved",
    )

    with pytest.raises(AccessRequestAlreadyDecidedError):
        approve_access_request(
            db=db,
            request_id=request.id,
            approver=approver,
            reason="Approved again",
        )


def test_cannot_provision_before_approval(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    provisioner = create_user(
        db,
        department,
        "provisioner",
        "EMP002",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP003",
    )
    role = create_role(db)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Need access",
    )

    with pytest.raises(AccessRequestNotApprovedError):
        provision_access_request(
            db=db,
            request_id=request.id,
            provisioner=provisioner,
        )


def test_cannot_provision_same_role_twice(db):
    department = create_department(db)

    requester = create_user(
        db,
        department,
        "requester",
        "EMP001",
    )
    approver = create_user(
        db,
        department,
        "approver",
        "EMP002",
    )
    target = create_user(
        db,
        department,
        "target",
        "EMP003",
    )
    role = create_role(db)

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Need access",
    )

    approve_access_request(
        db=db,
        request_id=request.id,
        approver=approver,
        reason="Approved",
    )

    provision_access_request(
        db=db,
        request_id=request.id,
        provisioner=approver,
    )

    duplicate_request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=role.id,
        justification="Requesting same role again",
    )

    approve_access_request(
        db=db,
        request_id=duplicate_request.id,
        approver=approver,
        reason="Approved",
    )

    with pytest.raises(AccessRequestAlreadyProvisionedError):
        provision_access_request(
            db=db,
            request_id=duplicate_request.id,
            provisioner=approver,
        )


def test_sod_conflict_blocks_provisioning_and_records_audit(db):
    department = create_department(db)

    requester = create_user(db, department, "requester", "EMP101")
    approver = create_user(db, department, "approver", "EMP102")
    target = create_user(db, department, "target", "EMP103")

    initiator_role = create_role(db, "Payment Initiator")
    approver_role = create_role(db, "Payment Approver")

    db.add(
        UserRole(
            user_id=target.id,
            role_id=initiator_role.id,
        )
    )
    db.commit()

    request = create_access_request(
        db=db,
        requester_id=requester.id,
        target_user_id=target.id,
        role_id=approver_role.id,
        justification="Request payment approval access",
    )

    approve_access_request(
        db=db,
        request_id=request.id,
        approver=approver,
        reason="Approved for testing",
    )

    with pytest.raises(SodConflictError, match="SoD policy"):
        provision_access_request(
            db=db,
            request_id=request.id,
            provisioner=approver,
        )

    assignments = (
        db.query(UserRole)
        .filter(UserRole.user_id == target.id)
        .all()
    )

    assert {item.role_id for item in assignments} == {
        initiator_role.id
    }
    assert request.status == "APPROVED"
    assert request.provisioned_at is None

    event = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == EventType.SOD_VIOLATION)
        .one()
    )

    assert event.actor == approver.username
    assert event.target == target.username
    assert event.result == "DENIED"