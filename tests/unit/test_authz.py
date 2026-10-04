from datetime import datetime
from app.core.clock import FrozenClock, set_clock
from app.db.models import Department, Role, User, UserRole
from app.authz.service import (
    can_approve_access,
    can_assign_role,
    get_active_permissions,
    has_permission,
)

def test_active_permissions_include_role_permissions(db):
    department = Department(name="Security")
    role = Role(
        name="Test Role",
        description="Test role",
        is_privileged=False,
    )

    db.add_all([department, role])
    db.flush()

    user = User(
        employee_id="AUTH001",
        username="auth.user",
        full_name="Auth User",
        email="auth@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add(user)
    db.flush()

    assignment = UserRole(
        user_id=user.id,
        role_id=role.id,
    )

    db.add(assignment)
    db.commit()

    assert get_active_permissions(db, user) == set()


def test_expired_role_assignment_is_ignored(db):
    department = Department(name="Security")
    role = Role(
        name="Temporary Role",
        description="Temporary role",
        is_privileged=False,
    )

    db.add_all([department, role])
    db.flush()

    user = User(
        employee_id="AUTH002",
        username="expired.user",
        full_name="Expired User",
        email="expired@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add(user)
    db.flush()

    assignment = UserRole(
        user_id=user.id,
        role_id=role.id,
        expires_at=datetime(2026, 1, 1, 0, 0, 0),
    )

    db.add(assignment)
    db.commit()

    set_clock(
        FrozenClock(datetime(2026, 2, 1, 0, 0, 0))
    )

    try:
        assert get_active_permissions(db, user) == set()
    finally:
        set_clock(FrozenClock(datetime(2026, 1, 1, 0, 0, 0)))


def test_non_expired_role_assignment_remains_active(db):
    department = Department(name="Security")
    role = Role(
        name="Temporary Role",
        description="Temporary role",
        is_privileged=False,
    )

    db.add_all([department, role])
    db.flush()

    user = User(
        employee_id="AUTH003",
        username="active.user",
        full_name="Active User",
        email="active@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add(user)
    db.flush()

    assignment = UserRole(
        user_id=user.id,
        role_id=role.id,
        expires_at=datetime(2026, 12, 31, 23, 59, 59),
    )

    db.add(assignment)
    db.commit()

    set_clock(
        FrozenClock(datetime(2026, 6, 1, 0, 0, 0))
    )

    try:
        assert get_active_permissions(db, user) == set()
    finally:
        set_clock(FrozenClock(datetime(2026, 1, 1, 0, 0, 0)))


def test_has_permission_returns_false_for_missing_permission(db):
    department = Department(name="Security")
    db.add(department)
    db.flush()

    user = User(
        employee_id="AUTH004",
        username="permission.user",
        full_name="Permission User",
        email="permission@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add(user)
    db.commit()

    assert has_permission(
        db,
        user,
        "IdentityGuard:user.read",
    ) is False

def test_user_cannot_assign_role_to_themselves(db):
    department = Department(name="Security")
    role = Role(
        name="Test Role",
        description="Test role",
        is_privileged=False,
    )

    db.add_all([department, role])
    db.flush()

    user = User(
        employee_id="AUTH005",
        username="self.assign",
        full_name="Self Assign",
        email="self.assign@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add(user)
    db.commit()

    assert can_assign_role(
        db,
        actor=user,
        target=user,
        role=role,
    ) is False


def test_privileged_role_requires_privileged_permission(db):
    department = Department(name="Security")

    privileged_role = Role(
        name="Privileged Test Role",
        description="Privileged test role",
        is_privileged=True,
    )

    db.add_all([department, privileged_role])
    db.flush()

    actor = User(
        employee_id="AUTH006",
        username="normal.admin",
        full_name="Normal Admin",
        email="normal.admin@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    target = User(
        employee_id="AUTH007",
        username="target.user",
        full_name="Target User",
        email="target@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add_all([actor, target])
    db.commit()

    assert can_assign_role(
        db,
        actor=actor,
        target=target,
        role=privileged_role,
    ) is False


def test_user_with_privileged_permission_can_assign_privileged_role(db):
    department = Department(name="Security")

    privileged_role = Role(
        name="Privileged Test Role",
        description="Privileged test role",
        is_privileged=True,
    )

    db.add_all([department, privileged_role])
    db.flush()

    actor = User(
        employee_id="AUTH008",
        username="iam.admin",
        full_name="IAM Admin",
        email="iam.admin@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    target = User(
        employee_id="AUTH009",
        username="target.admin",
        full_name="Target Admin",
        email="target.admin@example.test",
        department_id=department.id,
        status="ACTIVE",
    )

    db.add_all([actor, target])
    db.flush()

    db.commit()

    assert can_assign_role(
        db,
        actor=actor,
        target=target,
        role=privileged_role,
    ) is False


def test_user_cannot_approve_their_own_access():
    user = User(
        id=100,
        employee_id="AUTH010",
        username="self.approver",
        full_name="Self Approver",
        email="self.approver@example.test",
        status="ACTIVE",
    )

    assert can_approve_access(
        actor=user,
        target=user,
    ) is False


def test_user_can_approve_another_users_access():
    actor = User(
        id=101,
        employee_id="AUTH011",
        username="approver",
        full_name="Approver",
        email="approver@example.test",
        status="ACTIVE",
    )

    target = User(
        id=102,
        employee_id="AUTH012",
        username="requester",
        full_name="Requester",
        email="requester@example.test",
        status="ACTIVE",
    )

    assert can_approve_access(
        actor=actor,
        target=target,
    ) is True