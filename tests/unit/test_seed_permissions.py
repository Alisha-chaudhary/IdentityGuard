from sqlalchemy import select

from datetime import datetime, timedelta, timezone
from app.db.models import User, Permission, Role, RolePermission
from app.db.seed import seed


def _role_permissions(db, role_name):
    role = db.scalar(
        select(Role).where(Role.name == role_name)
    )
    assert role is not None

    return {
        (mapping.permission.resource.name, mapping.permission.action)
        for mapping in role.role_permissions
    }


def test_fresh_seed_keeps_security_auditor_read_only(db):
    seed(db)

    permissions = _role_permissions(db, "Security Auditor")

    assert ("IdentityGuard", "audit.read") in permissions
    assert ("IdentityGuard", "access_review.view") in permissions
    assert ("IdentityGuard", "reports.read") in permissions
    assert ("IdentityGuard", "access_review.decide") not in permissions


def test_existing_seed_removes_only_obsolete_security_auditor_decision(
    db,
):
    seed(db)

    auditor = db.scalar(
        select(Role).where(Role.name == "Security Auditor")
    )
    iam_admin = db.scalar(
        select(Role).where(Role.name == "IAM Administrator")
    )
    decide_permission = db.scalar(
        select(Permission).where(
            Permission.action == "access_review.decide"
        )
    )

    assert auditor is not None
    assert iam_admin is not None
    assert decide_permission is not None

    # Simulate the obsolete mapping found in an older seeded database.
    db.add(
        RolePermission(
            role_id=auditor.id,
            permission_id=decide_permission.id,
        )
    )
    db.commit()

    seed(db)

    auditor_permissions = _role_permissions(db, "Security Auditor")
    assert (
        "IdentityGuard",
        "access_review.decide",
    ) not in auditor_permissions

    # The permission remains available in the catalogue.
    assert db.get(Permission, decide_permission.id) is not None

    # The cleanup must not grant or remove this permission for IAM Admin.
    iam_permissions = _role_permissions(db, "IAM Administrator")
    assert (
        "IdentityGuard",
        "access_review.decide",
    ) not in iam_permissions

def test_existing_seed_removes_help_desk_platform_permissions(db):
    seed(db)

    help_desk = db.scalar(
        select(Role).where(Role.name == "Help Desk")
    )
    assert help_desk is not None

    # Simulate old platform permissions in an existing database.
    old_permissions = db.scalars(
        select(Permission).where(
            Permission.action.in_(["user.read", "role.remove"])
        )
    ).all()

    for permission in old_permissions:
        db.add(
            RolePermission(
                role_id=help_desk.id,
                permission_id=permission.id,
            )
        )
    db.commit()

    seed(db)

    help_desk_permissions = _role_permissions(db, "Help Desk")
    assert not any(
        resource == "IdentityGuard"
        for resource, _action in help_desk_permissions
    )

    # Existing platform permissions for privileged roles remain intact.
    iam_admin_permissions = _role_permissions(db, "IAM Administrator")
    assert ("IdentityGuard", "user.read") in iam_admin_permissions
    assert ("IdentityGuard", "role.remove") in iam_admin_permissions

def test_seed_backfills_password_without_reactivating_disabled_user(db):
    seed(db)

    user = db.scalar(
        select(User).where(User.username == "alisha.c")
    )
    assert user is not None

    user.password_hash = None
    user.status = "DISABLED"
    user.failed_attempts = 3
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    original_locked_until = user.locked_until
    db.commit()

    seed(db)

    db.refresh(user)

    assert user.password_hash
    assert user.status == "DISABLED"
    assert user.failed_attempts == 3
    assert _as_naive_utc(user.locked_until) == _as_naive_utc(
    original_locked_until
)


def test_seed_backfills_password_without_unlocking_locked_user(db):
    seed(db)

    user = db.scalar(
        select(User).where(User.username == "alisha.c")
    )
    assert user is not None

    user.password_hash = None
    user.status = "LOCKED"
    user.failed_attempts = 5
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    original_locked_until = user.locked_until
    db.commit()

    seed(db)

    db.refresh(user)

    assert user.password_hash
    assert user.status == "LOCKED"
    assert user.failed_attempts == 5
    assert _as_naive_utc(user.locked_until) == _as_naive_utc(
    original_locked_until
)


def test_seed_does_not_reactivate_terminated_user(db):
    seed(db)

    user = db.scalar(
        select(User).where(User.username == "alisha.c")
    )
    assert user is not None

    user.password_hash = None
    user.status = "TERMINATED"
    user.failed_attempts = 2
    db.commit()

    seed(db)

    db.refresh(user)

    assert user.password_hash
    assert user.status == "TERMINATED"
    assert user.failed_attempts == 2

def _as_naive_utc(value):
    if value is not None and value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value
