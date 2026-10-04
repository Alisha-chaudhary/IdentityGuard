import pytest
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import Department, Role, User, UserRole
from app.db.seed import seed


def _user(
    username="u1",
    employee_id="E1",
    department_id=1,
    status="ACTIVE",
):
    return User(
        employee_id=employee_id,
        username=username,
        full_name="Test User",
        email=f"{username}@example.test",
        department_id=department_id,
        status=status,
    )


def test_foreign_keys_are_enforced(db):
    db.add(_user(department_id=999))

    with pytest.raises(IntegrityError):
        db.commit()


def test_duplicate_username_rejected(db):
    db.add(Department(id=1, name="Finance"))
    db.commit()

    db.add(_user(username="dup", employee_id="E1"))
    db.commit()

    db.add(_user(username="dup", employee_id="E2"))

    with pytest.raises(IntegrityError):
        db.commit()


def test_invalid_user_status_rejected(db):
    db.add(Department(id=1, name="Finance"))
    db.commit()

    db.add(_user(status="SUPERUSER"))

    with pytest.raises(IntegrityError):
        db.commit()


def test_seed_creates_expected_data(db):
    seed(db)

    assert len(db.scalars(select(User)).all()) == 7
    assert len(db.scalars(select(Role)).all()) == 11


def test_seed_is_idempotent(db):
    seed(db)
    seed(db)

    assert len(db.scalars(select(User)).all()) == 7


def test_role_permissions_resolve_through_relationships(db):
    seed(db)

    role = db.scalar(
        select(Role).where(Role.name == "Finance Analyst")
    )

    perms = {
        (rp.permission.resource.name, rp.permission.action)
        for rp in role.role_permissions
    }

    assert perms == {("finance-ledger", "read")}


def test_privileged_roles_are_flagged(db):
    seed(db)

    privileged = {
        r.name
        for r in db.scalars(
            select(Role).where(Role.is_privileged)
        )
    }

    assert privileged == {
        "System Administrator",
        "Database Administrator",
        "IAM Administrator",
    }


def test_seed_contains_stale_access_case(db):
    seed(db)

    meera = db.scalar(
        select(User).where(User.username == "meera.iyer")
    )

    roles = {ur.role.name for ur in meera.user_roles}

    assert meera.department.name == "HR"
    assert "Finance Analyst" in roles  # stale: she moved to HR


def test_user_role_can_have_expiry(db):
    department = Department(name="Test")
    db.add(department)
    db.flush()

    user = User(
        employee_id="TEST001",
        username="expiry.user",
        full_name="Expiry User",
        email="expiry@example.test",
        status="ACTIVE",
        department_id=department.id,
    )

    role = Role(
        name="Temporary Role",
        description="Role with an expiry",
        is_privileged=False,
    )

    db.add_all([user, role])
    db.flush()

    expires_at = datetime(2026, 12, 31, 23, 59, 59)

    assignment = UserRole(
        user_id=user.id,
        role_id=role.id,
        expires_at=expires_at,
    )

    db.add(assignment)
    db.commit()

    db.refresh(assignment)

    assert assignment.expires_at == expires_at