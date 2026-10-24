import pytest
from sqlalchemy import select

from app.core.security import verify_password
from app.db.models import Role, User, UserRole
from app.db.seed import seed, seed_demo_platform

# Register PAM models before the in-memory test database is created.
from app.pam.models import PamAccount, PamSafe  # noqa: F401


SEED_PASSWORD = "Shared-Seed-Password-2026!"
RECRUITER_PASSWORD = "Recruiter-Demo-Only-Password-2026!"
UPDATED_RECRUITER_PASSWORD = "Updated-Recruiter-Password-2026!"


def _prepare_demo(db, monkeypatch):
    seed(db)
    monkeypatch.setenv(
        "IDENTITYGUARD_RECRUITER_DEMO_PASSWORD",
        RECRUITER_PASSWORD,
    )
    monkeypatch.delenv(
        "IDENTITYGUARD_RESET_RECRUITER_DEMO_PASSWORD",
        raising=False,
    )
    seed_demo_platform(db, SEED_PASSWORD)


def _recruiter(db):
    user = db.scalar(
        select(User).where(User.username == "recruiter.demo")
    )
    assert user is not None
    return user


def _assigned_roles(db, user):
    return set(
        db.scalars(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user.id)
        ).all()
    )


def _role_permissions(db, role_name):
    role = db.scalar(
        select(Role).where(Role.name == role_name)
    )
    assert role is not None

    return {
        (mapping.permission.resource.name, mapping.permission.action)
        for mapping in role.role_permissions
    }


def test_recruiter_demo_uses_its_dedicated_password(db, monkeypatch):
    _prepare_demo(db, monkeypatch)

    user = _recruiter(db)

    assert verify_password(RECRUITER_PASSWORD, user.password_hash)
    assert not verify_password(SEED_PASSWORD, user.password_hash)
    assert user.status == "ACTIVE"


def test_recruiter_demo_has_only_security_auditor_role(db, monkeypatch):
    _prepare_demo(db, monkeypatch)

    user = _recruiter(db)

    assert _assigned_roles(db, user) == {"Security Auditor"}

    assert _role_permissions(db, "Security Auditor") == {
        ("IdentityGuard", "user.read"),
        ("IdentityGuard", "audit.read"),
        ("IdentityGuard", "access_review.view"),
        ("IdentityGuard", "reports.read"),
    }


def test_recruiter_demo_is_skipped_without_dedicated_password(
    db, monkeypatch
):
    seed(db)
    monkeypatch.delenv(
        "IDENTITYGUARD_RECRUITER_DEMO_PASSWORD",
        raising=False,
    )

    seed_demo_platform(db, SEED_PASSWORD)

    user = db.scalar(
        select(User).where(User.username == "recruiter.demo")
    )
    assert user is None


def test_recruiter_password_is_not_reset_without_opt_in(
    db, monkeypatch
):
    _prepare_demo(db, monkeypatch)

    monkeypatch.setenv(
        "IDENTITYGUARD_RECRUITER_DEMO_PASSWORD",
        UPDATED_RECRUITER_PASSWORD,
    )
    seed_demo_platform(db, SEED_PASSWORD)

    user = _recruiter(db)

    assert verify_password(RECRUITER_PASSWORD, user.password_hash)
    assert not verify_password(
        UPDATED_RECRUITER_PASSWORD,
        user.password_hash,
    )


def test_recruiter_password_resets_only_with_opt_in(
    db, monkeypatch
):
    _prepare_demo(db, monkeypatch)

    monkeypatch.setenv(
        "IDENTITYGUARD_RECRUITER_DEMO_PASSWORD",
        UPDATED_RECRUITER_PASSWORD,
    )
    monkeypatch.setenv(
        "IDENTITYGUARD_RESET_RECRUITER_DEMO_PASSWORD",
        "true",
    )

    seed_demo_platform(db, SEED_PASSWORD)

    user = _recruiter(db)

    assert verify_password(UPDATED_RECRUITER_PASSWORD, user.password_hash)
    assert not verify_password(RECRUITER_PASSWORD, user.password_hash)


def test_recruiter_demo_rejects_additional_roles(db, monkeypatch):
    _prepare_demo(db, monkeypatch)

    user = _recruiter(db)
    admin_role = db.scalar(
        select(Role).where(Role.name == "IAM Administrator")
    )
    assert admin_role is not None

    db.add(UserRole(user_id=user.id, role_id=admin_role.id))
    db.commit()

    with pytest.raises(RuntimeError, match="additional roles"):
        seed_demo_platform(db, SEED_PASSWORD)
