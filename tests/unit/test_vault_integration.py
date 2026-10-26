"""Integration tests for the Vault secret access workflow.

Tests use mocked Vault clients and in-memory SQLite databases. They cover:
- Read with active IdentityGuard grant succeeds
- Read without IdentityGuard grant is denied
- Vault 403 (policy denial) is propagated
- Vault 404 (secret not found) is propagated
- Vault unreachable is propagated
- Secret values are never recorded in audit reasons
- Grant check reflects IdentityGuard state only
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from app.audit.events import EventType
from app.db.base import Base
from app.db.models import (
    AuditEvent,
    Department,
    Role,
    User,
    UserRole,
)
from app.db.session import make_engine
from app.vault.client import VaultClient, VaultError
from app.vault.integration import (
    VaultAccessError,
    VaultSecretAccessService,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class MockVaultClient:
    """A mock Vault client that returns canned responses or raises errors."""

    def __init__(
        self,
        secret_data=None,
        error=None,
        health=True,
    ) -> None:
        self.secret_data = secret_data or {"value": "synthetic", "description": "test"}
        self.error = error
        self.health_val = health
        self.read_calls = []

    def read_secret(self, path=None):
        self.read_calls.append(path)
        if self.error:
            raise self.error
        return dict(self.secret_data)

    def health(self):
        return self.health_val

    def summarize(self):
        return "mock vault"


@pytest.fixture
def db():
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker

    session = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False
    )()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def seed_user(db, username, employee_id, status="ACTIVE", external_id=None):
    dept = db.get(Department, 1)
    if dept is None:
        dept = Department(id=1, name="Dept 1")
        db.add(dept)
        db.flush()
    user = User(
        employee_id=employee_id,
        username=username,
        full_name=username.replace(".", " ").title(),
        email=f"{username}@example.test",
        department_id=dept.id,
        status=status,
    )
    db.add(user)
    db.flush()
    if external_id:
        from app.db.models import ExternalIdentity

        ei = ExternalIdentity(
            provider="ldap",
            external_id=external_id,
            local_user_id=user.id,
            dn=f"uid={username},ou=people,dc=example,dc=test",
            username=username,
            last_seen_at=utcnow(),
            sync_status="matched",
        )
        db.add(ei)
        db.flush()
    db.commit()
    db.refresh(user)
    return user


def seed_role(db, name, is_privileged=False):
    role = Role(name=name, description=name, is_privileged=is_privileged)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


def seed_user_role(db, user, role):
    ur = UserRole(user_id=user.id, role_id=role.id)
    db.add(ur)
    db.commit()
    db.refresh(ur)
    return ur


# ------------------------------------------------------------------
# Read with active grant
# ------------------------------------------------------------------


def test_read_with_active_grant_succeeds(db):
    """User with active IdentityGuard grant can read the secret."""
    user = seed_user(db, "vault.user", "VU001")
    role = seed_role(db, "Vault Secret Access")
    seed_user_role(db, user, role)
    mock_vault = MockVaultClient(
        secret_data={"value": "synthetic-value", "description": "A test secret"}
    )
    service = VaultSecretAccessService(db, mock_vault)

    result = service.read_synthetic_secret(user, "identityguard-lab/data/synthetic/test-secret")

    assert result["access_granted"] is True
    assert result["identityguard_grant"] is True
    assert result["vault_policy_enforced"] is True
    assert "value" in result["secret_keys"]
    assert len(mock_vault.read_calls) == 1


# ------------------------------------------------------------------
# Read without grant
# ------------------------------------------------------------------


def test_read_without_grant_denied(db):
    """User without IdentityGuard grant is denied."""
    user = seed_user(db, "no-grant.user", "VU002")
    mock_vault = MockVaultClient()
    service = VaultSecretAccessService(db, mock_vault)

    with pytest.raises(VaultAccessError) as exc:
        service.read_synthetic_secret(user, "identityguard-lab/data/synthetic/test-secret")

    assert exc.value.status_code == 403
    assert mock_vault.read_calls == []  # Vault never contacted


# ------------------------------------------------------------------
# Vault policy denial (403)
# ------------------------------------------------------------------


def test_vault_403_propagated(db):
    """Vault policy denial (403) is propagated as VaultAccessError."""
    user = seed_user(db, "vault.user", "VU001")
    role = seed_role(db, "Vault Secret Access")
    seed_user_role(db, user, role)
    mock_vault = MockVaultClient(error=VaultError("policy denied", status_code=403))
    service = VaultSecretAccessService(db, mock_vault)

    with pytest.raises(VaultAccessError) as exc:
        service.read_synthetic_secret(user, "identityguard-lab/data/synthetic/test-secret")

    assert exc.value.status_code == 403


# ------------------------------------------------------------------
# Vault secret not found (404)
# ------------------------------------------------------------------


def test_vault_404_propagated(db):
    """Vault secret not found (404) is propagated."""
    user = seed_user(db, "vault.user", "VU001")
    role = seed_role(db, "Vault Secret Access")
    seed_user_role(db, user, role)
    mock_vault = MockVaultClient(error=VaultError("not found", status_code=404))
    service = VaultSecretAccessService(db, mock_vault)

    with pytest.raises(VaultAccessError) as exc:
        service.read_synthetic_secret(user, "identityguard-lab/data/synthetic/missing")

    assert exc.value.status_code == 404


# ------------------------------------------------------------------
# Vault unreachable
# ------------------------------------------------------------------


def test_vault_unreachable_propagated(db):
    """Vault connection error is propagated."""
    import httpx

    user = seed_user(db, "vault.user", "VU001")
    role = seed_role(db, "Vault Secret Access")
    seed_user_role(db, user, role)
    mock_vault = MockVaultClient(error=VaultError("Cannot connect to Vault"))
    service = VaultSecretAccessService(db, mock_vault)

    with pytest.raises(VaultAccessError):
        service.read_synthetic_secret(user, "identityguard-lab/data/synthetic/test-secret")


# ------------------------------------------------------------------
# Secret value never in audit
# ------------------------------------------------------------------


def test_secret_value_not_in_audit(db):
    """Secret values are never recorded in audit reasons."""
    user = seed_user(db, "vault.user", "VU001")
    role = seed_role(db, "Vault Secret Access")
    seed_user_role(db, user, role)
    mock_vault = MockVaultClient(
        secret_data={"value": "TOP-SECRET-VALUE", "description": "test"}
    )
    service = VaultSecretAccessService(db, mock_vault)

    service.read_synthetic_secret(user, "identityguard-lab/data/synthetic/test-secret")

    events = db.scalars(select(AuditEvent)).all()
    for e in events:
        assert "TOP-SECRET-VALUE" not in e.reason
        assert "TOP-SECRET-VALUE" not in e.target
        assert "TOP-SECRET-VALUE" not in e.actor


# ------------------------------------------------------------------
# Grant check
# ------------------------------------------------------------------


def test_grant_check_without_grant(db):
    """Grant check returns False when no role is assigned."""
    user = seed_user(db, "no-grant.user", "VU003")
    mock_vault = MockVaultClient()
    service = VaultSecretAccessService(db, mock_vault)

    assert service.has_active_grant(user, "any-path") is False


def test_grant_check_with_grant(db):
    """Grant check returns True when role is assigned and active."""
    user = seed_user(db, "vault.user", "VU001")
    role = seed_role(db, "Vault Secret Access")
    seed_user_role(db, user, role)
    mock_vault = MockVaultClient()
    service = VaultSecretAccessService(db, mock_vault)

    assert service.has_active_grant(user, "any-path") is True


def test_grant_check_expired_assignment(db):
    """Grant check returns False when the role assignment is expired."""
    from datetime import timedelta

    user = seed_user(db, "vault.user", "VU001")
    role = seed_role(db, "Vault Secret Access")
    ur = UserRole(
        user_id=user.id,
        role_id=role.id,
        expires_at=utcnow() - timedelta(hours=1),
    )
    db.add(ur)
    db.commit()
    mock_vault = MockVaultClient()
    service = VaultSecretAccessService(db, mock_vault)

    assert service.has_active_grant(user, "any-path") is False


def test_grant_check_disabled_user(db):
    """Grant check returns False when the user is disabled."""
    user = seed_user(db, "vault.user", "VU001", status="DISABLED")
    role = seed_role(db, "Vault Secret Access")
    seed_user_role(db, user, role)
    mock_vault = MockVaultClient()
    service = VaultSecretAccessService(db, mock_vault)

    assert service.has_active_grant(user, "any-path") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
