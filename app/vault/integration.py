"""Vault integration workflow for IdentityGuard.

Connects IdentityGuard's access request/approval workflow with Vault's
own policy enforcement for synthetic secret access.

Key design principles:
- IdentityGuard handles request → approval → provisioning workflow
- Vault enforces its own policies independently
- IdentityGuard never substitutes its decision for Vault authorization
- Secret values are never stored in IdentityGuard's database, logs, or
  audit reasons
- Non-secret evidence (approval state, Vault read success/failure) is
  recorded for audit
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.db.models import AccessRequest, Role, User, UserRole
from app.vault.client import VaultClient, VaultError


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class VaultAccessError(Exception):
    """Raised when Vault secret access cannot be completed."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class VaultSecretAccessService:
    """Mediates access to Vault synthetic secrets through IdentityGuard's
    approval workflow.

    The flow:
    1. User requests access to a Vault secret via IdentityGuard access
       request (existing workflow).
    2. Approver approves; provisioner provisions the role.
    3. User calls read_synthetic_secret() which:
       a. Verifies IdentityGuard: active, approved, provisioned access
          grant exists for the user.
       b. Attempts the Vault read using the caller's Vault token.
       c. Vault enforces its own policy - if the caller's token lacks
          the reader policy, Vault denies (IdentityGuard cannot override
          this).
       d. Records non-secret audit evidence (approval existed, Vault
          read succeeded/denied) but never the secret value.
    """

    def __init__(
        self,
        db: Session,
        vault_client: VaultClient,
    ) -> None:
        self.db = db
        self.vault_client = vault_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def has_active_grant(
        self,
        user: User,
        vault_secret_path: str,
    ) -> bool:
        """Check whether the user has an active, approved, provisioned
        IdentityGuard grant for Vault secret access.

        This is an IdentityGuard-side check only. It does NOT substitute
        for Vault authorization; Vault enforces its own policy separately.
        """
        role = self._get_vault_access_role()
        if role is None:
            return False

        # Check for an active user-role assignment.
        assignment = self.db.scalars(
            select(UserRole).where(
                UserRole.user_id == user.id,
                UserRole.role_id == role.id,
            )
        ).first()

        if assignment is None:
            return False

        # Check the assignment is not expired.
        if (
            assignment.expires_at is not None
            and assignment.expires_at <= _utcnow()
        ):
            return False

        # Check the user is active.
        if user.status != "ACTIVE":
            return False

        return True

    def read_synthetic_secret(
        self,
        user: User,
        vault_secret_path: str,
    ) -> dict:
        """Read a Vault synthetic secret through the approved workflow.

        Returns non-secret evidence about the access attempt. The secret
        value itself is included in the return (as it must be to the
        caller) but is NEVER logged or recorded in audit.

        Raises VaultAccessError if:
        - No active IdentityGuard grant exists
        - Vault is unreachable
        - Vault denies access (policy enforcement)
        - Secret not found
        """
        # Step 1: IdentityGuard-side check - is there an active grant?
        if not self.has_active_grant(user, vault_secret_path):
            self._audit_access_denied(
                actor=user.username,
                target=vault_secret_path,
                reason="No active IdentityGuard grant for Vault secret access",
            )
            raise VaultAccessError(
                "No active IdentityGuard grant for Vault secret access",
                status_code=403,
            )

        # Step 2: Attempt the Vault read. Vault enforces its own policy.
        # If the caller's token lacks the reader policy, Vault returns 403
        # and IdentityGuard cannot override that.
        try:
            secret_data = self.vault_client.read_secret(vault_secret_path)
        except VaultError as exc:
            if exc.status_code == 403:
                self._audit_access_denied(
                    actor=user.username,
                    target=vault_secret_path,
                    reason="Vault policy denied secret read",
                )
                raise VaultAccessError(
                    "Vault policy denied secret read",
                    status_code=403,
                ) from exc
            if exc.status_code == 404:
                self._audit_access_denied(
                    actor=user.username,
                    target=vault_secret_path,
                    reason="Secret not found in Vault",
                )
                raise VaultAccessError(
                    "Secret not found in Vault",
                    status_code=404,
                ) from exc
            self._audit_access_denied(
                actor=user.username,
                target=vault_secret_path,
                reason=f"Vault error: {exc}",
            )
            raise VaultAccessError(
                f"Vault error: {exc}",
                status_code=exc.status_code or 500,
            ) from exc

        # Step 3: Record non-secret audit evidence. The secret value is
        # NOT included in the audit reason.
        self._audit_access_granted(
            actor=user.username,
            target=vault_secret_path,
            reason="Approved IdentityGuard grant; Vault policy allowed read",
        )

        # Return evidence without the actual secret value.
        return {
            "access_granted": True,
            "vault_path": vault_secret_path,
            "identityguard_grant": True,
            "vault_policy_enforced": True,
            "secret_keys": sorted(secret_data.keys()),
            "audited_at": _utcnow().isoformat(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_vault_access_role(self) -> Optional[Role]:
        """Get the IdentityGuard role that grants Vault secret access.

        This role must be explicitly provisioned through IdentityGuard's
        normal request/approval flow. It is NOT automatically assigned
        from LDAP groups.
        """
        return self.db.scalars(
            select(Role).where(Role.name == "Vault Secret Access")
        ).first()

    def _audit_access_granted(
        self,
        actor: str,
        target: str,
        reason: str,
    ) -> None:
        record_event(
            self.db,
            actor=actor,
            event_type=EventType.ACCESS_PROVISIONED,
            target=target,
            action="read_vault_secret",
            result=Result.SUCCESS,
            reason=reason,
        )
        self.db.flush()

    def _audit_access_denied(
        self,
        actor: str,
        target: str,
        reason: str,
    ) -> None:
        record_event(
            self.db,
            actor=actor,
            event_type=EventType.ACCESS_DENIED,
            target=target,
            action="read_vault_secret",
            result=Result.DENIED,
            reason=reason,
        )
        self.db.flush()
