"""Vault API routes for IdentityGuard.

Endpoints for requesting and reading synthetic Vault secrets through
IdentityGuard's approval workflow. Vault enforces its own policies;
IdentityGuard never substitutes its decision for Vault authorization.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_permission
from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.db.models import User
from app.vault.client import VaultClient, VaultError
from app.vault.integration import VaultAccessError, VaultSecretAccessService

router = APIRouter(prefix="/vault", tags=["Vault"])


def _get_vault_client() -> VaultClient:
    """Build a Vault client from environment variables.

    The token comes from IDENTITYGUARD_VAULT_TOKEN which is set at
    runtime and never committed to source control.
    """
    return VaultClient.from_env()


def _get_vault_service(
    db: Session = Depends(get_db),
    vault_client: VaultClient = Depends(_get_vault_client),
) -> VaultSecretAccessService:
    return VaultSecretAccessService(db=db, vault_client=vault_client)


@router.get("/health")
def vault_health(
    vault_client: VaultClient = Depends(_get_vault_client),
) -> dict:
    """Check Vault health. Never exposes the token."""
    healthy = vault_client.health()
    return {
        "healthy": healthy,
        "vault_addr": vault_client.addr,
        "token_configured": bool(vault_client._token),
    }


@router.get("/grant")
def check_grant(
    current_user: User = Depends(get_current_user),
    service: VaultSecretAccessService = Depends(_get_vault_service),
) -> dict:
    """Check whether the current user has an active IdentityGuard grant
    for Vault secret access. This is an IdentityGuard-side check only;
    Vault authorization is verified separately on secret read."""
    has_grant = service.has_active_grant(current_user, "")
    record_event(
        service.db,
        actor=current_user.username,
        event_type=EventType.ACCESS_DENIED
        if not has_grant
        else EventType.ACCESS_PROVISIONED,
        target="vault:grant-check",
        action="check_grant",
        result=Result.SUCCESS if has_grant else Result.DENIED,
        reason=f"Vault secret access grant: {'active' if has_grant else 'none'}",
    )
    service.db.commit()
    return {
        "has_grant": has_grant,
        "username": current_user.username,
    }


@router.get("/secret/{path:path}")
def read_secret(
    path: str,
    current_user: User = Depends(
        require_permission("vault-secret:read")
    ),
    service: VaultSecretAccessService = Depends(_get_vault_service),
) -> dict:
    """Read a Vault synthetic secret through the approved workflow.

    Requires an active IdentityGuard grant (provisioned role) AND Vault
    policy authorization. Vault enforces its own policy independently.
    Secret values are returned to the caller but never logged or
    recorded in audit.
    """
    try:
        result = service.read_synthetic_secret(current_user, path)
    except VaultAccessError as exc:
        raise HTTPException(
            status_code=exc.status_code or status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except VaultError as exc:
        raise HTTPException(
            status_code=exc.status_code or status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )
    return result
