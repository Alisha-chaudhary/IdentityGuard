"""LDAP API routes for IdentityGuard.

Endpoints for directory synchronization: dry-run (default) and controlled
apply mode. All operations are audited.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_permission
from app.db.models import User
from app.ldap.client import LdapClient
from app.ldap.sync import (
    DirectorySynchronizer,
    MODE_APPLY,
    MODE_DRY_RUN,
)

router = APIRouter(prefix="/ldap", tags=["LDAP"])


def _get_ldap_client() -> LdapClient:
    """Build an LDAP client from environment variables."""
    return LdapClient.from_env()


def _get_sync_service(
    db: Session = Depends(get_db),
    ldap_client: LdapClient = Depends(_get_ldap_client),
) -> DirectorySynchronizer:
    return DirectorySynchronizer(db=db, ldap_client=ldap_client, mode=MODE_DRY_RUN)


@router.get("/health")
def ldap_health(
    ldap_client: LdapClient = Depends(_get_ldap_client),
) -> dict:
    """Check LDAP connectivity. Never exposes bind credentials."""
    try:
        ldap_client.open()
        ldap_client.bind()
        ldap_client.close()
        return {"healthy": True, "uri": ldap_client.uri}
    except Exception as exc:  # pragma: no cover - infrastructure errors
        return {"healthy": False, "uri": ldap_client.uri, "error": str(exc)}


@router.get("/sync")
def sync_dry_run(
    current_user: User = Depends(
        require_permission("IdentityGuard:access_review.view")
    ),
    service: DirectorySynchronizer = Depends(_get_sync_service),
) -> dict:
    """Run a dry-run LDAP synchronization.

    Returns a change report without modifying any local users or role
    assignments. Requires access_review.view permission.
    """
    try:
        service.ldap_client.open()
        service.ldap_client.bind()
        report = service.synchronize()
    finally:
        service.ldap_client.close()
    return report.as_dict()


@router.post("/sync/apply")
def sync_apply(
    current_user: User = Depends(
        require_permission("IdentityGuard:access.provision")
    ),
    db: Session = Depends(get_db),
    ldap_client: LdapClient = Depends(_get_ldap_client),
) -> dict:
    """Run LDAP synchronization in apply mode.

    Requires explicit operator action and access.provision permission.
    Applies approved changes to local users and role assignments.
    Privileged roles are never auto-assigned.
    """
    try:
        ldap_client.open()
        ldap_client.bind()
        service = DirectorySynchronizer.apply(db, ldap_client)
        report = service.synchronize()
    finally:
        ldap_client.close()
    return report.as_dict()
