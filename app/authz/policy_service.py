from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.authz.policy_engine import Decision, PolicyDocument, evaluate_policy, load_policy
from app.db.models import Role, User


def _get_active_permissions(db, actor):
    from app.authz.service import get_active_permissions

    return get_active_permissions(db, actor)

POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "identityguard_policy.json"


def _load_policy() -> PolicyDocument:
    return load_policy(POLICY_PATH)


def _subject(actor: User, db: Session) -> Dict[str, Any]:
    permissions = sorted(_get_active_permissions(db, actor))
    return {
        "id": str(actor.id),
        "roles": [],
        "permissions": permissions,
        "platform_access": any(p.startswith("IdentityGuard:") for p in permissions),
    }


def _resource(role: Role, target: User) -> Dict[str, Any]:
    return {
        "id": f"role:{role.id}",
        "attributes": {
            "name": role.name,
            "is_privileged": bool(getattr(role, "is_privileged", False)),
            "target_user_id": str(target.id),
        },
    }


def _audit_result_for(decision: str) -> str:
    """Map a policy engine decision to a valid AuditEvent.result value.

    The audit_events table only accepts SUCCESS / DENIED / FAILURE, so the
    engine's "allow" / "deny" strings must be translated before recording.
    """
    if decision == "allow":
        return "SUCCESS"
    return "DENIED"


def can_assign_role_with_policy(db: Session, actor: User, target: User, role: Role) -> bool:
    """Policy-driven role assignment decision.

    Returns only the boolean decision. A DB-backed audit event is recorded
    for every decision using a valid audit result value.

    Fail-closed: if recording the audit event fails, the transaction is
    rolled back and the error propagates so the caller denies the assignment
    instead of granting it.
    """
    decision: Decision = evaluate_policy(
        _load_policy(),
        {
            "subject": _subject(actor, db),
            "action": "IdentityGuard:role.assign",
            "resource": _resource(role, target),
            "context": {
                "actor_id": str(actor.id),
                "target_user_id": str(target.id),
                "role_is_privileged": bool(getattr(role, "is_privileged", False)),
            },
        },
    )

    from app.audit.service import record_event
    from app.audit.events import EventType

    try:
        record_event(
            db,
            actor=str(actor.id),
            event_type=EventType.POLICY_DECISION,
            target=f"user:{target.id}",
            action="role.assign",
            result=_audit_result_for(decision.decision),
            reason=f"{decision.reason}; matched={decision.matched_rules}",
        )
    except Exception:
        # An audit-write failure must not silently grant privileged access.
        # Roll back anything touched here and deny.
        db.rollback()
        raise

    return decision.decision == "allow"
