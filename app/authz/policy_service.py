from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.authz.policy_engine import Decision, PolicyDocument, evaluate_policy, load_policy
from app.db.models import Role, User

logger = logging.getLogger("identityguard")


def _audit_result(policy_decision: str) -> str:
    """Map a policy engine decision to an audit result the database accepts.

    The audit_events.result column is constrained to SUCCESS / DENIED /
    FAILURE, while the policy engine emits lowercase "allow" / "deny".
    """
    if policy_decision == "deny":
        return "DENIED"
    if policy_decision == "allow":
        return "SUCCESS"
    # Any unexpected decision (e.g. engine misconfiguration) is treated as a
    # processing failure rather than silently recorded as allow or deny.
    return "FAILURE"


def _get_active_permissions(db, actor):
    from app.authz.service import get_active_permissions

    return get_active_permissions(db, actor)

POLICY_PATH = (
    Path(__file__).resolve().parents[1] / "policies" / "identityguard_policy.json"
)


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


def can_assign_role_with_policy(db: Session, actor: User, target: User, role: Role) -> bool:
    """Policy-driven role assignment decision.

    Returns only the boolean decision. A DB-backed audit event is recorded
    when the audit service is available.
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

    try:
        from app.audit.service import record_event
        from app.audit.events import EventType

        record_event(
            db,
            actor=str(actor.id),
            event_type=EventType.POLICY_DECISION,
            target=f"user:{target.id}",
            action="role.assign",
            result=_audit_result(decision.decision),
            reason=f"{decision.reason}; matched={decision.matched_rules}",
        )
    except Exception:
        # Do not swallow an audit failure: roll back so the session stays
        # usable, then fail closed. A privileged authorization decision must
        # not be granted (or recorded as granted) when the audit trail that
        # backs it cannot be written.
        db.rollback()
        logger.exception("Policy audit write failed; failing closed")
        raise

    return decision.decision == "allow"
