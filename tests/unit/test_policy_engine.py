import json
from pathlib import Path

from app.authz.policy_engine import evaluate_policy, load_policy

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "app" / "policies" / "identityguard_policy.json"


def make_request(actor_id, target_id, perms, is_privileged):
    return {
        "subject": {"id": actor_id, "permissions": perms},
        "action": "IdentityGuard:role.assign",
        "resource": {
            "id": "role:1",
            "attributes": {"is_privileged": is_privileged, "name": "demo-role", "target_user_id": target_id},
        },
        "context": {"actor_id": actor_id, "target_user_id": target_id},
    }


def test_default_deny_without_permission():
    policy = load_policy(POLICY_PATH)
    decision = evaluate_policy(policy, make_request("a", "b", [], False))
    assert decision.decision == "deny"


def test_self_assignment_denied_even_with_permission():
    policy = load_policy(POLICY_PATH)
    decision = evaluate_policy(policy, make_request("same", "same", ["IdentityGuard:role.assign"], False))
    assert decision.decision == "deny"
    assert "deny-self-role-assignment" in decision.matched_rules


def test_standard_assignment_allowed():
    policy = load_policy(POLICY_PATH)
    decision = evaluate_policy(policy, make_request("a", "b", ["IdentityGuard:role.assign"], False))
    assert decision.decision == "allow"


def test_privileged_assignment_requires_privileged_permission():
    policy = load_policy(POLICY_PATH)
    denied = evaluate_policy(policy, make_request("a", "b", ["IdentityGuard:role.assign"], True))
    allowed = evaluate_policy(policy, make_request("a", "b", ["IdentityGuard:role.assign_privileged"], True))
    assert denied.decision == "deny"
    assert allowed.decision == "allow"
