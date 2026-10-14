from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Condition:
    left: str
    op: str
    right: Optional[Any] = None
    value: Optional[Any] = None


@dataclass
class PolicyRule:
    id: str
    effect: str  # "allow" or "deny"
    actions: List[str] = field(default_factory=lambda: ["*"])
    resources: List[str] = field(default_factory=lambda: ["*"])
    conditions: List[Condition] = field(default_factory=list)


@dataclass
class PolicyDocument:
    version: str = "1.0"
    default_effect: str = "deny"
    policies: List[PolicyRule] = field(default_factory=list)


@dataclass
class Decision:
    decision: str
    matched_rules: List[str] = field(default_factory=list)
    reason: str = ""


def load_policy(path: str | Path) -> PolicyDocument:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules = []
    for raw in data.get("policies", []):
        rules.append(
            PolicyRule(
                id=raw["id"],
                effect=raw["effect"],
                actions=raw.get("actions", ["*"]),
                resources=raw.get("resources", ["*"]),
                conditions=[Condition(**cond) for cond in raw.get("conditions", [])],
            )
        )
    return PolicyDocument(
        version=data.get("version", "1.0"),
        default_effect=data.get("default_effect", "deny"),
        policies=rules,
    )


def _root(request: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "subject": request["subject"],
        "resource": request["resource"],
        "context": request.get("context", {}),
        "action": request["action"],
    }


def resolve_path(path: str, request: Dict[str, Any]) -> Any:
    cur: Any = _root(request)
    for part in path.split("."):
        if isinstance(cur, dict):
            if part in cur:
                cur = cur[part]
            elif "attributes" in cur and isinstance(cur["attributes"], dict) and part in cur["attributes"]:
                cur = cur["attributes"][part]
            else:
                return None
        else:
            return None
    return cur


def _as_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def eval_condition(cond: Condition, request: Dict[str, Any]) -> bool:
    left = resolve_path(cond.left, request)

    if cond.right is not None:
        raw = cond.right
        if isinstance(raw, str) and raw.split(".")[0] in {"subject", "resource", "context", "action"}:
            right = resolve_path(raw, request)
        else:
            right = raw
    else:
        right = cond.value

    op = cond.op.lower()
    if op == "equals":
        return left == right
    if op in {"not_equals", "ne"}:
        return left != right
    if op == "exists":
        return left is not None
    if op == "in":
        return left in (right if isinstance(right, (list, tuple, set)) else [right])
    if op == "contains":
        if isinstance(left, (list, tuple, set)):
            return right in left
        if isinstance(left, str):
            return str(right) in left
        return False
    if op in {"gte", "ge"}:
        return _as_number(left) >= _as_number(right)
    if op == "gt":
        return _as_number(left) > _as_number(right)
    if op in {"lte", "le"}:
        return _as_number(left) <= _as_number(right)
    if op == "lt":
        return _as_number(left) < _as_number(right)
    raise ValueError(f"Unknown operator: {cond.op}")


def rule_applies(rule: PolicyRule, request: Dict[str, Any]) -> bool:
    if not any(fnmatch.fnmatch(request["action"], pattern) for pattern in rule.actions):
        return False
    if not any(fnmatch.fnmatch(request["resource"]["id"], pattern) for pattern in rule.resources):
        return False
    return all(eval_condition(condition, request) for condition in rule.conditions)


def evaluate_policy(policy: PolicyDocument, request: Dict[str, Any]) -> Decision:
    matched = [rule for rule in policy.policies if rule_applies(rule, request)]
    denies = [rule for rule in matched if rule.effect.lower() == "deny"]
    allows = [rule for rule in matched if rule.effect.lower() == "allow"]

    if denies:
        decision = "deny"
        reason = "Deny rule matched: " + ", ".join(rule.id for rule in denies)
    elif allows:
        decision = "allow"
        reason = "Allow rule matched: " + ", ".join(rule.id for rule in allows)
    else:
        decision = policy.default_effect.lower()
        reason = "No matching rule; default effect applied."

    return Decision(decision=decision, matched_rules=[rule.id for rule in matched], reason=reason)
