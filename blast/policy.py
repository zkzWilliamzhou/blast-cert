"""Pure policy decision function.

Policy is data. The decision function never reads files, never inspects the
clock, and never mutates its inputs.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from .model import (
    EXIT_ALLOW,
    EXIT_CONFIRM,
    EXIT_DENY,
    STATUS_ANALYZED,
    STATUS_ERROR,
    STATUS_OPAQUE,
    VERDICT_ALLOW,
    VERDICT_CONFIRM,
    VERDICT_DENY,
    Decision,
    EvalResult,
    EvidenceReport,
    digest_of,
)

POLICY_SCHEMA_VERSION = 1
DEFAULT_POLICY = os.path.join(os.path.dirname(__file__), "policy.json")
_DECISIONS = frozenset(("allow", "confirm", "deny"))
_RANK = {"allow": 0, "confirm": 1, "deny": 2}
_RANK_DECISION = {0: VERDICT_ALLOW, 1: VERDICT_CONFIRM, 2: VERDICT_DENY}
_EXIT = {VERDICT_ALLOW: EXIT_ALLOW, VERDICT_CONFIRM: EXIT_CONFIRM,
         VERDICT_DENY: EXIT_DENY}


class PolicyError(ValueError):
    pass


_POLICY_CACHE: Dict[str, "Policy"] = {}


class Policy:
    def __init__(self, data: Dict[str, Any], path: str = "<memory>"):
        self.data = data
        self.path = path
        self.version = str(data["version"])
        self.digest = digest_of(data)
        self.default = data["default"]
        self.rules: Dict[str, str] = data["rules"]
        self.on_unknown = data["on_unknown"]
        self.on_opaque = data["on_opaque"]
        self.on_error = data["on_error"]
        self.on_truncated = data["on_truncated"]
        self.sensitive_escalation = data["sensitive_escalation"]

    def decision_for(self, capability: str) -> str:
        return self.rules.get(capability, self.default)


def validate_policy(data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise PolicyError("policy must be an object")
    if data.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise PolicyError("unsupported policy schema_version")
    required = ("version", "default", "on_unknown", "on_opaque", "on_error",
                "on_truncated", "sensitive_escalation", "rules")
    for key in required:
        if key not in data:
            raise PolicyError("policy missing %s" % key)
    for key in ("default", "on_unknown", "on_opaque", "on_error",
                "on_truncated", "sensitive_escalation"):
        if data[key] not in _DECISIONS:
            raise PolicyError("policy.%s must be allow, confirm or deny" % key)
    if data["default"] != "deny":
        raise PolicyError("policy.default must be deny")
    for key in ("on_unknown", "on_opaque", "on_error", "on_truncated",
                "sensitive_escalation"):
        if data[key] != "deny":
            raise PolicyError("policy.%s must be deny; fail-closed is not configurable"
                              % key)
    if not isinstance(data["rules"], dict):
        raise PolicyError("policy.rules must be an object")
    for capability, decision in data["rules"].items():
        if decision not in _DECISIONS:
            raise PolicyError("policy.rules.%s is invalid" % capability)


def load_policy(path: Optional[str] = None) -> Policy:
    target = path or DEFAULT_POLICY
    stat = os.stat(target)
    key = "%s|%d|%d" % (os.path.abspath(target), stat.st_mtime_ns, stat.st_size)
    cached = _POLICY_CACHE.get(key)
    if cached is not None:
        return cached
    with open(target, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    validate_policy(data)
    policy = Policy(data, target)
    _POLICY_CACHE[key] = policy
    return policy


def decide(eval_result: EvalResult, evidence: EvidenceReport,
           policy: Policy, strict: bool = False) -> Decision:
    reasons = []
    rank = 0

    if eval_result.status == STATUS_ERROR:
        reasons.append("parse or lexer error: %s" % policy.on_error)
        rank = max(rank, _RANK[policy.on_error])
    if eval_result.status == STATUS_OPAQUE:
        reasons.append("opaque construct: %s" % policy.on_opaque)
        rank = max(rank, _RANK[policy.on_opaque])
    if eval_result.unknowns:
        reasons.append("%d unknown facts: %s" % (len(eval_result.unknowns), policy.on_unknown))
        rank = max(rank, _RANK[policy.on_unknown])
    if evidence.truncated:
        reasons.append("evidence budget reached: %s" % policy.on_truncated)
        rank = max(rank, _RANK[policy.on_truncated])
    if any(f.sensitive for f in evidence.findings):
        reasons.append("sensitive filesystem object: %s" % policy.sensitive_escalation)
        rank = max(rank, _RANK[policy.sensitive_escalation])

    for assertion in eval_result.assertions:
        decision = policy.decision_for(assertion.capability)
        rank = max(rank, _RANK[decision])

    if eval_result.status == STATUS_ANALYZED and not eval_result.unknowns and rank == 0:
        reasons.append("all capabilities are explicitly allowed by policy")

    verdict = _RANK_DECISION[rank]
    if strict and verdict == VERDICT_CONFIRM:
        verdict = VERDICT_DENY
        reasons.append("strict mode upgrades confirm to deny")

    return Decision(verdict, tuple(sorted(set(reasons))), _EXIT[verdict])
