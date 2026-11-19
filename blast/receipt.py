"""Portable, offline-verifiable effect receipts."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .api import analyze
from .model import (
    EXIT_DENY,
    AnalysisResult,
    digest_of,
    plain,
)

RECEIPT_SCHEMA_VERSION = 1
RECEIPT_KIND = "blast-effect-receipt"


def build_receipt(result: AnalysisResult, command: str) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "tool": {"name": "blast", "version": result.tool_version},
        "input": {"command": command, "sha256": result.input_sha256},
        "analysis": plain(result),
    }
    receipt = dict(body)
    receipt["digest"] = digest_of(body)
    return receipt


def _check(checks: List[Dict[str, Any]], name: str, ok: bool,
           detail: str) -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def verify_receipt(receipt: Dict[str, Any], root: str = ".",
                   catalog_path: Optional[str] = None,
                   policy_path: Optional[str] = None) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    stored_digest = receipt.get("digest", "")
    body = {k: v for k, v in receipt.items() if k != "digest"}
    recomputed = digest_of(body)
    _check(checks, "digest", stored_digest == recomputed,
           "stored %s / recomputed %s" % (stored_digest[:12], recomputed[:12]))
    _check(checks, "kind", receipt.get("kind") == RECEIPT_KIND,
           str(receipt.get("kind")))
    _check(checks, "schema", receipt.get("schema_version") == RECEIPT_SCHEMA_VERSION,
           str(receipt.get("schema_version")))

    analysis = receipt.get("analysis") or {}
    command = (receipt.get("input") or {}).get("command")
    if not isinstance(command, str):
        _check(checks, "command", False, "receipt has no command string")
        return {"ok": False, "checks": checks, "exit_code": EXIT_DENY}
    _check(checks, "command", True, "%d bytes" % len(command))

    dialect = analysis.get("dialect", "bash")
    fresh = analyze(command, root=root, catalog_path=catalog_path,
                    policy_path=policy_path, dialect=dialect)
    fresh_plain = plain(fresh)

    _check(checks, "catalog_digest",
           analysis.get("catalog_digest") == fresh_plain.get("catalog_digest"),
           "receipt %s / current %s" % (
               str(analysis.get("catalog_digest"))[:12],
               str(fresh_plain.get("catalog_digest"))[:12]))
    _check(checks, "policy_digest",
           analysis.get("policy_digest") == fresh_plain.get("policy_digest"),
           "receipt %s / current %s" % (
               str(analysis.get("policy_digest"))[:12],
               str(fresh_plain.get("policy_digest"))[:12]))
    _check(checks, "assertions",
           analysis.get("assertions") == fresh_plain.get("assertions"),
           "capability manifest changed")
    _check(checks, "verdict",
           analysis.get("verdict") == fresh_plain.get("verdict"),
           "receipt %s / current %s" % (
               analysis.get("verdict"), fresh_plain.get("verdict")))
    old_evidence = analysis.get("evidence") or {}
    new_evidence = fresh_plain.get("evidence") or {}
    _check(checks, "evidence_digest",
           old_evidence.get("digest") == new_evidence.get("digest"),
           "receipt %s / current %s" % (
               str(old_evidence.get("digest"))[:12],
               str(new_evidence.get("digest"))[:12]))

    failed = [c["name"] for c in checks if not c["ok"]]
    return {
        "ok": not failed,
        "checks": checks,
        "drift": failed,
        "current_verdict": fresh.verdict,
        "exit_code": 0 if not failed else EXIT_DENY,
    }


def diff_receipts(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    def caps(receipt: Dict[str, Any]):
        return sorted(set(
            a.get("capability", "") for a in
            (receipt.get("analysis") or {}).get("assertions", [])
        ))

    def evidence(receipt: Dict[str, Any]):
        return (receipt.get("analysis") or {}).get("evidence") or {}

    left_caps, right_caps = caps(left), caps(right)
    left_ev, right_ev = evidence(left), evidence(right)
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "left_verdict": (left.get("analysis") or {}).get("verdict"),
        "right_verdict": (right.get("analysis") or {}).get("verdict"),
        "added_capabilities": sorted(set(right_caps) - set(left_caps)),
        "removed_capabilities": sorted(set(left_caps) - set(right_caps)),
        "left_matched": left_ev.get("matched_count", 0),
        "right_matched": right_ev.get("matched_count", 0),
        "left_bytes": left_ev.get("total_bytes", 0),
        "right_bytes": right_ev.get("total_bytes", 0),
        "evidence_changed": left_ev.get("digest") != right_ev.get("digest"),
        "digest_equal": left.get("digest") == right.get("digest"),
    }
