"""Deterministic human and machine reports."""
from __future__ import annotations

from typing import List

from .model import AnalysisResult, pretty_json


def render_json(result: AnalysisResult) -> str:
    return pretty_json(result)


def render_text(result: AnalysisResult) -> str:
    lines: List[str] = []
    lines.append("blast %s | verdict: %s | status: %s" % (
        result.tool_version, result.verdict.upper(), result.status))
    lines.append("input sha256: %s" % result.input_sha256)
    lines.append("catalog: %s (%s)" % (result.catalog_version, result.catalog_digest[:12]))
    lines.append("policy: %s (%s)" % (result.policy_version, result.policy_digest[:12]))
    lines.append("")
    lines.append("CAPABILITIES (%d)" % len(result.assertions))
    if result.assertions:
        for a in result.assertions:
            lines.append("  %-24s %-18s %-9s %s" % (
                a.capability, a.object[:18], a.scope, a.rule_id))
    else:
        lines.append("  none")
    lines.append("")
    lines.append("EVIDENCE (%d objects, %d bytes%s)" % (
        result.evidence.matched_count, result.evidence.total_bytes,
        ", truncated" if result.evidence.truncated else ""))
    for finding in result.evidence.findings[:20]:
        marker = " sensitive" if finding.sensitive else ""
        marker += " git" if finding.in_git_worktree else ""
        marker += " outside-root" if finding.outside_root else ""
        lines.append("  %-48s %-12s %10d%s" % (
            finding.path[:48], finding.kind, finding.size, marker))
    if result.evidence.matched_count > 20:
        lines.append("  ... %d more" % (result.evidence.matched_count - 20))
    lines.append("")
    lines.append("UNKNOWN FACTS (%d)" % len(result.unknowns))
    for u in result.unknowns[:20]:
        lines.append("  %-28s %s" % (u.kind, u.raw[:60]))
    lines.append("")
    lines.append("PARSE ISSUES (%d)" % len(result.parse_issues))
    for issue in result.parse_issues[:20]:
        lines.append("  %-28s %s" % (issue.code, issue.message))
    lines.append("")
    lines.append("REASONS")
    for reason in result.reasons:
        lines.append("  - %s" % reason)
    lines.append("")
    lines.append("exit: %d" % result.exit_code)
    return "\n".join(lines)


def render_explain(result: AnalysisResult) -> str:
    lines: List[str] = []
    lines.append("Verdict: %s. blast did not run this command." % result.verdict)
    if result.assertions:
        caps = sorted(set(a.capability for a in result.assertions))
        lines.append("It can %s." % ", ".join(caps))
    if result.evidence.matched_count:
        lines.append("Against the current directory it matched %d objects totalling %d bytes."
                     % (result.evidence.matched_count, result.evidence.total_bytes))
        sensitive = [f.path for f in result.evidence.findings if f.sensitive]
        if sensitive:
            lines.append("Protected objects: %s." % ", ".join(sensitive[:8]))
    else:
        lines.append("It matched no concrete objects in the current directory.")
    if result.unknowns:
        kinds = sorted(set(u.kind for u in result.unknowns))
        lines.append("It could not determine %s, so the gate stays closed."
                     % ", ".join(kinds))
    if result.parse_issues:
        lines.append("Parse issues: %s."
                     % ", ".join(sorted(set(i.code for i in result.parse_issues))))
    for reason in result.reasons:
        lines.append("Reason: %s." % reason)
    lines.append("Scope: static intent against a directory snapshot. Use a sandbox at runtime.")
    return "\n".join(lines)
