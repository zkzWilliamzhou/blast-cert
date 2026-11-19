"""Command line interface. Parses only blast's own arguments."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from .api import analyze
from .catalog import load_catalog
from .model import (
    EXIT_DENY,
    EXIT_ERROR,
    pretty_json,
    sha256_text,
)
from .policy import load_policy
from .receipt import build_receipt, diff_receipts, verify_receipt
from .report import render_explain, render_json, render_text

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _add_analysis_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("command", nargs="?", help="shell command to analyze")
    parser.add_argument("-c", "--command-string", dest="command_string",
                        help="shell command to analyze (alternative to positional)")
    parser.add_argument("--root", default=".", help="directory to read evidence from")
    parser.add_argument("--catalog", help="path to a command catalog JSON file")
    parser.add_argument("--policy", help="path to a policy JSON file")
    parser.add_argument("--dialect", default="bash", choices=("bash", "posix"))
    parser.add_argument("--strict", action="store_true",
                        help="upgrade confirm to deny")
    parser.add_argument("--trusted-env", action="append", default=[],
                        metavar="KEY=VALUE",
                        help="declare a trusted variable value")
    parser.add_argument("--trusted-home", help="declare a trusted HOME value")
    parser.add_argument("--format", default="text", choices=("text", "json", "explain"))
    parser.add_argument("-o", "--output", help="write a receipt to this path")


def _trusted_env(raw: Sequence[str]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for item in raw:
        if "=" not in item:
            raise ValueError("--trusted-env needs KEY=VALUE, got %r" % item)
        key, value = item.split("=", 1)
        if not key:
            raise ValueError("--trusted-env key cannot be empty")
        values[key] = value
    return values


def _resolve_command(args: argparse.Namespace) -> str:
    command = args.command_string if args.command_string is not None else args.command
    if command is None:
        if not sys.stdin.isatty():
            command = sys.stdin.read()
        else:
            raise ValueError("no command supplied")
    return command


def _run_analysis(args: argparse.Namespace, command: str) -> Any:
    return analyze(
        command,
        root=args.root,
        catalog_path=args.catalog,
        policy_path=args.policy,
        dialect=args.dialect,
        strict=args.strict,
        trusted_env=_trusted_env(args.trusted_env),
        trusted_home=args.trusted_home,
    )


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
        if not content.endswith("\n"):
            handle.write("\n")


def _emit(content: str) -> None:
    sys.stdout.write(content)
    if not content.endswith("\n"):
        sys.stdout.write("\n")


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        command = _resolve_command(args)
        result = _run_analysis(args, command)
    except (ValueError, OSError) as exc:
        sys.stderr.write("blast: %s\n" % exc)
        return EXIT_ERROR
    if args.format == "json":
        rendered = render_json(result)
    elif args.format == "explain":
        rendered = render_explain(result)
    else:
        rendered = render_text(result)
    _emit(rendered)
    if args.output:
        receipt = build_receipt(result, command)
        try:
            _write(args.output, pretty_json(receipt))
        except OSError as exc:
            sys.stderr.write("blast: cannot write receipt to %s: %s\n" % (
                args.output, exc))
            return EXIT_ERROR
    return result.exit_code


def _cmd_receipt(args: argparse.Namespace) -> int:
    try:
        command = _resolve_command(args)
        result = _run_analysis(args, command)
        receipt = build_receipt(result, command)
        rendered = pretty_json(receipt)
    except (ValueError, OSError) as exc:
        sys.stderr.write("blast: %s\n" % exc)
        return EXIT_ERROR
    if args.output:
        try:
            _write(args.output, rendered)
        except OSError as exc:
            sys.stderr.write("blast: cannot write receipt to %s: %s\n" % (
                args.output, exc))
            return EXIT_ERROR
        _emit("receipt written to %s (digest %s)" % (
            args.output, receipt["digest"][:12]))
    else:
        _emit(rendered)
    return result.exit_code


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("%s must contain a JSON object" % path)
    return data


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        receipt = _load_json(args.receipt)
        report = verify_receipt(
            receipt, root=args.root,
            catalog_path=args.catalog, policy_path=args.policy,
        )
    except (ValueError, OSError, TypeError) as exc:
        sys.stderr.write("blast: %s\n" % exc)
        return EXIT_ERROR
    if args.format == "json":
        _emit(pretty_json(report))
    else:
        _emit("verify: %s" % ("OK" if report["ok"] else "DRIFT"))
        for check in report["checks"]:
            _emit("  %-18s %s %s" % (
                check["name"], "ok" if check["ok"] else "FAIL", check["detail"]))
        if report["drift"]:
            _emit("  drift: %s" % ", ".join(report["drift"]))
    return report["exit_code"]


def _cmd_diff(args: argparse.Namespace) -> int:
    try:
        left = _load_json(args.left)
        right = _load_json(args.right)
        report = diff_receipts(left, right)
    except (ValueError, OSError, TypeError) as exc:
        sys.stderr.write("blast: %s\n" % exc)
        return EXIT_ERROR
    if args.format == "json":
        _emit(pretty_json(report))
    else:
        _emit("diff: %s" % ("identical" if report["digest_equal"] else "different"))
        _emit("  verdict: %s -> %s" % (report["left_verdict"], report["right_verdict"]))
        _emit("  added: %s" % (", ".join(report["added_capabilities"]) or "none"))
        _emit("  removed: %s" % (", ".join(report["removed_capabilities"]) or "none"))
        _emit("  evidence: %d -> %d objects, %d -> %d bytes, changed=%s" % (
            report["left_matched"], report["right_matched"],
            report["left_bytes"], report["right_bytes"],
            report["evidence_changed"]))
    return 0


def _selftest_payload() -> Dict[str, Any]:
    corpus_path = os.path.join(REPO_ROOT, "tests", "corpus.json")
    catalog = load_catalog()
    policy = load_policy()
    checks: List[Dict[str, Any]] = []
    corpus = []
    if os.path.isfile(corpus_path):
        with open(corpus_path, "r", encoding="utf-8") as handle:
            corpus = json.load(handle)
    checks.append({"name": "catalog_valid", "ok": True,
                   "detail": "%d command specs" % len(catalog.commands)})
    checks.append({"name": "policy_valid", "ok": True,
                   "detail": "version %s" % policy.version})

    benign = ["ls -la", "pwd", "true", "git status", "echo hello"]
    for command in benign:
        result = analyze(command, root=REPO_ROOT)
        checks.append({
            "name": "benign:%s" % command,
            "ok": result.verdict == "allow",
            "detail": result.verdict,
        })

    for entry in corpus:
        command = entry.get("command")
        if not isinstance(command, str):
            continue
        result = analyze(command, root=REPO_ROOT)
        caps = set(a.capability for a in result.assertions)
        expected = set(entry.get("expect_capabilities", []))
        ok = result.verdict != "allow" and expected.issubset(caps)
        checks.append({
            "name": "redteam:%s" % sha256_text(command)[:10],
            "ok": ok,
            "detail": "verdict=%s missing=%s" % (
                result.verdict, sorted(expected - caps)),
        })

    first = analyze("rm -rf /tmp/x", root=REPO_ROOT)
    second = analyze("rm -rf /tmp/x", root=REPO_ROOT)
    checks.append({
        "name": "deterministic",
        "ok": pretty_json(first) == pretty_json(second),
        "detail": "byte-identical JSON",
    })
    receipt = build_receipt(first, "rm -rf /tmp/x")
    tampered = dict(receipt)
    tampered["digest"] = "0" * 64
    checks.append({
        "name": "receipt_tamper",
        "ok": verify_receipt(tampered, root=REPO_ROOT)["ok"] is False,
        "detail": "tampered receipt rejected",
    })

    failed = [c for c in checks if not c["ok"]]
    return {
        "ok": not failed,
        "total": len(checks),
        "passed": len(checks) - len(failed),
        "failed": len(failed),
        "checks": checks,
        "exit_code": 0 if not failed else EXIT_DENY,
    }


def _cmd_selftest(args: argparse.Namespace) -> int:
    try:
        report = _selftest_payload()
    except (ValueError, OSError, TypeError) as exc:
        sys.stderr.write("blast: %s\n" % exc)
        return EXIT_ERROR
    if args.format == "json":
        _emit(pretty_json(report))
    else:
        _emit("selftest: %s (%d/%d passed)" % (
            "OK" if report["ok"] else "FAIL", report["passed"], report["total"]))
        for check in report["checks"]:
            if not check["ok"]:
                _emit("  FAIL %s: %s" % (check["name"], check["detail"]))
    return report["exit_code"]


def _cmd_catalog_check(args: argparse.Namespace) -> int:
    try:
        catalog = load_catalog(args.catalog)
        policy = load_policy(args.policy)
        ids = set()
        duplicates = []
        for spec in catalog.commands.values():
            for rule in spec["arg_rules"]:
                if rule["id"] in ids:
                    duplicates.append(rule["id"])
                ids.add(rule["id"])
    except (ValueError, OSError, TypeError) as exc:
        sys.stderr.write("blast: %s\n" % exc)
        return EXIT_ERROR
    report = {
        "ok": not duplicates,
        "catalog_version": catalog.version,
        "catalog_digest": catalog.digest,
        "policy_version": policy.version,
        "policy_digest": policy.digest,
        "command_specs": len(catalog.commands),
        "arg_rules": len(ids),
        "duplicate_rule_ids": duplicates,
    }
    _emit(pretty_json(report) if args.format == "json" else
          "catalog-check: %s (%d specs, %d rules, digest %s)" % (
              "OK" if report["ok"] else "FAIL", report["command_specs"],
              report["arg_rules"], catalog.digest[:12]))
    return 0 if report["ok"] else EXIT_DENY


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blast",
        description="Offline, filesystem-grounded pre-execution impact certificates.",
    )
    sub = parser.add_subparsers(dest="subcommand")

    check = sub.add_parser("check", help="analyze a command and gate it")
    _add_analysis_args(check)
    check.set_defaults(func=_cmd_check)

    explain = sub.add_parser("explain", help="plain-language analysis")
    _add_analysis_args(explain)
    explain.set_defaults(func=_cmd_explain)

    receipt = sub.add_parser("receipt", help="build a portable certificate")
    _add_analysis_args(receipt)
    receipt.set_defaults(func=_cmd_receipt)

    verify = sub.add_parser("verify", help="verify a receipt against current state")
    verify.add_argument("receipt")
    verify.add_argument("--root", default=".")
    verify.add_argument("--catalog")
    verify.add_argument("--policy")
    verify.add_argument("--format", default="text", choices=("text", "json"))
    verify.set_defaults(func=_cmd_verify)

    diff = sub.add_parser("diff", help="compare two receipts")
    diff.add_argument("left")
    diff.add_argument("right")
    diff.add_argument("--format", default="text", choices=("text", "json"))
    diff.set_defaults(func=_cmd_diff)

    selftest = sub.add_parser("selftest", help="run built-in regression checks")
    selftest.add_argument("--format", default="text", choices=("text", "json"))
    selftest.set_defaults(func=_cmd_selftest)

    catalog_check = sub.add_parser("catalog-check", help="validate catalog and policy")
    catalog_check.add_argument("--catalog")
    catalog_check.add_argument("--policy")
    catalog_check.add_argument("--format", default="text", choices=("text", "json"))
    catalog_check.set_defaults(func=_cmd_catalog_check)

    return parser


def _cmd_explain(args: argparse.Namespace) -> int:
    args.format = "explain"
    return _cmd_check(args)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "subcommand", None):
        parser.print_help()
        return 0
    return int(args.func(args))
