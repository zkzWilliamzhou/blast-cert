"""Capability evaluation.

The result is a conservative superset: every effect that can be seen in the
declared dialect subset appears as an assertion, and every effect that cannot
be determined appears as an Unknown. Unknowns block ``allow``.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from .catalog import Catalog
from .model import (
    STATUS_ANALYZED,
    STATUS_ERROR,
    STATUS_OPAQUE,
    Assertion,
    EvalResult,
    Invocation,
    ParseIssue,
    Span,
    SyntaxModel,
    Unknown,
    Word,
)
from .nested import expand_invocations

CAP_META: Dict[str, Tuple[str, str, str]] = {
    "FS_READ": ("read", "file", "exact"),
    "FS_WRITE": ("write", "file", "exact"),
    "FS_APPEND": ("append", "file", "exact"),
    "FS_DELETE": ("delete", "file", "prefix"),
    "FS_DELETE_RECURSIVE": ("delete", "directory", "prefix"),
    "FS_TRUNCATE": ("truncate", "file", "exact"),
    "FS_CHMOD": ("chmod", "file", "exact"),
    "FS_CHOWN": ("chown", "file", "exact"),
    "FS_DEVICE_WRITE": ("write", "device", "exact"),
    "FS_DESTRUCTIVE": ("destroy", "file", "prefix"),
    "SENSITIVE_PATH": ("access", "file", "exact"),
    "EVIDENCE_DESTROY": ("destroy", "file", "exact"),
    "NET_OUTBOUND": ("connect", "network", "exact"),
    "NET_FETCH_TO_EXEC": ("execute", "network", "exact"),
    "NET_LISTEN": ("bind", "network", "exact"),
    "PROCESS_SPAWN": ("spawn", "process", "exact"),
    "CODE_EXEC_OPAQUE": ("execute", "process", "unknown"),
    "CODE_EVAL": ("evaluate", "process", "unknown"),
    "CODE_EXTERNAL_SCRIPT": ("execute", "file", "unknown"),
    "CODE_DYNAMIC_DISPATCH": ("dispatch", "process", "unknown"),
    "PRIVILEGE_ESCALATION": ("elevate", "process", "exact"),
    "PERSISTENCE": ("persist", "process", "exact"),
    "CREDENTIAL_WRITE": ("write", "credential", "exact"),
    "ENV_MUTATION": ("mutate", "environment", "exact"),
    "DB_DESTRUCTIVE": ("destroy", "database", "exact"),
    "CLOUD_STATE_BULK": ("destroy", "resource", "exact"),
    "VCS_READ": ("read", "vcs", "exact"),
    "VCS_HISTORY_REWRITE": ("rewrite", "vcs", "exact"),
    "PACKAGE_MUTATION": ("mutate", "package", "exact"),
    "RESOURCE_EXHAUSTION": ("exhaust", "process", "exact"),
    "UNKNOWN_EFFECT": ("unknown", "process", "unknown"),
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SENSITIVE_PREFIXES: Tuple[str, ...] = (
    "/etc", "/dev", "/boot", "/usr", "/bin", "/sbin", "/proc", "/sys",
    "/root", "/var/log", "/var/lib", "/lib", "/lib64", "/opt", "/srv",
    "/home", "/private", "/System", "/Library", "/Windows",
)
SENSITIVE_NAMES: Tuple[str, ...] = (
    "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", ".bashrc",
    ".bash_profile", ".profile", ".zshrc", ".ssh", ".aws", ".gnupg",
    ".gitconfig", ".npmrc", ".netrc", ".env", "ld.so.preload",
    "ld.so.conf", "sudoers", "shadow", "passwd", "cron.d", "crontab",
    "master.key", "credentials", ".bash_history", ".zsh_history",
)
CREDENTIAL_NAMES: Tuple[str, ...] = (
    "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", ".ssh",
    ".aws", ".gnupg", ".netrc", "credentials", "shadow", ".env",
)
EVIDENCE_NAMES: Tuple[str, ...] = (
    ".bash_history", ".zsh_history", "audit.log", "auth.log", "syslog",
)
PERSISTENCE_NAMES: Tuple[str, ...] = (
    "cron.d", "crontab", "systemd", "launchd", "rc.local", "profile.d",
    "sudoers.d", "ld.so.preload", ".bashrc", ".profile", ".zshrc",
    "authorized_keys",
)
DEVICE_PREFIXES: Tuple[str, ...] = ("/dev/",)

FETCHERS = frozenset((
    "curl", "wget", "nc", "ncat", "netcat", "socat", "fetch", "http",
))
DECODERS = frozenset((
    "base64", "xxd", "openssl", "uudecode", "gunzip", "unzip",
))
INTERPRETERS = frozenset((
    "sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh",
    "python", "python3", "perl", "ruby", "node", "php", "lua", "pwsh",
    "powershell", "deno", "bun", "eval",
))
EVAL_NAMES = frozenset(("eval", "source", ".", "exec"))
EXTERNAL_SCRIPT_NAMES = frozenset((
    "bash", "sh", "dash", "zsh", "ksh", "fish", "source", ".", "exec",
    "python", "python3", "perl", "ruby", "node", "php",
))
WRAPPER_NAMES = frozenset((
    "sudo", "su", "doas", "pkexec", "nohup", "timeout", "env", "xargs",
    "command", "builtin",
))
WRITE_VALUE_FLAGS = frozenset((
    "-o", "--output", "-O", "--output-document", "-out", "--out",
))
SUBSTITUTION_PARTS = frozenset((
    "command_substitution", "backtick", "arithmetic", "process_substitution",
))
DYNAMIC_NAME_HINTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("rm", ("FS_DELETE", "FS_DELETE_RECURSIVE")),
    ("dd", ("FS_DEVICE_WRITE", "FS_WRITE")),
    ("mkfs", ("FS_DEVICE_WRITE", "FS_DESTRUCTIVE")),
    ("chmod", ("FS_CHMOD",)),
    ("chown", ("FS_CHOWN",)),
    ("shred", ("FS_DELETE",)),
    ("curl", ("NET_OUTBOUND",)),
    ("wget", ("NET_OUTBOUND",)),
    ("git", ("VCS_HISTORY_REWRITE",)),
)
SENSITIVE_ENV = frozenset((
    "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "IFS", "PYTHONPATH",
    "NODE_OPTIONS", "BASH_ENV", "ENV", "SHELL", "HOME", "PS4",
    "PERL5LIB", "GIT_SSH_COMMAND", "LD_AUDIT",
))
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)


def _span_for_word(word: Optional[Word], fallback: Span) -> Span:
    return word.span if word is not None else fallback


def _word_scope(word: Optional[Word]) -> str:
    if word is None:
        return "exact"
    if not word.known:
        return "dynamic"
    if any(p.kind == "glob" for p in word.parts):
        return "pattern"
    return "exact"


def _word_object(word: Optional[Word], fallback: str) -> str:
    if word is None:
        return fallback
    if word.known and word.value is not None:
        return word.value
    return word.raw or fallback


def is_sensitive(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if normalized in ("", "/", "~", ".") or normalized.startswith("~/"):
        return True
    if ".." in normalized.split("/"):
        return True
    for prefix in SENSITIVE_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return True
    lowered = normalized.lower()
    return any(name in lowered for name in SENSITIVE_NAMES)


class _Emitter:
    def __init__(self) -> None:
        self.assertions: List[Assertion] = []
        self.unknowns: List[Unknown] = []
        self.issues: List[ParseIssue] = []

    def add(
        self,
        cap: str,
        rule_id: str,
        reason: str,
        obj: str,
        span: Span,
        raw: str,
        word: Optional[Word] = None,
        scope: Optional[str] = None,
        object_kind: Optional[str] = None,
        severity: str = "info",
    ) -> None:
        action, default_kind, default_scope = CAP_META[cap]
        if scope is not None:
            final_scope = scope
        elif word is None:
            final_scope = default_scope
        else:
            word_scope = _word_scope(word)
            if word_scope in ("dynamic", "pattern"):
                final_scope = word_scope
            elif default_scope == "prefix":
                final_scope = "prefix"
            else:
                final_scope = word_scope
        self.assertions.append(Assertion(
            capability=cap,
            action=action,
            object=obj,
            object_kind=object_kind or default_kind,
            scope=final_scope,
            confidence="definite" if word is None or word.known else "unknown",
            rule_id=rule_id,
            reason=reason,
            severity=severity,
            span=span,
            raw=raw,
        ))

    def unknown(self, kind: str, reason: str, span: Span, raw: str) -> None:
        self.unknowns.append(Unknown(kind, reason, span, raw))


def _split_args(inv: Invocation, spec: Dict[str, object], em: _Emitter) -> Tuple[
    List[str], List[Word], List[Word], List[str]
]:
    flags: List[str] = []
    operands: List[Word] = []
    scanned: List[Word] = []
    unknown_flags: List[str] = []
    known_flags: Dict[str, List[str]] = spec["flags"]  # type: ignore[assignment]
    value_flags = set(spec["value_flags"])  # type: ignore[arg-type]
    args = list(inv.args)
    i = 0
    options_done = False
    while i < len(args):
        word = args[i]
        if options_done:
            operands.append(word)
            scanned.append(word)
            i += 1
            continue
        text = word.value if word.known and word.value is not None else word.raw
        if text == "--":
            options_done = True
            i += 1
            continue
        if text.startswith("-") and text != "-" and len(text) > 1:
            flag = text
            attached: Optional[Word] = None
            if "=" in text and text.startswith("--"):
                flag, value = text.split("=", 1)
                attached = Word(value, (), "literal", value, word.span)
            candidates = [flag]
            if (flag not in known_flags and flag.startswith("-")
                    and not flag.startswith("--") and len(flag) > 2):
                candidates = ["-" + ch for ch in flag[1:]]
            for candidate in candidates:
                if candidate in known_flags:
                    flags.append(candidate)
                    for cap in known_flags[candidate]:
                        em.add(cap, "catalog.flag.%s" % candidate,
                               "flag %s declared in catalog" % candidate,
                               candidate, word.span, word.raw, word,
                               severity="high" if cap in ("FS_DELETE", "CODE_EVAL") else "info")
                else:
                    unknown_flags.append(candidate)
                    em.unknown("UNKNOWN_FLAG",
                               "flag %s has no declared semantics" % candidate,
                               word.span, word.raw)
            if attached is not None:
                scanned.append(attached)
                operands.append(attached)
                if any(c in WRITE_VALUE_FLAGS for c in candidates):
                    em.add("FS_WRITE", "syntax.value_flag_output",
                           "option writes to a named output file",
                           attached.value or attached.raw, attached.span,
                           attached.raw, attached, severity="high")
            if flag in value_flags and attached is None and i + 1 < len(args):
                i += 1
                value_word = args[i]
                scanned.append(value_word)
                if flag in WRITE_VALUE_FLAGS:
                    em.add("FS_WRITE", "syntax.value_flag_output",
                           "option writes to a named output file",
                           _word_object(value_word, flag), value_word.span,
                           value_word.raw, value_word, severity="high")
                if not value_word.known:
                    em.unknown("DYNAMIC_FLAG_VALUE",
                               "option value depends on runtime state",
                               value_word.span, value_word.raw)
            i += 1
            continue
        operands.append(word)
        scanned.append(word)
        i += 1
    return flags, operands, scanned, unknown_flags


def _assignment_map(model: SyntaxModel) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for pipeline in model.pipelines:
        for cmd in pipeline.commands:
            for raw in cmd.assignments:
                match = _ASSIGN.match(raw)
                if match and "$" not in match.group(2) and "`" not in match.group(2):
                    values[match.group(1)] = match.group(2)
    return values


def _dynamic_hint(word: Word, assignments: Dict[str, str]) -> Optional[str]:
    chunks: List[str] = []
    for part in word.parts:
        if part.kind == "variable":
            name = part.value.lstrip("$").strip("{}")
            if name in assignments:
                chunks.append(assignments[name])
            else:
                return None
        elif part.kind in ("literal", "single", "double", "escape", "glob", "ansi_c"):
            chunks.append(part.value)
        else:
            return None
    return "".join(chunks) or None


def _apply_arg_rules(spec: Dict[str, object], scanned: List[Word], em: _Emitter) -> None:
    for rule in spec["arg_rules"]:  # type: ignore[union-attr]
        match = rule["match"]
        values = rule["values"]
        caps = rule["add"]
        for word in scanned:
            text = _word_object(word, "")
            hit = False
            obj = text
            if match == "any_arg" and text in values:
                hit = True
            elif match == "any_arg_contains" and any(v.upper() in text.upper() for v in values):
                hit = True
            elif match == "arg_prefix":
                for prefix in values:
                    if text.startswith(prefix):
                        hit = True
                        obj = text[len(prefix):]
                        break
            if not hit:
                continue
            for cap in caps:
                em.add(cap, rule["id"], rule["reason"], obj, word.span,
                       word.raw, word, severity=rule["severity"])


def _path_caps(path: str, span: Span, raw: str, word: Optional[Word], em: _Emitter) -> None:
    lowered = path.lower()
    if is_sensitive(path):
        em.add("SENSITIVE_PATH", "path.sensitive",
               "path touches a protected system or credential location",
               path, span, raw, word, severity="critical")
    if any(n in lowered for n in CREDENTIAL_NAMES):
        em.add("CREDENTIAL_WRITE", "path.credential",
               "path holds credentials", path, span, raw, word, severity="critical")
    if any(n in lowered for n in EVIDENCE_NAMES):
        em.add("EVIDENCE_DESTROY", "path.evidence",
               "path holds audit or history evidence", path, span, raw, word,
               severity="critical")
    if any(n in lowered for n in PERSISTENCE_NAMES):
        em.add("PERSISTENCE", "path.persistence",
               "path changes future session behavior", path, span, raw, word,
               severity="critical")
    if any(n in lowered for n in ("ld.so.preload", "sudoers", "sudoers.d",
                                  "authorized_keys", "cron.d", "systemd",
                                  "launchd", "rc.local")):
        em.add("PRIVILEGE_ESCALATION", "path.privilege",
               "path can change code execution or privileges in later sessions",
               path, span, raw, word, severity="critical")
    if any(path.startswith(p) for p in DEVICE_PREFIXES):
        em.add("FS_DEVICE_WRITE", "path.device",
               "path is a device node", path, span, raw, word, severity="critical")


def _process_redirects(model: SyntaxModel, em: _Emitter) -> None:
    seen: Set[Tuple[int, int]] = set()
    for pipeline in model.pipelines:
        for cmd in pipeline.commands:
            for redirect in cmd.redirects:
                key = (redirect.span.start, redirect.span.end)
                if key in seen:
                    continue
                seen.add(key)
                op = redirect.op
                target = redirect.target
                raw = target.raw if target is not None else op
                span = _span_for_word(target, redirect.span)
                obj = _word_object(target, op)
                if op in (">&", "<&"):
                    continue
                if op in (">", ">|", "&>"):
                    caps = ["FS_WRITE", "FS_TRUNCATE"]
                elif op == ">>":
                    caps = ["FS_APPEND", "FS_WRITE"]
                elif op == "<":
                    caps = ["FS_READ"]
                elif op == "<<<":
                    caps = ["FS_READ"]
                else:
                    caps = ["FS_READ"]
                for cap in caps:
                    em.add(cap, "syntax.redirect.%s" % op,
                           "redirect %s writes or reads a target" % op,
                           obj, span, raw, target,
                           severity="high" if cap != "FS_READ" else "info")
                if target is not None:
                    _path_caps(obj, span, raw, target, em)
                    if not target.known:
                        em.unknown("DYNAMIC_REDIRECT_TARGET",
                                   "redirect target cannot be determined statically",
                                   target.span, target.raw)


def _process_pipelines(model: SyntaxModel, em: _Emitter) -> None:
    for pipeline in model.pipelines:
        commands = list(pipeline.commands)
        names: List[Optional[str]] = []
        for cmd in commands:
            if cmd.words and cmd.words[0].known and cmd.words[0].value:
                names.append(cmd.words[0].value)
            else:
                names.append(None)
        for idx in range(len(commands) - 1):
            producer = names[idx]
            consumer = names[idx + 1]
            if consumer not in INTERPRETERS:
                continue
            if producer in FETCHERS:
                em.add("NET_FETCH_TO_EXEC", "pipeline.network_to_interpreter",
                       "network client writes unverified bytes into an interpreter",
                       "%s|%s" % (producer, consumer), pipeline.span,
                       "%s | %s" % (producer, consumer), severity="critical")
                em.unknown("PIPELINE_TO_INTERPRETER",
                           "downloaded content is executed without inspection",
                           pipeline.span, "%s | %s" % (producer, consumer))
            elif producer in DECODERS:
                em.add("CODE_EXEC_OPAQUE", "pipeline.decoder_to_interpreter",
                       "decoded bytes are executed without inspection",
                       "%s|%s" % (producer, consumer), pipeline.span,
                       "%s | %s" % (producer, consumer), severity="critical")
                em.unknown("DECODED_PAYLOAD",
                           "decoded payload has unknown content",
                           pipeline.span, "%s | %s" % (producer, consumer))
        for cmd in commands:
            if cmd.background:
                em.add("PERSISTENCE", "syntax.background",
                       "command is detached from the invoking shell",
                       "background", cmd.span, "&", severity="high")


def _process_assignments(model: SyntaxModel, em: _Emitter) -> None:
    seen: Set[Tuple[str, int]] = set()
    for pipeline in model.pipelines:
        for cmd in pipeline.commands:
            raws = list(cmd.assignments)
            for word in cmd.words[1:] if cmd.words else ():
                if word.known and word.value and _ASSIGN.match(word.value):
                    raws.append(word.value)
            for raw in raws:
                match = _ASSIGN.match(raw)
                if not match:
                    continue
                key = (raw, cmd.span.start)
                if key in seen:
                    continue
                seen.add(key)
                name, value = match.group(1), match.group(2)
                if name not in SENSITIVE_ENV:
                    continue
                em.add("ENV_MUTATION", "assignment.sensitive_env",
                       "assignment changes a security-relevant environment variable",
                       name, cmd.span, raw, severity="high")
                if name in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "BASH_ENV",
                            "NODE_OPTIONS", "PYTHONPATH", "PERL5LIB", "GIT_SSH_COMMAND"):
                    em.add("PRIVILEGE_ESCALATION", "assignment.injection",
                           "environment variable can inject code into later processes",
                           name, cmd.span, raw, severity="critical")
                    em.add("PERSISTENCE", "assignment.injection_persistence",
                           "injected environment survives into later processes",
                           name, cmd.span, raw, severity="critical")
                if "$" in value or "`" in value:
                    em.unknown("DYNAMIC_ENV_VALUE",
                               "environment value cannot be determined statically",
                               cmd.span, raw)


def _process_invocation(
    inv: Invocation, model: SyntaxModel, catalog: Catalog,
    assignments: Dict[str, str], em: _Emitter,
) -> None:
    name_word = inv.name
    span = name_word.span
    raw_name = name_word.raw

    if not name_word.known:
        em.add("CODE_DYNAMIC_DISPATCH", "syntax.dynamic_command_name",
               "command name depends on runtime state",
               raw_name, span, raw_name, name_word,
               scope="dynamic", severity="critical")
        em.add("CODE_EXEC_OPAQUE", "syntax.dynamic_command_name",
               "dynamic dispatch executes an unknown program",
               raw_name, span, raw_name, name_word,
               scope="dynamic", severity="critical")
        em.unknown("DYNAMIC_COMMAND_NAME",
                   "command name is not statically resolvable", span, raw_name)
        hint = _dynamic_hint(name_word, assignments)
        stripped = raw_name.lstrip("'\"")
        matched = False
        for prefix, caps in DYNAMIC_NAME_HINTS:
            source_text = hint if hint else stripped
            if not source_text.startswith(prefix):
                continue
            matched = True
            for cap in caps:
                em.add(cap, "syntax.dynamic_name_hint",
                       "dynamic command name begins with a known destructive verb",
                       raw_name, span, raw_name, name_word,
                       scope="dynamic", severity="critical")
        if hint and not matched:
            em.add("CODE_EXEC_OPAQUE", "syntax.dynamic_name_hint",
                   "dynamic command name resolves to an unmodeled program",
                   raw_name, span, raw_name, name_word,
                   scope="dynamic", severity="critical")
        return

    name = name_word.value or ""
    if any(ord(ch) > 127 for ch in name):
        em.unknown("NON_ASCII_COMMAND_NAME",
                   "command name contains non-ASCII characters", span, raw_name)
    if name_word.obfuscated:
        em.unknown("OBFUSCATED_COMMAND_NAME",
                   "command name uses escapes or empty quotes to hide its spelling",
                   span, raw_name)

    known = catalog.is_known(name)
    spec = catalog.spec(name)
    if not known:
        em.unknown("UNKNOWN_COMMAND",
                   "command %s has no catalog rule" % name, span, raw_name)
        for cap in spec["base"]:
            em.add(cap, "catalog.default.unknown_command",
                   "unmodeled executable effects cannot be enumerated",
                   name, span, raw_name, severity="critical")
        return

    em.add("PROCESS_SPAWN", "catalog.known_command",
           "command %s is a modeled executable" % name,
           name, span, raw_name)

    flags, operands, scanned, _unknown_flags = _split_args(inv, spec, em)
    del flags

    operand_dependent = spec["operand_kind"] in (
        "path", "network", "selector", "sql", "package",
    )
    for cap in spec["base"]:
        if operand_dependent:
            for word in operands:
                obj = _word_object(word, name)
                em.add(cap, "catalog.base.%s" % name,
                       "declared base capability of %s" % name,
                       obj, word.span, word.raw, word,
                       severity="high" if cap in ("FS_DELETE", "FS_DEVICE_WRITE",
                                                  "DB_DESTRUCTIVE", "CLOUD_STATE_BULK") else "info")
                if spec["operand_kind"] == "path":
                    _path_caps(obj, word.span, word.raw, word, em)
        else:
            em.add(cap, "catalog.base.%s" % name,
                   "declared base capability of %s" % name,
                   name, span, raw_name)

    _apply_arg_rules(spec, scanned, em)

    for word in operands + ([inv.name] if not operands else []):
        if word is inv.name:
            continue
        if not word.known:
            em.unknown("DYNAMIC_OPERAND",
                       "operand depends on runtime state", word.span, word.raw)

    if name in EVAL_NAMES:
        em.add("CODE_EVAL", "syntax.eval", "construct evaluates a string as code",
               name, span, raw_name, severity="critical")
        em.unknown("EVAL_OPAQUE", "evaluated content is not in the analyzed string",
                   span, raw_name)

    if name in EXTERNAL_SCRIPT_NAMES:
        for word in operands:
            if word.known and word.value and not word.value.startswith("-"):
                em.add("CODE_EXTERNAL_SCRIPT", "syntax.external_script",
                       "external script content is outside the analyzed string",
                       word.value, word.span, word.raw, word, severity="critical")
                em.unknown("EXTERNAL_SCRIPT_UNREAD",
                           "external script content cannot be enumerated offline",
                           word.span, word.raw)

    all_words = [inv.name] + list(operands) + list(scanned)
    seen_spans: Set[Tuple[int, int]] = set()
    for word in all_words:
        for part in word.parts:
            key = (part.span.start, part.span.end)
            if key in seen_spans:
                continue
            seen_spans.add(key)
            if part.kind not in SUBSTITUTION_PARTS:
                continue
            em.add("CODE_EXEC_OPAQUE", "syntax.substitution",
                   "substituted content is produced by an unread command or stream",
                   word.raw, word.span, word.raw, word, severity="critical")
            if part.kind == "process_substitution" and any(
                    f in part.value for f in FETCHERS):
                em.add("NET_FETCH_TO_EXEC", "syntax.process_substitution_fetch",
                       "process substitution fetches remote content",
                       word.raw, word.span, word.raw, word, severity="critical")
            em.unknown("SUBSTITUTION_OPAQUE",
                       "%s content is outside the analyzed string" % part.kind,
                       word.span, word.raw)

    if name in WRAPPER_NAMES:
        for word in operands:
            if word.known and word.value and word.value.startswith("-"):
                continue
            em.add("CODE_EXEC_OPAQUE", "syntax.wrapper_executable",
                   "wrapper invokes an executable whose effects are not enumerated",
                   _word_object(word, name), word.span, word.raw, word,
                   severity="critical")
            em.unknown("WRAPPED_EXECUTABLE",
                       "wrapped executable effects are outside the catalog",
                       word.span, word.raw)
            break

    if any(not w.known for w in operands) and name in INTERPRETERS:
        em.add("CODE_EVAL", "syntax.interpreter_dynamic_input",
               "interpreter receives a dynamic payload", name, span, raw_name,
               severity="critical")


def evaluate(model: SyntaxModel, catalog: Catalog,
             dialect: str = "bash") -> EvalResult:
    em = _Emitter()
    em.issues = list(model.issues)
    assignments = _assignment_map(model)

    _process_redirects(model, em)
    _process_pipelines(model, em)
    _process_assignments(model, em)
    for inv in expand_invocations(model, catalog, dialect):
        _process_invocation(inv, model, catalog, assignments, em)

    has_error = any(i.level == "error" for i in em.issues)
    has_opaque = any(i.level == "opaque" for i in em.issues)
    if has_error:
        status = STATUS_ERROR
    elif has_opaque or em.unknowns:
        status = STATUS_OPAQUE
    else:
        status = STATUS_ANALYZED

    return EvalResult(
        assertions=tuple(em.assertions),
        unknowns=tuple(em.unknowns),
        status=status,
    )
