"""Frozen value objects and canonical serialization for blast.

Nothing in this module touches the filesystem, the network, or a process.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional, Tuple

SCHEMA_VERSION = 1
TOOL_VERSION = "0.1.0"

WORD_LITERAL = "literal"
WORD_DYNAMIC = "dynamic"
WORD_OPAQUE = "opaque"
WORD_ERROR = "error"

STATUS_ANALYZED = "analyzed"
STATUS_OPAQUE = "opaque"
STATUS_ERROR = "error"

VERDICT_ALLOW = "allow"
VERDICT_CONFIRM = "confirm"
VERDICT_DENY = "deny"

EXIT_ALLOW = 0
EXIT_CONFIRM = 10
EXIT_DENY = 20
EXIT_ERROR = 30

CAPABILITIES: Tuple[str, ...] = (
    "FS_READ",
    "FS_WRITE",
    "FS_APPEND",
    "FS_DELETE",
    "FS_DELETE_RECURSIVE",
    "FS_TRUNCATE",
    "FS_CHMOD",
    "FS_CHOWN",
    "FS_DEVICE_WRITE",
    "FS_DESTRUCTIVE",
    "SENSITIVE_PATH",
    "EVIDENCE_DESTROY",
    "NET_OUTBOUND",
    "NET_FETCH_TO_EXEC",
    "NET_LISTEN",
    "PROCESS_SPAWN",
    "CODE_EXEC_OPAQUE",
    "CODE_EVAL",
    "CODE_EXTERNAL_SCRIPT",
    "CODE_DYNAMIC_DISPATCH",
    "PRIVILEGE_ESCALATION",
    "PERSISTENCE",
    "CREDENTIAL_WRITE",
    "ENV_MUTATION",
    "DB_DESTRUCTIVE",
    "CLOUD_STATE_BULK",
    "VCS_READ",
    "VCS_HISTORY_REWRITE",
    "PACKAGE_MUTATION",
    "RESOURCE_EXHAUSTION",
    "UNKNOWN_EFFECT",
)


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    line: int
    col: int

    def slice_of(self, source: str) -> str:
        return source[self.start:self.end]


@dataclass(frozen=True)
class WordPart:
    kind: str
    value: str
    span: Span


@dataclass(frozen=True)
class Word:
    raw: str
    parts: Tuple[WordPart, ...]
    state: str
    value: Optional[str]
    span: Span
    obfuscated: bool = False
    provenance: str = ""

    @property
    def known(self) -> bool:
        return self.state == WORD_LITERAL and self.value is not None


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    span: Span
    word: Optional[Word] = None


@dataclass(frozen=True)
class Redirect:
    op: str
    target: Optional[Word]
    fd: Optional[int]
    span: Span


@dataclass(frozen=True)
class SimpleCommand:
    words: Tuple[Word, ...]
    redirects: Tuple[Redirect, ...]
    assignments: Tuple[str, ...]
    span: Span
    background: bool


@dataclass(frozen=True)
class Pipeline:
    commands: Tuple[SimpleCommand, ...]
    span: Span


@dataclass(frozen=True)
class Invocation:
    name: Word
    args: Tuple[Word, ...]
    redirects: Tuple[Redirect, ...]
    assignments: Tuple[str, ...]
    pipeline_index: int
    position: int
    pipe_in: bool
    pipe_out: bool
    background: bool
    span: Span


@dataclass(frozen=True)
class Assertion:
    capability: str
    action: str
    object: str
    object_kind: str
    scope: str
    confidence: str
    rule_id: str
    reason: str
    severity: str
    span: Span
    raw: str


@dataclass(frozen=True)
class Unknown:
    kind: str
    reason: str
    span: Span
    raw: str


@dataclass(frozen=True)
class ParseIssue:
    code: str
    message: str
    level: str
    span: Span
    raw: str


@dataclass(frozen=True)
class FsFinding:
    path: str
    kind: str
    size: int
    sha256: str
    sensitive: bool
    in_git_worktree: bool
    outside_root: bool


@dataclass(frozen=True)
class EvidenceReport:
    findings: Tuple[FsFinding, ...]
    total_bytes: int
    truncated: bool
    digest: str
    matched_count: int

    @staticmethod
    def empty() -> "EvidenceReport":
        return EvidenceReport((), 0, False, sha256_text(""), 0)


@dataclass(frozen=True)
class EvalResult:
    assertions: Tuple[Assertion, ...]
    unknowns: Tuple[Unknown, ...]
    status: str


@dataclass(frozen=True)
class Decision:
    verdict: str
    reasons: Tuple[str, ...]
    exit_code: int


@dataclass(frozen=True)
class AnalysisResult:
    schema_version: int
    tool_version: str
    input_sha256: str
    dialect: str
    catalog_version: str
    catalog_digest: str
    policy_version: str
    policy_digest: str
    status: str
    assertions: Tuple[Assertion, ...]
    unknowns: Tuple[Unknown, ...]
    parse_issues: Tuple[ParseIssue, ...]
    evidence: EvidenceReport
    verdict: str
    reasons: Tuple[str, ...]
    exit_code: int


@dataclass(frozen=True)
class SyntaxModel:
    pipelines: Tuple[Pipeline, ...]
    invocations: Tuple[Invocation, ...]
    issues: Tuple[ParseIssue, ...]
    span: Span


@dataclass(frozen=True)
class LexResult:
    tokens: Tuple[Token, ...]
    issues: Tuple[ParseIssue, ...]
    span: Span


@dataclass(frozen=True)
class Budget:
    max_input_bytes: int = 20000
    max_tokens: int = 4096
    max_files: int = 2000
    max_depth: int = 64
    max_hash_bytes: int = 1048576


def plain(obj: Any) -> Any:
    """Convert frozen dataclasses and tuples into JSON-safe structures."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: plain(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [plain(v) for v in obj]
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    if isinstance(obj, float):
        raise ValueError("floats are forbidden in deterministic output")
    raise TypeError("unsupported type in serialization: %r" % (type(obj),))


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        plain(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_text(obj: Any) -> str:
    return canonical_bytes(obj).decode("utf-8")


def pretty_json(obj: Any) -> str:
    return json.dumps(
        plain(obj), sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(obj: Any) -> str:
    return sha256_bytes(canonical_bytes(obj))


def issue_span(source: str) -> Span:
    return Span(0, len(source), 1, 1)
