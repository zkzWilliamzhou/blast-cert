"""Read-only filesystem evidence resolution.

Resolves literal and glob path assertions into concrete objects. Never writes,
never follows a symlink outside the root, and stops at a hard budget.
"""
from __future__ import annotations

import glob
import hashlib
import os
from typing import Dict, List, Optional, Tuple

from .capabilities import is_sensitive
from .model import Assertion, Budget, EvidenceReport, FsFinding, digest_of

FILE_CAPS = frozenset((
    "FS_READ", "FS_WRITE", "FS_APPEND", "FS_DELETE", "FS_DELETE_RECURSIVE",
    "FS_TRUNCATE", "FS_CHMOD", "FS_CHOWN", "FS_DEVICE_WRITE", "FS_DESTRUCTIVE",
    "SENSITIVE_PATH", "EVIDENCE_DESTROY", "CREDENTIAL_WRITE", "PERSISTENCE",
    "CODE_EXTERNAL_SCRIPT",
))
GLOB_CHARS = ("*", "?", "[")


def _hash_file(path: str, link_target: Optional[str], budget: Budget) -> str:
    digest = hashlib.sha256()
    if link_target is not None:
        digest.update(b"symlink:")
        digest.update(link_target.encode("utf-8", "replace"))
        return digest.hexdigest()
    try:
        with open(path, "rb") as handle:
            remaining = budget.max_hash_bytes
            while remaining > 0:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
    except OSError:
        digest.update(b"unreadable")
    return digest.hexdigest()


def _inside(root_real: str, candidate_real: str) -> bool:
    try:
        return os.path.commonpath((root_real, candidate_real)) == root_real
    except ValueError:
        return False


def _relative(root_real: str, candidate_real: str) -> str:
    rel = os.path.relpath(candidate_real, root_real)
    return "." if rel == "." else rel.replace(os.sep, "/")


def _git_worktree(root: str, rel: str) -> bool:
    parts = rel.split("/")
    for depth in range(len(parts), 0, -1):
        candidate = os.path.join(root, *parts[:depth - 1], ".git") if depth > 1 else os.path.join(root, ".git")
        if os.path.isdir(candidate) or os.path.isfile(candidate):
            return True
    return False


def _finding(
    root: str, root_real: str, path: str, budget: Budget, outside: bool = False
) -> FsFinding:
    rel = _relative(root_real, os.path.realpath(path)) if not outside else path
    sensitive = is_sensitive(rel) or is_sensitive(path) or outside
    size = 0
    kind = "missing"
    link_target: Optional[str] = None
    if not outside:
        try:
            if os.path.islink(path):
                kind = "symlink"
                link_target = os.readlink(path)
            elif os.path.isdir(path):
                kind = "dir"
            elif os.path.isfile(path):
                size = os.path.getsize(path)
                kind = "file_partial" if size > budget.max_hash_bytes else "file"
            else:
                kind = "other"
        except OSError:
            kind = "unreadable"
    hashable = kind in ("file", "file_partial")
    return FsFinding(
        path=rel,
        kind=kind,
        size=size,
        sha256=_hash_file(path, link_target, budget) if hashable else "",
        sensitive=sensitive,
        in_git_worktree=_git_worktree(root, rel) if not outside else False,
        outside_root=outside,
    )


def _walk_tree(path: str, budget: Budget, out: List[str]) -> bool:
    root_depth = path.rstrip(os.sep).count(os.sep)
    truncated = False
    for current, dirs, files in os.walk(path, followlinks=False):
        if current.count(os.sep) - root_depth > budget.max_depth:
            dirs[:] = []
            truncated = True
            continue
        dirs.sort()
        files.sort()
        for name in files:
            out.append(os.path.join(current, name))
            if len(out) >= budget.max_files:
                return True
        if len(out) >= budget.max_files:
            return True
    return truncated


def _paths_for(assertion: Assertion, root: str, root_real: str,
               budget: Budget) -> Tuple[List[str], bool, bool, bool]:
    """Return (paths, outside_root, truncated, glob_escape)."""
    obj = assertion.object
    if not obj or len(obj) > 4096 or obj.startswith("-"):
        return [], False, False, False
    if "$" in obj or "`" in obj or obj.startswith("~"):
        return [], True, False, False
    if root_real == os.path.sep and os.path.isabs(obj):
        return [], True, False, False
    if not (os.path.isabs(obj) or "/" in obj or obj in (".", "..")
            or any(ch in obj for ch in GLOB_CHARS)):
        candidate = os.path.join(root, obj)
        if not os.path.lexists(candidate):
            return [], False, False, False

    has_glob = any(ch in obj for ch in GLOB_CHARS)
    if os.path.isabs(obj):
        pattern = obj
        literal = os.path.realpath(obj)
        if not has_glob and not _inside(root_real, literal):
            return [], True, False, False
    else:
        candidate = os.path.normpath(os.path.join(root, obj))
        pattern = candidate
        literal = os.path.realpath(candidate)
        if not has_glob and not _inside(root_real, literal):
            return [], True, False, False

    paths: List[str] = []
    truncated = False
    glob_escape = False
    if has_glob:
        for matched in glob.iglob(pattern, recursive=False):
            matched_real = os.path.realpath(matched)
            if not _inside(root_real, matched_real):
                truncated = True
                glob_escape = True
                continue
            paths.append(matched_real)
            if len(paths) >= budget.max_files:
                truncated = True
                break
    elif os.path.lexists(literal):
        if os.path.isdir(literal) and assertion.scope == "prefix":
            truncated = _walk_tree(literal, budget, paths)
        else:
            paths.append(literal)
    else:
        return [], False, False, False
    return paths, False, truncated, glob_escape


def resolve(assertions: Tuple[Assertion, ...], root: str,
            budget: Optional[Budget] = None) -> EvidenceReport:
    budget = budget or Budget()
    root_abs = os.path.abspath(root)
    root_real = os.path.realpath(root_abs)
    findings: Dict[str, FsFinding] = {}
    truncated = False

    for assertion in assertions:
        if assertion.capability not in FILE_CAPS:
            continue
        if assertion.object_kind not in ("file", "directory", "device", "credential"):
            continue
        if assertion.scope in ("dynamic", "unknown"):
            continue
        if any(ch in assertion.object for ch in ("$", "`")):
            continue
        paths, outside, path_truncated, glob_escape = _paths_for(
            assertion, root_abs, root_real, budget
        )
        truncated = truncated or path_truncated
        if outside or glob_escape:
            marker = assertion.object
            key = "outside:" + marker
            if key not in findings:
                findings[key] = FsFinding(
                    path=marker, kind="outside_root", size=0, sha256="",
                    sensitive=True, in_git_worktree=False, outside_root=True,
                )
            continue
        for path in paths:
            if len(findings) >= budget.max_files:
                truncated = True
                break
            rel = _relative(root_real, path)
            if rel in findings:
                continue
            findings[rel] = _finding(root_abs, root_real, path, budget)

    ordered = tuple(sorted(findings.values(), key=lambda f: f.path))
    total = sum(f.size for f in ordered)
    digest = digest_of([{
        "path": f.path, "kind": f.kind, "size": f.size, "sha256": f.sha256,
        "sensitive": f.sensitive, "in_git_worktree": f.in_git_worktree,
        "outside_root": f.outside_root,
    } for f in ordered])
    return EvidenceReport(
        findings=ordered,
        total_bytes=total,
        truncated=truncated,
        digest=digest,
        matched_count=len(ordered),
    )
