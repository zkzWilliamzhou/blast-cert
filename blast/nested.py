"""Bounded expansion of statically visible nested commands.

A wrapper such as ``sudo rm -rf /`` and an interpreter with a literal
``-c`` string both contain a second command that a human can read. This
module surfaces those inner invocations so the capability evaluator can
report their effects too. It never executes anything and stops at a hard
depth and cycle budget.
"""
from __future__ import annotations

from typing import Dict, Optional, Set, Tuple

from .catalog import Catalog
from .model import Invocation, Span, SyntaxModel, Word
from .parser import parse

MAX_NESTED_DEPTH = 3
MAX_NESTED_COMMANDS = 64

WRAPPERS = frozenset((
    "sudo", "su", "doas", "pkexec", "nohup", "timeout", "env", "xargs",
    "command", "builtin",
))
INTERPRETERS_WITH_C = frozenset((
    "sh", "bash", "dash", "zsh", "ksh", "fish", "python", "python3",
    "perl", "ruby", "node", "php", "pwsh", "powershell", "deno", "bun",
))
EVAL_WITH_LITERAL = frozenset(("eval", "source", ".", "exec"))
C_FLAGS = frozenset(("-c", "-e", "--command", "-cmd"))


def _word_value(word: Word) -> Optional[str]:
    return word.value if word.known and word.value is not None else None


def _synthetic(outer: Invocation, words: Tuple[Word, ...],
               offset: int) -> Optional[Invocation]:
    if not words:
        return None
    start = words[0].span.start
    end = words[-1].span.end
    span = Span(start, end, words[0].span.line, words[0].span.col)
    return Invocation(
        name=words[0],
        args=words[1:],
        redirects=outer.redirects,
        assignments=outer.assignments,
        pipeline_index=outer.pipeline_index,
        position=outer.position + offset,
        pipe_in=False,
        pipe_out=False,
        background=outer.background,
        span=span,
    )


def _wrapper_inner(outer: Invocation, catalog: Catalog) -> Tuple[Invocation, ...]:
    name = _word_value(outer.name)
    if name not in WRAPPERS:
        return ()
    for index, word in enumerate(outer.args):
        value = _word_value(word)
        if value is None or value.startswith("-"):
            continue
        if not catalog.is_known(value):
            return ()
        synthetic = _synthetic(outer, outer.args[index:], 1000 + index)
        return (synthetic,) if synthetic else ()
    return ()


def _literal_c_payload(outer: Invocation) -> Optional[str]:
    name = _word_value(outer.name)
    if name not in INTERPRETERS_WITH_C:
        return None
    args = list(outer.args)
    for index, word in enumerate(args):
        value = _word_value(word)
        if value is None or value not in C_FLAGS:
            continue
        if index + 1 < len(args):
            payload = _word_value(args[index + 1])
            if payload is not None:
                return payload
        if value.startswith("-c") and len(value) > 2:
            return value[2:]
    return None


def _eval_payload(outer: Invocation) -> Optional[str]:
    name = _word_value(outer.name)
    if name not in EVAL_WITH_LITERAL:
        return None
    for word in outer.args:
        payload = _word_value(word)
        if payload is not None and not payload.startswith("-"):
            return payload
    return None


def expand_invocations(
    model: SyntaxModel,
    catalog: Catalog,
    dialect: str = "bash",
    depth: int = 0,
    seen: Optional[Set[str]] = None,
    counter: Optional[Dict[str, int]] = None,
) -> Tuple[Invocation, ...]:
    """Return original invocations plus bounded synthetic inner invocations."""
    seen = set() if seen is None else seen
    counter = {"count": 0} if counter is None else counter
    out: list = list(model.invocations)

    if depth >= MAX_NESTED_DEPTH or counter["count"] >= MAX_NESTED_COMMANDS:
        return tuple(out)

    for outer in model.invocations:
        payload: Optional[str] = None
        for candidate in (_literal_c_payload(outer), _eval_payload(outer)):
            if candidate is not None:
                payload = candidate
                break
        if payload and payload not in seen:
            seen.add(payload)
            counter["count"] += 1
            inner_model = parse(payload, dialect)
            inner = expand_invocations(
                inner_model, catalog, dialect, depth + 1, seen, counter
            )
            for index, inv in enumerate(inner):
                out.append(Invocation(
                    name=inv.name,
                    args=inv.args,
                    redirects=inv.redirects,
                    assignments=inv.assignments,
                    pipeline_index=outer.pipeline_index,
                    position=outer.position + 10000 + depth * 1000 + index,
                    pipe_in=False,
                    pipe_out=False,
                    background=outer.background,
                    span=inv.span,
                ))
        for synthetic in _wrapper_inner(outer, catalog):
            counter["count"] += 1
            out.append(synthetic)

    return tuple(out)
