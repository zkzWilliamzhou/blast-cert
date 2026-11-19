"""Syntax model: tokens become commands, redirects, pipelines and invocations.

This is a declared subset of bash and POSIX sh. Anything outside that subset
produces a structured issue at level ``error`` or ``opaque``.
"""
from __future__ import annotations

import re
from typing import List, Optional

from .lexer import lex
from .model import (
    Budget,
    Invocation,
    LexResult,
    ParseIssue,
    Pipeline,
    Redirect,
    SimpleCommand,
    Span,
    SyntaxModel,
    Token,
    Word,
)

REDIRECT_OPS = frozenset((">", ">>", "<", "<<", "<<<", ">|", ">&", "<&", "&>"))
SEPARATORS = frozenset((";", "&&", "||", "\n"))
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _span_cover(tokens: List[Token], fallback: Span) -> Span:
    if not tokens:
        return fallback
    start = tokens[0].span.start
    end = tokens[-1].span.end
    return Span(start, end, tokens[0].span.line, tokens[0].span.col)


def _numeric(word: Optional[Word]) -> Optional[int]:
    if word is None or not word.known:
        return None
    if word.value is not None and word.value.isdigit():
        return int(word.value)
    return None


def _build_stage(
    tokens: List[Token], issues: List[ParseIssue], fallback: Span
) -> SimpleCommand:
    words: List[Word] = []
    redirects: List[Redirect] = []
    background = False
    i = 0

    while i < len(tokens):
        tok = tokens[i]
        if tok.kind == "comment":
            i += 1
            continue
        if tok.kind != "operator":
            if tok.word is not None:
                words.append(tok.word)
            i += 1
            continue

        op = tok.text
        if op == "&":
            background = True
            i += 1
            continue
        if op in ("(", ")"):
            issues.append(ParseIssue(
                "UNSUPPORTED_SUBSHELL",
                "subshell grouping is outside the declared dialect subset",
                "error", tok.span, op,
            ))
            i += 1
            continue
        if op not in REDIRECT_OPS:
            i += 1
            continue

        fd: Optional[int] = None
        if words and op in (">", ">>", "<", ">|", "&>"):
            candidate = _numeric(words[-1])
            if candidate is not None:
                fd = candidate
                words.pop()

        target: Optional[Word] = None
        if i + 1 < len(tokens) and tokens[i + 1].kind == "word":
            target = tokens[i + 1].word
            i += 1
            if op in (">&", "<&") and _numeric(target) is not None:
                target = None

        if op == "<<":
            issues.append(ParseIssue(
                "HEREDOC_OPAQUE",
                "heredoc body is not part of the analyzed string", "opaque",
                tok.span, tok.text,
            ))
        if target is None and op not in (">&", "<&"):
            issues.append(ParseIssue(
                "MISSING_REDIRECT_TARGET", "redirect has no target word",
                "error", tok.span, op,
            ))
        redirects.append(Redirect(op, target, fd, tok.span))
        i += 1

    leading: List[str] = []
    while words and _ASSIGNMENT.match(words[0].raw or ""):
        leading.append(words.pop(0).raw or "")

    return SimpleCommand(
        words=tuple(words),
        redirects=tuple(redirects),
        assignments=tuple(leading),
        span=_span_cover(tokens, fallback),
        background=background,
    )


def parse(source: str, dialect: str = "bash", budget: Optional[Budget] = None) -> SyntaxModel:
    budget = budget or Budget()
    lexed: LexResult = lex(source, dialect, budget)
    issues: List[ParseIssue] = list(lexed.issues)
    fallback = Span(0, len(source), 1, 1)
    tokens = list(lexed.tokens)

    segments: List[List[Token]] = []
    current: List[Token] = []
    for tok in tokens:
        if tok.kind == "operator" and tok.text in SEPARATORS:
            if current:
                segments.append(current)
            current = []
            continue
        current.append(tok)
    if current:
        segments.append(current)

    pipelines: List[Pipeline] = []
    invocations: List[Invocation] = []

    for seg_index, segment in enumerate(segments):
        stages: List[List[Token]] = []
        stage: List[Token] = []
        for tok in segment:
            if tok.kind == "operator" and tok.text == "|":
                stages.append(stage)
                stage = []
            else:
                stage.append(tok)
        stages.append(stage)

        commands: List[SimpleCommand] = []
        for pos, st in enumerate(stages):
            cmd = _build_stage(st, issues, _span_cover(segment, fallback))
            commands.append(cmd)
            if not cmd.words:
                continue
            invocations.append(Invocation(
                name=cmd.words[0],
                args=cmd.words[1:],
                redirects=cmd.redirects,
                assignments=cmd.assignments,
                pipeline_index=seg_index,
                position=pos,
                pipe_in=pos > 0,
                pipe_out=pos < len(stages) - 1,
                background=cmd.background,
                span=cmd.span,
            ))
        pipelines.append(Pipeline(tuple(commands), _span_cover(segment, fallback)))

    return SyntaxModel(
        pipelines=tuple(pipelines),
        invocations=tuple(invocations),
        issues=tuple(issues),
        span=fallback,
    )
