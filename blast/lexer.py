"""Shell lexer with source spans.

This module tokenizes. It deliberately does not implement shell semantics.
Command substitution, redirects, pipelines and parameter semantics belong to
``parser.py`` and ``capabilities.py``.
"""
from __future__ import annotations

import unicodedata
from typing import List, Optional, Tuple

from .model import (
    WORD_DYNAMIC,
    WORD_ERROR,
    WORD_LITERAL,
    WORD_OPAQUE,
    Budget,
    LexResult,
    ParseIssue,
    Span,
    Token,
    Word,
    WordPart,
)

OPERATORS: Tuple[str, ...] = (
    "<<<", "&&", "||", ">>", "<<", ">|", ">&", "<&", "&>",
    "<(", ">(", ";", "|", "&", "(", ")", ">", "<", "\n",
)

DYNAMIC_PARTS = frozenset(("variable", "tilde", "unknown"))
OPAQUE_PARTS = frozenset((
    "command_substitution", "backtick", "arithmetic", "process_substitution",
))
RESOLVABLE_PARTS = frozenset((
    "literal", "single", "double", "escape", "glob", "ansi_c",
))

ESCAPE_MAP = {
    "n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b",
    "f": "\f", "v": "\v", "0": "\0", "\\": "\\", "'": "'", '"': '"',
    "$": "$", "`": "`",
}


def _forbidden_chars(source: str) -> List[Tuple[int, str]]:
    found: List[Tuple[int, str]] = []
    for i, ch in enumerate(source):
        if ch in ("\n", "\t"):
            continue
        cp = ord(ch)
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            found.append((i, "U+%04X invisible or private-use character" % cp))
        elif cat == "Cc":
            found.append((i, "U+%04X control character" % cp))
        elif 0x200B <= cp <= 0x200F or 0x202A <= cp <= 0x202E or 0x2060 <= cp <= 0x2069:
            found.append((i, "U+%04X bidirectional or zero-width character" % cp))
    return found


def _line_col(source: str, offset: int) -> Tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last = source.rfind("\n", 0, offset)
    col = offset - last if last >= 0 else offset + 1
    return line, col


def _span(source: str, start: int, end: int) -> Span:
    line, col = _line_col(source, start)
    return Span(start, end, line, col)


def _match_operator(source: str, i: int) -> Optional[str]:
    for op in OPERATORS:
        if source.startswith(op, i):
            return op
    return None


def _find_closing(source: str, i: int, opener: str, closer: str, limit: int) -> int:
    """Find a matching closer from the position after the opener."""
    depth = 1
    j = i
    while j < limit:
        c = source[j]
        if c == "\\" and j + 1 < limit:
            j += 2
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _find_quote_end(source: str, i: int, quote: str, limit: int) -> int:
    """Find the closing quote, skipping backslash-escaped characters."""
    j = i
    while j < limit:
        c = source[j]
        if c == "\\" and j + 1 < limit:
            j += 2
            continue
        if c == quote:
            return j
        j += 1
    return -1


def _decode_double(text: str) -> str:
    """Decode only the escapes POSIX allows inside double quotes."""
    out: List[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] in ('"', "\\", "$", "`", "\n"):
            nxt = text[i + 1]
            out.append("" if nxt == "\n" else nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _decode_ansi_c(text: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c != "\\" or i + 1 >= len(text):
            out.append(c)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt == "x":
            j = i + 2
            hex_part = ""
            while j < len(text) and j < i + 4 and text[j] in "0123456789abcdefABCDEF":
                hex_part += text[j]
                j += 1
            if hex_part:
                out.append(chr(int(hex_part, 16) % 0x110000))
                i = j
                continue
            out.append("x")
            i += 2
            continue
        if nxt in "01234567":
            j = i + 1
            oct_part = ""
            while j < len(text) and j < i + 4 and text[j] in "01234567":
                oct_part += text[j]
                j += 1
            out.append(chr(int(oct_part, 8) % 0x110000))
            i = j
            continue
        out.append(ESCAPE_MAP.get(nxt, nxt))
        i += 2
    return "".join(out)


def _variable_end(source: str, i: int, limit: int) -> int:
    """Return the end offset of a $-introduced expansion starting at i."""
    j = i + 1
    if j >= limit:
        return j
    c = source[j]
    if c == "(":
        if source.startswith("((", j):
            end = source.find("))", j + 2, limit)
            return limit if end < 0 else end + 2
        close = _find_closing(source, j + 1, "(", ")", limit)
        return limit if close < 0 else close + 1
    if c == "{":
        close = _find_closing(source, j + 1, "{", "}", limit)
        return limit if close < 0 else close + 1
    if c.isalpha() or c == "_":
        j += 1
        while j < limit and (source[j].isalnum() or source[j] == "_"):
            j += 1
        return j
    return j + 1


class _WordBuilder:
    def __init__(self, source: str, start: int):
        self.source = source
        self.start = start
        self.end = start
        self.parts: List[WordPart] = []
        self.obfuscated = False
        self.error = False

    def add(self, kind: str, value: str, start: int, end: int) -> None:
        self.parts.append(WordPart(kind, value, _span(self.source, start, end)))
        self.end = end
        if kind in ("escape", "ansi_c"):
            self.obfuscated = True
        if kind in ("single", "double") and value == "":
            self.obfuscated = True
        if kind == "unknown":
            self.error = True

    def flush(self, issues: List[ParseIssue]) -> Optional[Word]:
        if self.end <= self.start and not self.parts:
            return None
        raw = self.source[self.start:self.end]
        kinds = [p.kind for p in self.parts]
        if self.error or WORD_ERROR in kinds:
            state, value = WORD_ERROR, None
        elif any(k in OPAQUE_PARTS for k in kinds):
            state, value = WORD_OPAQUE, None
        elif any(k in DYNAMIC_PARTS for k in kinds):
            state, value = WORD_DYNAMIC, None
        else:
            state = WORD_LITERAL
            value = "".join(p.value for p in self.parts)
        return Word(
            raw=raw,
            parts=tuple(self.parts),
            state=state,
            value=value,
            span=_span(self.source, self.start, self.end),
            obfuscated=self.obfuscated,
        )


def lex(source: str, dialect: str = "bash", budget: Optional[Budget] = None) -> LexResult:
    """Tokenize shell source. Never executes anything."""
    budget = budget or Budget()
    limit = len(source)
    issues: List[ParseIssue] = []
    tokens: List[Token] = []

    if dialect not in ("bash", "posix"):
        issues.append(ParseIssue(
            "UNSUPPORTED_DIALECT",
            "unsupported dialect: %s" % dialect,
            "error", _span(source, 0, limit), source[:120],
        ))
        return LexResult(tuple(tokens), tuple(issues), _span(source, 0, limit))

    if not source.strip():
        issues.append(ParseIssue(
            "EMPTY_COMMAND", "no command supplied", "error",
            Span(0, len(source), 1, 1), source[:120],
        ))
        return LexResult(tuple(tokens), tuple(issues), _span(source, 0, limit))

    if len(source.encode("utf-8")) > budget.max_input_bytes:
        issues.append(ParseIssue(
            "INPUT_TOO_LARGE", "input exceeds %d bytes" % budget.max_input_bytes,
            "error", _span(source, 0, limit), source[:120],
        ))
        return LexResult(tuple(tokens), tuple(issues), _span(source, 0, limit))

    for offset, message in _forbidden_chars(source):
        issues.append(ParseIssue(
            "INVISIBLE_CHARACTER", message, "error",
            _span(source, offset, offset + 1), source[offset:offset + 1],
        ))
        break

    i = 0
    builder: Optional[_WordBuilder] = None
    overflow = False

    def flush() -> None:
        nonlocal builder, overflow
        if builder is not None:
            word = builder.flush(issues)
            if word is not None:
                tokens.append(Token("word", word.raw, word.span, word))
                if len(tokens) > budget.max_tokens:
                    issues.append(ParseIssue(
                        "TOKEN_BUDGET", "token budget exceeded", "error",
                        word.span, word.raw[:120],
                    ))
                    overflow = True
            builder = None

    while i < limit:
        if overflow:
            break
        c = source[i]

        if c in (" ", "\t"):
            flush()
            i += 1
            continue

        if c == "\\" and i + 1 < limit and source[i + 1] == "\n":
            flush()
            i += 2
            continue

        if c == "#" and builder is None:
            j = source.find("\n", i)
            j = limit if j < 0 else j
            tokens.append(Token("comment", source[i:j], _span(source, i, j)))
            i = j
            continue

        op = _match_operator(source, i)
        if op is not None:
            flush()
            if op in ("<(", ">("):
                close = _find_closing(source, i + 2, "(", ")", limit)
                end = limit if close < 0 else close + 1
                if close < 0:
                    issues.append(ParseIssue(
                        "UNTERMINATED_SUBSTITUTION",
                        "unterminated process substitution", "error",
                        _span(source, i, limit), source[i:limit][:120],
                    ))
                part = WordPart(
                    "process_substitution", source[i:end], _span(source, i, end)
                )
                word = Word(
                    raw=source[i:end], parts=(part,), state=WORD_OPAQUE,
                    value=None, span=_span(source, i, end),
                )
                tokens.append(Token("word", word.raw, word.span, word))
                if len(tokens) > budget.max_tokens:
                    issues.append(ParseIssue(
                        "TOKEN_BUDGET", "token budget exceeded", "error",
                        word.span, word.raw[:120],
                    ))
                    overflow = True
                i = end
                continue
            tokens.append(Token("operator", op, _span(source, i, i + len(op))))
            i += len(op)
            if len(tokens) > budget.max_tokens:
                issues.append(ParseIssue(
                    "TOKEN_BUDGET", "token budget exceeded", "error",
                    _span(source, i - 1, i), "",
                ))
                break
            continue

        if builder is None:
            builder = _WordBuilder(source, i)

        if c == "'":
            close = source.find("'", i + 1, limit)
            if close < 0:
                builder.add("unknown", source[i + 1:limit], i, limit)
                issues.append(ParseIssue(
                    "UNTERMINATED_QUOTE", "unterminated single quote", "error",
                    _span(source, i, limit), source[i:limit][:120],
                ))
                i = limit
            else:
                builder.add("single", source[i + 1:close], i, close + 1)
                i = close + 1
            continue

        if c == '"':
            close = _find_quote_end(source, i + 1, '"', limit)
            if close < 0:
                builder.add("unknown", source[i + 1:limit], i, limit)
                issues.append(ParseIssue(
                    "UNTERMINATED_QUOTE", "unterminated double quote", "error",
                    _span(source, i, limit), source[i:limit][:120],
                ))
                i = limit
            else:
                inner = source[i + 1:close]
                builder.add("double", _decode_double(inner), i, close + 1)
                if "$(" in inner:
                    builder.add("command_substitution", "$(", i + 1, min(close, i + 3))
                elif "$" in inner:
                    marker = "$" + "{" if "${" in inner else "$"
                    builder.add("variable", marker, i + 1,
                                min(close, i + 1 + len(marker)))
                if "`" in inner:
                    builder.add("backtick", "`", i + 1, min(close, i + 2))
                i = close + 1
            continue

        if source.startswith("$'", i):
            close = source.find("'", i + 2, limit)
            if close < 0:
                builder.add("unknown", source[i + 2:limit], i, limit)
                issues.append(ParseIssue(
                    "UNTERMINATED_QUOTE", "unterminated ANSI-C quote", "error",
                    _span(source, i, limit), source[i:limit][:120],
                ))
                i = limit
            else:
                builder.add("ansi_c", _decode_ansi_c(source[i + 2:close]), i, close + 1)
                i = close + 1
            continue

        if source.startswith("$((", i) or source.startswith("$(", i):
            end = _variable_end(source, i, limit)
            if end >= limit and not source.endswith(")"):
                issues.append(ParseIssue(
                    "UNTERMINATED_SUBSTITUTION", "unterminated command substitution",
                    "error", _span(source, i, limit), source[i:limit][:120],
                ))
            builder.add("command_substitution", source[i:end], i, end)
            i = end
            continue

        if source.startswith("${", i):
            end = _variable_end(source, i, limit)
            raw = source[i:end]
            builder.add("variable", raw, i, end)
            if "IFS" in raw or "!" in raw:
                builder.obfuscated = True
            i = end
            continue

        if c == "`":
            close = source.find("`", i + 1, limit)
            if close < 0:
                builder.add("unknown", source[i + 1:limit], i, limit)
                issues.append(ParseIssue(
                    "UNTERMINATED_BACKTICK", "unterminated backtick substitution",
                    "error", _span(source, i, limit), source[i:limit][:120],
                ))
                i = limit
            else:
                builder.add("backtick", source[i + 1:close], i, close + 1)
                i = close + 1
            continue

        if c == "$":
            end = _variable_end(source, i, limit)
            builder.add("variable", source[i:end], i, end)
            i = end
            continue

        if c == "\\":
            if i + 1 < limit:
                builder.add("escape", source[i + 1], i, i + 2)
                i += 2
            else:
                builder.add("unknown", "\\", i, i + 1)
                i += 1
            continue

        if c == "~":
            builder.add("tilde", "~", i, i + 1)
            i += 1
            continue

        if c in "*?[":
            builder.add("glob", c, i, i + 1)
            i += 1
            continue

        j = i
        while j < limit and source[j] not in " \t\n;|&<>()'\"`$\\~*?[":
            j += 1
        if j == i:
            j = i + 1
        builder.add("literal", source[i:j], i, j)
        i = j

    flush()
    return LexResult(tuple(tokens), tuple(issues), _span(source, 0, limit))
