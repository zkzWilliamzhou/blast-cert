"""Bounded, auditable partial expansion.

Only values explicitly supplied by the caller are substituted. An unknown
variable never becomes a guessed path or a guessed command name.
"""
from __future__ import annotations

import re
from typing import Dict, Optional

from .model import WORD_DYNAMIC, WORD_LITERAL, Word, WordPart

_VAR_NAME = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")


def _variable_name(value: str) -> Optional[str]:
    match = _VAR_NAME.match(value)
    return match.group(1) if match else None


def expand_word(
    word: Word,
    trusted_env: Optional[Dict[str, str]] = None,
    trusted_home: Optional[str] = None,
) -> Word:
    """Resolve a dynamic word only when every dynamic part has trusted data."""
    if word.state != WORD_DYNAMIC:
        return word

    env: Dict[str, str] = dict(trusted_env or {})
    if trusted_home is not None:
        env["HOME"] = trusted_home

    parts = []
    used_trusted = False
    for part in word.parts:
        if part.kind == "variable":
            name = _variable_name(part.value)
            if name is not None and name in env:
                parts.append(WordPart("literal", env[name], part.span))
                used_trusted = True
            else:
                return word
        elif part.kind == "tilde":
            if "HOME" in env:
                parts.append(WordPart("literal", env["HOME"], part.span))
                used_trusted = True
            else:
                return word
        elif part.kind == "unknown":
            return word
        else:
            parts.append(part)

    value = "".join(p.value for p in parts)
    return Word(
        raw=word.raw,
        parts=tuple(parts),
        state=WORD_LITERAL,
        value=value,
        span=word.span,
        obfuscated=word.obfuscated,
        provenance="trusted-env" if used_trusted else "",
    )
