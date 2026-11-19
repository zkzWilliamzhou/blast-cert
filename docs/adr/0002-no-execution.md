# ADR 0002: the analyzer never executes the analyzed string

Status: accepted

## Context

Executing a command to discover its effects would destroy the tool's purpose and would turn an admission check into an attack surface. Expanding `$(...)` or decoding a base64 payload would produce a false sense of certainty.

## Decision

No module in `blast/` imports `subprocess`, calls `os.system`, calls `eval` or `exec`, or constructs a shell. The lexer and parser build a model from text. The evidence resolver reads the filesystem in read-only mode. Payload decoders are flagged as opaque structures and never invoked.

## Consequences

The tool cannot know the content of a remote script, a variable's value, an alias, a function body, or a symlink target outside the root. Those limits appear in the README and in each receipt. Runtime enforcement remains the job of a sandbox.
