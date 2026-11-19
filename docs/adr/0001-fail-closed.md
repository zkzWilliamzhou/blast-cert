# ADR 0001: unknowns and errors deny

Status: accepted

## Context

`blast` is an admission check. A caller that receives `allow` will run the command. An analyzer that cannot determine a command name, a path, a redirect target, or the content of a substituted string must not produce `allow`, because "no dangerous rule matched" is not a safety proof.

## Decision

`AnalysisResult.status` is one of `analyzed`, `opaque`, `error`. Every parse error at level `error`, every `Unknown`, and every internal exception sets `verdict = deny`. A printed warning never substitutes for a structured decision. `opaque` and `error` are distinct so reports can say why the gate closed.

## Consequences

Legitimate dynamic commands require an explicit policy exception or a human confirmation path. That friction is the intended cost. Tests must include at least one case where an exception is raised inside the pipeline and the result is still a structured `deny`.
