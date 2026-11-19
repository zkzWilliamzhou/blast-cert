# CONTEXT

Shared language for agents working in this repository. Read `GLOSSARY.md` first.

## One-line model

A Command source becomes a syntax model, becomes assertions plus unknowns, becomes Evidence plus a Decision, becomes a Receipt. Each arrow is a pure function. No arrow runs the command.

## Rules that bind every change

- Unknowns and errors end at `deny`. There is no path from an exception to `allow`.
- The analyzer reads the filesystem. It never writes to it, except an explicit receipt output path.
- Digests cover canonical JSON with sorted keys. Absolute paths and wall-clock values stay out of digests.
- Catalog changes need a positive fixture, a negative fixture, an opaque fixture, and a deletion test.
- A fixture that changes from `deny` to `allow` needs explicit approval in the ledger.
- The tool is an admission check. Runtime enforcement belongs to a sandbox. Do not write copy that says otherwise.

## Module map

| Module | One responsibility |
|---|---|
| `model.py` | Frozen value objects and canonical serialization. |
| `lexer.py` | Shell source to tokens and words with spans. |
| `expand.py` | Bounded, auditable partial expansion. |
| `parser.py` | Tokens to invocations, redirects, pipelines, assignments. |
| `catalog.json` | Declarative command knowledge. |
| `capabilities.py` | Syntax model and catalog to assertions and unknowns. |
| `evidence.py` | Assertions to concrete filesystem findings. |
| `policy.py` | Assertions, unknowns, and Evidence to a Decision. |
| `report.py` | Human and machine rendering. |
| `receipt.py` | Build, verify, diff portable certificates. |
| `cli.py` | Argument parsing and exit codes only. |

## ADRs

- `docs/adr/0001-fail-closed.md`: unknowns and errors deny.
- `docs/adr/0002-no-execution.md`: the analyzer never executes the analyzed string.
- `docs/adr/0003-deterministic-output.md`: no wall clock, no absolute paths in digests.
