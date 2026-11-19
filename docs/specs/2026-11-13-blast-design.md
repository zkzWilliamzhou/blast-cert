# blast: design document

Date: 2026-11-13
Status: approved by delegation (see "Approval" below)
Owner: the manager agent

## Intent and why

You paste a command into a terminal. An AI coding agent suggested it, or a README did, or a colleague sent it. You want to know what it will change on your machine before you press enter. Today you can ask a syntax explainer what the flags mean, or a linter whether the script has bugs. Neither one tells you which of your files it will delete.

`blast` answers a narrower question with evidence: given a shell command string and a directory, enumerate the concrete filesystem objects that the command would affect, bind them to a capability manifest, and emit a portable certificate that anyone can verify offline later. It never runs the command. It reads the directory in read-only mode.

The why: coding agents now hold real credentials. Public incidents from 2025 and 2026 include agents deleting production databases and cloud volumes. A pre-execution gate that shows "this deletes 1,247 files, 3.2 GB, including `~/.ssh/id_ed25519` and a git repo with uncommitted changes" gives a human or a policy engine something to refuse. A score out of 100 gives them nothing to check. Prior research for this project is in `docs/research/`.

## Novelty claim, stated with its boundary

Three research agents scanned prior art. Direction A (pre-execution command analysis) has direct competitors: `command_shield`, `ursh`, `gate.cat`, `TrustShell`, `Aegis`. A plain "detect dangerous commands and return a verdict" would repeat existing work and would fail the requirement that the function not exist already. See `docs/research/prior-art-scan.md`.

The function this project claims as new is a **filesystem-grounded, verifiable pre-execution impact certificate**:

1. Concrete enumeration. The tool resolves static path operands and globs against the real directory tree and reports the matched files, their sizes, and their hashes. It marks sensitive paths and git work trees. Existing analyzers output abstract capabilities such as `FS_DELETE`; they do not output the affected objects on the target machine.
2. Binding. A single document binds the exact command text, the capability manifest with source spans, the concrete evidence set, the catalog digest, the policy digest, and the verdict under one SHA-256 digest.
3. Offline verification. `blast verify` re-resolves the certificate against the current directory and reports drift. `blast diff` compares two certificates. No server, account, key, or network call takes part.

No tool in the scanned set ships this combination. That is a claim about a composition, not a claim that no adjacent tool exists. We do not assert absolute worldwide novelty, since we cannot prove a negative. The README carries the same boundary.

On stars: 105,000 GitHub stars is an external outcome, not an engineering deliverable. Install friction, first-output time, JSON schema, hook integration, accuracy reports, license, and CI are controllable. News cycles, platform traffic, and social spread are not. We build for the former and report the latter as an observation, never a promise. See `docs/research/prior-art-scan.md` section "105k stars".

## Goals

- Parse a declared shell dialect (bash or POSIX sh) into commands, redirects, pipelines, assignments, and words with source spans, without executing anything.
- Produce a conservative capability manifest. Every possible call, write, delete, execution, network fetch, and substitution either appears as an assertion or appears in `unknowns`.
- Fail closed. Parse errors, dynamic command names, command substitution, `eval`, `source`, external scripts, unknown commands, invisible Unicode, and any internal exception produce `deny`, never `allow`.
- Resolve literal and glob path operands against a read-only root and report matched objects with a hard resource budget.
- Emit deterministic JSON. Same input, same root, same catalog, same policy produces byte-identical output.
- Emit a portable receipt with a digest, plus `verify` and `diff` commands.
- Ship with zero runtime dependencies on Python 3.8 or newer.

## Non-goals

- Executing, sandboxing, or rolling back commands. `blast` is an admission check. Runtime enforcement belongs to Landlock, seccomp, AppArmor, or a container.
- Full bash semantics. We model a declared subset and mark everything outside it as opaque.
- Predicting runtime values of variables, aliases, functions, PATH, sudo policy, symlink targets, or remote script contents.
- Virus scanning, secret scanning, or malware classification.
- A daemon, a server, an account system, or telemetry.

## Anti-goals

- A verdict of `allow` on any input containing an unknown or an error.
- A risk score as the primary output. Scores hide the evidence.
- Silent unicode normalization, silent partial expansion, or swallowing an exception and continuing.
- Any network call from the analyzer.
- Documentation that claims the tool makes commands safe.

## Constraints

- Python standard library only. `tomllib` is 3.11+, so catalog and policy ship as JSON.
- No `eval`, `exec`, `os.system`, `subprocess`, `shell=True`, or third-party imports in the analyzer path.
- `shlex` may tokenize only. Command substitution, redirects, pipelines, and parameter semantics come from the project's own syntax model.
- Read-only filesystem access. No writes outside an explicit `-o` receipt path.
- Hard budgets: 20,000 input bytes, 4,096 tokens, 2,000 matched files, 64 directory levels, 1 second of path enumeration work.
- Deterministic serialization: sorted keys, UTF-8, no NaN, no wall clock, no absolute paths inside digests.
- Every assertion carries a source span, a rule id, and a reason.
- Exit codes are stable: 0 allow, 10 confirm, 20 deny, 30 internal error.

## Approaches considered

**Approach 1: another static danger detector.** Build a rule table, output ALLOW/REVIEW/DENY. Cheapest to implement, easiest to demo. Rejected. Three separate research agents found direct competitors shipping exactly this. It fails the novelty requirement and adds a fourth near-identical tool.

**Approach 2: a runtime wrapper with copy-on-write and undo.** Wrap every command in an overlay, record actual effects, and roll back. Strong value and a clean story. Rejected. It needs kernel features or a compiled preload shim, breaks portability, changes how users run every command, and introduces the exact unsafe execution surface this project should avoid. High adoption friction would also hurt the star goal.

**Approach 3: read-only, filesystem-grounded impact certificate.** Parse statically, resolve path operands against the real tree, bind the result into a verifiable receipt, gate with a policy. Chosen. It keeps zero adoption friction (`blast check 'cmd'` produces output in under a second), it adds a function the scanned competitors lack, and it stays inside a pure, offline, testable core. Its cost is a narrower claim: the certificate describes static intent against a directory snapshot, not runtime truth. We state that cost in the README and in every receipt.

## Decisions made in this document

These are manager rulings. The requester delegated all design decisions to the manager and asked for work to continue until done, so no question round went to the human partner.

- Ruling 1: language is Python 3.8+ standard library. Reason: zero install friction and full test coverage without a package registry. Cost if wrong: slower path enumeration on huge trees, bounded by the file budget.
- Ruling 2: catalog and policy are JSON, not TOML. Reason: Python 3.10 runtime here has no `tomllib`. Cost if wrong: less pleasant hand editing.
- Ruling 3: default verdict denies unknowns. Reason: the product is an admission gate. Cost if wrong: more confirmations for legitimate dynamic commands, which is the correct failure direction.
- Ruling 4: no execution, ever, including in tests of the analyzer. Tests build directories and read them; they never run untrusted command strings.
- Ruling 5: receipts carry no timestamp. Reason: byte-identical output is a testable property and a stronger guarantee than a human-readable date.
- Ruling 6: the tool reports drift on `verify` rather than claiming the receipt is still valid. Reason: directory state changes.

## What is left to the builder

Exact module boundaries, catalog rule ids, policy defaults, CLI flag names, and the test corpus layout live in the implementation plan. The spec fixes the invariants; the plan fixes the interfaces.

## Approval

The requester wrote "brainstorming deep-thinking and grilling yourself", "you are the boss", and "start working until the work is done". That waives the human approval gate in the brainstorming workflow and hands the design tree to the manager. The self-grilling rounds, the rulings above, and the rejection record are in `docs/WORKFLOW.md`. No product code existed before this document was written.
