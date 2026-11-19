# Workflow, agent roles, and the manager's gates

## What actually ran

Three research subagents ran with isolated contexts and produced files in `docs/research/`. Each had one job, a written brief, and a required artifact:

| Role | Agent | Artifact | Gate |
|---|---|---|---|
| R1 Prior-art scout | dispatched research subagent | `prior-art-scan.md` | Reject if no direct competitors named, or if any repository or star count is invented. |
| R2 Red-team threat modeler | dispatched research subagent | `threat-model.md` | Reject if fewer than 40 concrete command samples, or if it claims zero false negatives are achievable. |
| R3 Standards and architecture researcher | dispatched research subagent | `analyzer-design-principles.md` | Reject if it does not state the boundary of `shlex`, or if it omits fail-closed constraints. |

All three passed on first submission. R1 delivered the finding that changed the product: direction A already has direct competitors. That finding forced the redesign recorded in the design doc. A manager who accepts a report that contradicts the plan and keeps building has failed the job.

The remaining roles are staged review seats in this session, each with its own artifact and its own rejection rule. They are not separate autonomous coding agents; the runtime here provides one research subagent type. Stating that plainly is part of the audit trail.

| Role | Stage | Artifact | Rejection rule |
|---|---|---|---|
| A4 Design and self-grilling | before code | `docs/specs/...-design.md`, this file | Reject if approaches lack tradeoffs, or if novelty is asserted without a boundary. |
| A5 Implementer | build | `blast/*.py` | Reject if any module imports a third-party package, executes a string, or swallows an exception into `allow`. |
| A6 Red-team corpus owner | test | `tests/test_redteam.py`, `tests/corpus.json` | Reject if any of the 48 samples yields `allow`, or if a capability label goes unasserted. |
| A7 Static reviewer | audit rounds 1 to 8 | `audit/rounds.md`, `audit/run_audit.py` | Reject on any failing check. Fix and re-run the full round, not the single test. |
| A8 Security reviewer | audit rounds 5 to 8 | same ledger | Reject on symlink escape, path traversal, budget overrun, invisible Unicode, or digest bypass. |
| A9 Architecture reviewer | after round 8 | `docs/architecture-review.html` | Uses `improve-codebase-architecture` vocabulary. Must prove behavior identity before and after any refactor. |
| A10 Release reviewer | final | `README.md`, `CHANGELOG.md`, CI | Reject if a README command does not produce the output the README shows. |

## Self-grilling rounds

The grilling skill asks the frontier of the design tree in rounds, with a recommended answer for each question. The requester told the manager to grill itself, so the manager answered and recorded each ruling.

**Round 1, frontier: what the product is for.**

- Q1: Does "make a difference" mean saving time, or preventing harm? Recommended: preventing harm at scale. Answer: accepted. Harm prevention drives the safety design and rules out a convenience-only tool.
- Q2: Which harm is growing in 2026 and still structurally open? Recommended: agents acting with real credentials, with no concrete pre-execution evidence. Answer: accepted, with the qualification that R1 found the admission-gate category crowded.
- Q3: What counts as success? Recommended: a verifiable artifact a human or CI can refuse, not a star count. Answer: accepted. R1 confirmed stars are not engineerable.

**Round 2, frontier unlocked by Round 1: where the gap sits.**

- Q4: Should we build a fourth danger detector? Recommended: no. Answer: rejected as an approach. R1 named five direct competitors.
- Q5: Is a runtime wrapper with undo viable? Recommended: no. Answer: rejected. Portability, friction, and the unsafe execution surface.
- Q6: Does any competitor bind static intent to the concrete files on the target machine and let a third party verify it offline? Recommended: no, within the scanned set; state the boundary. Answer: accepted. This became the product.
- Q7: Do we claim absolute novelty? Recommended: no. Answer: accepted. We claim a composition and publish the prior art list.

**Round 3, frontier unlocked by Round 2: safety semantics.**

- Q8: What does sound mean here? Recommended: a conservative superset, with unknowns blocking `allow`. Answer: accepted. R3 supplied the definition.
- Q9: What happens on a parse error or an internal exception? Recommended: structured `deny`, never a printed warning. Answer: accepted.
- Q10: Do we decode base64 payloads to inspect them? Recommended: no. Answer: accepted. R2 showed decoding creates false safety. We flag the structure and mark it opaque.
- Q11: Do we normalize invisible Unicode before analysis? Recommended: no, reject it. Answer: accepted. R2 ranked this among the five hardest false-negative sources.

**Round 4, frontier unlocked by Round 3: delivery.**

- Q12: JSON or TOML for catalog and policy? Recommended: JSON, because the runtime is Python 3.10. Answer: accepted.
- Q13: Timestamps in receipts? Recommended: none. Answer: accepted. Determinism is testable.
- Q14: Minimum Python? Recommended: 3.8. Answer: accepted.
- Q15: Do we need a human approval pause before code? Recommended: no, the requester delegated it. Answer: accepted, recorded in the design doc.

Frontier empty. Every branch has a recorded answer. No silent assumptions remain.

## Manager rules

1. No stage advances while its gate has an open finding. The agent revises its part; the manager re-runs the whole gate.
2. Evidence beats reports. A claim that tests pass needs fresh command output in the same round.
3. A report that contradicts the plan changes the plan. It does not get filed and ignored.
4. Any change to program behavior during the architecture pass requires a golden-output diff showing no difference. The requester forbade changing program function.
5. Every round writes what it found and what it fixed. A round with no findings still records the command and its output.
6. No invented results, no invented repositories, no invented star counts, no invented test passes.
