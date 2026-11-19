# blast audit ledger

The manager runs `python3 audit/run_audit.py --round N --note "..."` for each
round. Every round re-runs its checks with fresh commands and records the
output below. A round with failures is rejected; the code is revised and the
full round runs again. No claim of completion rests on a previous round's
output.

Roles: A7 static reviewer owns rounds 1-4, A8 security reviewer owns rounds
5-8, A10 release reviewer owns round 9. The manager accepts or rejects each
round.

---

## Round 1 — 2026-11-13 18:15:04

Manager note: Baseline gate: compiler, full unittest suite, ruff, built-in selftest and catalog validation. Reject if any gate lacks fresh passing output.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ................................................................................ | ---------------------------------------------------------------------- | Ran 80 tests in 4.070s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 2 — 2026-11-13 18:15:14

Manager note: Added AST scan for execution/network primitives, byte-identical determinism over 53 commands, and receipt clean/tamper/drift proof. Reject if any primitive appears or any byte differs.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ................................................................................ | ---------------------------------------------------------------------- | Ran 80 tests in 3.643s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 3 — 2026-11-13 18:15:23

Manager note: Security reviewer added two adversarial inputs: an empty command and a word-only command beyond the token budget. Reject if either produces allow or lacks a structured parse error.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ................................................................................ | ---------------------------------------------------------------------- | Ran 80 tests in 3.656s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: FAIL — verdict=allow issue=False
- `token_budget`: FAIL — verdict=deny issue=False tokens=0

Findings: empty_command, token_budget

Manager ruling: Reject. Revise the failing parts and re-run this round.

---

## Round 3 — 2026-11-13 18:16:17

Manager note: Revision: lexer now emits EMPTY_COMMAND for blank input and enforces the token budget on word tokens, not only operators. Added two regression tests. Re-running the full round.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 .................................................................................. | ---------------------------------------------------------------------- | Ran 82 tests in 3.692s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 4 — 2026-11-13 18:16:29

Manager note: Security reviewer added CLI failure paths: unwritable -o output and a receipt built for a denied command. Reject if a traceback escapes or a denied receipt exits 0.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 .................................................................................. | ---------------------------------------------------------------------- | Ran 82 tests in 3.693s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: FAIL — exit=1 traceback=True   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: FAIL — exit=0 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }

Findings: output_write_failure, receipt_exit_code

Manager ruling: Reject. Revise the failing parts and re-run this round.

---

## Round 4 — 2026-11-13 19:03:56

Manager note: Revision: check and receipt now catch OSError on -o writes and return EXIT_ERROR without a traceback; receipt returns the verdict exit code instead of always 0. Added three CLI regression tests. Environment restored ruff. Re-running the full round.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ..................................................................................... | ---------------------------------------------------------------------- | Ran 85 tests in 6.188s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: PASS — exit=30 traceback=False   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: PASS — exit=20 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 5 — 2026-11-13 19:04:11

Manager note: Security reviewer added an AST check that no package module catches BaseException, plus a policy-tamper invariant. Reject if an interpreter-level exception is swallowed or a weakened policy is accepted.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ..................................................................................... | ---------------------------------------------------------------------- | Ran 85 tests in 6.953s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: PASS — exit=30 traceback=False   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: PASS — exit=20 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }
- `baseexception`: FAIL — api.py
- `policy_invariant`: PASS — verdict=deny internal=True

Findings: baseexception

Manager ruling: Reject. Revise the failing parts and re-run this round.

---

## Round 5 — 2026-11-13 19:04:53

Manager note: Revision: analyze now catches Exception instead of BaseException, so KeyboardInterrupt and SystemExit propagate while analysis failures still fail closed. Added two exception-boundary regression tests. Re-running the full round.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ....................................................................................... | ---------------------------------------------------------------------- | Ran 87 tests in 7.027s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: PASS — exit=30 traceback=False   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: PASS — exit=20 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }
- `baseexception`: PASS — only Exception is caught
- `policy_invariant`: PASS — verdict=deny internal=True

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 6 — 2026-11-13 19:05:09

Manager note: Security reviewer added a combined evidence-safety check: symlink escape, root=/ hashing, invisible Unicode, unterminated quotes, dynamic paths and subshells. Reject if evidence is read outside root or any opaque input is allowed.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ....................................................................................... | ---------------------------------------------------------------------- | Ran 87 tests in 6.264s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: PASS — exit=30 traceback=False   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: PASS — exit=20 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }
- `baseexception`: PASS — only Exception is caught
- `policy_invariant`: PASS — verdict=deny internal=True
- `evidence_safety`: PASS — symlink_escape=True root_hash=True denied=True issues=True

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 7 — 2026-11-13 19:08:51

Manager note: Release reviewer added README/LICENSE/CHANGELOG/CI/examples. Every documented quickstart command is executed fresh and must produce the output the README claims. Golden baseline captured separately before the architecture pass.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ....................................................................................... | ---------------------------------------------------------------------- | Ran 87 tests in 6.370s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: PASS — exit=30 traceback=False   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: PASS — exit=20 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }
- `baseexception`: PASS — only Exception is caught
- `policy_invariant`: PASS — verdict=deny internal=True
- `evidence_safety`: PASS — symlink_escape=True root_hash=True denied=True issues=True
- `readme`: PASS — missing=[] quickstart_failures=[] commands_documented=True

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 8 — 2026-11-13 19:09:48

Manager note: Optimization review: added stat-keyed catalog/policy cache identity and a 53-analysis throughput budget, on top of every release gate. Reject if a cache returns stale data or the analyzer regresses past 8 seconds.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ....................................................................................... | ---------------------------------------------------------------------- | Ran 87 tests in 6.091s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: PASS — exit=30 traceback=False   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: PASS — exit=20 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }
- `baseexception`: PASS — only Exception is caught
- `policy_invariant`: PASS — verdict=deny internal=True
- `evidence_safety`: PASS — symlink_escape=True root_hash=True denied=True issues=True
- `readme`: PASS — missing=[] quickstart_failures=[] commands_documented=True
- `cache_identity`: PASS — catalog_cached=True policy_cached=True (stat-keyed, no stale mtime)
- `throughput`: PASS — 53 analyses in 0.030s (budget 8.000s)

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---

## Round 9 — 2026-11-13 19:11:53

Manager note: Final release gate. Architecture review proposed deepening opportunities only; pre/post golden proofs are 22/22 byte-identical with the same canonical digest, so no program function changed. All 19 checks re-run fresh, including golden and optimization gates.

Fresh command output (each check re-ran its command in this round):

- `compileall`: PASS — exit=0 (no output)
- `unittest`: PASS — exit=0 ....................................................................................... | ---------------------------------------------------------------------- | Ran 87 tests in 6.130s | OK
- `ruff`: PASS — exit=0 All checks passed!
- `selftest`: PASS — exit=0 57/57 passed   "exit_code": 0, |   "failed": 0, |   "ok": true, |   "passed": 57, |   "total": 57 | }
- `catalog_check`: PASS — exit=0 181 specs, 5 rules   "command_specs": 181, |   "duplicate_rule_ids": [], |   "ok": true, |   "policy_digest": "c3f3d0baeea65b48d5e749841b619bf7fc599720e7b71a0f1794c0460db77331", |   "policy_version": "0.1.0" | }
- `forbidden_imports`: PASS — no execution or network primitives
- `determinism`: PASS — 53 commands byte-identical
- `receipt`: PASS — clean=True tamper_rejected=True drift_detected=True
- `empty_command`: PASS — verdict=deny issue=True
- `token_budget`: PASS — verdict=deny issue=True tokens=1
- `output_write_failure`: PASS — exit=30 traceback=False   "schema_version": 1, |   "status": "analyzed", |   "tool_version": "0.1.0", |   "unknowns": [], |   "verdict": "deny" | }
- `receipt_exit_code`: PASS — exit=20 expected=20   "schema_version": 1, |   "tool": { |     "name": "blast", |     "version": "0.1.0" |   } | }
- `baseexception`: PASS — only Exception is caught
- `policy_invariant`: PASS — verdict=deny internal=True
- `evidence_safety`: PASS — symlink_escape=True root_hash=True denied=True issues=True
- `readme`: PASS — missing=[] quickstart_failures=[] commands_documented=True
- `cache_identity`: PASS — catalog_cached=True policy_cached=True (stat-keyed, no stale mtime)
- `throughput`: PASS — 53 analyses in 0.041s (budget 8.000s)
- `golden`: PASS — 22 golden outputs byte-identical

Findings: none

Manager ruling: Accept. All selected gates produced fresh passing evidence.

---
