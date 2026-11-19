# Changelog

All notable changes to `blast` are recorded here. Format follows Keep a Changelog.

## 0.1.0 — 2026-11-13

Initial release. Offline, filesystem-grounded pre-execution impact certificates
for shell commands.

### Added

- Pure analysis pipeline: `lexer` -> `parser` -> `expand` -> `nested` ->
  `capabilities` -> `evidence` -> `policy` -> `report` / `receipt`.
- Fail-closed `Decision`: `allow`, `confirm`, `deny`; unknown, opaque, error,
  truncated, and sensitive inputs always deny.
- Declarative catalog of 181 command specs with 5 targeted arg rules, generated
  by `tools/build_catalog.py` and validated by `catalog-check`.
- Read-only Evidence resolution with symlink-escape, root=`/`, glob, size, and
  file-count budgets; partial hashes are marked `file_partial`.
- Portable Receipt with `build`, `verify`, and `diff`; tamper and drift detection.
- CLI: `check`, `explain`, `receipt`, `verify`, `diff`, `selftest`,
  `catalog-check`; stable exit codes 0 / 10 / 20 / 30 / 2.
- 48 labeled red-team samples, 87 unit and integration tests, deletion tests for
  every catalog rule, and a nine-round audit ledger in `audit/rounds.md`.
- Golden-output baseline in `audit/golden/` used as the behavior identity proof
  for the architecture review.
- Documentation: README, CONTEXT, GLOSSARY, plan, design spec, prior-art scan,
  threat model, analyzer design principles, three ADRs, workflow, and
  `docs/architecture-review.html`.

### Fixed during audit

- Round 3: blank input produced `allow`; word-only input bypassed the token
  budget. The lexer now emits `EMPTY_COMMAND` and enforces the budget on every
  token kind.
- Round 4: an unwritable `-o` path emitted a traceback; `receipt` always exited
  0 even for a denied command. Both handlers now catch `OSError` and `receipt`
  returns the verdict exit code.
- Round 5: `analyze` caught `BaseException`, swallowing `KeyboardInterrupt` and
  `SystemExit`. It now catches `Exception`: analysis failures still fail closed,
  interpreter-level interrupts propagate.
- Architecture pass: no behavior changed. Golden outputs before and after the
  review are byte-identical (round 9).

### Known limitations

- The analyzed language is a documented Bash/POSIX subset, not a complete shell
  implementation. Unsupported constructs are rejected rather than guessed.
- `allow` is an admission decision, not a safety proof. Runtime enforcement
  belongs to a sandbox.
- Receipts prove evidence at analysis time; they do not prevent TOCTOU changes
  between check and execution.
