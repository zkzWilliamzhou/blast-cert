# blast Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `blast`, a zero-dependency offline CLI that turns a shell command into a filesystem-grounded, verifiable pre-execution impact certificate with a fail-closed policy verdict.

**Architecture:** A staged pure pipeline: custom lexer with spans, syntax model of words/commands/redirects/pipelines, declarative command catalog, capability evaluator, read-only filesystem evidence resolver, pure policy engine, deterministic reporters and receipt builder. The analyzer never executes a string and never touches the network.

**Tech Stack:** Python 3.8+ standard library only, `unittest`, `json`, `hashlib`, `argparse`, `dataclasses`, `pathlib`, `unicodedata`, `fnmatch`.

**Spec:** `docs/specs/2026-11-13-blast-design.md`

## Global Constraints

- Zero third-party runtime imports in `blast/`.
- No `eval`, `exec`, `os.system`, `subprocess`, `shell=True`, or network imports in the analyzer path.
- Parse errors, unknowns, opaque constructs, and internal exceptions produce `verdict=deny` and structured output.
- Every assertion carries a source span, a rule id, and a reason.
- Deterministic JSON: sorted keys, UTF-8, no NaN, no wall clock, no absolute paths inside digests.
- Budgets: 20,000 input bytes, 4,096 tokens, 2,000 matched files, 64 directory levels.
- Exit codes: 0 allow, 10 confirm, 20 deny, 30 internal error.
- Read-only filesystem access except an explicit `-o` receipt path.
- Supported dialects: `bash`, `posix`. Anything else is an error.
- No product behavior change during the architecture pass; prove it with golden output diffs.

## Review Focus

1. Unclosed quotes and unterminated command substitution: expect `deny` with a structured parse error, never a partial `allow`.
2. A path operand containing `$VAR` or `$(...)`: expect `scope=dynamic`, an unknown, and `deny`.
3. A symlink inside the root that points outside it: expect no enumeration of the target, a sensitive flag, and `deny`.
4. Invisible Unicode, CR, NUL, and homoglyphs in a command name: expect a structured rejection, not silent normalization.
5. A tampered receipt: expect `verify` to report digest mismatch and exit nonzero.
6. A catalog rule removed while its positive fixture stays: expect the deletion test to fail.
7. Oversized input or a glob matching more than the file budget: expect a truncated, deterministic report and `deny`.
8. Same input analyzed twice: expect byte-identical JSON.

---

### Task 1: Value objects and catalog

**Files:**
- Create: `blast/model.py`
- Create: `blast/catalog.json`
- Test: `tests/test_model.py`

**Interfaces:**
- Produces: `Span(start:int,end:int,line:int,col:int)`, `WordPart(kind:str,value:str,span:Span)`, `Word(raw:str,parts:tuple,state:str,value:Optional[str],span:Span)`, `Token`, `Redirect`, `SimpleCommand`, `Pipeline`, `Assertion(capability,action,object,object_kind,scope,confidence,evidence,rule_id,reason)`, `Unknown`, `AnalysisResult`, `FsFinding`. All frozen dataclasses.

- [ ] Step 1: Write failing tests for frozen value objects, JSON round trip, and catalog schema validation (duplicate ids, unknown fields).
- [ ] Step 2: Run `python3 -m unittest tests.test_model -v`, expect import failure.
- [ ] Step 3: Implement `model.py` and `catalog.json` with a versioned schema and 60 command specs.
- [ ] Step 4: Run the tests, expect pass.
- [ ] Step 5: Commit.

### Task 2: Lexer

**Files:**
- Create: `blast/lexer.py`
- Test: `tests/test_lexer.py`

**Interfaces:**
- Consumes: `Span`, `Token`, `WordPart`, `Word` from Task 1.
- Produces: `lex(source:str, dialect:str) -> LexResult(tokens, words, errors)`.

- [ ] Step 1: Write failing tests for quotes, escapes, operators, `;`, `&&`, `||`, `|`, `&`, redirects, `$(...)`, backticks, `$'...'`, comments, line continuation, unclosed quote, invisible Unicode, CR, NUL.
- [ ] Step 2: Run, expect failure.
- [ ] Step 3: Implement `lexer.py` with explicit spans and a token budget.
- [ ] Step 4: Run, expect pass.
- [ ] Step 5: Commit.

### Task 3: Syntax model and bounded expansion

**Files:**
- Create: `blast/parser.py`
- Create: `blast/expand.py`
- Test: `tests/test_parser.py`

**Interfaces:**
- Consumes: `LexResult`.
- Produces: `parse(source:str, dialect:str) -> SyntaxModel(pipelines, assignments, errors)`, `expand_word(word:Word, trusted_env:dict) -> Word`.

- [ ] Step 1: Write failing tests for pipelines, redirect targets, assignments, `--`, background, dynamic command names, and half-expansion refusal.
- [ ] Step 2: Run, expect failure.
- [ ] Step 3: Implement both modules.
- [ ] Step 4: Run, expect pass.
- [ ] Step 5: Commit.

### Task 4: Capability evaluator

**Files:**
- Create: `blast/capabilities.py`
- Test: `tests/test_capabilities.py`

**Interfaces:**
- Consumes: `SyntaxModel`, `catalog`.
- Produces: `evaluate(model, catalog) -> EvalResult(assertions, unknowns, status)`.

- [ ] Step 1: Write failing tests for each capability family, `curl|sh`, `base64 -d|sh`, `sudo`, `eval`, `source`, unknown command, and every rule's positive and negative fixture.
- [ ] Step 2: Run, expect failure.
- [ ] Step 3: Implement catalog-driven evaluation plus syntax-derived assertions for redirects, pipelines, assignments, and interpreters.
- [ ] Step 4: Run, expect pass.
- [ ] Step 5: Commit.

### Task 5: Read-only filesystem evidence

**Files:**
- Create: `blast/evidence.py`
- Test: `tests/test_evidence.py`

**Interfaces:**
- Consumes: `EvalResult`.
- Produces: `resolve(assertions, root:Path, budget:Budget) -> EvidenceReport(findings, total_bytes, truncated, digest)`.

- [ ] Step 1: Write failing tests for literal files, globs, `~`, `..`, symlink escapes, sensitive paths, git work trees, budget truncation, and determinism.
- [ ] Step 2: Run, expect failure.
- [ ] Step 3: Implement `evidence.py` with pure path computation and read-only enumeration.
- [ ] Step 4: Run, expect pass.
- [ ] Step 5: Commit.

### Task 6: Policy and verdict

**Files:**
- Create: `blast/policy.json`, `blast/policy.py`
- Test: `tests/test_policy.py`

**Interfaces:**
- Consumes: `EvalResult`, `EvidenceReport`.
- Produces: `decide(eval_result, evidence, policy) -> Decision(verdict, reasons, exit_code)`.

- [ ] Step 1: Write failing tests for default deny, deny precedence, unknown handling, error handling, sensitive-path escalation, and strict mode.
- [ ] Step 2: Run, expect failure.
- [ ] Step 3: Implement a pure decision function.
- [ ] Step 4: Run, expect pass.
- [ ] Step 5: Commit.

### Task 7: Reports, receipts, CLI

**Files:**
- Create: `blast/report.py`, `blast/receipt.py`, `blast/cli.py`, `blast/__init__.py`, `blast/__main__.py`, `pyproject.toml`, `blast` launcher
- Test: `tests/test_receipt.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: all prior modules.
- Produces: `check`, `explain`, `receipt`, `verify`, `diff`, `selftest`, `catalog-check` subcommands with stable exit codes.

- [ ] Step 1: Write failing tests for deterministic JSON, receipt digest, tamper detection, drift detection, diff, and CLI exit codes.
- [ ] Step 2: Run, expect failure.
- [ ] Step 3: Implement all modules and the launcher.
- [ ] Step 4: Run, expect pass.
- [ ] Step 5: Commit.

### Task 8: Red-team corpus and deletion tests

**Files:**
- Create: `tests/corpus.json`, `tests/test_redteam.py`, `tests/test_deletion.py`, `examples/`
- Test: `tests/test_redteam.py`

**Interfaces:**
- Consumes: the public `analyze` entry point.
- Produces: 48 labeled samples from `docs/research/threat-model.md` plus benign controls; per-rule deletion tests.

- [ ] Step 1: Write the corpus with expected capabilities and a forbidden `allow` verdict.
- [ ] Step 2: Run, expect failure.
- [ ] Step 3: Implement tests and fix the analyzer until every sample passes.
- [ ] Step 4: Run, expect pass.
- [ ] Step 5: Commit.

### Task 9: Audit rounds 1 to 8

**Files:**
- Create: `audit/run_audit.py`, `audit/rounds.md`
- Test: `audit/run_audit.py`

**Interfaces:**
- Consumes: the whole package.
- Produces: eight or more recorded rounds with fresh command output, findings, fixes, and re-runs.

- [ ] Step 1: Implement the audit driver with ten mechanical checks.
- [ ] Step 2: Run each round, record output.
- [ ] Step 3: Fix each finding and re-run the full round.
- [ ] Step 4: Commit.

### Task 10: Architecture pass with behavior lock

**Files:**
- Create: `GLOSSARY.md`, `CONTEXT.md`, `docs/adr/0001-fail-closed.md`, `docs/architecture-review.html`, `audit/golden/`
- Test: `tests/test_golden.py`

**Interfaces:**
- Consumes: the built package.
- Produces: an HTML review using the `improve-codebase-architecture` vocabulary, one deepening refactor, and a golden-output equality proof.

- [ ] Step 1: Freeze golden JSON for a 40-command corpus before refactoring.
- [ ] Step 2: Write the HTML report with ranked candidates and before/after diagrams.
- [ ] Step 3: Apply one refactor that changes no interface behavior.
- [ ] Step 4: Re-run golden comparison, expect byte-identical output.
- [ ] Step 5: Commit.

### Task 11: Release material

**Files:**
- Create: `README.md`, `LICENSE`, `CHANGELOG.md`, `.github/workflows/ci.yml`, `examples/hook.sh`, `examples/policy.json`
- Test: `tests/test_readme.py`

**Interfaces:**
- Consumes: the CLI.
- Produces: a README whose every quickstart command is executed in a test and compared to the documented output.

- [ ] Step 1: Write README with prior art, limits, install, quickstart, JSON schema, hook integration, and honest star framing.
- [ ] Step 2: Write CI and examples.
- [ ] Step 3: Run the README verification test.
- [ ] Step 4: Commit.

## Self-review

Spec coverage: design doc sections map to Tasks 1-8 (invariants), 9 (audit), 10 (architecture), 11 (release). Step scan: each step names one action with a checkable result. Type consistency: interfaces are named once in the producing task and consumed by name later. Review Focus: all eight items have owning tasks (1, 2, 5, 6, 7, 8, 9, 11). Proportion: the plan names signatures and assertions, not bodies.
