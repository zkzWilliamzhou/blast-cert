# ADR 0003: deterministic output and digest scope

Status: accepted

## Context

Receipts are portable certificates. If the same command against the same directory produced different bytes on two machines, `verify` and `diff` would be meaningless. Absolute paths and wall-clock values are machine-specific.

## Decision

Canonical JSON uses sorted keys, UTF-8, compact separators, and rejects NaN. Digests cover only relative paths, file sizes, kinds, hashes, assertions, unknowns, catalog digest, policy digest, and the command source hash. No timestamp and no absolute path enters a digest. Human text output may show the root path; the digest excludes it.

## Consequences

Receipts have no human-readable creation date. Drift detection compares filesystem state, not time. A test asserts byte-identical JSON across two independent runs.
