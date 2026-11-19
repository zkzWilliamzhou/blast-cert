# Golden outputs

`root/` is a fixed, checked-in filesystem snapshot: four regular files and one
relative symlink. `baseline.json` holds the canonical JSON of `analyze()` for 22
commands against that snapshot, covering `allow`, `confirm`, `deny`, globs,
symlinks, outside-root paths, nested commands, opaque constructs, invisible
Unicode, unterminated quotes, subshells, and empty input.

This baseline is the behavior identity proof required before any architecture
work. The architecture review in `docs/architecture-review.html` proposes
deepening opportunities only; it does not change program behavior. Round 9 of
`audit/run_audit.py` re-runs every case and compares byte-for-byte with
`baseline.json`. Any difference means a function changed and the review is
rejected.

To regenerate after an intentional behavior change (which requires explicit
manager approval in `audit/rounds.md`), run `python3 -m blast selftest` and the
generator used when the baseline was first written. Never regenerate silently.
