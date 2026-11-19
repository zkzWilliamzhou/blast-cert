#!/bin/sh
# Pre-execution admission gate example for blast.
#
# blast never runs the string under analysis. This hook deliberately does not
# run it either: an allow decision is permission to proceed INTO YOUR OWN
# sandbox, not a statement that the command is safe.
#
# Usage:
#   ./examples/hook.sh 'rm -rf ./build'
#   BLAST_ROOT=/path/to/worktree ./examples/hook.sh 'cat report.txt'
#
# Add --policy examples/policy.json to the blast invocation for a stricter gate.

set -u

if [ "$#" -eq 0 ]; then
    echo "usage: hook.sh COMMAND" >&2
    exit 30
fi

ROOT="${BLAST_ROOT:-.}"
COMMAND="$*"

OUTPUT=$(python3 -m blast check "$COMMAND" --root "$ROOT" --format explain 2>&1)
STATUS=$?
printf '%s\n' "$OUTPUT"

case "$STATUS" in
    0)
        echo "gate: allow. Run the command inside your own sandbox." >&2
        exit 0
        ;;
    10)
        echo "gate: confirm. Ask a human, or re-run with --strict." >&2
        exit 10
        ;;
    20)
        echo "gate: deny. Do not run this command." >&2
        exit 20
        ;;
    *)
        echo "gate: error ($STATUS). Do not run this command." >&2
        exit "$STATUS"
        ;;
esac
