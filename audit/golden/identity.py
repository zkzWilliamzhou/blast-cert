"""Record a pre- or post-architecture behavior identity proof.

Compares canonical analysis output for every golden case with the checked-in
baseline. The architecture review may propose deepening opportunities, but it
must not change any function of the program. This script makes that claim
checkable instead of rhetorical.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from blast.api import analyze  # noqa: E402
from blast.model import canonical_text  # noqa: E402

BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
PROOF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "identity-proof.json")
GOLDEN_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "root")


def measure() -> dict:
    with open(BASELINE, "r", encoding="utf-8") as handle:
        baseline = json.load(handle)
    digest = hashlib.sha256()
    mismatches = []
    for item in baseline:
        current = canonical_text(analyze(item["command"], root=GOLDEN_ROOT))
        digest.update(current.encode("utf-8"))
        if current != item["canonical"]:
            mismatches.append(item["command"])
    return {
        "cases": len(baseline),
        "matches": len(baseline) - len(mismatches),
        "mismatches": mismatches,
        "canonical_digest": digest.hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=("pre", "post"), required=True)
    args = parser.parse_args()
    result = measure()

    proof = {
        "purpose": "Behavior identity proof for the improve-codebase-architecture pass",
        "method": "canonical JSON of analyze() compared byte-for-byte with baseline.json",
    }
    if os.path.isfile(PROOF):
        with open(PROOF, "r", encoding="utf-8") as handle:
            proof = json.load(handle)
    proof[args.stage + "_architecture"] = result
    if "pre_architecture" in proof and "post_architecture" in proof:
        pre = proof["pre_architecture"]
        post = proof["post_architecture"]
        proof["behavior_unchanged"] = (
            pre["matches"] == pre["cases"] == post["matches"] == post["cases"]
            and pre["canonical_digest"] == post["canonical_digest"]
        )
        proof["ruling"] = (
            "ACCEPT: no function changed during the architecture pass"
            if proof["behavior_unchanged"] else
            "REJECT: program behavior changed; restore the baseline"
        )
    with open(PROOF, "w", encoding="utf-8") as handle:
        json.dump(proof, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")

    print("%s-architecture: %d/%d byte-identical, digest %s" % (
        args.stage, result["matches"], result["cases"],
        result["canonical_digest"][:12]))
    if result["mismatches"]:
        print("mismatches:", result["mismatches"][:5])
    return 0 if result["matches"] == result["cases"] else 1


if __name__ == "__main__":
    sys.exit(main())
