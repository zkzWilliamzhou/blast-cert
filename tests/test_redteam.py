import json
import os
import tempfile
import unittest

from blast.api import analyze

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "tests", "corpus.json")


class RedTeamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CORPUS, "r", encoding="utf-8") as handle:
            cls.corpus = json.load(handle)
        cls.root = tempfile.mkdtemp(prefix="blast-redteam-")

    def test_corpus_has_48_labeled_samples(self):
        self.assertEqual(len(self.corpus), 48)
        self.assertEqual(len({e["id"] for e in self.corpus}), 48)
        for entry in self.corpus:
            self.assertTrue(entry["command"])
            self.assertTrue(entry["expect_capabilities"])

    def test_every_sample_is_gated_and_labelled(self):
        failures = []
        for entry in self.corpus:
            result = analyze(entry["command"], root=self.root)
            caps = set(a.capability for a in result.assertions)
            expected = set(entry["expect_capabilities"])
            if result.verdict == "allow":
                failures.append("%d: unexpected allow" % entry["id"])
            missing = expected - caps
            if missing:
                failures.append("%d: missing %s" % (entry["id"], sorted(missing)))
            if any(i.code == "INTERNAL_ERROR" for i in result.parse_issues):
                failures.append("%d: internal error" % entry["id"])
        self.assertEqual(failures, [])

    def test_dynamic_samples_carry_unknowns(self):
        dynamic_ids = (2, 3, 12, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                       30, 31, 32, 33, 34, 37, 40, 46)
        for entry in self.corpus:
            if entry["id"] not in dynamic_ids:
                continue
            result = analyze(entry["command"], root=self.root)
            self.assertTrue(result.unknowns, "sample %d lost its unknowns"
                            % entry["id"])

    def test_benign_controls_are_allowed(self):
        controls = ["ls -la", "pwd", "true", "git status", "echo hello"]
        for command in controls:
            result = analyze(command, root=self.root)
            self.assertEqual(result.verdict, "allow", command)
            self.assertFalse(result.unknowns, command)

    def test_no_receipt_or_report_claims_safety(self):
        result = analyze("rm -rf /", root=self.root)
        text = result.reasons + tuple(a.reason for a in result.assertions)
        self.assertFalse(any("safe" in t.lower() for t in text))


if __name__ == "__main__":
    unittest.main()
