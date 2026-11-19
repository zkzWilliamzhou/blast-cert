import os
import tempfile
import unittest

from blast.api import analyze
from blast.model import Budget


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="blast-ev-")
        self.outside = tempfile.mkdtemp(prefix="blast-out-")
        with open(os.path.join(self.outside, "secret.txt"), "w", encoding="utf-8") as f:
            f.write("SECRET")
        with open(os.path.join(self.root, "a.txt"), "w", encoding="utf-8") as f:
            f.write("hello\n")
        with open(os.path.join(self.root, "b.log"), "w", encoding="utf-8") as f:
            f.write("log\n")
        os.mkdir(os.path.join(self.root, ".git"))
        os.symlink(os.path.join(self.outside, "secret.txt"),
                   os.path.join(self.root, "link"))

    def test_literal_file_is_enumerated(self):
        result = analyze("cat a.txt", root=self.root)
        paths = [f.path for f in result.evidence.findings]
        self.assertIn("a.txt", paths)
        self.assertTrue(any(f.in_git_worktree for f in result.evidence.findings))

    def test_glob_is_enumerated(self):
        result = analyze("cat *.log", root=self.root)
        self.assertIn("b.log", [f.path for f in result.evidence.findings])

    def test_symlink_escape_is_not_read(self):
        result = analyze("cat link", root=self.root)
        self.assertTrue(any(f.outside_root for f in result.evidence.findings))
        hashes = [f.sha256 for f in result.evidence.findings if f.sha256]
        self.assertEqual(hashes, [])

    def test_parent_traversal_is_outside_root(self):
        result = analyze("cat ../secret.txt", root=self.root)
        self.assertTrue(any(f.outside_root for f in result.evidence.findings))

    def test_root_filesystem_does_not_hash_etc_passwd(self):
        if os.name != "posix":
            self.skipTest("POSIX only")
        result = analyze("cat /etc/passwd", root="/")
        self.assertFalse(any(f.path == "/etc/passwd" and f.sha256
                             for f in result.evidence.findings))
        self.assertTrue(any(f.outside_root for f in result.evidence.findings))

    def test_budget_truncation_is_deterministic_and_denies(self):
        for index in range(20):
            with open(os.path.join(self.root, "f%02d.txt" % index), "w",
                      encoding="utf-8") as f:
                f.write("x")
        first = analyze("rm -rf *", root=self.root,
                        budget=Budget(max_files=5))
        second = analyze("rm -rf *", root=self.root,
                         budget=Budget(max_files=5))
        self.assertTrue(first.evidence.truncated)
        self.assertEqual(first.evidence.digest, second.evidence.digest)
        self.assertEqual(first.verdict, "deny")

    def test_dynamic_path_is_never_half_expanded(self):
        result = analyze("rm -rf $TARGET/*", root=self.root)
        self.assertTrue(any(u.kind == "DYNAMIC_OPERAND" for u in result.unknowns))
        self.assertEqual(result.verdict, "deny")

    def test_large_file_is_marked_partial(self):
        big = os.path.join(self.root, "big.bin")
        with open(big, "wb") as f:
            f.write(b"x" * 2048)
        result = analyze("cat big.bin", root=self.root,
                         budget=Budget(max_hash_bytes=64))
        kinds = [f.kind for f in result.evidence.findings]
        self.assertIn("file_partial", kinds)


if __name__ == "__main__":
    unittest.main()
