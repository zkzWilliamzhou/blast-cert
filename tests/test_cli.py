import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        return subprocess.run(
            [sys.executable, "-m", "blast"] + list(args),
            cwd=ROOT, input=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True, timeout=60,
        )

    def test_explain_never_claims_safety(self):
        proc = self.run_cli("explain", "rm -rf /", "--root", tempfile.mkdtemp())
        self.assertIn("did not run this command", proc.stdout)
        self.assertIn("Use a sandbox", proc.stdout)
        self.assertEqual(proc.returncode, 20)

    def test_strict_upgrades_confirm_to_deny(self):
        root = tempfile.mkdtemp()
        normal = self.run_cli("check", "echo hi > out.txt", "--root", root,
                              "--format", "json")
        strict = self.run_cli("check", "echo hi > out.txt", "--root", root,
                              "--format", "json", "--strict")
        self.assertEqual(normal.returncode, 10)
        self.assertEqual(strict.returncode, 20)

    def test_stdin_command(self):
        proc = self.run_cli("check", "--format", "json",
                            stdin="rm -rf /\n")
        self.assertEqual(proc.returncode, 20)

    def test_unsupported_dialect_denies(self):
        proc = self.run_cli("check", "ls", "--dialect", "fish")
        self.assertEqual(proc.returncode, 2)

    def test_invisible_unicode_is_rejected(self):
        proc = self.run_cli("check", "echo\u200bhi", "--format", "json")
        self.assertEqual(proc.returncode, 20)

    def test_unwritable_output_fails_cleanly(self):
        bad = os.path.join(tempfile.mkdtemp(), "missing", "receipt.json")
        proc = self.run_cli("check", "rm -rf /", "--root", tempfile.mkdtemp(),
                            "-o", bad, "--format", "json")
        self.assertEqual(proc.returncode, 30)
        self.assertNotIn("Traceback", proc.stdout)

    def test_denied_receipt_exits_deny(self):
        proc = self.run_cli("receipt", "rm -rf /", "--root", tempfile.mkdtemp())
        self.assertEqual(proc.returncode, 20)
        self.assertIn("verdict", proc.stdout)

    def test_receipt_write_failure_fails_cleanly(self):
        bad = os.path.join(tempfile.mkdtemp(), "missing", "receipt.json")
        proc = self.run_cli("receipt", "cat a.txt", "--root", tempfile.mkdtemp(),
                            "-o", bad)
        self.assertEqual(proc.returncode, 30)
        self.assertNotIn("Traceback", proc.stdout)


if __name__ == "__main__":
    unittest.main()
