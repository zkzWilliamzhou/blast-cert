import json
import os
import subprocess
import sys
import tempfile
import unittest

from blast.api import analyze
from blast.receipt import build_receipt, diff_receipts, verify_receipt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="blast-receipt-")
        self.file = os.path.join(self.root, "a.txt")
        with open(self.file, "w", encoding="utf-8") as handle:
            handle.write("hello\n")

    def test_verify_clean_receipt(self):
        result = analyze("cat a.txt", root=self.root)
        receipt = build_receipt(result, "cat a.txt")
        report = verify_receipt(receipt, root=self.root)
        self.assertTrue(report["ok"], report["checks"])

    def test_tampered_digest_is_rejected(self):
        result = analyze("cat a.txt", root=self.root)
        receipt = build_receipt(result, "cat a.txt")
        receipt["digest"] = "0" * 64
        self.assertFalse(verify_receipt(receipt, root=self.root)["ok"])

    def test_drift_in_file_content_is_detected(self):
        result = analyze("cat a.txt", root=self.root)
        receipt = build_receipt(result, "cat a.txt")
        with open(self.file, "w", encoding="utf-8") as handle:
            handle.write("changed\n")
        report = verify_receipt(receipt, root=self.root)
        self.assertFalse(report["ok"])
        self.assertIn("evidence_digest", report["drift"])

    def test_diff_reports_added_capability(self):
        left = build_receipt(analyze("cat a.txt", root=self.root), "cat a.txt")
        right = build_receipt(analyze("rm -rf a.txt", root=self.root), "rm -rf a.txt")
        report = diff_receipts(left, right)
        self.assertIn("FS_DELETE", report["added_capabilities"])
        self.assertTrue(report["evidence_changed"] or report["digest_equal"] is False)

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "blast"] + list(args),
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=60,
        )

    def test_cli_check_exit_codes_and_json(self):
        allow = self.run_cli("check", "ls -la", "--root", self.root, "--format", "json")
        self.assertEqual(allow.returncode, 0)
        payload = json.loads(allow.stdout)
        self.assertEqual(payload["verdict"], "allow")
        deny = self.run_cli("check", "rm -rf /", "--root", self.root, "--format", "json")
        self.assertEqual(deny.returncode, 20)
        self.assertEqual(json.loads(deny.stdout)["verdict"], "deny")

    def test_cli_receipt_verify_diff(self):
        receipt_path = os.path.join(self.root, "receipt.json")
        made = self.run_cli("receipt", "cat a.txt", "--root", self.root,
                            "-o", receipt_path)
        self.assertEqual(made.returncode, 0)
        verified = self.run_cli("verify", receipt_path, "--root", self.root,
                                "--format", "json")
        self.assertEqual(verified.returncode, 0)
        self.assertTrue(json.loads(verified.stdout)["ok"])
        diffed = self.run_cli("diff", receipt_path, receipt_path, "--format", "json")
        self.assertEqual(diffed.returncode, 0)
        self.assertTrue(json.loads(diffed.stdout)["digest_equal"])

    def test_cli_selftest_and_catalog_check(self):
        selftest = self.run_cli("selftest", "--format", "json")
        self.assertEqual(selftest.returncode, 0, selftest.stdout + selftest.stderr)
        self.assertTrue(json.loads(selftest.stdout)["ok"])
        check = self.run_cli("catalog-check", "--format", "json")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertTrue(json.loads(check.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
