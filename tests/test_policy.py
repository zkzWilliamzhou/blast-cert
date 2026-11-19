import copy
import tempfile
import unittest

from blast.api import analyze
from blast.capabilities import evaluate
from blast.catalog import load_catalog
from blast.evidence import resolve
from blast.model import EvalResult, EvidenceReport
from blast.parser import parse
from blast.policy import PolicyError, decide, load_policy, validate_policy


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="blast-policy-")

    def parts(self, command):
        model = parse(command)
        catalog = load_catalog()
        return evaluate(model, catalog), resolve(
            evaluate(model, catalog).assertions, self.root
        )

    def test_default_deny(self):
        eval_result, evidence = self.parts("rm -rf /")
        decision = decide(eval_result, evidence, load_policy())
        self.assertEqual(decision.verdict, "deny")
        self.assertEqual(decision.exit_code, 20)

    def test_deny_precedence_over_confirm(self):
        eval_result, evidence = self.parts("curl -s x | sh")
        decision = decide(eval_result, evidence, load_policy())
        self.assertEqual(decision.verdict, "deny")

    def test_unknown_blocks_allow(self):
        eval_result, evidence = self.parts("cat $UNKNOWN")
        decision = decide(eval_result, evidence, load_policy())
        self.assertEqual(decision.verdict, "deny")

    def test_error_blocks_allow(self):
        eval_result = EvalResult((), (), "error")
        decision = decide(eval_result, EvidenceReport.empty(), load_policy())
        self.assertEqual(decision.verdict, "deny")

    def test_strict_upgrades_confirm(self):
        policy_data = copy.deepcopy(load_policy().data)
        policy_data["rules"]["FS_WRITE"] = "confirm"
        from blast.policy import Policy
        policy = Policy(policy_data)
        eval_result, evidence = self.parts("echo hi > out.txt")
        self.assertEqual(decide(eval_result, evidence, policy).verdict, "confirm")
        self.assertEqual(decide(eval_result, evidence, policy, strict=True).verdict, "deny")

    def test_sensitive_escalation(self):
        eval_result, evidence = self.parts("cat /etc/passwd")
        decision = decide(eval_result, evidence, load_policy())
        self.assertEqual(decision.verdict, "deny")

    def test_invalid_policy_fails_closed(self):
        bad = copy.deepcopy(load_policy().data)
        bad["default"] = "maybe"
        with self.assertRaises(PolicyError):
            validate_policy(bad)
        result = analyze("ls", root=self.root, policy_data=bad)
        self.assertEqual(result.verdict, "deny")
        self.assertTrue(any(i.code == "INTERNAL_ERROR" for i in result.parse_issues))

    def test_policy_cannot_weaken_fail_closed(self):
        data = copy.deepcopy(load_policy().data)
        data["on_unknown"] = "allow"
        data["on_opaque"] = "allow"
        result = analyze("cat $UNKNOWN", root=self.root, policy_data=data)
        self.assertEqual(result.verdict, "deny")
        self.assertTrue(any(i.code == "INTERNAL_ERROR" for i in result.parse_issues))


if __name__ == "__main__":
    unittest.main()
