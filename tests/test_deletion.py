import copy
import tempfile
import unittest

from blast.api import analyze
from blast.catalog import CatalogError, load_catalog, validate_catalog

TRIGGERS = {
    "rm.root_operand": "rm -rf /",
    "dd.device_write": "dd of=/dev/sda",
    "dd.any_device": "dd of=/tmp/out",
    "psql.drop": 'psql -c "DROP DATABASE prod"',
    "mysql.drop": 'mysql -e "DELETE FROM users WHERE 1=1"',
}


class DeletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="blast-deletion-")
        cls.full = load_catalog().data

    def rule_ids(self, result):
        return sorted(set(a.rule_id for a in result.assertions))

    def test_every_arg_rule_is_necessary_for_its_trigger(self):
        all_rules = []
        for spec in self.full["commands"].values():
            all_rules.extend(spec["arg_rules"])
        self.assertTrue(all_rules)
        for rule in all_rules:
            rid = rule["id"]
            self.assertIn(rid, TRIGGERS, "no trigger fixture for %s" % rid)
            command = TRIGGERS[rid]
            full_result = analyze(command, root=self.root,
                                  catalog_data=copy.deepcopy(self.full))
            self.assertIn(rid, self.rule_ids(full_result))

            reduced = copy.deepcopy(self.full)
            for spec in reduced["commands"].values():
                spec["arg_rules"] = [r for r in spec["arg_rules"] if r["id"] != rid]
            reduced_result = analyze(command, root=self.root,
                                     catalog_data=reduced)
            self.assertNotIn(rid, self.rule_ids(reduced_result))
            self.assertNotEqual(self.rule_ids(full_result),
                                self.rule_ids(reduced_result))

    def test_removing_default_rule_makes_catalog_invalid(self):
        data = copy.deepcopy(self.full)
        del data["commands"]["__default__"]
        with self.assertRaises(CatalogError):
            validate_catalog(data)
        result = analyze("madeup --flag", root=self.root, catalog_data=data)
        self.assertEqual(result.verdict, "deny")
        self.assertTrue(any(i.code == "INTERNAL_ERROR"
                            for i in result.parse_issues))

    def test_removing_a_command_rule_changes_the_default_path(self):
        data = copy.deepcopy(self.full)
        del data["commands"]["rm"]
        result = analyze("rm -rf /", root=self.root, catalog_data=data)
        self.assertTrue(any(u.kind == "UNKNOWN_COMMAND" for u in result.unknowns))
        self.assertEqual(result.verdict, "deny")


if __name__ == "__main__":
    unittest.main()
