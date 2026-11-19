import copy
import dataclasses
import unittest

from blast.catalog import CatalogError, load_catalog, validate_catalog
from blast.model import WORD_LITERAL, Span, Word, WordPart, canonical_text, digest_of, plain


class ModelTests(unittest.TestCase):
    def test_frozen_value_objects(self):
        span = Span(0, 3, 1, 1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            span.start = 5
        word = Word("ls", (WordPart("literal", "ls", span),),
                    WORD_LITERAL, "ls", span)
        self.assertTrue(word.known)

    def test_canonical_serialization_is_deterministic(self):
        obj = {"b": [1, 2], "a": {"z": None, "y": True}}
        self.assertEqual(canonical_text(obj), canonical_text(obj))
        self.assertEqual(canonical_text(obj), '{"a":{"y":true,"z":null},"b":[1,2]}')
        self.assertEqual(digest_of(obj), digest_of(obj))

    def test_floats_are_forbidden(self):
        with self.assertRaises(ValueError):
            canonical_text({"x": 1.5})

    def test_plain_rejects_unknown_types(self):
        with self.assertRaises(TypeError):
            plain({"x": object()})

    def test_catalog_loads_and_has_default(self):
        catalog = load_catalog()
        self.assertIn("__default__", catalog.commands)
        self.assertGreater(len(catalog.commands), 100)
        self.assertEqual(len(catalog.digest), 64)

    def test_catalog_rejects_duplicate_rule_ids(self):
        data = copy.deepcopy(load_catalog().data)
        rule = copy.deepcopy(data["commands"]["rm"]["arg_rules"][0])
        data["commands"]["find"]["arg_rules"].append(rule)
        with self.assertRaises(CatalogError):
            validate_catalog(data)

    def test_catalog_rejects_unknown_fields(self):
        data = copy.deepcopy(load_catalog().data)
        data["commands"]["ls"]["surprise"] = True
        with self.assertRaises(CatalogError):
            validate_catalog(data)

    def test_catalog_rejects_missing_positive_fixture(self):
        data = copy.deepcopy(load_catalog().data)
        data["commands"]["ls"]["tests"]["positive"] = []
        with self.assertRaises(CatalogError):
            validate_catalog(data)

    def test_catalog_rejects_bad_capability(self):
        data = copy.deepcopy(load_catalog().data)
        data["commands"]["ls"]["base"] = ["NOT_A_CAPABILITY"]
        with self.assertRaises(CatalogError):
            validate_catalog(data)


if __name__ == "__main__":
    unittest.main()
