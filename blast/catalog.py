"""Load and validate the declarative command catalog."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from .model import CAPABILITIES, digest_of

CATALOG_SCHEMA_VERSION = 1
DEFAULT_CATALOG = os.path.join(os.path.dirname(__file__), "catalog.json")

_OPERAND_KINDS = frozenset(("path", "network", "selector", "sql", "package", "none"))
_MATCH_KINDS = frozenset(("any_arg", "any_arg_contains", "arg_prefix"))
_SPEC_KEYS = frozenset((
    "family", "operand_kind", "base", "flags", "value_flags", "arg_rules", "tests",
))
_TEST_KEYS = frozenset(("positive", "negative", "opaque"))


class CatalogError(ValueError):
    pass


_CATALOG_CACHE: Dict[str, "Catalog"] = {}


class Catalog:
    def __init__(self, data: Dict[str, Any], path: str = "<memory>"):
        self.data = data
        self.path = path
        self.version = str(data["version"])
        self.digest = digest_of(data)
        self.commands: Dict[str, Any] = data["commands"]

    def spec(self, name: str) -> Dict[str, Any]:
        return self.commands.get(name, self.commands["__default__"])

    def is_known(self, name: str) -> bool:
        return name in self.commands and name != "__default__"


def validate_catalog(data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise CatalogError("catalog must be an object")
    if data.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise CatalogError("unsupported catalog schema_version")
    if not isinstance(data.get("version"), str) or not data["version"]:
        raise CatalogError("catalog version must be a non-empty string")
    commands = data.get("commands")
    if not isinstance(commands, dict) or "__default__" not in commands:
        raise CatalogError("catalog needs a commands object with __default__")

    caps = set(CAPABILITIES)
    seen_ids = set()
    for name, spec in commands.items():
        if not isinstance(spec, dict):
            raise CatalogError("command %s must be an object" % name)
        missing = _SPEC_KEYS - set(spec)
        extra = set(spec) - _SPEC_KEYS
        if missing:
            raise CatalogError("command %s missing %s" % (name, sorted(missing)))
        if extra:
            raise CatalogError("command %s has unknown fields %s" % (name, sorted(extra)))
        if spec["operand_kind"] not in _OPERAND_KINDS:
            raise CatalogError("command %s has invalid operand_kind" % name)
        for key in ("base", "value_flags"):
            if not isinstance(spec[key], list):
                raise CatalogError("command %s.%s must be a list" % (name, key))
        for cap in spec["base"]:
            if cap not in caps:
                raise CatalogError("command %s has unknown capability %s" % (name, cap))
        if not isinstance(spec["flags"], dict):
            raise CatalogError("command %s.flags must be an object" % name)
        for flag, added in spec["flags"].items():
            if not isinstance(flag, str) or not isinstance(added, list):
                raise CatalogError("command %s has malformed flag %r" % (name, flag))
            for cap in added:
                if cap not in caps:
                    raise CatalogError("command %s flag %s has unknown capability %s"
                                       % (name, flag, cap))
        for rule in spec["arg_rules"]:
            if not isinstance(rule, dict) or set(rule) != {
                "id", "match", "values", "add", "severity", "reason"
            }:
                raise CatalogError("command %s has a malformed arg_rule" % name)
            rid = rule["id"]
            if rid in seen_ids:
                raise CatalogError("duplicate rule id %s" % rid)
            seen_ids.add(rid)
            if rule["match"] not in _MATCH_KINDS:
                raise CatalogError("rule %s has invalid match" % rid)
            if not isinstance(rule["values"], list) or not rule["values"]:
                raise CatalogError("rule %s needs values" % rid)
            for cap in rule["add"]:
                if cap not in caps:
                    raise CatalogError("rule %s has unknown capability %s" % (rid, cap))
        tests = spec["tests"]
        if not isinstance(tests, dict) or set(tests) != _TEST_KEYS:
            raise CatalogError("command %s has malformed tests" % name)
        for key in _TEST_KEYS:
            if not isinstance(tests[key], list):
                raise CatalogError("command %s.tests.%s must be a list" % (name, key))
        if not tests["positive"]:
            raise CatalogError("command %s needs at least one positive fixture" % name)


def load_catalog(path: Optional[str] = None) -> Catalog:
    target = path or DEFAULT_CATALOG
    stat = os.stat(target)
    key = "%s|%d|%d" % (os.path.abspath(target), stat.st_mtime_ns, stat.st_size)
    cached = _CATALOG_CACHE.get(key)
    if cached is not None:
        return cached
    with open(target, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    validate_catalog(data)
    catalog = Catalog(data, target)
    _CATALOG_CACHE[key] = catalog
    return catalog
