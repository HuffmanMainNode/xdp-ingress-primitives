#!/usr/bin/env python3
"""Validate and compile declarative IPv4 ingress deny rules.

This module never loads, attaches, or updates an eBPF program or map.
It emits deterministic map key/value bytes for an external operator workflow.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


SCHEMA_VERSION = "1.0"
MAX_RULES = 4096
RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class RuleError(ValueError):
    """Raised when an ingress rule document is invalid."""


def _unique_object(pairs: List[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuleError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuleError("cannot read rule file " + str(path) + ": " + str(exc))


def validate_rules(document: Any) -> List[Dict[str, str]]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "rules"}:
        raise RuleError("rule document must contain exactly schema_version and rules")
    if document["schema_version"] != SCHEMA_VERSION:
        raise RuleError("schema_version must be '1.0'")
    rules = document["rules"]
    if not isinstance(rules, list):
        raise RuleError("rules must be an array")
    if len(rules) > MAX_RULES:
        raise RuleError("rule count exceeds the BPF map capacity of 4096")

    ids = set()
    addresses = set()
    normalized = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or set(rule) != {"id", "source_ipv4", "action"}:
            raise RuleError("rules[" + str(index) + "] must contain exactly id, source_ipv4, and action")
        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not RULE_ID_RE.fullmatch(rule_id):
            raise RuleError("rules[" + str(index) + "].id is invalid")
        if rule_id in ids:
            raise RuleError("duplicate rule id: " + rule_id)
        ids.add(rule_id)

        address = rule["source_ipv4"]
        if not isinstance(address, str):
            raise RuleError("rules[" + str(index) + "].source_ipv4 must be a string")
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise RuleError("rules[" + str(index) + "].source_ipv4 is invalid: " + str(exc))
        if not isinstance(parsed, ipaddress.IPv4Address):
            raise RuleError("only IPv4 source addresses are supported")
        canonical_address = str(parsed)
        if canonical_address != address:
            raise RuleError("source_ipv4 must use canonical dotted-decimal notation")
        if canonical_address in addresses:
            raise RuleError("duplicate IPv4 source address: " + canonical_address)
        addresses.add(canonical_address)

        if rule["action"] != "drop":
            raise RuleError("only explicit 'drop' rules are supported")
        normalized.append({"id": rule_id, "source_ipv4": canonical_address, "action": "drop"})

    normalized.sort(key=lambda item: (int(ipaddress.IPv4Address(item["source_ipv4"])), item["id"]))
    return normalized


def compile_map_updates(document: Any) -> Dict[str, Any]:
    rules = validate_rules(document)
    updates = []
    for rule in rules:
        address = ipaddress.IPv4Address(rule["source_ipv4"])
        updates.append({
            "map": "deny_src_ipv4",
            "key_hex": address.packed.hex(),
            "value_hex": "01",
            "rule_id": rule["id"],
            "source_ipv4": rule["source_ipv4"],
            "action": "drop",
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "preview_only",
        "map": "deny_src_ipv4",
        "updates": updates,
        "program_load_or_map_update_performed": False,
        "default_action": "XDP_PASS",
        "default_action_semantics": "pass-through to the normal networking stack; not fail-closed",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xdp-rules",
        description="Validate and preview exact IPv4 XDP deny-map entries; does not load or attach BPF.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a versioned ingress rule document")
    validate.add_argument("rules", type=Path)
    compile_command = commands.add_parser("compile", help="emit deterministic map update bytes without applying them")
    compile_command.add_argument("rules", type=Path)
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        document = load_json(args.rules)
        rules = validate_rules(document)
        if args.command == "validate":
            print(json.dumps({"status": "valid", "rule_count": len(rules)}, indent=2, sort_keys=True))
        else:
            print(json.dumps(compile_map_updates(document), indent=2, sort_keys=True))
        return 0
    except RuleError as exc:
        print(json.dumps({"status": "invalid", "error": str(exc)}, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
