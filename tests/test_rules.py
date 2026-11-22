import json
import tempfile
import unittest
import jsonschema
from pathlib import Path

import xdp_rules


class XdpRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "rules.json"

    def tearDown(self):
        self.temp.cleanup()

    def document(self):
        return {
            "schema_version": "1.0",
            "rules": [
                {"id": "deny-doc-2", "source_ipv4": "198.51.100.2", "action": "drop"},
                {"id": "deny-doc-1", "source_ipv4": "198.51.100.1", "action": "drop"},
            ],
        }

    def test_valid_rules_are_normalized_and_sorted(self):
        rules = xdp_rules.validate_rules(self.document())
        self.assertEqual([r["source_ipv4"] for r in rules], ["198.51.100.1", "198.51.100.2"])

    def test_compiler_emits_network_order_map_key_bytes(self):
        output = xdp_rules.compile_map_updates(self.document())
        self.assertEqual(output["mode"], "preview_only")
        self.assertFalse(output["program_load_or_map_update_performed"])
        self.assertEqual(output["updates"][0]["key_hex"], "c6336401")
        self.assertEqual(output["updates"][0]["value_hex"], "01")
        self.assertEqual(output["default_action"], "XDP_PASS")

    def test_ipv6_is_rejected(self):
        document = self.document()
        document["rules"][0]["source_ipv4"] = "2001:db8::1"
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)

    def test_cidr_is_rejected(self):
        document = self.document()
        document["rules"][0]["source_ipv4"] = "198.51.100.0/24"
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)

    def test_noncanonical_ipv4_is_rejected(self):
        document = self.document()
        document["rules"][0]["source_ipv4"] = "198.051.100.2"
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)

    def test_duplicate_rule_id_is_rejected(self):
        document = self.document()
        document["rules"][1]["id"] = document["rules"][0]["id"]
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)

    def test_duplicate_source_address_is_rejected(self):
        document = self.document()
        document["rules"][1]["source_ipv4"] = document["rules"][0]["source_ipv4"]
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)

    def test_only_drop_action_is_supported(self):
        document = self.document()
        document["rules"][0]["action"] = "pass"
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)

    def test_unknown_fields_are_rejected(self):
        document = self.document()
        document["rules"][0]["comment"] = "unexpected"
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)

    def test_duplicate_json_keys_are_rejected(self):
        self.path.write_text('{"schema_version":"1.0","schema_version":"1.0","rules":[]}', encoding="utf-8")
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.load_json(self.path)

    def test_rule_limit_is_enforced(self):
        document = {
            "schema_version": "1.0",
            "rules": [
                {"id": "r" + str(i), "source_ipv4": "10." + str((i >> 16) & 255) + "." + str((i >> 8) & 255) + "." + str(i & 255), "action": "drop"}
                for i in range(4097)
            ],
        }
        with self.assertRaises(xdp_rules.RuleError):
            xdp_rules.validate_rules(document)


    def test_rule_document_matches_versioned_schema(self):
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "ingress-rules.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(self.document())


if __name__ == "__main__":
    unittest.main()
