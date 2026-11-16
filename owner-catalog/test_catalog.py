import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import catalog


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.value = catalog.strict_json((Path(__file__).parent / "catalog.json").read_bytes())
        self.digest = self.value["catalog_digest"]
        unit = next(u for u in self.value["units"] if u["component_id"] == "qxctl")
        self.request = {"unit_id": unit["unit_id"], "native_version": unit["native_version"],
                        "definition_sha256": unit["definition_sha256"],
                        "owner_contract": unit["runtime_owner"]["contract"],
                        "profile": "macos15-arm64", "operation": "stage_carrier"}

    def reseal(self, value):
        value.pop("catalog_digest")
        value["catalog_digest"] = "sha256:" + catalog.sha(catalog.canonical(value))
        return value["catalog_digest"]

    def test_complete_delivery_and_owner_coverage(self):
        catalog.validate(self.value, self.digest)
        self.assertEqual(len(self.value["units"]), 66)
        go = [u for u in self.value["units"] if u["kind"] == "go_command"]
        self.assertEqual({u["component_id"] for u in go}, set(catalog.GO_OWNERS))
        self.assertEqual(sum(u["runtime_owner"]["kind"] == "module_receipt_owner" for u in go), 3)
        self.assertEqual(sum(u["runtime_owner"]["runtime_receipt"] is None for u in go), 4)
        self.assertTrue(all(not u["runtime_owner"]["generic_receipt_delete_authorized"] for u in self.value["units"]))
        self.assertEqual(sum(len(u["platform_candidates"]) for u in self.value["units"]), 263)
        snv = next(u for u in self.value["units"] if u["component_id"] == "snv-local-observer")
        self.assertEqual(len(snv["platform_candidates"]), 3)
        with self.assertRaises(catalog.InvalidCatalog):
            catalog.classify(self.value, self.digest, {"unit_id": snv["unit_id"], "native_version": snv["native_version"],
                "definition_sha256": snv["definition_sha256"], "owner_contract": snv["runtime_owner"]["contract"],
                "profile": "macos15-arm64", "operation": "stage_carrier"})

    def test_all_profile_operation_classifications_are_nonexecuting(self):
        with patch.object(catalog.subprocess, "check_output", side_effect=AssertionError("classification spawned a process")):
            for unit in self.value["units"]:
                request = {"unit_id": unit["unit_id"], "native_version": unit["native_version"],
                           "definition_sha256": unit["definition_sha256"], "owner_contract": unit["runtime_owner"]["contract"]}
                for profile in unit["platform_candidates"]:
                    for operation in catalog.OPERATIONS:
                        result = catalog.classify(self.value, self.digest, {**request, "profile": profile["profile"], "operation": operation})
                        self.assertFalse(result["execution_authorized"])
                        self.assertFalse(result["owner_invoked"])
                        self.assertFalse(result["platform_accepted"])
                        if operation not in ("stage_carrier", "verify_carrier"):
                            self.assertEqual(result["disposition"], "blocked_pending_owner_qualification")

    def test_owner_substitution_rejected_even_when_rehashed(self):
        for field, replacement in (("contract", "evil.shell.v1"), ("kind", "module_receipt_owner"),
                                   ("runtime_receipt", "symphony.knowledge.install-receipt.v2"),
                                   ("generic_receipt_delete_authorized", True), ("owner_invocation_implemented", True)):
            with self.subTest(field=field):
                value = copy.deepcopy(self.value)
                unit = next(u for u in value["units"] if u["component_id"] == "qxctl")
                unit["runtime_owner"][field] = replacement
                with self.assertRaises(catalog.InvalidCatalog):
                    catalog.validate(value, self.reseal(value))

    def test_no_package_supplied_argv_privilege_or_hidden_activation(self):
        for field in ("argv", "executable", "sudo", "post_link", "automatic_activation"):
            value = copy.deepcopy(self.value)
            value["units"][0]["runtime_owner"][field] = "/untrusted/package/helper"
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.validate(value, self.reseal(value))
        with self.assertRaises(catalog.InvalidCatalog):
            catalog.classify(self.value, self.digest, {**self.request, "argv": ["delete", "all"]})

    def test_unknown_unit_and_owner_fail_closed(self):
        for replacement in ({"unit_id": "PKG-GO-user-module"}, {"owner_contract": "custom.v1"}):
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.classify(self.value, self.digest, {**self.request, **replacement})

    def test_wrong_version_definition_and_profile_refused(self):
        for replacement in ({"native_version": "latest"}, {"native_version": "0.1.0-dev/../other"},
                            {"native_version": "0.1.1"}, {"definition_sha256": "0" * 64},
                            {"profile": "windows-amd64"}, {"profile": "ubuntu24.04-*"}):
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.classify(self.value, self.digest, {**self.request, **replacement})

    def test_extra_missing_wrong_type_and_unknown_operation(self):
        bad = [{**self.request, "unsafe": True}, {**self.request, "operation": "force_remove"},
               {**self.request, "native_version": 1}, {k: v for k, v in self.request.items() if k != "owner_contract"}]
        for request in bad:
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.classify(self.value, self.digest, request)

    def test_trust_digest_is_independently_required(self):
        for digest in (None, "", "latest", "sha256:" + "0" * 64):
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.validate(self.value, digest)
        changed = copy.deepcopy(self.value)
        changed["source_evidence"][0]["sha256"] = "0" * 64
        with self.assertRaises(catalog.InvalidCatalog):
            catalog.validate(changed, self.digest)

    def test_source_identity_and_critical_version_cannot_be_relabelled(self):
        for field, replacement in (("format_version", 2), ("format_version", True),
                                   ("schema", "symphony.distribution.runtime-owner-catalog.v99"),
                                   ("contract_source", {"commit": "0" * 40, "tree": catalog.SOURCE_TREE}),
                                   ("delivery_snapshot_sha256", "0" * 64)):
            value = copy.deepcopy(self.value); value[field] = replacement
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.validate(value, self.reseal(value))

    def test_catalog_cannot_be_promoted_to_release_or_execution(self):
        for field in ("runtime_execution_authorized", "publication_authorized", "release_acceptance_complete"):
            value = copy.deepcopy(self.value); value[field] = True
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.validate(value, self.reseal(value))

    def test_catalog_source_evidence_closed_and_complete(self):
        for mutation in (lambda v: v["source_evidence"].pop(),
                         lambda v: v["source_evidence"][0].update(extra=True),
                         lambda v: v["source_evidence"][0].update(sha256="0" * 64),
                         lambda v: v["source_evidence"][0].update(path="../private")):
            value = copy.deepcopy(self.value); mutation(value)
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.validate(value, self.reseal(value))

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(catalog.InvalidCatalog):
                catalog.strict_json(data)

    def test_catalog_contains_no_publisher_runtime_state(self):
        text = json.dumps(self.value)
        for forbidden in ("/Users/", "/home/", "private_key", "access_token", "TOPS_ID=", "hardware_serial"):
            self.assertNotIn(forbidden, text)
        self.assertFalse(any(u["runtime_owner"]["live_removal_qualified"] for u in self.value["units"]))


if __name__ == "__main__":
    unittest.main()
