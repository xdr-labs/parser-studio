"""Frozen value-free regression for the optional Dictionary pass."""
import json
import unittest
from pathlib import Path

from benchmark_stellar_dictionary import (
    SECURITY_CACHE,SECURITY_MANIFEST,evaluate,
)
from benchmark_multipass_cef import CACHE as CEF_CACHE,MANIFEST as CEF_MANIFEST


@unittest.skipUnless(
    SECURITY_MANIFEST.is_file() and SECURITY_CACHE.is_dir() and
    CEF_MANIFEST.is_file() and CEF_CACHE.is_dir(),
    "Local research-only security fixtures unavailable",
)
class StellarDictionaryBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=evaluate()

    def test_all_source_records_occurrences_and_trees_are_preserved(self):
        security=self.result["security_commercial"]
        self.assertEqual(392,security["records"])
        self.assertEqual(392,security["raw_preserved"])
        self.assertEqual(392,security["source_tree_preserved"])
        self.assertEqual(392,security["source_extraction_normalization_attempted_false"])
        self.assertEqual(27991,security["source_occurrences"])
        self.assertEqual(
            security["source_occurrences"],
            security["mapped_occurrences"]+security["unmapped_occurrences"],
        )
        self.assertEqual(626,security["mapped_occurrences"])
        self.assertEqual(27365,security["unmapped_occurrences"])
        self.assertEqual({"DICTIONARY_TYPE_REJECTED:severity":6},security["issues"])

    def test_cef_standard_alias_mapping_is_bounded_and_deterministic(self):
        commercial=self.result["cef_commercial"]
        authored=self.result["cef_authored"]
        self.assertEqual((22,482,39,443),(
            commercial["records"],commercial["source_occurrences"],
            commercial["mapped_occurrences"],commercial["unmapped_occurrences"],
        ))
        self.assertEqual({"cef_standard_alias":39},commercial["mapping_rule_classes"])
        self.assertEqual({},commercial["issues"])
        self.assertEqual((96,900,120,780),(
            authored["records"],authored["source_occurrences"],
            authored["mapped_occurrences"],authored["unmapped_occurrences"],
        ))
        self.assertEqual({"cef_standard_alias":120},authored["mapping_rule_classes"])
        self.assertEqual({},authored["issues"])

    def test_summary_contract_is_value_free_and_never_claims_target_or_native(self):
        encoded=json.dumps(self.result,sort_keys=True)
        self.assertEqual("parser-studio.poc.stellar-dictionary-coverage.v0.1",
                         self.result["contract"])
        self.assertTrue(self.result["unknown_vendor_fields_preserved"])
        self.assertFalse(self.result["automatic_generic_alias_inference"])
        self.assertTrue(self.result["source_extraction_gate_independent"])
        self.assertFalse(self.result["native_verified"])
        self.assertFalse(self.result["target_verified"])
        self.assertFalse(self.result["raw_redistributed"])
        for forbidden in ("PRIVATE_VALUE","192.0.2.10","203.0.113."):
            self.assertNotIn(forbidden,encoded)


if __name__=="__main__":
    unittest.main()
