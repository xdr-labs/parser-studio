"""Immutable acceptance for the earlier PR #20 integration evidence."""
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
SUMMARY=HERE/'generic-structural-integration-summary.json'


class GenericStructuralIntegrationQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=json.loads(SUMMARY.read_text())

    def test_large_frozen_gate(self):
        total=self.result['large']['total']
        self.assertEqual(948,total['events'])
        self.assertEqual(684,total['current_SOURCE_PARSED'])
        self.assertEqual(948,total['raw_preserved'])
        self.assertEqual(461,total['old_complete'])
        self.assertEqual(461,total['old_complete_exact'])
        self.assertEqual(0,total['old_complete_divergence'])
        self.assertEqual(223,total['promoted'])

    def test_postfreeze_gate_and_juniper_exception_repair(self):
        total=self.result['postfreeze']['total']
        self.assertEqual(708,total['events'])
        self.assertEqual(496,total['current_SOURCE_PARSED'])
        self.assertEqual(708,total['raw_preserved'])
        self.assertEqual(283,total['old_complete'])
        self.assertEqual(283,total['old_complete_exact'])
        self.assertEqual(0,total['old_complete_divergence'])
        self.assertEqual(213,total['promoted'])
        self.assertEqual(7,total['old_exception'])
        self.assertEqual(7,total['old_exception_repaired'])

    def test_independent_commercial_gold_remains_exact(self):
        total=self.result['independent_commercial_gold']['total']
        self.assertEqual(391,total['reference_scored_events'])
        self.assertEqual(27968,total['gold_fields'])
        self.assertEqual(27968,total['TP'])
        self.assertEqual(0,total['FP'])
        self.assertEqual(0,total['FN'])
        self.assertEqual(1.0,total['f1'])

    def test_independent_json_gold_remains_exact(self):
        total=self.result['independent_json_gold']['total']
        self.assertEqual(94,total['events'])
        self.assertEqual(4601,total['fields'])
        self.assertEqual(4601,total['TP'])
        self.assertEqual(0,total['FP'])
        self.assertEqual(0,total['FN'])
        self.assertEqual(0,total['false_complete'])
        self.assertEqual(1.0,total['f1'])


if __name__=='__main__':
    unittest.main()
