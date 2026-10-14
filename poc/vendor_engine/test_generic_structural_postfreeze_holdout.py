"""Acceptance for the frozen 708-event post-v2 holdout."""
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
SUMMARY=HERE/'generic-structural-postfreeze-holdout-summary.json'


class GenericStructuralPostFreezeHoldoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=json.loads(SUMMARY.read_text())

    def test_frozen_candidate_has_no_complete_regression(self):
        total=self.result['total']
        self.assertEqual(708,total['events'])
        self.assertEqual(496,total['candidate_SOURCE_PARSED'])
        self.assertEqual(708,total['raw_preserved'])
        self.assertEqual(283,total['baseline_complete'])
        self.assertEqual(283,total['complete_exact_span_equivalence'])
        self.assertEqual(0,total['complete_divergence'])

    def test_baseline_exceptions_are_explicit_and_candidate_does_not_crash(self):
        total=self.result['total']
        self.assertEqual(7,total['baseline_exception'])
        self.assertEqual(
            {'ValueError:CANDIDATE_DISPLAY_PATH_MISMATCH':7},
            self.result['baseline_exception_types'],
        )
        self.assertEqual(7,total['candidate_status_on_baseline_exception_RAW_ONLY'])

    def test_promotions_are_not_published_as_independent_gold(self):
        total=self.result['total']
        self.assertEqual(213,total['incomplete_promoted'])
        self.assertEqual(557,total['promoted_missing_occurrences'])
        self.assertEqual(0,total['promoted_missing_stable_source_segments'])
        self.assertEqual(551,total['promoted_missing_nonempty'])
        self.assertEqual(
            551,total['promoted_missing_nonempty_overlap_candidate']
        )
        self.assertEqual(
            0,total['promoted_missing_nonempty_disjoint_candidate']
        )
        self.assertEqual(6,total['promoted_missing_zero_length'])
        self.assertFalse(self.result['promotion_accuracy_independently_certified'])
        self.assertFalse(self.result['field_semantics_scored'])


if __name__=='__main__':
    unittest.main()
