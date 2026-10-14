"""Acceptance for the frozen 708-event post-v2 holdout."""
import unittest

from generic_structural_postfreeze_holdout import CACHE,run


class GenericStructuralPostFreezeHoldoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CACHE.exists():
            raise unittest.SkipTest('Post-freeze holdout cache unavailable')
        cls.result=run()

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
        self.assertFalse(self.result['promotion_accuracy_independently_certified'])
        self.assertFalse(self.result['field_semantics_scored'])


if __name__=='__main__':
    unittest.main()
