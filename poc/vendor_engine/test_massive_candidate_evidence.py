"""Value-free acceptance for massive candidate-only evidence."""
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


class MassiveCandidateEvidenceTests(unittest.TestCase):
    def test_partial_recovery_is_additive_and_never_complete(self):
        result=json.loads(
            (HERE/'generic-structural-massive-partial-recovery.json').read_text()
        )
        total=result['total']
        self.assertEqual(3607,total['events'])
        self.assertEqual(3607,total['raw_preserved'])
        self.assertEqual(3607,total['old_spans_preserved'])
        self.assertEqual(2465,total['base_SOURCE_PARSED'])
        self.assertEqual(2465,total['final_SOURCE_PARSED'])
        self.assertEqual(769,total['events_with_any_addition'])
        self.assertEqual(1319,total['added_total'])
        self.assertFalse(result['automatic_complete_allowed'])
        self.assertFalse(result['semantic_roles_assigned'])

    def test_crossfold_span_candidates_are_train_holdout_disjoint(self):
        result=json.loads(
            (HERE/'generic-structural-massive-crossfold-candidate.json').read_text()
        )
        total=result['total']
        self.assertEqual(5,result['fold_count'])
        self.assertEqual(1113,total['holdout_events'])
        self.assertEqual(460,total['candidate_events'])
        self.assertEqual(4009,total['candidate_spans'])
        self.assertEqual(3329,total['fresh_after_partial'])
        self.assertFalse(result['same_event_sha_train_holdout_overlap'])
        self.assertFalse(result['semantic_roles_assigned'])
        self.assertFalse(result['automatic_apply_allowed'])


if __name__=='__main__':
    unittest.main()
