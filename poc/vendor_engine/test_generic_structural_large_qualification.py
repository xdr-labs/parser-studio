"""Frozen 948-event large qualification acceptance for Generic Structural PoC."""
from pathlib import Path
import unittest

from generic_structural_large_qualification import CACHE,run


class GenericStructuralLargeQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required=(
            CACHE/'independent_vendor_holdout'/'manifest.json',
            CACHE/'commercial_security_20261014'/'manifest.json',
            CACHE/'security_sources'/'aws_waf.raw',
        )
        if not all(path.exists() for path in required):
            raise unittest.SkipTest('Pinned large qualification caches unavailable')
        cls.result=run()

    def test_frozen_status_gain_has_zero_complete_regressions(self):
        parent=self.result['parent_candidate_status']['total']
        current=self.result['current_candidate_status']['total']
        self.assertEqual(948,current['events'])
        self.assertEqual(461,current['baseline_complete'])
        self.assertEqual(461,current['complete_exact_span_equivalence'])
        self.assertEqual(0,current['complete_divergence'])
        self.assertEqual(684,current['candidate_SOURCE_PARSED'])
        self.assertEqual(223,current['incomplete_promoted'])
        self.assertEqual(0,current['promoted_extra_spans'])
        self.assertEqual(0,current['promoted_missing_baseline_spans'])
        self.assertEqual(567,parent['candidate_SOURCE_PARSED'])
        self.assertEqual(8,parent['complete_divergence'])

    def test_independent_gold_is_exact(self):
        commercial=self.result['independent_commercial_gold']['candidate']['total']
        self.assertEqual(391,commercial['reference_scored_events'])
        self.assertEqual(27968,commercial['gold_fields'])
        self.assertEqual(27968,commercial['TP'])
        self.assertEqual(0,commercial['FP'])
        self.assertEqual(0,commercial['FN'])
        self.assertEqual(1.0,commercial['f1'])
        json_gold=self.result['independent_json_gold']['total']
        self.assertEqual(94,json_gold['events'])
        self.assertEqual(4601,json_gold['fields'])
        self.assertEqual(4601,json_gold['TP'])
        self.assertEqual(0,json_gold['FP'])
        self.assertEqual(0,json_gold['FN'])
        self.assertEqual(0,json_gold['false_complete'])
        self.assertEqual(1.0,json_gold['f1'])

    def test_asa_event_code_improves_lower_bound_without_false_complete(self):
        parent=self.result['asa_parent_lower_bound']
        current=self.result['asa_current_lower_bound']
        self.assertEqual(261,current['events'])
        self.assertEqual(1049,current['baseline_source_backed_spans'])
        self.assertLess(parent['baseline_span_recall'],0.53)
        self.assertGreaterEqual(current['baseline_span_recall'],0.945)
        self.assertEqual(0,current['candidate_SOURCE_PARSED'])
        self.assertEqual(5,current['candidate_RAW_ONLY'])

    def test_template_layers_remain_candidate_only(self):
        global_template=self.result['asa_residual_template']
        self.assertTrue(global_template['available'])
        self.assertEqual(104,global_template['holdout_records'])
        self.assertEqual(20,global_template['matched'])
        self.assertEqual(8,global_template['status_SOURCE_SPAN_CANDIDATE_ONLY'])
        self.assertFalse(global_template['automatic_apply_allowed'])
        routed=self.result['asa_shape_routed_recipe']
        self.assertTrue(routed['available'])
        self.assertEqual(45,routed['routing']['routable'])
        self.assertEqual(8,routed['routing']['matched'])
        lower=routed['baseline_lower_bound']
        self.assertEqual(28,lower['generic_missing'])
        self.assertEqual(24,lower['combined_missing'])
        self.assertFalse(routed['automatic_apply_allowed'])


if __name__=='__main__':
    unittest.main()
