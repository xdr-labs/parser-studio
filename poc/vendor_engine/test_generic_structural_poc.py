"""Acceptance tests for the vendor-agnostic structural parsing PoC."""
from pathlib import Path
import unittest

from generic_structural_poc import parse_generic_structural
from generic_structural_poc_benchmark import (
    ISE,ISE_EXPECTED,NEGATIVE_CASES,PFSENSE,
    frozen_oracle_eval,ise_eval,pfsense_eval,recipe_eval,
    post_tuning_fresh_eval,residual_template_eval,
)


class GenericStructuralPoCTests(unittest.TestCase):
    def test_candidate_does_not_import_vendor_specific_profiles(self):
        source=(Path(__file__).with_name('generic_structural_poc.py')).read_text()
        for name in (
            'security_meraki','security_watchguard','security_juniper',
            'security_cisco_ise','security_pfsense','security_asa',
        ):
            self.assertNotIn(name,source)

    def test_frozen_public_profile_oracle_is_exact(self):
        result=frozen_oracle_eval()
        self.assertEqual(10,result['events'])
        self.assertEqual(10,result['exact_events'])
        self.assertEqual(
            {'tp':186,'fp':0,'fn':0,'precision':1.0,'recall':1.0,'f1':1.0},
            result['span_metrics'],
        )

    def test_negative_controls_never_false_complete(self):
        for raw in NEGATIVE_CASES:
            with self.subTest(raw=raw[:48]):
                self.assertNotEqual('SOURCE_PARSED',parse_generic_structural(raw).status)

    def test_pfsense_wide_positional_csv_promotes_without_changing_spans(self):
        result=pfsense_eval()
        self.assertEqual('PARTIAL',result['baseline_status'])
        self.assertEqual('SOURCE_PARSED',result['candidate_status'])
        self.assertTrue(result['span_sets_equal'])
        self.assertEqual(0,result['candidate_residual_bytes'])
        short='<134>Mar 12 10:04:11 fw01 app: one,two,three,four'
        self.assertNotEqual('SOURCE_PARSED',parse_generic_structural(short).status)

    def test_cisco_ise_space_keys_repeats_and_source_slices(self):
        result=ise_eval(ISE,ISE_EXPECTED)
        self.assertEqual('PARTIAL',result['baseline_status'])
        self.assertEqual('SOURCE_PARSED',result['candidate_status'])
        self.assertTrue(result['expected_kv_exact'])
        self.assertTrue(result['kv_source_slices_exact'])
        self.assertEqual(0,result['candidate_residual_bytes'])
        self.assertEqual(2,result['repeated_cisco_av_pair_occurrences'])

    def test_recipe_synthesis_generalizes_without_vendor_identity(self):
        result=recipe_eval()
        self.assertEqual(3,result['holdouts'])
        self.assertEqual(3,result['exact_holdouts'])
        self.assertEqual(
            {'mixed','comma_kv'},
            {row['recipe']['mode'] for row in result['rows']},
        )

    def test_post_tuning_fresh_holdout_keeps_qualified_cases_and_adds_source_backed_fields(self):
        result=post_tuning_fresh_eval()
        self.assertEqual(6,result['events'])
        self.assertEqual(
            result['qualified_complete_oracle_events'],
            result['qualified_exact_events'],
        )
        self.assertEqual(4,result['qualified_exact_events'])
        self.assertEqual(2,result['baseline_incomplete_events'])
        self.assertEqual(
            2,result['baseline_incomplete_promoted_with_source_backing']
        )

    def test_generic_event_code_tokens_are_additive_not_complete(self):
        raw='prefix %EDGE-6-302013: unstructured body'
        event=parse_generic_structural(raw)
        self.assertEqual('PARTIAL',event.status)
        self.assertEqual(
            {'part_0':'EDGE','part_1':'6','part_2':'302013'},
            event.vendor_fields['generic']['event_code'],
        )
        self.assertEqual(
            ['EDGE','6','302013'],
            [
                raw.encode()[span.start_byte:span.end_byte].decode()
                for span in event.value_spans
                if span.path.startswith('generic.event_code.')
            ],
        )
        quoted=(
            'note="literal %EDGE-6-302013: text" other=ok third=yes '
            'fourth=yes fifth=yes'
        )
        quoted_event=parse_generic_structural(quoted)
        self.assertEqual('SOURCE_PARSED',quoted_event.status)
        self.assertNotIn('generic',quoted_event.vendor_fields)
        multiple='%EDGE-6-302013: first %ALT-4-106023: second'
        self.assertNotEqual('SOURCE_PARSED',parse_generic_structural(multiple).status)

    def test_residual_template_is_candidate_only_when_dependency_present(self):
        result=residual_template_eval()
        if not result.get('available'):
            self.skipTest(result.get('reason','optional Drain3 unavailable'))
        self.assertEqual('PARTIAL',result['generic_status'])
        self.assertTrue(result['template_match'])
        self.assertEqual('SOURCE_SPAN_CANDIDATE_ONLY',result['alignment_status'])
        self.assertTrue(result['exact_variable_spans'])
        self.assertEqual(6,result['candidate_variable_spans'])
        self.assertFalse(result['semantic_names_inferred'])
        self.assertFalse(result['automatic_apply_allowed'])


if __name__=='__main__':
    unittest.main()
