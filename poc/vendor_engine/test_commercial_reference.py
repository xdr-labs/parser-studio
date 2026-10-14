"""Oracle independence, exact occurrence scores, and denominator guards."""
import copy,json,unittest
from unittest.mock import patch
from pathlib import Path
from commercial_reference import reference_record
from benchmark_commercial_security import compare,canonical
from security_source import parse_security_source

class CommercialReferenceTests(unittest.TestCase):
    def test_reference_is_independent_of_production_decoders(self):
        raw='<134>1 2026-10-14T10:11:12Z gw CheckPoint 1 - [user:"Zoë"; user:"two"; value:"a;b\\\"c"]'
        with patch('security_source.parse_security_source',side_effect=AssertionError('Oracle cannot call candidate')):
            out=reference_record(raw,'checkpoint_81')
        self.assertEqual(['Zoë','two'],out.tree['body']['user'])
        self.assertEqual(10,len(out.cells))
        cells=[x for x in out.cells if x[0]==('body','user')]
        self.assertEqual(['Zoë','two'],[raw.encode()[x[2]:x[3]].decode() for x in cells])

    def test_equal_values_different_offsets_and_csv_empty_columns(self):
        raw='Oct 14 10:11:12 gw - 1,2026/10/14 10:11:12,001,THREAT,"a,b",same,same,,'
        ref=reference_record(raw,'panos_threat')
        actual=parse_security_source(raw)
        self.assertEqual(ref.tree,actual.vendor_fields)
        self.assertEqual('',ref.tree['body']['column_8'])
        same=[c for c in ref.cells if c[1]=='same']
        self.assertEqual(2,len(same));self.assertNotEqual(same[0][2],same[1][2])

    def test_exact_identity_type_and_value_are_not_interchangeable(self):
        self.assertNotEqual(canonical(('a',),'1'),canonical(('a',),1))
        self.assertNotEqual(canonical(('a',),'1'),canonical(('b',),'1'))
        self.assertEqual(canonical(('body','a'),'1'),canonical(('a',),'1'))
        self.assertNotEqual(canonical(('syslog','pri'),'1'),canonical(('pri',),'1'))

    def test_bad_source_not_forgiven_by_reference(self):
        with self.assertRaisesRegex(ValueError,'QUOTE_UNCLOSED'):
            reference_record('safe=yes message="unterminated','fortigate_74')
        with self.assertRaises(ValueError):reference_record('[user:"x"] junk','checkpoint_80')

    @unittest.skipUnless((Path(__file__).parent/'.cache/commercial_security_20261014/manifest.json').is_file(),'Local research-only fixtures unavailable')
    def test_every_commercial_record_is_accounted_without_false_success(self):
        report=compare();old=report['baseline']['total'];new=report['candidate']['total']
        self.assertEqual(392,new['all_events']);self.assertEqual(392,new['raw_preserved'])
        self.assertEqual(391,new['reference_scored_events']);self.assertEqual(1,new['reference_excluded_events'])
        self.assertEqual(1,new['excluded_event_not_false_green'])
        self.assertEqual(27968,new['gold_fields']);self.assertEqual(27968,new['TP'])
        self.assertEqual(0,new['FP']+new['FN']);self.assertEqual(391,new['exact_all_field_events'])
        self.assertEqual((26985,147,983),(old['TP'],old['FP'],old['FN']))
        self.assertEqual(3,new['exact_composite_fields'])
        self.assertFalse(report['dictionary_attempted']);self.assertFalse(report['masking_optimization'])

    def test_first_prospective_result_retains_two_unscored_inputs(self):
        p=Path(__file__).parent
        result=json.loads((p/'commercial-prospective-summary.json').read_text())
        counts=result['candidate']['total']
        self.assertEqual((28,26,2),(counts['all_events'],counts['reference_scored_events'],counts['reference_excluded_events']))
        self.assertEqual(687,counts['TP'])
        self.assertTrue(result['candidate_frozen_before_first_additional_raw'])
        self.assertEqual(result['frozen_source_sha256']['security_pairs.py'],result['candidate_sha256']['security_pairs.py'])

    @unittest.skipUnless((Path(__file__).parent/'.cache/commercial_prospective_20261014/manifest.json').is_file(),'Local prospective security fixtures unavailable')
    def test_post_exposure_colon_key_followup_is_separately_verified(self):
        p=Path(__file__).parent.resolve()
        result=compare(manifest_path=p/'commercial-prospective-manifest.json',cache_path=p/'.cache/commercial_prospective_20261014')
        counts=result['candidate']['total']
        self.assertEqual(28,counts['all_events']);self.assertEqual(28,counts['reference_scored_events'])
        self.assertEqual((779,0,0),(counts['TP'],counts['FP'],counts['FN']))
        self.assertEqual(28,counts['exact_tree_events'])
        self.assertEqual(0,counts.get('reference_excluded_events',0))

if __name__=='__main__':unittest.main()
