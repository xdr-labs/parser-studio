"""Independent Java header references preserve denominators and first failures."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_java_headers import ROOT,RAW_PINS,evaluate,reference_header

class JavaHeaderReferenceTests(unittest.TestCase):
    def test_reference_reconstruction_has_unicode_byte_offsets(self):
        row={'Date':'2026-11-14','Time':'10:11:12,123','Level':'INFO','Node':'worker-Ž',
             'Component':'Example','Id':'42','Content':'opaque body'}
        raw='2026-11-14 10:11:12,123 - INFO  [worker-Ž:Example@42] - opaque body'
        expected=reference_header('Zookeeper',raw,row)
        self.assertEqual(6,len(expected))
        for value,a,b in expected.values():self.assertEqual(value,raw.encode()[a:b].decode())
    def test_reference_terminal_spaces_do_not_exclude_valid_headers(self):
        row={'Date':'26/11/14','Time':'10:11:12','Level':'INFO','Component':'Worker','Content':'body'}
        raw='26/11/14 10:11:12 INFO Worker: body  '
        self.assertEqual(4,len(reference_header('Spark',raw,row)))
        with self.assertRaisesRegex(ValueError,'RECONSTRUCTION_MISMATCH'):
            reference_header('Spark',raw+'unannotated-content',row)

    def test_references_cannot_silently_accept_changed_raw(self):
        row={'Date':'26/11/14','Time':'10:11:12','Level':'INFO','Component':'Worker','Content':'body'}
        with self.assertRaisesRegex(ValueError,'RECONSTRUCTION_MISMATCH'):
            reference_header('Spark','26/11/14 10:11:12 INFO Worker: different',row)
    @unittest.skipUnless((ROOT/'java-envelope-frozen-predictions.json').is_file() and
        all((ROOT/'loghub'/f'{name}_2k.log_structured.csv').is_file() for name in RAW_PINS),
        'Optional licensed local Java references unavailable')
    def test_frozen_first_pass_preserves_failure_and_denominators(self):
        report=evaluate();total=report['total']
        self.assertEqual(4000,total['all_events'])
        self.assertEqual(4000,total['reference_scored_events'])
        self.assertEqual(0,total['excluded_reference_events'])
        self.assertEqual(292,total['reference_unannotated_trailing_whitespace_events'])
        self.assertEqual(20000,total['reference_header_fields'])
        self.assertEqual((8000,0,12000),(total['TP'],total['FP'],total['FN']))
        self.assertEqual(0,report['families'][1]['exact_header_events'])
        self.assertFalse(report['body_accuracy_verified'])
        self.assertFalse(report['reference_templates_used_for_training'])

    @unittest.skipUnless((ROOT/'java-envelope-frozen-predictions.json').is_file() and
        all((ROOT/'loghub'/f'{name}_2k.log_structured.csv').is_file() for name in RAW_PINS),
        'Optional licensed local Java references unavailable')
    def test_current_conservative_context_has_no_false_reference_fields(self):
        report=evaluate(current=True);total=report['total']
        self.assertEqual(4000,total['reference_scored_events'])
        self.assertEqual((16140,0,3860),(total['TP'],total['FP'],total['FN']))
        self.assertEqual(2000,total['auxiliary_context_exact'])
        self.assertEqual(2000,total['auxiliary_context_fields'])
        self.assertEqual('EXPLORATORY_AFTER_EXPOSURE',report['evidence_class'])
        self.assertEqual(4000,total['original_records_preserved'])
        self.assertFalse(report['body_accuracy_verified'])

if __name__=='__main__':unittest.main()
