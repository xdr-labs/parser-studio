import unittest

from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch


class MultiPassSecurityGateTests(unittest.TestCase):
    def test_stream_framing_can_dispatch_each_record_to_multipass_parser(self):
        raw='{"action":"BLOCK"}\nLEEF:2.0|V|IPS|1|42|x7C|src=192.0.2.1|act=deny'
        batch=parse_security_batch(raw,parser=parse_security_multipass)
        self.assertEqual(2,len(batch.frames))
        self.assertEqual('BLOCK',batch.frames[0].event.vendor_fields['action'])
        self.assertEqual('deny',batch.frames[1].event.vendor_fields['leef_extension']['act'])

    def test_all_required_security_families_hold_exact_accuracy_and_safety(self):
        from benchmark_multipass_security_gate import evaluate
        result=evaluate()

        direct=result['security_json_cee']['direct']
        self.assertEqual((2110,0,0),(direct['TP'],direct['FP'],direct['FN']))
        self.assertEqual(77,direct['raw_preserved'])
        self.assertEqual(0,direct['false_complete'])

        cee=result['security_json_cee']['cee']
        self.assertEqual((5127,0,0),(cee['TP'],cee['FP'],cee['FN']))
        self.assertEqual(198,cee['exact_events'])

        commercial=result['commercial_ngfw']['total']
        self.assertEqual((27968,0,0),(commercial['TP'],commercial['FP'],commercial['FN']))
        self.assertEqual(392,commercial['raw_preserved'])
        self.assertEqual(391,commercial['exact_tree_events'])
        self.assertEqual(1,commercial['reference_excluded_events'])

        cef=result['cef']
        self.assertEqual((482,0,0),(cef['total']['TP'],cef['total']['FP'],cef['total']['FN']))
        self.assertEqual((900,0,0),(cef['authored']['TP'],cef['authored']['FP'],cef['authored']['FN']))
        self.assertEqual(0,cef['authored']['falsely_complete'])
        expected_groups={
            'test-checkpoint.json':83,
            'test-cisco-asa.json':75,
            'test-fp-ngfw-smc.json':162,
            'test-trend-micro.json':162,
        }
        self.assertEqual(expected_groups,{name:metrics['TP'] for name,metrics in cef['groups'].items()})
        self.assertTrue(all(m['FP']==0 and m['FN']==0 for m in cef['groups'].values()))

        leef=result['leef']
        self.assertEqual((3552,0,0),(leef['authored']['TP'],leef['authored']['FP'],leef['authored']['FN']))
        self.assertEqual((19,0,0),(leef['external_xa6']['TP'],leef['external_xa6']['FP'],leef['external_xa6']['FN']))
        self.assertEqual(0,leef['authored']['falsely_complete'])

        framing=result['stream_framing']
        self.assertEqual((6048,0,0),(framing['TP'],framing['FP'],framing['FN']))
        self.assertEqual(216,framing['exact_record_boundaries'])
        self.assertEqual(216,framing['exact_record_trees'])
        self.assertEqual(0,framing['false_record_boundaries']+framing['missing_record_boundaries'])

        document=result['document_state']
        self.assertEqual(1,document['physical_record_ledger_exact'])
        self.assertEqual(document['declared_rows'],document['declared_exact_tree'])
        self.assertEqual(document['declared_rows'],document['declared_exact_spans'])
        self.assertEqual(document['ordinary_records'],document['ordinary_unchanged'])
        self.assertEqual(document['rotated_without_types'],document['rotated_without_types_not_complete'])

        residual=result['residual']['candidate']
        self.assertEqual((2160,0,0),(residual['TP'],residual['FP'],residual['FN']))
        self.assertEqual(72,residual['exact_events'])
        self.assertEqual(0,residual['false_complete'])

        malformed=result['malformed_controls']
        self.assertEqual(malformed['records'],malformed['raw_preserved'])
        self.assertEqual(0,malformed['false_complete'])
        self.assertEqual(0,malformed['stream_truncated_false_complete'])
        self.assertEqual(1,malformed['stream_raw_preserved'])

        required={'AWS WAF','Suricata/IDS/IPS','FortiGate','PAN-OS','Check Point',
                  'Cisco ASA','Forcepoint NGFW/SMC','Trend Micro','CEF','LEEF','CEE',
                  'Syslog-wrapped variants','nested JSON/arrays','malformed/truncated',
                  'duplicate/repeated fields','escaped/quoted values'}
        self.assertTrue(required<=set(result['coverage']))
        self.assertFalse(result['runtime_is_acceptance_gate'])
        self.assertFalse(result['dictionary_attempted'])
        self.assertFalse(result['masking_optimization'])


if __name__=='__main__':
    unittest.main()
