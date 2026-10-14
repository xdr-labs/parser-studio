"""Independently generated typed/source-coordinate evidence for transports."""
from pathlib import Path
import json
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_security_envelopes import evaluate
from benchmark_security_sources import MANIFEST


class SecurityEnvelopeReferenceTests(unittest.TestCase):
    @unittest.skipUnless(all((MANIFEST.parent/'.cache'/x['cache_path']).is_file()
        for x in json.loads(MANIFEST.read_text())['fixtures']),
        'Previously pinned source examples unavailable locally')
    def test_every_derived_field_value_type_identity_and_span_matches(self):
        result=evaluate();new=result['candidate']['total'];old=result['baseline']['total']
        self.assertEqual(77,result['original_source_examples'])
        self.assertEqual(462,result['derived_transport_events'])
        self.assertEqual(14200,new['gold_fields'])
        self.assertEqual((14200,0,0),(new['TP'],new['FP'],new['FN']))
        self.assertEqual((4605,77,9595),(old['TP'],old['FP'],old['FN']))
        self.assertEqual(462,new['exact_event'])
        self.assertEqual(462,new['raw_preserved'])
        self.assertEqual(0,result['excluded_events'])
        self.assertFalse(result['dictionary_attempted'])
        self.assertFalse(result['masking_optimization'])
        self.assertFalse(result['native_verified'])


if __name__=='__main__':unittest.main()
