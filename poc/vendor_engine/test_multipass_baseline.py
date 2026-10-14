import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent

class MultiPassBaselineTests(unittest.TestCase):
    def test_owner_accuracy_baseline_manifest_is_pinned(self):
        data=json.loads((ROOT/'multipass-baseline.json').read_text())
        self.assertEqual('parser-studio.poc.accuracy-first-multipass-baseline.v1',data['contract'])
        self.assertEqual('9d3f1ff57f53aba8268b2ad216eecc67421dfa2a',data['pr16_head'])
        self.assertEqual('872e3a583844bbbc0aa56f9d185936273c5baa33',data['pr15_evidence_head'])
        self.assertEqual(233,data['baseline_tests']['passed'])
        self.assertEqual(0,data['baseline_tests']['failed'])
        self.assertEqual(27968,data['commercial_source']['TP'])
        self.assertEqual((0,0),(data['commercial_source']['FP'],data['commercial_source']['FN']))
        self.assertEqual(6048,data['security_framing']['TP'])
        self.assertEqual((0,0),(data['security_framing']['FP'],data['security_framing']['FN']))
        self.assertFalse(data['runtime_is_acceptance_gate'])
        self.assertTrue(data['safety_bounds_required'])
        self.assertFalse(data['dictionary_attempted'])
        self.assertFalse(data['masking_optimization'])

if __name__=='__main__': unittest.main()
