import unittest
from benchmark_multipass_adjudication import evaluate
class MultiPassAdjudicatorBenchmarkTests(unittest.TestCase):
    def test_mp5_acceptance_metrics(self):
        r=evaluate();c=r['commercial_source']
        self.assertEqual((27968,0,0),(c['TP'],c['FP'],c['FN']));self.assertEqual(391,c['exact_tree_events'])
        self.assertEqual(r['waf_suricata_records'],r['waf_suricata_base_identical'])
        self.assertEqual((482,0,0),(r['cef_commercial']['TP'],r['cef_commercial']['FP'],r['cef_commercial']['FN']))
        self.assertEqual((900,0,0),(r['cef_authored']['TP'],r['cef_authored']['FP'],r['cef_authored']['FN']))
        self.assertEqual((3552,0,0),(r['leef_authored']['TP'],r['leef_authored']['FP'],r['leef_authored']['FN']))
        self.assertEqual((19,0,0),(r['leef_external_xa6']['TP'],r['leef_external_xa6']['FP'],r['leef_external_xa6']['FN']))
        self.assertFalse(r['runtime_is_acceptance_gate'])
if __name__=='__main__':unittest.main()
