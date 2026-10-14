import unittest
from benchmark_multipass_leef import evaluate,MANIFEST,CACHE

class MultiPassLEEFBenchmarkTests(unittest.TestCase):
    @unittest.skipUnless(MANIFEST.is_file() and (CACHE/'example-0.leef').is_file(),'Local rights-reviewed LEEF documentation example unavailable')
    def test_mp3_acceptance_metrics(self):
        result=evaluate();auth=result['authored'];ext=result['external_xa6']
        self.assertEqual((0,0,3552),(auth['baseline']['TP'],auth['baseline']['FP'],auth['baseline']['FN']))
        self.assertEqual((3552,0,0),(auth['candidate']['TP'],auth['candidate']['FP'],auth['candidate']['FN']))
        self.assertEqual(192,auth['candidate']['exact_records']);self.assertEqual(0,auth['candidate']['falsely_complete'])
        self.assertEqual((0,0,19),(ext['baseline']['TP'],ext['baseline']['FP'],ext['baseline']['FN']))
        self.assertEqual((19,0,0),(ext['candidate']['TP'],ext['candidate']['FP'],ext['candidate']['FN']))
        self.assertEqual(1,ext['candidate']['exact_records']);self.assertEqual(1,ext['candidate']['raw_preserved'])

if __name__=='__main__':unittest.main()
