import unittest
from pathlib import Path
from benchmark_multipass_cef import evaluate,MANIFEST,CACHE

class MultiPassCEFBenchmarkTests(unittest.TestCase):
    @unittest.skipUnless(MANIFEST.is_file() and all((CACHE/name).is_file() for name in ('test-checkpoint.json','test-cisco-asa.json','test-fp-ngfw-smc.json','test-trend-micro.json')),
                         'Local rights-reviewed CEF source cache unavailable')
    def test_mp2_acceptance_metrics(self):
        result=evaluate();commercial=result['commercial'];authored=result['authored'];malformed=result['malformed']
        self.assertEqual((482,0,0),(commercial['candidate']['TP'],commercial['candidate']['FP'],commercial['candidate']['FN']))
        self.assertEqual((482,0,0),(commercial['baseline']['TP'],commercial['baseline']['FP'],commercial['baseline']['FN']))
        self.assertEqual((840,36,60),(authored['baseline']['TP'],authored['baseline']['FP'],authored['baseline']['FN']))
        self.assertEqual((900,0,0),(authored['candidate']['TP'],authored['candidate']['FP'],authored['candidate']['FN']))
        self.assertEqual(36,authored['baseline']['falsely_complete']);self.assertEqual(0,authored['candidate']['falsely_complete'])
        self.assertEqual(0,malformed['candidate']['falsely_complete'])
        self.assertEqual(24,malformed['candidate']['raw_preserved'])

if __name__=='__main__':unittest.main()
