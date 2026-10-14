import unittest
from benchmark_unseen_json_oracle import evaluate

class UnseenJsonOracleTests(unittest.TestCase):
    def test_new_json_vendor_slice_is_exact_without_relabeling_other_formats(self):
        result=evaluate();t=result['total']
        self.assertEqual(32,t['events'])
        self.assertEqual(3372,t['TP'])
        self.assertEqual(0,t['FP'])
        self.assertEqual(0,t['FN'])
        self.assertEqual(32,t['exact'])
        self.assertEqual(32,t['raw_preserved'])
        self.assertEqual(0,t['false_complete'])
        self.assertEqual('INDEPENDENT_STDLIB_JSON_GOLD_ONLY_NOT_ALL_VENDOR_FAMILIES',result['evidence_class'])

if __name__=='__main__':unittest.main()
