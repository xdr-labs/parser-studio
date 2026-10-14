import unittest

from benchmark_multipass_residual import evaluate


class MultiPassResidualBenchmarkTests(unittest.TestCase):
    def test_residual_pass_improves_exact_fields_without_fp_or_false_complete(self):
        result=evaluate();before=result['baseline'];after=result['candidate']
        self.assertEqual(72,result['all_events'])
        self.assertGreater(after['TP'],before['TP'])
        self.assertLess(after['FN'],before['FN'])
        self.assertLessEqual(after['FP'],before['FP'])
        self.assertEqual(0,after['FP'])
        self.assertEqual(0,after['FN'])
        self.assertEqual(after['gold_fields'],after['TP'])
        self.assertEqual(after['events'],after['exact_events'])
        self.assertEqual(after['events'],after['raw_preserved'])
        self.assertLessEqual(after['false_complete'],before['false_complete'])
        self.assertEqual(0,after['false_complete'])
        self.assertFalse(result['runtime_is_acceptance_gate'])
        self.assertFalse(result['dictionary_attempted'])
        self.assertFalse(result['masking_optimization'])


if __name__=='__main__':
    unittest.main()
