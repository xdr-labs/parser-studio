"""Independent security holdout status is never misreported as field accuracy."""
import unittest
from benchmark_unseen_vendor_gate import evaluate

class UnseenVendorGateTests(unittest.TestCase):
    def test_holdout_is_real_and_failure_is_visible(self):
        result=evaluate();total=result['total']
        self.assertGreaterEqual(total['events'],500)
        self.assertGreaterEqual(len(result['families']),5)
        self.assertEqual(total['events'],sum(total.get(k,0) for k in ('SOURCE_PARSED','PARTIAL','RAW_ONLY','exceptions')))
        self.assertEqual(0,total.get('raw_loss',0))
        self.assertEqual(0,total.get('exceptions',0))
        self.assertEqual('FAIL',result['complete_rate_gate'])
        self.assertEqual('NOT_QUALIFIED',result['final_engine_exit_gate'])
        self.assertEqual('NOT_MEASURED_INDEPENDENT_ORACLE_PENDING',result['exact_field_value_type_span_f1'])

if __name__=='__main__':unittest.main()
