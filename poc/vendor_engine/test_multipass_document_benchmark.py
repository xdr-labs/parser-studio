import unittest
from benchmark_multipass_document import evaluate

class MultiPassDocumentBenchmarkTests(unittest.TestCase):
    def test_mp4_state_isolation_acceptance(self):
        c=evaluate()['counts']
        self.assertEqual(240,c['physical_records'])
        self.assertEqual(1,c['physical_record_ledger_exact'])
        self.assertEqual(c['declared_rows'],c['declared_exact_tree'])
        self.assertEqual(c['declared_rows'],c['declared_exact_spans'])
        self.assertEqual(c['rotated_without_types'],c['rotated_without_types_not_complete'])
        self.assertEqual(c['ordinary_records'],c['ordinary_unchanged'])

if __name__=='__main__':unittest.main()
