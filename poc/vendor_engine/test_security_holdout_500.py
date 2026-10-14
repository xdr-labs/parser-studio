"""Pin the derived 500-case lexical stress evidence without calling it vendor holdout."""
import unittest
from benchmark_security_holdout_500 import evaluate

class SecurityLexicalMutationTests(unittest.TestCase):
    def test_five_hundred_lexical_mutations_preserve_exact_source(self):
        result=evaluate();tot=result['total']
        self.assertEqual('DERIVED_LEXICAL_MUTATIONS_OF_PREVIOUSLY_SEEN_VENDOR_FIXTURES_NOT_NEW_VENDOR_TRAFFIC',result['evidence_class'])
        self.assertEqual(500,tot['events'])
        self.assertEqual(500,tot['exact'])
        self.assertEqual(500,tot['raw_preserved'])
        self.assertEqual(0,tot['FP'])
        self.assertEqual(0,tot['FN'])
        self.assertEqual(0,tot['false_complete'])
        self.assertEqual(tot['fields'],tot['TP'])

if __name__=='__main__':unittest.main()
