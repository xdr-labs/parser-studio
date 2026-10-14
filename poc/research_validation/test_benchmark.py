"""Independent scorer regression; no external corpus inspection or engine edits."""
import unittest
from benchmark import Probe, make_kv, score, synthetic_families
from candidate import parse_candidate
from source_parse import SourceEvent, ValueSpan

class ScorerTests(unittest.TestCase):
    def test_exact_duplicate_occurrences(self):
        p=make_kv([('tag','a',''),('tag','b','')])
        result=score([p],[parse_candidate(p.raw)])
        self.assertEqual(result['exact_native_key_value_byte_span']['TP'],2)
        self.assertEqual(result['exact_field_events'],1)

    def test_dropping_one_duplicate_is_not_success(self):
        p=make_kv([('tag','a',''),('tag','b','')])
        event=SourceEvent(p.raw,vendor_fields={'tag':'a'},value_spans=[ValueSpan('tag',4,5)],covered=[(0,len(p.raw))],primitive_fields=1)
        result=score([p],[event])
        self.assertEqual(result['exact_native_key_value_byte_span']['TP'],1)
        self.assertEqual(result['exact_native_key_value_byte_span']['FN'],1)
        self.assertEqual(result['falsely_complete_events'],1)

    def test_wrong_span_is_both_false_positive_and_false_negative(self):
        p=make_kv([('x','abc','')])
        event=SourceEvent(p.raw,vendor_fields={'x':'abc'},value_spans=[ValueSpan('x',1,4)],covered=[(0,len(p.raw))],primitive_fields=1)
        result=score([p],[event])['exact_native_key_value_byte_span']
        self.assertEqual((result['TP'],result['FP'],result['FN']),(0,1,1))

    def test_parser_exception_never_counts_as_exact_empty_success(self):
        result=score([Probe('bad',(),False)],[ValueError('test failure')])
        self.assertEqual(result['parser_exceptions'],1)
        self.assertEqual(result['exact_field_events'],0)

    def test_synthetic_train_is_hash_disjoint(self):
        families=synthetic_families()
        for family in families.values():
            self.assertFalse(set(family['train']) & {p.raw for p in family['test']})
        self.assertEqual(sum(len(f['test']) for f in families.values()),264)

if __name__=='__main__':unittest.main()
