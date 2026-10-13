"""Synthetic oracle tests of source parsing success independent of roles."""
import hashlib
import json
import unittest
from source_field_metrics import SourceField,SourceRecord,score_source_fields


def rec(raw,fields=(),status="SOURCE_PARSED",unparsed_bytes=0):
    return SourceRecord(hashlib.sha256(raw.encode()).hexdigest(),tuple(SourceField(*x) for x in fields),status,len(raw.encode()),unparsed_bytes)


class SourceFieldMetricsTests(unittest.TestCase):
    def test_correct_vendor_fields_and_empty_values(self):
        gold=[rec('a',[('kv:srcip','192.0.2.4'),('kv:weird.vendor','two words'),('kv:empty','')])]
        metric=score_source_fields(gold,list(gold))
        self.assertEqual({'TP':3,'FP':0,'FN':0,'precision':1.0,'recall':1.0,'f1':1.0},metric['exact_source_field'])
        self.assertFalse(metric['semantic_mapping_attempted'])

    def test_correct_value_but_wrong_vendor_path_is_not_tp(self):
        gold=[rec('a',[('kv:srcip','192.0.2.4')])]
        seen=[rec('a',[('kv:destip','192.0.2.4')])]
        m=score_source_fields(gold,seen)['exact_source_field']
        self.assertEqual([0,1,1],[m['TP'],m['FP'],m['FN']])

    def test_json_typed_string_vs_integer_and_null_distinct(self):
        gold=[rec('a',[('/count',80),('/empty',None),('/list',[1,'two'])])]
        seen=[rec('a',[('/count','80'),('/empty',None),('/list',[1,'two'])])]
        m=score_source_fields(gold,seen)['exact_source_field']
        self.assertEqual([2,1,1],[m['TP'],m['FP'],m['FN']])

    def test_duplicate_field_occurrences_are_counted(self):
        gold=[rec('a',[('kv:key','first'),('kv:key','second')])]
        seen=[rec('a',[('kv:key','second')])]
        m=score_source_fields(gold,seen)['exact_source_field']
        self.assertEqual([1,0,1],[m['TP'],m['FP'],m['FN']])

    def test_metadata_only_record_stays_in_event_ledger(self):
        gold=[rec('a',status='STRUCTURED_EMPTY'),rec('b',[('kv:a','v')])]
        seen=[rec('a',status='STRUCTURED_EMPTY'),rec('b',status='RAW_ONLY',unparsed_bytes=1)]
        m=score_source_fields(gold,seen)
        self.assertEqual(2,m['raw_records_accounted'])
        self.assertEqual(1,m['raw_only_records'])
        self.assertEqual(1,m['structured_empty_records'])
        self.assertEqual(1,m['exact_source_field']['FN'])
        self.assertEqual(1,m['unparsed_bytes'])

    def test_no_raw_values_leak_into_report(self):
        name='customer-top-secret-12345'
        m=score_source_fields([rec('a',[('kv:username',name)])],[rec('a',[('kv:username',name)])])
        self.assertNotIn(name,json.dumps(m))
        self.assertNotIn('username',json.dumps(m))

    def test_record_reordering_cannot_manufacture_agreement(self):
        gold=[rec('x'),rec('y')]
        with self.assertRaisesRegex(ValueError,'SOURCE_RECORD_IDENTITY_MISMATCH'):
            score_source_fields(gold,list(reversed(gold)))

    def test_bogus_counts_do_not_count_as_complete_parsing(self):
        gold=[rec('a',[('kv:key','v')])]
        obs=[rec('a',[('kv:key','v')],status='PARTIAL',unparsed_bytes=1)]
        m=score_source_fields(gold,obs)
        self.assertEqual(1,m['exact_source_field']['TP'])
        self.assertEqual(0,m['fully_parsed_records'])
        self.assertEqual(1,m['partial_records'])

    def test_event_count_mismatch_and_bad_contract_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'SOURCE_EVENT_COUNT_MISMATCH'):
            score_source_fields([rec('a')],[])
        wrong=SourceRecord('invalid',tuple(),'SOURCE_PARSED',1,0)
        with self.assertRaisesRegex(ValueError,'INVALID_SOURCE_RECORD_CONTRACT'):
            score_source_fields([wrong],[wrong])


if __name__=='__main__':
    unittest.main()
