"""Independent oracle and accounting tests; no licensed source fixtures."""
from __future__ import annotations
import dataclasses
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from security_reference import json_reference,kv_reference
from benchmark_security import score

class SecurityReferenceTests(unittest.TestCase):
    def test_bare_interior_quote_is_not_shell_concatenation(self):
        raw='dstip=Unknown"AUTH-ID" action=deny'
        ref=kv_reference(raw)
        self.assertTrue(ref.complete)
        self.assertEqual(ref.tree['dstip'],'Unknown"AUTH-ID"')
        self.assertEqual(raw.encode()[ref.fields[0][2]:ref.fields[0][3]],b'Unknown"AUTH-ID"')

    def test_bare_apostrophe_is_literal_not_an_unclosed_shell_quote(self):
        ref=kv_reference("user=O'Brien action=deny")
        self.assertTrue(ref.complete)
        self.assertEqual(ref.tree,{'user':"O'Brien",'action':'deny'})

    def test_bare_unknown_escape_and_escaped_space(self):
        ref=kv_reference(r'path=C:\folder\name message=visible\ value')
        self.assertEqual(ref.tree,{'path':r'C:\folder\name','message':'visible value'})

    def test_json_repeated_values_and_colliding_display_paths(self):
        raw='{"a.b":"same","a":{"b":"same"},"arr":[false,0,null],"arr[0]":"same"}'
        ref=json_reference(raw)
        self.assertEqual(len(ref.fields),6)
        self.assertEqual([f[0] for f in ref.fields], [('a.b',),('a','b'),('arr',0),('arr',1),('arr',2),('arr[0]',)])
        for _,value,a,b in ref.fields:
            self.assertEqual(json.loads(raw.encode()[a:b]),value)

    def test_json_utf8_escaped_string_root_array_and_empty_containers(self):
        raw='[{"label":"Zoë","escaped":"\\u2603","empty":[],"blank":{}},9007199254740993]'
        ref=json_reference(raw)
        self.assertEqual(len(ref.fields),3)
        self.assertIn('empty',ref.tree['$array'][0])
        self.assertEqual(ref.fields[-1][1],9007199254740993)
        for _,value,a,b in ref.fields:self.assertEqual(json.loads(raw.encode()[a:b]),value)

    def test_invalid_json_never_yields_partial_oracle_success(self):
        for raw in ('{"x":1,"x":2}','{"x":NaN}','{"x":1} tail','{"x":"bad\nline"}'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):json_reference(raw)

    def test_partial_kv_prefix_and_duplicate_occurrences(self):
        raw='tag=a tag=a msg="unclosed fake=x'
        ref=kv_reference(raw)
        self.assertFalse(ref.complete);self.assertEqual(ref.tree,{'tag':['a','a']})
        self.assertEqual(len(ref.fields),2)

    def test_wrapped_vendor_body_offsets(self):
        raw='<134>1 2026-10-14T10:00:00Z sensor app 1 ID - src=192.0.2.1 action=deny'
        ref=kv_reference(raw)
        self.assertEqual(ref.tree,{'src':'192.0.2.1','action':'deny'})
        self.assertEqual(ref.body_start_byte,raw.index('src='))

    def test_nul_corruption_is_not_success_or_silently_excluded(self):
        raw='src=192.0.2.1\x00';ref=kv_reference(raw)
        self.assertFalse(ref.scorable)
        event={'raw':raw,'vendor_fields':{},'value_spans':[],'status':'RAW_ONLY'}
        s=score([ref],[event])
        self.assertEqual(s['input_records'],1)
        self.assertEqual(s['invalid_inputs_not_field_scored'],1)
        self.assertIsNone(s['exact_native_key_value_byte_span']['f1'])
        self.assertEqual(s['fully_correct_and_complete_records'] if 'fully_correct_and_complete_records' in s else 0,0)

    def test_empty_container_loss_fails_tree_and_complete(self):
        raw='{"items":[],"x":1}';ref=json_reference(raw)
        _,_,a,b=ref.fields[0]
        event={'raw':raw,'vendor_fields':{'x':1},'value_spans':[{'path':'x','source_segments':['x'],'start_byte':a,'end_byte':b}],'status':'SOURCE_PARSED'}
        s=score([ref],[event])
        self.assertEqual(s['exact_native_key_value_byte_span']['TP'],1)
        self.assertEqual(s['exact_vendor_tree_records'],0)
        self.assertEqual(s['falsely_complete_records'],1)

    def test_wrong_identity_not_hidden_by_same_value(self):
        raw='{"a":1}';ref=json_reference(raw);_,_,a,b=ref.fields[0]
        event={'raw':raw,'vendor_fields':{'b':1},'value_spans':[{'path':'b','source_segments':['b'],'start_byte':a,'end_byte':b}],'status':'SOURCE_PARSED'}
        s=score([ref],[event]);m=s['exact_native_key_value_byte_span']
        self.assertEqual((m['TP'],m['FP'],m['FN']),(0,1,1))

if __name__=='__main__':unittest.main()
