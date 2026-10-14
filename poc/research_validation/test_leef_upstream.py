"""Independent LEEF reference and metric accounting regressions."""
import dataclasses
import unittest
from benchmark_leef_upstream import native_reference
from benchmark_security_followon import leef_cases,leaf_metrics,parse_security_leef,parse_security_source

class LEEFReferenceTests(unittest.TestCase):
    def test_literal_backslash_tab_is_not_new_field(self):
        row=native_reference(r'LEEF:1.0|V|IPS|1|42|src=a\tdst=b')
        self.assertEqual(row['tree']['leef_extension'],{'src':r'a\tdst=b'})
        self.assertEqual(len(row['refs']),6)
    def test_real_tab_and_utf8_offsets(self):
        raw='LEEF:1.0|V|IPS|1|42|usrName=Zoë\taction=deny'
        row=native_reference(raw)
        self.assertEqual(len(row['refs']),7)
        for path,value,a,b in row['refs']:self.assertEqual(raw.encode()[a:b].decode(),value)
    def test_incomplete_v2_is_not_silently_repaired(self):
        with self.assertRaises(ValueError):native_reference('LEEF:2.0|V|IPS|1|42|a=b')
    def test_duplicate_key_retains_all_occurrences(self):
        row=native_reference('LEEF:2.0|V|IPS|1|42|^|tag=a^tag=b')
        self.assertEqual(row['tree']['leef_extension']['tag'],['a','b'])
        self.assertEqual(len(row['refs']),8)
    def test_unsupported_header_escape_is_not_false_gold(self):
        with self.assertRaises(ValueError):native_reference(r'LEEF:1.0|V\|X|IPS|1|42|a=b')
    def test_wrong_span_is_false_positive_and_false_negative(self):
        row=leef_cases()[0]
        def incorrect(raw):
            event=parse_security_leef(raw,base_parser=parse_security_source)
            event.value_spans[-1]=dataclasses.replace(event.value_spans[-1],start_byte=event.value_spans[-1].start_byte+1)
            return event
        measured=leaf_metrics([row],incorrect)
        self.assertEqual((measured['FP'],measured['FN'],measured['exact_records']),(1,1,0))

if __name__=='__main__':unittest.main()
