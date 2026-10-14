"""Visible source KV occurrences, quote boundaries and no-loss recovery."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_parse import parse_source,assert_source_accounting

class SourceKeyValueTests(unittest.TestCase):
    def test_duplicate_values_and_following_fields_are_not_dropped(self):
        raw='user=alice group=ops group=admins action=allow'
        out=parse_source(raw)
        self.assertEqual({'user':'alice','group':['ops','admins'],'action':'allow'},out.vendor_fields)
        self.assertEqual(4,out.primitive_fields)
        self.assertEqual('SOURCE_PARSED',out.status)
        spans=[x for x in out.value_spans if x.path=='group']
        self.assertEqual(['ops','admins'],[raw.encode()[x.start_byte:x.end_byte].decode() for x in spans])
        assert_source_accounting(out)

    def test_single_quotes_empty_values_unicode_and_escaped_quote(self):
        raw="name='Zoë analyst' note='O\\'Brien' empty='' next=ok"
        out=parse_source(raw)
        self.assertEqual({'name':'Zoë analyst','note':"O'Brien",'empty':'','next':'ok'},out.vendor_fields)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual(4,len(out.value_spans))
        assert_source_accounting(out)

    def test_underscore_keys_and_leading_space_preserve_source_names(self):
        raw='  _vendor=alpha user=alice action=allow  '
        out=parse_source(raw)
        self.assertEqual({'_vendor':'alpha','user':'alice','action':'allow'},out.vendor_fields)
        self.assertEqual('KV',out.syntax)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual(0,out.residual_bytes)
        assert_source_accounting(out)

    def test_unquoted_escaped_space_and_unknown_escape_remain_visible(self):
        raw=r'path=C:\Program\ Files message=hello\ world action=allow'
        out=parse_source(raw)
        self.assertEqual({'path':r'C:\Program Files','message':'hello world','action':'allow'},out.vendor_fields)
        self.assertEqual('SOURCE_PARSED',out.status)
        assert_source_accounting(out)

    def test_malformed_quote_retains_prefix_and_opaque_tail(self):
        for tail in ('message="unterminated fake=x other=y',"message='closed'junk fake=x other=y"):
            raw='user=alice action=allow '+tail
            out=parse_source(raw)
            self.assertEqual({'user':'alice','action':'allow'},out.vendor_fields)
            self.assertEqual('PARTIAL',out.status)
            self.assertEqual(tail,''.join(raw[a:b] for a,b in out.unparsed))
            assert_source_accounting(out)

    def test_duplicate_empty_and_equal_values_keep_occurrence_spans(self):
        raw="x='' x=\"\" x=same x=same y=next"
        out=parse_source(raw)
        self.assertEqual(['','','same','same'],out.vendor_fields['x'])
        self.assertEqual(5,len(out.value_spans))
        self.assertEqual(5,out.primitive_fields)
        self.assertEqual('next',out.vendor_fields['y'])

    def test_unquoted_empty_value_remains_explicitly_partial(self):
        out=parse_source('empty= next=ok')
        self.assertEqual({'empty':'','next':'ok'},out.vendor_fields)
        self.assertEqual('PARTIAL',out.status)
        self.assertTrue(out.issues)

    def test_untrusted_object_keys_do_not_enter_exportable_field_tree(self):
        raw='safe=yes constructor=untrusted next=ok'
        out=parse_source(raw)
        self.assertEqual({'safe':'yes'},out.vendor_fields)
        self.assertEqual('PARTIAL',out.status)
        self.assertEqual(raw,out.raw)
        assert_source_accounting(out)

    def test_wrapped_duplicate_fields_keep_outer_and_inner_spans(self):
        raw="<134>Nov 14 10:11:12 host app: user=alice group='first value' group=second action=allow"
        out=parse_source(raw)
        self.assertEqual(['first value','second'],out.vendor_fields['body']['group'])
        self.assertEqual('SOURCE_PARSED',out.status)
        assert_source_accounting(out)

    def test_literal_t_key_and_tab_prefix_are_not_stripped_as_letters(self):
        for raw in ('t=value other=ok','\tt=value other=ok','<134>\tt=value other=ok'):
            event=parse_source(raw)
            self.assertEqual({'t':'value','other':'ok'},event.vendor_fields)
            self.assertEqual('SOURCE_PARSED',event.status)
            assert_source_accounting(event)

    def test_field_and_input_bounds_keep_unconsumed_source(self):
        from source_kv import decode_source_kv
        raw='a=one a=two a=three z=last'
        out=decode_source_kv(raw,max_fields=2)
        self.assertEqual({'a':['one','two']},out.fields)
        self.assertEqual(2,out.primitive_fields)
        self.assertIn('KV_SOURCE_FIELD_LIMIT',out.issues)
        self.assertLess(max(b for _,b in out.covered),len(raw))
        self.assertFalse(decode_source_kv('a=x'+chr(0)).fields)
        self.assertFalse(decode_source_kv('a='+'x'*131072).fields)
        with self.assertRaisesRegex(ValueError,'BOUND_INVALID'):
            decode_source_kv(raw,max_fields=0)

    def test_unmasked_generated_occurrences_and_decoded_values(self):
        from benchmark_source_kv import records
        from collections import Counter
        for record in records():
            event=parse_source(record['raw'])
            self.assertEqual(record['fields'],event.vendor_fields)
            expected=Counter(tuple(x) for x in record['spans'])
            observed=Counter((x.path,x.start_byte,x.end_byte) for x in event.value_spans)
            self.assertEqual(expected,observed)
            self.assertEqual(record['raw'],event.raw)
            assert_source_accounting(event)

if __name__=='__main__':unittest.main()
