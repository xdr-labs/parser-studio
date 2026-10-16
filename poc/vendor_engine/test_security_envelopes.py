"""Security-product headers must not hide structured original payloads."""
from pathlib import Path
import json
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from security_source import parse_security_source
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import parse_source,assert_source_accounting

CEF='CEF:0|Example|IPS|7.4|100|Detection|7|src=192.0.2.1 msg=signature x\\=y request=/a?x\\=1'
LEEF='LEEF:2.0|Example|Firewall|81|100|0x09|src=192.0.2.1\tmsg=two words; x=y\turl=/a?x=1'
PREFIXES=('Nov 14 10:11:12 gateway ', '<134>Nov 14 10:11:12 gateway ', '<134> ')


class SecurityEnvelopeTests(unittest.TestCase):
    def test_tagless_cef_and_leef_keep_every_body_value(self):
        for prefix in PREFIXES:
            for payload in (CEF,LEEF):
                with self.subTest(prefix=prefix,format=payload[:4]):
                    expected=parse_source(payload)
                    out=parse_security_source(prefix+payload)
                    self.assertEqual(expected.vendor_fields,out.vendor_fields.get('body'))
                    self.assertEqual('SOURCE_PARSED',out.status)
                    self.assertEqual(prefix+payload,out.raw)
                    shift=len(prefix.encode())
                    actual=[(s.path,s.start_byte,s.end_byte) for s in out.value_spans if s.path.startswith('body.')]
                    self.assertEqual([('body.'+s.path,shift+s.start_byte,shift+s.end_byte) for s in expected.value_spans],actual)
                    assert_source_accounting(out)

    def test_tagless_json_and_cee_nested_arrays_and_unicode(self):
        data={'event_type':'alert','headers':[{'name':'x','value':'Zoë'},{'name':'x','value':'Zoë'}],'rules':[], 'value':None}
        payload=json.dumps(data,ensure_ascii=False,indent=2)
        for prefix in PREFIXES:
            for marker in ('','@cee: '):
                out=parse_security_source(prefix+marker+payload)
                self.assertEqual(data,out.vendor_fields.get('body'))
                self.assertEqual('SOURCE_PARSED',out.status)
                self.assertTrue(all(s.source_segments[0]=='body' for s in out.value_spans if s.path.startswith('body.') and s.source_segments))
                assert_source_accounting(out)

    def test_year_bearing_bsd_security_header_is_separated_before_structured_body(self):
        prefix='<166>Oct 15 2026 00:05:03 EDGE-FW01 '
        for payload in (CEF,LEEF,'action=deny src_ip=192.0.2.10 dst_port=443'):
            with self.subTest(payload=payload[:8]):
                out=parse_security_source(prefix+payload)
                self.assertEqual('SOURCE_PARSED',out.status)
                self.assertEqual('166',out.vendor_fields['syslog']['pri'])
                self.assertEqual('2026',out.vendor_fields['syslog']['year'])
                self.assertEqual('EDGE-FW01',out.vendor_fields['syslog']['hostname'])
                self.assertIn('body',out.vendor_fields)
                assert_source_accounting(out)

    def test_pri_csv_body_is_preserved_but_no_column_meaning_claim(self):
        payload='1,2026/11/14 10:11:12,THREAT,"name, a=b",,'
        out=parse_security_source('<134>'+payload)
        self.assertEqual({'column_0':'1','column_1':'2026/11/14 10:11:12','column_2':'THREAT','column_3':'name, a=b','column_4':'','column_5':''},out.vendor_fields.get('body'))
        self.assertEqual('PARTIAL',out.status)
        self.assertIn('UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION',out.issues)
        self.assertFalse(out.normalization_attempted)
        assert_source_accounting(out)

    def test_new_header_layouts_are_shared_with_stream_framing(self):
        payload=json.dumps({'headers':[{'name':'x','value':'braces {} and []'}],'ruleGroupList':[]},indent=2)
        records=[PREFIXES[0]+payload,PREFIXES[1]+'@cee: '+payload,'<134> '+payload,PREFIXES[0]+CEF]
        batch=parse_security_batch('\r\n'.join(records))
        self.assertEqual(records,[f.raw for f in batch.frames])
        self.assertTrue(all(f.event.status=='SOURCE_PARSED' for f in batch.frames))
        assert_batch_accounting(batch)

    def test_invalid_header_or_prose_is_not_rescued_by_marker_search(self):
        for prefix in ('<192>Nov 14 10:11:12 gateway ','<134>Nov 31 10:11:12 gateway ', 'Nov 14 24:11:12 gateway ', 'Nov 14 10:11:12 gateway explanatory text '):
            out=parse_security_source(prefix+CEF)
            self.assertNotIn('cef_header',out.vendor_fields.get('body',{}))
            self.assertNotEqual('SOURCE_PARSED',out.status)
            assert_source_accounting(out)

    def test_malformed_structured_body_never_turns_into_csv_success(self):
        for payload in ('CEF:0|incomplete','LEEF:3.0|not|supported','@cee: {"x":','{"x":1,"x":2}'):
            out=parse_security_source(PREFIXES[0]+payload)
            self.assertNotEqual('SOURCE_PARSED',out.status)
            self.assertEqual(PREFIXES[0]+payload,out.raw)
            self.assertGreater(out.residual_bytes,0)

    def test_existing_tagged_headers_and_message_values_unchanged(self):
        for payload in (CEF,LEEF):
            raw='<134>Nov 14 10:11:12 gateway agent: '+payload
            self.assertEqual(parse_source(raw).vendor_fields,parse_security_source(raw).vendor_fields)
        raw='message="Nov 14 10:11:12 gateway CEF:0|opaque" action=deny'
        self.assertEqual(parse_source(raw).vendor_fields,parse_security_source(raw).vendor_fields)


if __name__=='__main__':unittest.main()
