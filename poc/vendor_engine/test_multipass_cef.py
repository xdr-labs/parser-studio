import dataclasses
import unittest
from security_source import parse_security_source
from source_parse import assert_source_accounting
try:
    from security_cef import parse_security_cef
except ModuleNotFoundError:
    parse_security_cef=None

P='CEF:0|Example|IPS|1|42|Blocked|7|'

class MultiPassCEFTests(unittest.TestCase):
    def parse(self,raw):
        self.assertIsNotNone(parse_security_cef)
        event=parse_security_cef(raw,base_parser=parse_security_source)
        self.assertEqual(raw,event.raw);assert_source_accounting(event);return event

    def test_literal_quotes_are_native_value_characters(self):
        for value in ('"blocked connection"','"quoted"suffix',"'literal'"):
            with self.subTest(value=value):
                event=self.parse(P+'msg='+value+' act=deny')
                self.assertEqual({'msg':value,'act':'deny'},event.vendor_fields['cef_extension'])
                self.assertEqual('SOURCE_PARSED',event.status)

    def test_only_last_space_before_next_key_is_separator(self):
        raw=P+'msg=blocked   act=deny  '
        event=self.parse(raw)
        self.assertEqual({'msg':'blocked  ','act':'deny'},event.vendor_fields['cef_extension'])
        span=next(x for x in event.value_spans if x.path=='cef_extension.msg')
        self.assertEqual(b'blocked  ',raw.encode()[span.start_byte:span.end_byte])

    def test_known_escapes_empty_unicode_and_duplicates(self):
        raw=P+r'msg=Zoë\nnext\=x tag=a tag=b empty= path=C:\\logs'
        event=self.parse(raw)
        self.assertEqual({'msg':'Zoë\nnext=x','tag':['a','b'],'empty':'','path':'C:\\logs'},event.vendor_fields['cef_extension'])
        self.assertEqual('PARTIAL',event.status)
        self.assertEqual(2,sum(x.path=='cef_extension.tag' for x in event.value_spans))

    def test_framed_cef_preserves_original_byte_spans(self):
        for prefix in ('<134>Oct 14 12:00:00 sensor ips: ','<134>1 2026-10-14T12:00:00Z sensor ips 1 ALERT - ','Oct 14 12:00:00 sensor ips: '):
            with self.subTest(prefix=prefix):
                raw=prefix+P+'msg="Zoë"   act=deny'
                event=self.parse(raw)
                self.assertEqual('"Zoë"  ',event.vendor_fields['body']['cef_extension']['msg'])
                span=next(x for x in event.value_spans if x.path=='body.cef_extension.msg')
                self.assertEqual('"Zoë"  ',raw.encode()[span.start_byte:span.end_byte].decode())

    def test_other_security_formats_are_unchanged(self):
        for raw in ('{"action":"BLOCK","labels":[]}','@cee: {"event_type":"alert"}','src=192.0.2.1 action=deny','LEEF:1.0|V|IPS|1|42|act=deny'):
            with self.subTest(raw=raw):
                self.assertEqual(dataclasses.asdict(parse_security_source(raw)),dataclasses.asdict(self.parse(raw)))

    def test_truncated_escape_and_incomplete_headers_never_false_complete(self):
        for raw in ('CEF:0|short',P+'msg=bad\\',P+'msg=\x00',P+'msg='+('x'*131072)):
            with self.subTest(raw=raw[:64]):self.assertNotEqual('SOURCE_PARSED',self.parse(raw).status)

    def test_no_substring_admission(self):
        raw='opaque prefix '+P+'msg="value"'
        self.assertEqual(dataclasses.asdict(parse_security_source(raw)),dataclasses.asdict(self.parse(raw)))

if __name__=='__main__': unittest.main()
