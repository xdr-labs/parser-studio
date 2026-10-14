"""CEF encoding conformance and isolation; inputs are authored security events."""
import dataclasses
from functools import partial
import unittest
from security_source import parse_security_source
from source_parse import assert_source_accounting
try:
    from security_cef import parse_security_cef
except ModuleNotFoundError as exc:
    if exc.name!='security_cef':raise
    def parse_security_cef(raw,*,base_parser):return base_parser(raw)

P='CEF:0|Example|IPS|1|42|Blocked|7|'

class SecurityCEFTests(unittest.TestCase):
    def parse(self,raw):
        e=parse_security_cef(raw,base_parser=parse_security_source)
        self.assertEqual(e.raw,raw);assert_source_accounting(e);return e
    def test_literal_quotes_and_suffix_are_preserved(self):
        for value in ('"blocked connection"','"quoted"suffix',"'literal'"):
            raw=P+'msg='+value+' act=deny';e=self.parse(raw)
            self.assertEqual(e.vendor_fields['cef_extension'],{'msg':value,'act':'deny'})
            self.assertEqual(e.status,'SOURCE_PARSED')
    def test_consecutive_spaces_are_part_of_previous_value(self):
        raw=P+'msg=blocked   act=deny  ';e=self.parse(raw)
        self.assertEqual(e.vendor_fields['cef_extension'],{'msg':'blocked  ','act':'deny'})
        span=next(s for s in e.value_spans if s.path=='cef_extension.msg')
        self.assertEqual(raw.encode()[span.start_byte:span.end_byte],b'blocked  ')
    def test_known_escapes_unicode_empty_and_duplicates(self):
        raw=P+r'msg=Zoë\nnext\=x tag=a tag=b empty= path=C:\\logs';e=self.parse(raw)
        self.assertEqual(e.vendor_fields['cef_extension'],{'msg':'Zoë\nnext=x','tag':['a','b'],'empty':'','path':'C:\\logs'})
        self.assertEqual(e.status,'PARTIAL')
        self.assertEqual(sum(s.path=='cef_extension.tag' for s in e.value_spans),2)
    def test_header_and_extension_escape_contracts_are_separate(self):
        e=self.parse(r'CEF:0|Example|IPS|1|42|A\|B=C|7|msg=a | b act=deny')
        self.assertEqual(e.vendor_fields['cef_header']['name'],'A|B=C')
        self.assertEqual(e.vendor_fields['cef_extension']['msg'],'a | b')
    def test_framed_byte_spans_are_original(self):
        for prefix in ('<134>Oct 14 12:00:00 sensor ips: ','<134>1 2026-10-14T12:00:00Z sensor ips 1 ALERT - ','Oct 14 12:00:00 sensor ips: '):
            raw=prefix+P+'msg="Zoë"   act=deny';e=self.parse(raw)
            self.assertEqual(e.vendor_fields['body']['cef_extension']['msg'],'"Zoë"  ')
            span=next(s for s in e.value_spans if s.path=='body.cef_extension.msg')
            self.assertEqual(raw.encode()[span.start_byte:span.end_byte].decode(),'"Zoë"  ')
    def test_other_security_formats_unchanged(self):
        for raw in ('{"action":"BLOCK","labels":[]}','@cee: {"event_type":"alert"}','src=192.0.2.1 action=deny','LEEF:1.0|V|IPS|1|42|act=deny',P+'act=deny'):
            self.assertEqual(dataclasses.asdict(self.parse(raw)),dataclasses.asdict(parse_security_source(raw)))
    def test_incomplete_and_oversize_do_not_become_complete(self):
        for raw in ('CEF:0|short',P+'msg=bad\\',P+'msg=\x00',P+'msg='+('x'*131072)):
            self.assertNotEqual(self.parse(raw).status,'SOURCE_PARSED')
    def test_no_substring_admission(self):
        raw='unknown-prefix '+P+'msg="value"'
        self.assertEqual(dataclasses.asdict(self.parse(raw)),dataclasses.asdict(parse_security_source(raw)))

if __name__=='__main__':unittest.main()
