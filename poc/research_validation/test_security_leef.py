"""Source-contract conformance, not independent production log accuracy."""
import dataclasses
import unittest
from security_source import parse_security_source
from source_parse import assert_source_accounting
from security_leef import parse_security_leef

class SecurityLEEFTests(unittest.TestCase):
    def parse(self,raw):
        event=parse_security_leef(raw,base_parser=parse_security_source)
        assert_source_accounting(event);self.assertEqual(event.raw,raw)
        return event
    def test_x_hex_pipe_keeps_empty_fields_and_quotes_literal(self):
        raw='LEEF:2.0|Vendor|IPS|11.1|42|x7C|src=192.0.2.1|user=|msg="test"|action=deny'
        event=self.parse(raw)
        self.assertEqual(event.status,'SOURCE_PARSED')
        self.assertEqual(event.vendor_fields['leef_extension'],{'src':'192.0.2.1','user':'','msg':'"test"','action':'deny'})
        self.assertEqual(event.vendor_fields['leef_header']['delimiter'],'x7C')
        self.assertEqual(len(event.value_spans),10)
    def test_x_hex_tab_works_with_unicode_byte_spans(self):
        raw='LEEF:2.0|Vendor|IPS|20|42|x09|user=Zoë\tmsg=a=b c\tcount=0003'
        event=self.parse(raw);self.assertEqual(event.status,'SOURCE_PARSED')
        for span in event.value_spans:
            root,key=span.path.split('.',1)
            self.assertEqual(raw.encode()[span.start_byte:span.end_byte].decode(),event.vendor_fields[root][key])
    def test_existing_supported_input_unchanged(self):
        for raw in ('{"action":"BLOCK"}','tag=a tag=b',
                    'CEF:0|V|IPS|1|1|name|1|src=192.0.2.1',
                    'LEEF:2.0|V|IPS|1|1|0x7c|src=192.0.2.1|user=a',
                    'LEEF:1.0|V|IPS|1|1|src=192.0.2.1\tuser=a'):
            self.assertEqual(dataclasses.asdict(self.parse(raw)),dataclasses.asdict(parse_security_source(raw)))
    def test_wrapped_x_hex_uses_only_true_body_boundary(self):
        body='LEEF:2.0|Vendor|IPS|1|42|x5e|src=192.0.2.1^action=deny'
        for prefix in ('<134>Oct 14 10:00:00 sensor ips: ',
                       '<134>1 2026-10-14T10:00:00Z sensor ips 1 ALERT - ',
                       'Oct 14 10:00:00 sensor ips: '):
            event=self.parse(prefix+body);self.assertEqual(event.status,'SOURCE_PARSED')
            self.assertEqual(event.vendor_fields['body']['leef_extension']['action'],'deny')
            self.assertTrue(all(s.start_byte>=len(prefix.encode()) for s in event.value_spans if s.path.startswith('body.')))
    def test_malformed_and_out_of_scope_are_not_promoted(self):
        for raw in ('LEEF:2.0|V|IPS|1|1|xGG|a=b','LEEF:2.0|V|IPS|1|1|x00|a=b',
                    'LEEF:2.0|V|IPS|1|1|x3d|a=b','LEEF:2.0|V|IPS|1|1|x5c|a=b',
                    'LEEF:2.0|V|IPS|1|1|x7c|broken',
                    'prefix LEEF:2.0|V|IPS|1|1|x7c|a=b'):
            self.assertNotEqual(self.parse(raw).status,'SOURCE_PARSED')
    def test_duplicate_native_occurrences_not_overwritten(self):
        event=self.parse('LEEF:2.0|Vendor|IPS|1|42|x7c|tag=a|tag=b|action=deny')
        self.assertEqual(event.vendor_fields['leef_extension']['tag'],['a','b'])
        self.assertEqual(len([s for s in event.value_spans if s.path=='leef_extension.tag']),2)

if __name__=='__main__':unittest.main()
