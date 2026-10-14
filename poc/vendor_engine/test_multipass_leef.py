import dataclasses
import unittest
from security_source import parse_security_source
from source_parse import assert_source_accounting
try:
    from security_leef import parse_security_leef
except ModuleNotFoundError:
    parse_security_leef=None

class MultiPassLEEFTests(unittest.TestCase):
    def parse(self,raw):
        self.assertIsNotNone(parse_security_leef)
        event=parse_security_leef(raw,base_parser=parse_security_source)
        self.assertEqual(raw,event.raw);assert_source_accounting(event);return event

    def test_x_hex_pipe_keeps_empty_fields_and_literal_quotes(self):
        raw='LEEF:2.0|Vendor|IPS|11.1|42|x7C|src=192.0.2.1|user=|msg="test"|action=deny'
        event=self.parse(raw)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual({'src':'192.0.2.1','user':'','msg':'"test"','action':'deny'},event.vendor_fields['leef_extension'])
        self.assertEqual('x7C',event.vendor_fields['leef_header']['delimiter'])

    def test_x_hex_tab_unicode_and_source_spans(self):
        raw='LEEF:2.0|Vendor|IPS|20|42|x09|user=Zoë\tmsg=a=b c\tcount=0003'
        event=self.parse(raw);self.assertEqual('SOURCE_PARSED',event.status)
        for span in event.value_spans:
            root,key=span.path.split('.',1);value=event.vendor_fields[root][key]
            self.assertEqual(value,raw.encode()[span.start_byte:span.end_byte].decode())

    def test_existing_literal_and_0x_delimiters_unchanged(self):
        for raw in ('LEEF:2.0|V|IPS|1|1|0x7c|src=192.0.2.1|user=a',
                    'LEEF:2.0|V|IPS|1|1|^|src=192.0.2.1^user=a',
                    'LEEF:1.0|V|IPS|1|1|src=192.0.2.1\tuser=a',
                    '{"action":"BLOCK"}','tag=a tag=b',
                    'CEF:0|V|IPS|1|1|name|1|src=192.0.2.1'):
            with self.subTest(raw=raw):
                self.assertEqual(dataclasses.asdict(parse_security_source(raw)),dataclasses.asdict(self.parse(raw)))

    def test_wrapped_x_hex_true_body_boundary(self):
        body='LEEF:2.0|Vendor|IPS|1|42|x5e|src=192.0.2.1^action=deny'
        prefixes=('<134>Oct 14 10:00:00 sensor ips: ',
                  '<134>1 2026-10-14T10:00:00Z sensor ips 1 ALERT - ',
                  'Oct 14 10:00:00 sensor ips: ')
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                event=self.parse(prefix+body);self.assertEqual('SOURCE_PARSED',event.status)
                self.assertEqual('deny',event.vendor_fields['body']['leef_extension']['action'])
                self.assertTrue(all(s.start_byte>=len(prefix.encode()) for s in event.value_spans if s.path.startswith('body.')))

    def test_malformed_x_hex_never_promoted(self):
        for raw in ('LEEF:2.0|V|IPS|1|1|xGG|a=b','LEEF:2.0|V|IPS|1|1|x00|a=b',
                    'LEEF:2.0|V|IPS|1|1|x3d|a=b','LEEF:2.0|V|IPS|1|1|x5c|a=b',
                    'LEEF:2.0|V|IPS|1|1|x7c|broken','prefix LEEF:2.0|V|IPS|1|1|x7c|a=b'):
            with self.subTest(raw=raw):self.assertNotEqual('SOURCE_PARSED',self.parse(raw).status)

    def test_duplicate_occurrences_preserved(self):
        event=self.parse('LEEF:2.0|Vendor|IPS|1|42|x7c|tag=a|tag=b|action=deny')
        self.assertEqual(['a','b'],event.vendor_fields['leef_extension']['tag'])
        self.assertEqual(2,sum(s.path=='leef_extension.tag' for s in event.value_spans))
        self.assertEqual('PARTIAL',event.status)

if __name__=='__main__':unittest.main()
