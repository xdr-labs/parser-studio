"""Independent authored security-log mutation controls, not vendor accuracy."""
import unittest
from multipass_adjudicator import parse_security_multipass,parse_security_once
from source_parse import assert_source_accounting

class SecurityGeneralizationEdges(unittest.TestCase):
    def test_nested_security_json_unicode_and_duplicate_value_positions(self):
        for i in range(30):
            raw=('<134>Oct 14 12:00:00 sensor ips: collector: '
                 '{"event_type":"alert","src":"192.0.2.1","dest":"192.0.2.1",'
                 '"rule":{"name":"Zoë '+str(i)+'","ids":[7,7,null,true]}}')
            base=parse_security_once(raw)
            final=parse_security_multipass(raw)
            assert_source_accounting(final)
            self.assertEqual(raw,final.raw)
            self.assertEqual({},base.vendor_fields['body'])
            self.assertEqual('alert',final.vendor_fields['body']['event_type'])
            self.assertEqual('Zoë '+str(i),final.vendor_fields['body']['rule']['name'])
            self.assertEqual([7,7,None,True],final.vendor_fields['body']['rule']['ids'])
            self.assertEqual('PARTIAL',final.status)
            self.assertEqual(2,len([s for s in final.value_spans if s.source_segments in [('body','src'),('body','dest')]]))

    def test_residual_adjacent_json_with_line_break_stays_single_partial_event(self):
        raw=('<134>Oct 14 12:00:00 sensor ips: collector: '
             '{"x":1}\n{"y":2}')
        event=parse_security_multipass(raw)
        assert_source_accounting(event)
        self.assertEqual({'x':1,'y':2},event.vendor_fields['body'])
        self.assertEqual('PARTIAL',event.status)
        self.assertEqual(raw,event.raw)
        self.assertEqual(2,len([s for s in event.value_spans if s.source_segments in [('body','x'),('body','y')]]))

    def test_residual_unknown_prose_must_not_be_skipped_to_find_later_json(self):
        raw=('<134>Oct 14 12:00:00 sensor ips: collector: '
             '{"x":1} garbage {"y":2}')
        event=parse_security_multipass(raw)
        assert_source_accounting(event)
        self.assertEqual({'x':1},event.vendor_fields['body'])
        self.assertNotEqual('SOURCE_PARSED',event.status)

    def test_unknown_security_text_does_not_become_false_complete(self):
        for raw in ('<134>Oct 14 12:00:00 sensor ips: collector: {not-json}',
                    '<134>Oct 14 12:00:00 sensor ips: collector: {"x":',
                    '<134>Oct 14 12:00:00 sensor ips: collector: CEF:broken',
                    '<134>Oct 14 12:00:00 sensor ips: collector: LEEF:bad'):
            with self.subTest(raw=raw[-18:]):
                event=parse_security_multipass(raw)
                assert_source_accounting(event)
                self.assertEqual(raw,event.raw)
                self.assertNotEqual('SOURCE_PARSED',event.status)

if __name__=='__main__':unittest.main()
