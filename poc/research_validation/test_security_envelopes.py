"""Authored security-event envelope regressions; no source-fixture dependence."""
import dataclasses
import json
import os
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'.cache/latest-baseline/poc/vendor_engine'))
import source_parse
sys.path.insert(0,str(HERE))
if os.environ.get('SECURITY_ENVELOPE_BASELINE')=='1':
    parse_security=lambda raw,**kw: source_parse.parse_source(raw)
else:
    from security_envelopes import parse_security

class SecurityEnvelopeTests(unittest.TestCase):
    def test_plain_cookie_nested_security_fields_and_exact_bytes(self):
        body='{"event_type":"alert","alert":{"signature":"Zoë test"},"http":{"headers":[{"name":"x","value":"1"},{"name":"x","value":"2"}]}}'
        raw='@cee: '+body;e=parse_security(raw)
        self.assertEqual(e.vendor_fields,json.loads(body));self.assertEqual(e.status,'SOURCE_PARSED')
        source_parse.assert_source_accounting(e)
        for s in e.value_spans:json.loads(raw.encode()[s.start_byte:s.end_byte])

    def test_rfc5424_cookie_keeps_header_and_body_namespaces(self):
        head='<134>1 2026-10-14T10:00:00Z sensor suricata 42 ALERT - '
        body='{"event_type":"alert","severity":2}'
        raw=head+'@cee: '+body;e=parse_security(raw)
        self.assertEqual(e.vendor_fields['body'],json.loads(body))
        self.assertEqual(e.vendor_fields['syslog']['appname'],'suricata')
        self.assertEqual(e.status,'SOURCE_PARSED');source_parse.assert_source_accounting(e)
        bodyspans=[s for s in e.value_spans if s.path.startswith('body.')]
        self.assertEqual(len(bodyspans),2)
        for s in bodyspans:self.assertGreaterEqual(s.start_byte,len((head+'@cee: ').encode()))

    def test_rfc3164_cookie_and_no_whitespace_variant(self):
        raw='<134>Oct 14 10:00:00 sensor suricata: @cee:{"event_type":"flow","bytes":9}'
        e=parse_security(raw);self.assertEqual(e.vendor_fields['body']['bytes'],9)
        self.assertEqual(e.status,'SOURCE_PARSED');source_parse.assert_source_accounting(e)

    def test_unterminated_cookie_json_never_becomes_generic_csv(self):
        raw='@cee: {"event_type":"alert","http":{"host":"example.test","x":'
        e=parse_security(raw);self.assertNotEqual(e.status,'SOURCE_PARSED')
        self.assertEqual(e.vendor_fields,{})
        source_parse.assert_source_accounting(e)

    def test_cookie_does_not_authorize_array_or_plain_text(self):
        for body in ('a,b,c','[1,2,3]',''):
            raw='@cee: '+body;e=parse_security(raw)
            self.assertNotEqual(e.status,'SOURCE_PARSED');self.assertEqual(e.vendor_fields,{})
            self.assertEqual(e.raw,raw);source_parse.assert_source_accounting(e)

    def test_marker_inside_payload_or_wrong_prefix_is_not_unwrapped(self):
        for raw in ('{"message":"@cee: payload","x":1}', 'msg="@cee: value" action=deny',
                    'prefix @cee: {"a":1}', '@ceex: {"a":1}'):
            self.assertEqual(dataclasses.asdict(parse_security(raw)),dataclasses.asdict(source_parse.parse_source(raw)))

    def test_plain_valid_security_formats_are_unchanged(self):
        for raw in ('{"action":"BLOCK","ruleGroupList":[],"httpRequest":{"headers":[]}}',
                    'src=192.0.2.1 action=deny', 'CEF:0|Vendor|IPS|1|22|test|5|src=192.0.2.1',
                    '<134>1 2026-10-14T10:00:00Z sensor app 1 - - action=deny'):
            self.assertEqual(dataclasses.asdict(parse_security(raw)),dataclasses.asdict(source_parse.parse_source(raw)))

    def test_limit_and_nul_are_not_unwrapped(self):
        for raw in ('@cee: {"x":1}\x00','@cee: '+(' ' * 131073)):
            e=parse_security(raw);self.assertEqual(e.raw,raw);self.assertEqual(e.vendor_fields,{})
            self.assertNotEqual(e.status,'SOURCE_PARSED')

if __name__=='__main__':unittest.main()
