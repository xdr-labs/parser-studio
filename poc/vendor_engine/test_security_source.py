"""Security log framing and complete nested source extraction, not prose mining."""
from pathlib import Path
import json
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_parse import parse_source,assert_source_accounting
from security_source import parse_security_source


def security_tree():
    return {'timestamp':'2026-10-14T10:11:12Z','event_type':'alert',
            'flow_id':9007199254740993,'src_ip':'2001:db8::1','dest_port':443,
            'alert':{'signature_id':2042,'action':'blocked','metadata':{'attack_target':['Server','Client'],'cve':['CVE-2026-0001']}},
            'http':{'url':'/login?q=a%3Db','headers':[{'name':'x-id','value':'first'},{'name':'x-id','value':'second'}]},
            'payload':'YWJjK2RlZj0=','message':'attempt failed user=x reason=y',
            'vendor.extension':{'empty':[],'optional':None,'unicode':'Zoë 😀'}}


def field_at(tree,path):
    for item in path:tree=tree[item]
    return tree


class SecuritySourceFramingTests(unittest.TestCase):
    def test_cee_json_preserves_every_nested_value_and_source_span(self):
        data=security_tree();raw='@cee: '+json.dumps(data,ensure_ascii=False)
        out=parse_security_source(raw)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual(data,out.vendor_fields)
        self.assertEqual(raw,out.raw);assert_source_accounting(out)
        for span in out.value_spans:
            self.assertIsNotNone(span.source_segments)
            self.assertEqual(field_at(data,span.source_segments),json.loads(raw.encode()[span.start_byte:span.end_byte]))

    def test_bsd_and_rfc5424_cee_payloads_keep_headers_and_body(self):
        data=security_tree();body='@cee: '+json.dumps(data,ensure_ascii=False)
        for prefix in ('Oct 14 10:11:12 sensor suricata: ',
                       '<134>Oct 14 10:11:12 sensor suricata: ',
                       '<134>1 2026-10-14T10:11:12Z sensor suricata 42 - - '):
            with self.subTest(prefix=prefix):
                raw=prefix+body;out=parse_security_source(raw)
                self.assertEqual('SOURCE_PARSED',out.status)
                self.assertEqual(data,out.vendor_fields['body'])
                self.assertIn('syslog',out.vendor_fields)
                self.assertEqual(raw,out.raw);assert_source_accounting(out)
                for span in out.value_spans:
                    if span.source_segments is not None:
                        self.assertEqual(field_at(out.vendor_fields,span.source_segments),json.loads(raw.encode()[span.start_byte:span.end_byte]))

    def test_regular_security_json_unchanged_and_no_message_template_mining(self):
        data=security_tree();raw=json.dumps(data)
        self.assertEqual(parse_source(raw),parse_security_source(raw))
        out=parse_security_source(raw)
        self.assertEqual('attempt failed user=x reason=y',out.vendor_fields['message'])
        self.assertNotIn('embedded_kv',out.vendor_fields)
        self.assertFalse(out.normalization_attempted)

    def test_cee_malformed_or_non_json_payload_never_falls_into_csv(self):
        for raw in ('@cee: a,b,c','@cee: {"event_type":"alert",','@cee: ',
                    '@cee: {"key":1,"key":2}','@cee: {"x":1} garbage'):
            out=parse_security_source(raw)
            self.assertEqual('RAW_ONLY',out.status)
            self.assertEqual({},out.vendor_fields)
            self.assertEqual(raw,out.raw);assert_source_accounting(out)
            self.assertNotIn('CSV',out.syntax)

    def test_marker_in_quoted_security_field_not_a_framing_instruction(self):
        data={'message':'@cee: {"fake":1}','event_type':'alert'}
        self.assertEqual(data,parse_security_source(json.dumps(data)).vendor_fields)

    def test_plain_prose_does_not_trigger_cee_payload_substring_search(self):
        raw='message says @cee: {"fake":1}'
        self.assertEqual(parse_source(raw),parse_security_source(raw))

    def test_unknown_payload_and_masked_token_remain_visible_not_reconstructed(self):
        data={'event_type':'alert','src_ip':'REDACTED','payload':'***','unknown':[{},[],None]}
        out=parse_security_source('@cee: '+json.dumps(data))
        self.assertEqual(data,out.vendor_fields)
        self.assertFalse(out.normalization_attempted)

    def test_input_limit_is_checked_before_removing_any_prefix(self):
        raw='@cee: '+json.dumps({'payload':'x'*131072})
        out=parse_security_source(raw)
        self.assertEqual('RAW_ONLY',out.status)
        self.assertEqual(raw,out.raw);assert_source_accounting(out)


if __name__=='__main__':unittest.main()
