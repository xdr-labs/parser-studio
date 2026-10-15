import dataclasses
import unittest

from multipass_adjudicator import parse_security_multipass
from security_source import parse_security_source
from source_parse import assert_source_accounting


class MultiPassResidualTests(unittest.TestCase):
    def test_syslog_body_recovers_explicit_nested_json_without_hiding_wrapper(self):
        raw=('<134>Oct 14 12:00:00 sensor ips: collector: '
             '{"event_type":"alert","src_ip":"192.0.2.1","alert":{"signature_id":42}}')
        baseline=parse_security_source(raw)
        self.assertEqual({},baseline.vendor_fields['body'])
        final=parse_security_multipass(raw)
        self.assertEqual('alert',final.vendor_fields['body']['event_type'])
        self.assertEqual(42,final.vendor_fields['body']['alert']['signature_id'])
        self.assertEqual('PARTIAL',final.status)
        self.assertIn('collector:', ''.join(raw[a:b] for a,b in final.unparsed))
        span=next(x for x in final.value_spans if x.source_segments==('body','src_ip'))
        self.assertEqual('"192.0.2.1"',raw.encode()[span.start_byte:span.end_byte].decode())
        assert_source_accounting(final)

    def test_cee_after_bounded_wrapper_is_recovered_inside_existing_body(self):
        raw=('<134>1 2026-10-14T12:00:00Z sensor ips 1 ALERT - relay: '
             '@cee: {"event_type":"alert","src_ip":"192.0.2.2"}')
        final=parse_security_multipass(raw)
        self.assertEqual({'event_type':'alert','src_ip':'192.0.2.2'},final.vendor_fields['body'])
        self.assertEqual('PARTIAL',final.status)
        self.assertIn('relay:', ''.join(raw[a:b] for a,b in final.unparsed))
        assert_source_accounting(final)

    def test_residual_recurses_through_nested_syslog_with_depth_bound(self):
        raw=('<134>1 2026-10-14T12:00:00Z relay outer 1 MSG - hop: '
             '<134>1 2026-10-14T12:00:01Z sensor ips 2 ALERT - collector: '
             '{"event_type":"alert","src_ip":"192.0.2.3"}')
        shallow=parse_security_multipass(raw,max_residual_depth=1)
        self.assertIn('syslog',shallow.vendor_fields['body'])
        self.assertEqual({},shallow.vendor_fields['body']['body'])
        deep=parse_security_multipass(raw,max_residual_depth=3)
        self.assertEqual('alert',deep.vendor_fields['body']['body']['event_type'])
        self.assertEqual('192.0.2.3',deep.vendor_fields['body']['body']['src_ip'])
        self.assertEqual('PARTIAL',deep.status)
        assert_source_accounting(deep)

    def test_depth_zero_preserves_mp5_exactly(self):
        raw='{"action":"BLOCK","headers":[{"name":"x","value":"a=b"}]}'
        self.assertEqual(
            dataclasses.asdict(parse_security_source(raw)),
            dataclasses.asdict(parse_security_multipass(raw,max_residual_depth=0)),
        )

    def test_existing_complete_cef_and_json_are_not_destructively_reinterpreted(self):
        rows=[
            '{"action":"BLOCK","labels":[]}',
            'CEF:0|V|IPS|1|42|Alert|5|src=192.0.2.5 act=deny',
            'LEEF:2.0|V|IPS|1|42|0x5e|src=192.0.2.6^act=deny',
        ]
        for raw in rows:
            with self.subTest(raw=raw[:8]):
                no_residual=parse_security_multipass(raw,max_residual_depth=0)
                final=parse_security_multipass(raw)
                self.assertEqual(dataclasses.asdict(no_residual),dataclasses.asdict(final))

    def test_conflicting_existing_body_field_is_not_replaced_by_residual(self):
        raw=('<134>Oct 14 12:00:00 sensor ips: '
             'src=192.0.2.10 action=deny collector: {"src":"198.51.100.9"}')
        no_residual=parse_security_multipass(raw,max_residual_depth=0)
        final=parse_security_multipass(raw)
        self.assertEqual(no_residual.vendor_fields['syslog'],final.vendor_fields['syslog'])
        self.assertEqual(no_residual.vendor_fields['body'],final.vendor_fields['body'])
        self.assertEqual('192.0.2.10',final.vendor_fields['body']['src'])
        self.assertIn('generic_atoms',final.vendor_fields)
        before={
            (span.path,span.start_byte,span.end_byte,span.source_segments)
            for span in no_residual.value_spans
        }
        after={
            (span.path,span.start_byte,span.end_byte,span.source_segments)
            for span in final.value_spans
        }
        self.assertTrue(before<=after)
        self.assertNotEqual('SOURCE_PARSED',final.status)
        assert_source_accounting(final)

    def test_arbitrary_prose_or_invalid_braces_are_not_promoted(self):
        raw='<134>Oct 14 12:00:00 sensor ips: user described {not json} in message'
        before=parse_security_multipass(raw,max_residual_depth=0)
        after=parse_security_multipass(raw)
        self.assertEqual(before.vendor_fields,after.vendor_fields)
        self.assertEqual(before.value_spans,after.value_spans)
        self.assertNotEqual('SOURCE_PARSED',after.status)

    def test_direct_field_limit_is_not_bypassed_by_residual_recursion(self):
        raw='CEF:0|V|IPS|1|42|Alert|5|'+' '.join(f'k{i}=v{i}' for i in range(1025))
        final=parse_security_multipass(raw)
        self.assertEqual('PARTIAL',final.status)
        self.assertIn('CEF_EXTENSION_LIMIT',final.issues)
        self.assertLessEqual(len(final.value_spans),1031)

    def test_invalid_depth_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_security_multipass('{"x":1}',max_residual_depth=99)


if __name__=='__main__':
    unittest.main()
