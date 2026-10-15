"""Candidate-only generic envelope/header recovery."""
import unittest

from generic_partial_envelope import augment_incomplete_envelope
from security_source import parse_security_source
from source_parse import assert_source_accounting


class GenericPartialEnvelopeTests(unittest.TestCase):
    def test_tag_only_bsd_reinterpretation_is_rejected_when_no_value_is_added(self):
        rows=(
            '<166>Mar 17 18:24:37 amp: Info: body remains prose',
            'Mar 17 18:24:37 amp: body remains prose',
        )
        for raw in rows:
            with self.subTest(raw=raw):
                base=parse_security_source(raw)
                event=augment_incomplete_envelope(base)
                assert_source_accounting(event)
                self.assertIs(event,base)
                self.assertNotIn('generic_envelope',event.vendor_fields)

    def test_nested_sequence_header_and_mnemonic_event_code_are_exact(self):
        raw=(
            '<147>4105777: example-wlc-01.example.com: 4105879: '
            'Jun  2 16:00:48.072 SGT: %AAA-3-BADSERVERTYPEERROR: '
            'body remains free text'
        )
        event=augment_incomplete_envelope(parse_security_source(raw))
        assert_source_accounting(event)
        self.assertEqual('PARTIAL',event.status)
        env=event.vendor_fields['generic_envelope']
        self.assertEqual('4105777',env['seq_0'])
        self.assertEqual('example-wlc-01.example.com',env['hostname'])
        self.assertEqual('4105879',env['seq_1'])
        self.assertEqual('SGT',env['label'])
        self.assertEqual(
            {'part_0':'AAA','part_1':'3','part_2':'BADSERVERTYPEERROR'},
            event.vendor_fields['generic_event_code'],
        )

    def test_ios_uptime_and_nexus_year_headers_add_exact_tokens_only(self):
        rows=(
            (
                '<165>7433: ASR920: 4105879: 2y10w: '
                '%SEC_LOGIN-5-LOGIN_SUCCESS: body remains prose',
                'GENERIC_IOS_UPTIME_HEADER',
                {'seq_0':'7433','hostname':'ASR920','seq_1':'4105879','uptime':'2y10w'},
                {'part_0':'SEC_LOGIN','part_1':'5','part_2':'LOGIN_SUCCESS'},
            ),
            (
                '<187>: 2025 Sep 25 08:49:23 UTC : '
                '%LOG_LOCAL7-3-SYSTEM_MSG: body remains prose',
                'GENERIC_NEXUS_YEAR_HEADER',
                {'year':'2025','month':'Sep','day':'25','time':'08:49:23','timezone':'UTC'},
                {'part_0':'LOG_LOCAL7','part_1':'3','part_2':'SYSTEM_MSG'},
            ),
        )
        for raw,syntax,expected,event_code in rows:
            with self.subTest(syntax=syntax):
                base=parse_security_source(raw)
                event=augment_incomplete_envelope(base)
                assert_source_accounting(event)
                self.assertEqual('PARTIAL',event.status)
                self.assertIn(syntax,event.syntax)
                for key,value in expected.items():
                    self.assertEqual(value,event.vendor_fields['generic_envelope'][key])
                self.assertEqual(event_code,event.vendor_fields['generic_event_code'])
                self.assertEqual(raw,event.raw)

    def test_standard_host_plus_tag_and_invalid_nested_header_abstain(self):
        for raw in (
            '<166>Mar 17 18:24:37 host amp: body',
            '<147>1: host: 2: Feb 30 18:24:37 SGT: body',
            '<147>1: host: 2: Mar 17 28:24:37 SGT: body',
            '<999>1: host: 2: Mar 17 18:24:37 SGT: body',
            '<147>x: host: 2: Jun 2 16:00:48 SGT: body',
        ):
            with self.subTest(raw=raw):
                event=augment_incomplete_envelope(parse_security_source(raw))
                self.assertNotIn('generic_envelope',event.vendor_fields)

    def test_complete_events_are_unchanged(self):
        event=parse_security_source('a=1 b=2 c=3 d=4 e=5')
        self.assertIs(event,augment_incomplete_envelope(event))


if __name__=='__main__':
    unittest.main()
