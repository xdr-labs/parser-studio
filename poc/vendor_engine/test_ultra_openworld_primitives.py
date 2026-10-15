"""Ultra open-world primitives discovered after the 8,076-event freeze."""
import unittest
from unittest.mock import patch

from generic_structural_poc import parse_generic_structural
from multipass_adjudicator import parse_security_once
from source_parse import assert_source_accounting
from ultra_template_crossfold_eval import _public_route


class UltraOpenWorldPrimitiveTests(unittest.TestCase):
    def test_template_public_route_never_publishes_source_event_code(self):
        route='ASA_BODY|EVENT_CODE+IP2|EC=VENDOR:6:302014'
        public=_public_route(route)
        self.assertTrue(public.startswith('ASA_BODY|EVENT_CODE+IP2|EC_SHA256='))
        self.assertNotIn('VENDOR',public)
        self.assertNotIn('302014',public)
        self.assertEqual('PRI_BODY|PRI',_public_route('PRI_BODY|PRI'))

    def test_ultra_fallbacks_never_replace_a_legacy_complete_result(self):
        raw=(
            '<142>May 10 15:19:05 gateway node app: '
            'src=192.0.2.1 dst=198.51.100.2 proto=tcp '
            'action=allow rule=web extra=ok'
        )
        with (
            patch(
                'generic_structural_poc._iso_host_json',
                side_effect=AssertionError('ULTRA_FALLBACK_CALLED'),
            ),
            patch(
                'generic_structural_poc._short_rfc5424_json',
                side_effect=AssertionError('ULTRA_FALLBACK_CALLED'),
            ),
            patch(
                'generic_structural_poc._bsd_timestamp_wide_csv',
                side_effect=AssertionError('ULTRA_FALLBACK_CALLED'),
            ),
            patch(
                'generic_structural_poc._rfc3164_loose_tail_kv',
                side_effect=AssertionError('ULTRA_FALLBACK_CALLED'),
            ),
        ):
            event=parse_generic_structural(raw)
        assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual('GENERIC_STRUCTURAL+MIXED',event.syntax)

    def test_short_rfc5424_prefix_with_json_body_is_bounded_and_lossless(self):
        raw=(
            '<5>1 2021-03-10T09:11:54Z VAULT '
            '{"format":"elastic","event":{"id":105,"ok":true}}'
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_SHORT_RFC5424_JSON',event.syntax)
        self.assertEqual('5',event.vendor_fields['syslog']['pri'])
        self.assertEqual('VAULT',event.vendor_fields['syslog']['hostname'])
        self.assertEqual(
            {'format':'elastic','event':{'id':105,'ok':True}},
            event.vendor_fields['body'],
        )
        malformed=(
            '<5>1 2021-03-10T09:11:54Z VAULT '
            '{"format":"elastic","event":'
        )
        self.assertNotEqual(
            'SOURCE_PARSED',parse_security_once(malformed).status
        )
        bad_time='<5>1 2021-99-99T99:99:99Z VAULT {"a":1}'
        self.assertNotEqual(
            'SOURCE_PARSED',parse_security_once(bad_time).status
        )

    def test_eight_column_structural_csv_requires_independent_shape_evidence(self):
        raw=(
            '003001000000,2024/04/18 18:38:20,audit,2561,gui-op,'
            'Mustang,"<show><config-locks><vsys>all</vsys></config-locks></show>",'
            'success'
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_POSITIONAL_CSV',event.syntax)
        self.assertEqual(8,len(event.value_spans))
        self.assertTrue(all(
            span.source_segments==(span.path,)
            for span in event.value_spans
        ))
        weak=(
            'alpha,beta,gamma,delta,epsilon,zeta,"quoted value",theta'
        )
        self.assertNotEqual('SOURCE_PARSED',parse_security_once(weak).status)
        seven=(
            '003001000000,2024/04/18 18:38:20,audit,2561,gui-op,'
            '"quoted",success'
        )
        self.assertNotEqual('SOURCE_PARSED',parse_security_once(seven).status)

    def test_rfc3164_host_prefix_with_bounded_comma_kv_tail(self):
        raw=(
            '<179>Mar 3 10:40:58 host.example APP_AUDIT '
            '0000083076 1 0 2022-03-03 10:40:58.892 +00:00 '
            '0000083143 25046 ERROR Connector: Joined domain unavailable, '
            'AD-Domain=example.local, AD-Log-Id=1645524126/39,'
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_RFC3164_TAIL',event.syntax)
        self.assertEqual(
            'example.local',
            event.vendor_fields['generic']['fields']['AD-Domain'],
        )
        self.assertEqual(
            '1645524126/39',
            event.vendor_fields['generic']['fields']['AD-Log-Id'],
        )
        self.assertGreaterEqual(
            len(event.vendor_fields['generic']['prefix_tokens']),8
        )
        data=raw.encode()
        for span in event.value_spans:
            self.assertEqual(
                data[span.start_byte:span.end_byte].decode(),
                data[span.start_byte:span.end_byte].decode(),
            )

        weak=(
            '<179>Mar 3 10:40:58 host.example short message, '
            'a=1, b=2,'
        )
        weak_event=parse_security_once(weak)
        self.assertNotIn('GENERIC_RFC3164_TAIL',weak_event.syntax)
        self.assertNotEqual('SOURCE_PARSED',weak_event.status)

        tag_only=(
            '<166>Mar 17 18:24:37 amp: Info message with words, '
            'a=1, b=2,'
        )
        tag_event=parse_security_once(tag_only)
        self.assertNotIn('GENERIC_RFC3164_TAIL',tag_event.syntax)

    def test_direct_json_failure_never_falls_back_to_mixed_grammar(self):
        malformed=(
            '{"event":{"id":7,"ok":true}',
            '[{"event":{"id":7}}',
            '{"a":1,"a":2}',
        )
        for raw in malformed:
            with self.subTest(raw=raw):
                event=parse_security_once(raw);assert_source_accounting(event)
                self.assertNotEqual('SOURCE_PARSED',event.status)
                self.assertNotIn('GENERIC_STRUCTURAL+MIXED',event.syntax)

    def test_mnemonic_event_code_is_additive_not_complete(self):
        raw=(
            '<147>4105777: node.example: 4105879: Jun 2 16:00:48.072 SGT: '
            '%AAA-3-BADSERVERTYPEERROR: trailing free text'
        )
        event=parse_generic_structural(raw);assert_source_accounting(event)
        self.assertNotEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_EVENT_CODE',event.syntax)
        self.assertEqual(
            {'part_0':'AAA','part_1':'3','part_2':'BADSERVERTYPEERROR'},
            event.vendor_fields['generic']['event_code'],
        )
        quoted='message="%AAA-3-BADSERVERTYPEERROR: literal" other prose'
        quoted_event=parse_generic_structural(quoted)
        self.assertNotIn(
            'event_code',quoted_event.vendor_fields.get('generic',{})
        )


if __name__=='__main__':
    unittest.main()
