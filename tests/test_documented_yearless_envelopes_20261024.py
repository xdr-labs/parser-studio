"""Regression for documented yearless text envelopes using independent golden bytes.

Only the metadata delimited by the producer's published format is given field
semantics. The rest remains a verbatim message. No year/timezone inference.
"""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import hashlib
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from multipass_adjudicator import parse_security_multipass
from security_source import parse_security_source
from source_parse import assert_source_accounting


class DocumentedYearlessEnvelopes(unittest.TestCase):
    def assert_source_fields(self,raw,expected,syntax):
        parsed=parse_security_multipass(raw)
        assert_source_accounting(parsed)
        self.assertEqual(parsed.syntax,syntax)
        self.assertEqual(parsed.status,'PARTIAL')
        self.assertEqual(parsed.issues,['FREE_TEXT_FIELD_ROLES_NEED_REVIEW'])
        self.assertEqual(parsed.vendor_fields,expected)
        self.assertEqual(parsed.primitive_fields,len(expected))
        self.assertEqual(len(parsed.value_spans),len(expected))
        self.assertEqual(parsed.source_bytes,len(raw.encode('utf8')))
        self.assertEqual(parsed.raw_sha256,hashlib.sha256(raw.encode('utf8')).hexdigest())
        self.assertFalse(parsed.native_verified)
        self.assertFalse(parsed.target_verified)
        self.assertEqual(parsed.unparsed,[])
        self.assertNotIn('timestamp',parsed.vendor_fields)
        self.assertNotIn('year',parsed.vendor_fields)
        for item in parsed.value_spans:
            self.assertEqual(item.source_segments,(item.path,))
            lexeme=raw.encode('utf8')[item.start_byte:item.end_byte].decode('utf8')
            self.assertEqual(lexeme,str(expected[item.path]))
        self.assertEqual(parsed,parse_security_multipass(raw))
        # No mutation of original when checking the metadata contract.
        self.assertEqual(parsed,deepcopy(parsed))

    def test_documented_bracketed_application_target(self):
        self.assert_source_fields(
            '[10.30 16:49:06] chrome.exe - proxy.example.org:5070 open through proxy example.org:5070 HTTPS',
            {'month_day':'10.30','clock':'16:49:06','application':'chrome.exe',
             'target_host':'proxy.example.org','target_port':5070,
             'message':'open through proxy example.org:5070 HTTPS'},
            'BRACKETED_MONTH_DAY_APPLICATION_TARGET'
        )

    def test_bracketed_x64_and_utf8_message_does_not_infer_action(self):
        self.assert_source_fields(
            '[07.26 13:47:39] chrome.exe *64 - host.example:443 close, 사용자 김민수 확인',
            {'month_day':'07.26','clock':'13:47:39','application':'chrome.exe *64',
             'target_host':'host.example','target_port':443,
             'message':'close, 사용자 김민수 확인'},
            'BRACKETED_MONTH_DAY_APPLICATION_TARGET'
        )

    def test_documented_logcat_threadtime(self):
        self.assert_source_fields(
            '03-17 16:13:38.811  1702  2395 D WindowManager: visible is false',
            {'month_day':'03-17','clock':'16:13:38.811','pid':1702,'tid':2395,
             'priority':'D','tag':'WindowManager','message':'visible is false'},
            'ANDROID_LOGCAT_THREADTIME'
        )

    def test_logcat_preserves_punctuation_and_utf8_untrusted_message(self):
        # Verify the independently documented envelope directly even when the
        # existing base extractor finds additional embedded KV occurrences.
        from security_documented_envelopes import parse_yearless_documented_envelope
        raw='03-17 16:13:38.820  1702  8671 W PowerManagerService: 김민수 user=true,token=a=b; not instructions'
        preview=parse_yearless_documented_envelope(raw)
        self.assertIsNotNone(preview)
        self.assertEqual(preview.vendor_fields['message'],
                         '김민수 user=true,token=a=b; not instructions')
        assert_source_accounting(preview)
        # The qualified existing KV observations are never overwritten by a
        # broad header parser, even though the header has more fields.
        from source_parse import parse_source
        previous=parse_source(raw)
        current=parse_security_source(raw)
        self.assertEqual(current.vendor_fields,previous.vendor_fields)
        self.assertEqual(current.value_spans,previous.value_spans)
        self.assertEqual(current.syntax,previous.syntax)

    def test_unrelated_realistic_logs_and_adversarial_invalid_headers_do_not_promote(self):
        rejected=[
            '[13.01 16:49:06] foo.exe - host.test:80 message',
            '[02.30 16:49:06] foo.exe - host.test:80 message',
            '[10.30 25:49:06] foo.exe - host.test:80 message',
            '[10.30 16:49:66] foo.exe - host.test:80 message',
            '[10.30 16:49:06] foo.exe - host.test:70000 message',
            '[10.30 16:49:06] foo.exe - host.test:0 message',
            '[10.30 16:49:06] foo.exe - host.test:80 message\nsecond',
            '[10.30 16:49:06] foo.exe - host.test:80',
            '[10.30 16:49:06] foo.exe - host.test:80 message\x00',
            '[10.30 16:49:06] foo.exe - host.test:80 message'+'X'*5000,
            '13-17 16:13:38.811  1702  2395 D WindowManager: visible',
            '02-30 16:13:38.811  1702  2395 D WindowManager: visible',
            '03-17 24:13:38.811  1702  2395 D WindowManager: visible',
            '03-17 16:61:38.811  1702  2395 D WindowManager: visible',
            '03-17 16:13:38.811  1702  2395 X WindowManager: visible',
            '03-17 16:13:38.811  1702  2395 D WindowManager: visible\nsecond',
            'Mar 17 16:13:38 fw01 filter[3]: user logged in',
            '<134>Mar 17 16:13:38 fw01 fw: action=deny srcip=192.0.2.10',
            'CEF:0|Test|Firewall|1|100|Example|5|src=192.0.2.10',
        ]
        for raw in rejected:
            with self.subTest(raw=raw[:90]):
                parsed=parse_security_source(raw)
                self.assertNotIn(parsed.syntax,(
                    'ANDROID_LOGCAT_THREADTIME',
                    'BRACKETED_MONTH_DAY_APPLICATION_TARGET'))
                assert_source_accounting(parsed)
                self.assertEqual(parsed.raw,raw)

    def test_live_preview_batch_contract_preserves_unknowns_and_offsets(self):
        from multipass_preview_api import preview_batch
        records=[
            '[10.30 16:49:06] chrome.exe - proxy.example.org:5070 open via HTTPS',
            '03-17 16:13:38.811  1702  2395 D WindowManager: visible is false',
            '[13.30 16:49:06] broken.exe - host.test:80 malformed date',
        ]
        source='\n'.join(records)
        result=preview_batch(source)
        self.assertEqual(result['eventCount'],3)
        self.assertEqual(result['sourceSha256'],hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(result['sourceBytes'],len(source.encode('utf8')))
        self.assertFalse(result['nativeVerified'])
        self.assertFalse(result['targetVerified'])
        self.assertEqual(len(result['events']),3)
        for number,event in enumerate(result['events']):
            raw=source.encode('utf8')[event['startByte']:event['endByte']].decode('utf8')
            self.assertEqual(raw,records[number])
            self.assertEqual(event['preview']['sourceSha256'],hashlib.sha256(raw.encode()).hexdigest())
            self.assertFalse(event['preview']['targetVerified'])
            self.assertFalse(event['preview']['nativeVerified'])
        self.assertEqual(result['events'][0]['preview']['status'],'PARTIAL')
        self.assertEqual(result['events'][1]['preview']['status'],'PARTIAL')
        self.assertIn('FREE_TEXT_FIELD_ROLES_NEED_REVIEW',
                      result['events'][0]['preview']['issues'])
        self.assertEqual(result['events'][0]['preview']['fields']['target_host'],'proxy.example.org')
        self.assertEqual(result['events'][1]['preview']['fields']['tag'],'WindowManager')
        self.assertNotIn('BRACKETED_MONTH_DAY_APPLICATION_TARGET',
                         result['events'][2]['preview']['syntax'])

    def test_no_source_examples_are_embedded_in_generated_code(self):
        # Grammar is bounded, transparent and no model/AI response is assumed.
        from security_documented_envelopes import LOGCAT, ACTIVITY
        self.assertLess(len(LOGCAT.pattern),400)
        self.assertLess(len(ACTIVITY.pattern),400)
        self.assertTrue(LOGCAT.fullmatch('03-17 16:13:38.811  1702  2395 D WindowManager: hello'))


if __name__=='__main__':unittest.main()
