"""Standards-grounded RFC 5424 free-form MSG source fidelity.

Hand-authored field and UTF-8 byte oracles; does not imply fluentd or target verification.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from multipass_preview_api import preview, preview_batch
from source_parse import assert_source_accounting,parse_source

HEAD='<134>1 2026-10-19T09:15:22.123Z fw01 application 12 audit [meta@12345 action="deny" src="192.0.2.10"] '
NIL='<134>1 2026-10-19T09:15:22.123Z fw01 app - evt - '
class Rfc5424SourceMessage(unittest.TestCase):
    def assert_exact_msg(self,raw,expected):
        source=parse_source(raw)
        assert_source_accounting(source)
        result=preview(raw)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertEqual(result['fields']['body'],{'message':expected})
        self.assertFalse(result['nativeVerified'])
        self.assertFalse(result['targetVerified'])
        self.assertEqual(result['issues'],[])
        self.assertEqual(result['residuals'],[])
        span=next(s for s in result['spans'] if s['path']=='body.message')
        original=raw.encode('utf8')
        self.assertEqual(original[span['startByte']:span['endByte']],expected.encode('utf8'))
        self.assertEqual(span['startByte'],original.rindex(expected.encode('utf8')))
        self.assertEqual(span['endByte'],len(original))
        self.assertEqual(result['sourceBytes'],len(original))
        return result

    def test_rfc5424_plain_msg_without_fake_semantic_fields(self):
        result=self.assert_exact_msg(HEAD+'firewall denied','firewall denied')
        self.assertEqual(result['syntax'],'SYSLOG_RFC5424+RFC5424_MSG')
        self.assertEqual(result['fields']['syslog']['structured_data']['meta@12345']['action'],'deny')

    def test_rfc5424_nil_sd_and_utf8_msg_byte_span(self):
        self.assert_exact_msg(NIL+'접근 차단 사용자 김민수','접근 차단 사용자 김민수')

    def test_utf8_sd_before_message_does_not_move_span(self):
        head='<134>1 2026-10-19T09:15:22Z fw01 app - evt [meta@12345 note="서울"] '
        self.assert_exact_msg(head+'로그 차단','로그 차단')

    def test_explicit_utf8_bom_is_syntax_not_message_value(self):
        result=self.assert_exact_msg(NIL+'\ufeff접근 거부','접근 거부')
        self.assertEqual(result['spans'][-1]['startByte'],len((NIL+'\ufeff').encode()))

    def test_kv_body_remains_structured_not_raw_message(self):
        result=preview(HEAD+'src=192.0.2.5 action=deny')
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertNotIn('message',result['fields']['body'])
        self.assertEqual(result['fields']['body']['src'],'192.0.2.5')

    def test_unclosed_quoted_kv_not_silently_marked_parsed(self):
        result=preview(HEAD+'action="unclosed src=192.0.2.5')
        self.assertNotEqual(result['status'],'SOURCE_PARSED')
        self.assertNotIn('message',result['fields'].get('body',{}))

    def test_malformed_structured_data_not_promoted(self):
        result=preview('<134>1 2026-10-19T09:15:22Z fw01 app - evt [meta@12345 action="broken] firewall denied')
        self.assertNotEqual(result['status'],'SOURCE_PARSED')

    def test_disallowed_pri_not_promoted(self):
        result=preview(HEAD.replace('<134>','<999>')+'firewall denied')
        self.assertNotEqual(result['status'],'SOURCE_PARSED')

    def test_multiline_message_is_not_a_single_complete_record(self):
        result=preview(HEAD+'firewall denied\nsecond physical record')
        self.assertNotEqual(result['status'],'SOURCE_PARSED')

    def test_batch_multiple_plain_msgs_preserves_original_accounting(self):
        data=NIL+'firewall denied\n'+NIL+'접근 차단'
        result=preview_batch(data)
        self.assertEqual(result['eventCount'],2)
        self.assertEqual(result['sourceBytes'],len(data.encode('utf8')))
        self.assertEqual([event['preview']['status'] for event in result['events']],['SOURCE_PARSED','SOURCE_PARSED'])
        for event,text in zip(result['events'],['firewall denied','접근 차단']):
            entry=event['preview']
            self.assertEqual(entry['fields']['body']['message'],text)
            self.assertEqual(entry['sourceBytes'],event['endByte']-event['startByte'])
            self.assertFalse(entry['nativeVerified'])

if __name__=='__main__':unittest.main()
