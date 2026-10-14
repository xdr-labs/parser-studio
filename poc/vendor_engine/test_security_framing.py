"""Security-source event boundaries; self-authored input, no external data IO."""
from pathlib import Path
import json
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from security_framing import parse_security_batch,assert_batch_accounting


class SecurityFramingTests(unittest.TestCase):
    def check_records(self, records, separator='\n', prefix='', suffix=''):
        raw=prefix+separator.join(records)+suffix
        result=parse_security_batch(raw)
        self.assertEqual(raw,result.raw)
        self.assertEqual(records,[frame.raw for frame in result.frames])
        assert_batch_accounting(result)
        return result

    def test_pretty_waf_and_ips_nested_json_are_two_events(self):
        waf={'timestamp':1791921600000,'action':'BLOCK',
             'httpRequest':{'headers':[{'name':'Host','value':'example.test'},
                                       {'name':'X-Note','value':'literal } ] { and \\" quote'}]},
             'ruleGroupList':[{'nonTerminatingMatchingRules':[{'ruleId':'test','action':'COUNT'}]}]}
        ips={'event_type':'alert','flow_id':9007199254740993,
             'alert':{'action':'blocked','metadata':{'labels':['alpha','beta']}},
             'http':{'url':'/api?json={a:[b]}','hostname':'example.test'}}
        result=self.check_records([json.dumps(waf,indent=2),json.dumps(ips,indent=4)])
        self.assertEqual([waf,ips],[frame.event.vendor_fields for frame in result.frames])
        self.assertTrue(all(frame.event.status=='SOURCE_PARSED' for frame in result.frames))

    def test_cee_prefixed_multiline_ips_and_syslog_json(self):
        obj={'event_type':'alert','alert':{'action':'blocked'},'http':{'url':'/a?x={y}'}}
        direct='@cee: '+json.dumps(obj,indent=2)
        wrapped='<134>1 2026-10-14T10:11:12Z sensor ips 4 alert - '+direct
        result=self.check_records([direct,wrapped])
        self.assertEqual(obj,result.frames[0].event.vendor_fields)
        self.assertEqual(obj,result.frames[1].event.vendor_fields['body'])
        self.assertTrue(all(f.event.status=='SOURCE_PARSED' for f in result.frames))

    def test_compact_ndjson_and_adjacent_json(self):
        values=[{'event_type':'alert','sequence':i} for i in range(3)]
        for sep in ('\n','\r\n','', ' \t '):
            result=self.check_records([json.dumps(v) for v in values],sep)
            self.assertEqual(values,[f.event.vendor_fields for f in result.frames])

    def test_mixed_security_formats_remain_separate(self):
        records=['<189>type=utm subtype=ips action=dropped srcip=192.0.2.1',
                 'CEF:0|Example|IPS|1|100|Test alert|7|src=192.0.2.1 act=blocked',
                 'LEEF:2.0|Example|IPS|1|100|0x09|src=192.0.2.1\taction=blocked',
                 json.dumps({'event_type':'alert','alert':{'severity':1}},indent=2)]
        result=self.check_records(records,'\r\n')
        self.assertTrue(all(f.event.status=='SOURCE_PARSED' for f in result.frames))

    def test_syslog_wrapped_multiline_json_retains_outer_fields(self):
        header='<134>1 2026-10-14T10:11:12Z sensor ips 4 alert - '
        obj={'event_type':'alert','http':{'url':'/a,[]{}','body':'escaped\nnewline'}}
        record=header+json.dumps(obj,indent=2)
        result=self.check_records([record,record])
        for frame in result.frames:
            self.assertEqual(obj,frame.event.vendor_fields['body'])
            self.assertEqual('sensor',frame.event.vendor_fields['syslog']['hostname'])

    def test_bom_crlf_and_unicode_exact_global_source_bytes(self):
        obj={'httpRequest':{'headers':[{'name':'User-Agent','value':'Zoë 😀'}]}}
        records=[json.dumps(obj,ensure_ascii=False,indent=2)]*2
        result=self.check_records(records,'\r\n\r\n',prefix='\ufeff \t',suffix='\r\n')
        data=result.raw.encode('utf8')
        for frame in result.frames:
            self.assertEqual(frame.raw,data[frame.start_byte:frame.end_byte].decode('utf8'))
            for span in frame.event.value_spans:
                segment=data[frame.start_byte+span.start_byte:frame.start_byte+span.end_byte]
                self.assertEqual(segment,frame.raw.encode('utf8')[span.start_byte:span.end_byte])

    def test_truncated_json_suffix_is_not_guessed_into_false_events(self):
        valid='{"event_type":"alert"}'
        incomplete='{"httpRequest":{"headers":[\n{"name":"Host","value":"example.test"}'
        result=self.check_records([valid,incomplete])
        self.assertEqual('RAW_ONLY',result.frames[-1].event.status)
        self.assertIn('FRAMING_TRUNCATED_JSON',result.frames[-1].event.issues)

    def test_balanced_invalid_json_is_opaque_and_next_record_survives(self):
        bad='{"event_type":}'
        valid='{"event_type":"alert","severity":1}'
        result=self.check_records([bad,valid])
        self.assertEqual('RAW_ONLY',result.frames[0].event.status)
        self.assertEqual('SOURCE_PARSED',result.frames[1].event.status)

    def test_json_trailing_nonseparator_content_is_not_false_green(self):
        record='{"action":"BLOCK"}suffix=not-a-new-event'
        result=self.check_records([record,'{"action":"ALLOW"}'])
        self.assertEqual('RAW_ONLY',result.frames[0].event.status)
        self.assertIn('FRAMING_JSON_TRAILING_CONTENT',result.frames[0].event.issues)

    def test_array_is_one_event_not_silently_exploded(self):
        value=[{'event_type':'alert'},{'event_type':'flow'}]
        result=self.check_records([json.dumps(value,indent=2)])
        self.assertEqual({'$array':value},result.frames[0].event.vendor_fields)

    def test_frame_limit_retains_entire_unprocessed_tail(self):
        raw='{"a":1}\n{"b":2}\n{"c":3}'
        result=parse_security_batch(raw,max_events=2)
        assert_batch_accounting(result)
        self.assertEqual(raw,result.raw)
        self.assertEqual('RAW_ONLY',result.frames[-1].event.status)
        self.assertIn('FRAMING_EVENT_LIMIT',result.frames[-1].event.issues)

    def test_report_contains_counts_not_sensitive_values(self):
        result=parse_security_batch('{"private_token":"unit-test-sensitive-value"}')
        report=json.dumps(result.report())
        self.assertNotIn('unit-test-sensitive-value',report)
        self.assertNotIn('private_token',report)
        self.assertFalse(result.report()['dictionary_attempted'])
        self.assertFalse(result.report()['native_verified'])

    def test_invalid_inputs_and_bounded_batch(self):
        for kwargs in ({'max_events':0},{'max_events':100001},{'max_bytes':0}):
            with self.assertRaises(ValueError):parse_security_batch('{}',**kwargs)
        with self.assertRaises(TypeError):parse_security_batch(b'{}')
        with self.assertRaises(ValueError):parse_security_batch('{"a":1}',max_bytes=4)
        result=parse_security_batch(' \t\r\n')
        self.assertEqual(0,len(result.frames));assert_batch_accounting(result)


if __name__=='__main__':unittest.main()
