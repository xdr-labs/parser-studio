"""Original security fields survive vendor framing without semantic guesses."""
import json
import unittest
from security_source import parse_security_source
from source_parse import assert_source_accounting
from security_framing import parse_security_batch,assert_batch_accounting

CP_HEADER='<134>1 2026-10-14T10:11:12Z gateway CheckPoint 42 - '

class CommercialSourceTests(unittest.TestCase):
    def check(self,raw):
        out=parse_security_source(raw)
        self.assertEqual(raw,out.raw)
        assert_source_accounting(out)
        self.assertFalse(out.normalization_attempted)
        return out

    def test_bracket_colon_values_delimiters_unknown_names_and_duplicates(self):
        raw=CP_HEADER+'[action:"Prevent"; resource:"https://example.test/a?q=x=y;z=1"; group:"ops"; group:"admins"; __nsons:"0"; empty:""]'
        out=self.check(raw)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual({'action':'Prevent','resource':'https://example.test/a?q=x=y;z=1','group':['ops','admins'],'__nsons':'0','empty':''},out.vendor_fields.get('body'))
        self.assertEqual('134',out.vendor_fields['syslog']['pri'])
        spans=[s for s in out.value_spans if s.path=='body.group']
        self.assertEqual(2,len(spans))
        self.assertEqual(['ops','admins'],[raw.encode()[s.start_byte:s.end_byte].decode() for s in spans])

    def test_bare_bracket_pairs_keep_quotes_backslashes_and_unicode(self):
        raw='[name:"Zoë analyst"; note:"a\\\"b\\\\c; ]"; path:"C:\\logs\\today"; empty:"";]'
        out=self.check(raw)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual({'name':'Zoë analyst','note':'a"b\\c; ]','path':r'C:\logs\today','empty':''},out.vendor_fields)
        target=next(s for s in out.value_spans if s.path=='name')
        self.assertEqual('Zoë analyst',raw.encode()[target.start_byte:target.end_byte].decode())

    def test_invalid_bracket_tail_preserves_only_completed_fields(self):
        for suffix in ('bad:"unterminated fake:\\"x\\"','bad:"x"junk; fake:"y"]','bad:x; fake:"y"]'):
            out=self.check(CP_HEADER+'[safe:"ok"; '+suffix)
            self.assertNotEqual('SOURCE_PARSED',out.status)
            self.assertEqual({'safe':'ok'},out.vendor_fields.get('body'))
            self.assertGreater(out.residual_bytes,0)

    def test_bracket_boundaries_limits_and_unsafe_keys_are_not_bypassed(self):
        for raw in ('prefix [safe:"x"; other:"y"]','[constructor:"x"; safe:"y"]','[safe:"x"] trailing','["ordinary","array"]'):
            out=self.check(raw)
            self.assertNotEqual('BRACKET_COLON_KV',out.syntax if raw.startswith('["') else '')
            if not raw.startswith('["'):self.assertNotEqual('SOURCE_PARSED',out.status)
        body='['+'; '.join(f'field_{i}:"{i}"' for i in range(1024))+']'
        self.assertEqual('SOURCE_PARSED',self.check(body).status)
        self.assertEqual('PARTIAL',self.check(body[:-1]+'; next:"over"]').status)

    def test_invalid_timestamp_preserves_real_rfc5424_fields_with_warning(self):
        raw='<134>1 2026-10-14T10:11:12--05:00 gateway CP-GW - IDS [cp@2620 action="Prevent" resource="a\\]b" src="192.0.2.1"]'
        out=self.check(raw)
        self.assertEqual('PARTIAL',out.status)
        self.assertIn('RFC5424_TIMESTAMP_INVALID',out.issues)
        self.assertEqual('2026-10-14T10:11:12--05:00',out.vendor_fields['syslog']['timestamp'])
        self.assertEqual('a]b',out.vendor_fields['syslog']['structured_data']['cp@2620']['resource'])
        self.assertEqual(0,out.residual_bytes)

    def test_pan_csv_short_ietf_and_nil_bsd_tag_preserve_all_columns(self):
        csv='1,2026/10/14 10:11:12,00123,DECRYPTION,allow,"x,y",,'
        for header in ('<134>1 2026-10-14T10:11:12+09:00 gw ', 'Oct 14 10:11:12 gw - '):
            out=self.check(header+csv)
            self.assertEqual({'column_0':'1','column_1':'2026/10/14 10:11:12','column_2':'00123','column_3':'DECRYPTION','column_4':'allow','column_5':'x,y','column_6':'','column_7':''},out.vendor_fields.get('body'))
            self.assertIn('UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION',out.issues)

    def test_new_frames_do_not_merge_events_or_parse_signature_text(self):
        records=[CP_HEADER+'[action:"Prevent"; signature:"word; key=value [text]"]', '<134>1 2026-10-14T10:11:12Z gw 1,2026/10/14 10:11:12,123,THREAT,block,']
        batch=parse_security_batch('\n'.join(records))
        self.assertEqual(records,[x.raw for x in batch.frames]);assert_batch_accounting(batch)
        self.assertEqual('word; key=value [text]',batch.frames[0].event.vendor_fields['body']['signature'])

    def test_strict_rfc5424_validator_not_globally_relaxed(self):
        from structured_source import extract_rfc5424
        raw='<134>1 invalid gateway app - - [id key="value"]'
        fragment,offset=extract_rfc5424(raw)
        self.assertIn('RFC5424_TIMESTAMP_INVALID',fragment.issues)
        self.assertIsNone(offset)
        self.assertFalse(fragment.fields)

    def test_source_sd_duplicate_keys_and_terminal_space_are_preserved_not_standardized(self):
        raw='<134>1 2026-10-14T10:11:12--05:00 gw CP-GW - IDS [id action="Prevent" user="one" user="two" ]'
        out=self.check(raw)
        self.assertEqual('PARTIAL',out.status)
        self.assertEqual(['one','two'],out.vendor_fields['syslog']['structured_data']['id']['user'])
        self.assertIn('RFC5424_TIMESTAMP_INVALID',out.issues)
        self.assertIn('RFC5424_DUPLICATE_SD_KEY',out.issues)
        self.assertEqual(2,len([x for x in out.value_spans if x.path=='syslog.structured_data.id.user']))
        self.assertEqual(0,out.residual_bytes)
        from structured_source import extract_rfc5424
        strict,_=extract_rfc5424(raw.replace('12--05:00','12-05:00'))
        self.assertIn('RFC5424_DUPLICATE_SD_KEY',strict.issues)
        self.assertFalse(strict.fields)

    def test_pri_native_kv_retains_priority_and_payload_without_mapping(self):
        out=self.check('<189>date=2026-10-14 user="Zoë" action=deny')
        self.assertEqual({'pri':'189'},out.vendor_fields.get('syslog'))
        self.assertEqual({'date':'2026-10-14','user':'Zoë','action':'deny'},out.vendor_fields.get('body'))
        self.assertEqual(4,len(out.value_spans))

    def test_literal_colon_inside_source_key_is_preserved(self):
        raw=CP_HEADER+'[methods::"GET: request / path"; source:tag:"prefix:value"; empty:""]'
        out=self.check(raw)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual({'methods:':'GET: request / path','source:tag':'prefix:value','empty':''},out.vendor_fields['body'])
        self.assertEqual({('body','methods:'),('body','source:tag'),('body','empty')},
                         {s.source_segments for s in out.value_spans if s.path.startswith('body.')})

if __name__=='__main__':unittest.main()
