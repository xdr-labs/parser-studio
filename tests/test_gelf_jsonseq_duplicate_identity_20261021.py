"""Source-only JSON framing: decoded object member identity cannot collapse."""
import hashlib
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from security_framing import parse_security_batch,assert_batch_accounting
from multipass_preview_api import preview_batch

class StrictJsonContainers(unittest.TestCase):
    def assert_rejected(self,raw,reason):
        report=preview_batch(raw)
        self.assertEqual(report['eventCount'],1)
        self.assertEqual(report['sourceBytes'],len(raw.encode('utf8')))
        self.assertEqual(report['sourceSha256'],hashlib.sha256(raw.encode('utf8')).hexdigest())
        entry=report['events'][0]['preview']
        self.assertEqual(entry['status'],'RAW_ONLY')
        self.assertEqual(entry['syntax'],'UNSUPPORTED_SOURCE_CONTAINER')
        self.assertEqual(entry['issues'],[reason])
        self.assertEqual(entry['fields'],{})
        self.assertFalse(entry['nativeVerified'])
        self.assertFalse(entry['targetVerified'])
        batch=parse_security_batch(raw)
        assert_batch_accounting(batch)
        self.assertEqual(len(batch.frames),1)
        self.assertEqual(batch.frames[0].raw,raw)
        self.assertEqual(batch.frames[0].event.vendor_fields,{})
        self.assertEqual(sum(x.end_byte-x.start_byte for x in batch.frames+batch.separators),
                         len(raw.encode('utf8')))

    def test_reject_gelf_nul_duplicate_root_nested_and_unicode_member_names(self):
        for raw in [
            '{"version":"1.1","host":"one","host":"two","short_message":"deny"}\x00',
            '{"version":"1.1","host":"gw","short_message":"deny","detail":{"user":"one","user":"two"}}\x00',
            '{"version":"1.1","host":"gw","short_message":"deny","\\u0061":1,"a":2}\x00',
        ]:
            with self.subTest(source_sha256=hashlib.sha256(raw.encode()).hexdigest()):
                self.assert_rejected(raw,'FRAMING_INVALID_GELF_JSON')

    def test_reject_rfc7464_json_sequence_duplicate_root_nested_array_and_escaped_names(self):
        for raw in [
            '\x1e{"action":"deny","action":"allow"}\n',
            '\x1e{"outer":{"src_ip":"192.0.2.1","src_ip":"198.51.100.1"}}\n',
            '\x1e{"items":[{"event":"one","event":"two"}]}\n',
            '\x1e{"\\u0061":"one","a":"two"}\n',
        ]:
            with self.subTest(source_sha256=hashlib.sha256(raw.encode()).hexdigest()):
                self.assert_rejected(raw,'FRAMING_JSON_SEQ_RECORD_INVALID')

    def test_valid_separate_objects_and_multilingual_source_remain_partial_without_native_claim(self):
        for raw,required in [
            ('{"version":"1.1","host":"gw","short_message":"김민수","left":{"k":"one"},"right":{"k":"two"}}\x00','김민수'),
            ('\x1e{"left":{"k":"one"},"right":{"k":"two"},"actor":"山田"}\n','山田'),
        ]:
            with self.subTest(label=required):
                result=preview_batch(raw)
                self.assertEqual(result['eventCount'],1)
                self.assertEqual(result['sourceBytes'],len(raw.encode('utf8')))
                event=result['events'][0]['preview']
                self.assertEqual(event['status'],'PARTIAL')
                self.assertIn('FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER',event['issues'])
                self.assertFalse(event['nativeVerified'])
                self.assertFalse(event['targetVerified'])
                self.assertIn(required,raw)
                batch=parse_security_batch(raw);assert_batch_accounting(batch)
                self.assertEqual(len(batch.frames),1)
                self.assertIn(required,batch.frames[0].raw)
                self.assertEqual(sum(x.end_byte-x.start_byte for x in batch.frames+batch.separators),
                                 len(raw.encode('utf8')))

if __name__=='__main__':
    unittest.main()
