"""Transport/source framing tests: original bytes, conservative completion, no target claims."""
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from security_framing import parse_security_batch,assert_batch_accounting
from multipass_preview_api import preview_batch

A1='type=SYSCALL msg=audit(1760870000.123:12): arch=c000003e syscall=59 success=yes'
A2='type=PATH msg=audit(1760870000.123:12): name="/tmp/한글"'
B1='type=USER_LOGIN msg=audit(1760870000.125:13): res=failed acct="김민수"'
C1='2026-10-19T08:20:00.123456789Z stdout P 안녕'
C2='2026-10-19T08:20:01.123456789Z stdout F 하세요'
C3='2026-10-19T08:20:02Z stderr F denied'
DOCKER1=json.dumps({'log':'user=김민수\n','stream':'stdout','time':'2026-10-19T08:20:00.123456789Z'},ensure_ascii=False)
DOCKER2=json.dumps({'log':'connection denied\n','stream':'stderr','time':'2026-10-19T08:20:01Z'},ensure_ascii=False)

class SourceContainerFraming(unittest.TestCase):
    def check_integrity(self,raw,expected):
        batch=parse_security_batch(raw)
        assert_batch_accounting(batch)
        self.assertEqual(len(batch.frames),expected)
        self.assertEqual(sum(x.end_byte-x.start_byte for x in batch.frames+batch.separators),
                         len(raw.encode('utf8')))
        for frame in batch.frames:
            self.assertEqual(raw.encode('utf8')[frame.start_byte:frame.end_byte].decode('utf8'),frame.raw)
            self.assertEqual(frame.event.raw,frame.raw)
            self.assertNotEqual(frame.event.status,'SOURCE_PARSED')
            self.assertFalse(frame.event.native_verified)
            self.assertFalse(frame.event.target_verified)
            for item in frame.event.value_spans:
                self.assertGreaterEqual(item.start_byte,0)
                self.assertLessEqual(item.end_byte,len(frame.raw.encode('utf8')))
        return batch

    def test_audit_contiguous_same_serial_groups_into_one_source_event(self):
        raw=A1+'\n'+A2+'\n'+B1+'\n'
        batch=self.check_integrity(raw,2)
        self.assertEqual(batch.frames[0].event.syntax,'LINUX_AUDIT_SERIAL_GROUP')
        self.assertEqual(batch.frames[0].event.vendor_fields['audit']['serial'],'12')
        self.assertEqual([x['type'] for x in batch.frames[0].event.vendor_fields['audit']['records']],
                         ['SYSCALL','PATH'])
        for span in batch.frames[0].event.value_spans:
            node=batch.frames[0].event.vendor_fields
            for segment in span.source_segments:
                node=node[segment]
            lexical=batch.frames[0].raw.encode('utf8')[span.start_byte:span.end_byte].decode('utf8')
            self.assertEqual(node,lexical)
        self.assertIn('한글',batch.frames[0].raw)
        self.assertEqual(batch.frames[0].event.status,'PARTIAL')
        self.assertEqual(batch.frames[1].event.vendor_fields['audit']['serial'],'13')
        result=preview_batch(raw)
        self.assertEqual(result['eventCount'],2)
        self.assertTrue(all(r['preview']['status']=='PARTIAL' for r in result['events']))

    def test_audit_same_serial_interleaved_is_not_merged_across_another_event(self):
        raw=A1+'\n'+B1+'\n'+A2+'\n'
        batch=self.check_integrity(raw,3)
        self.assertEqual([x.event.vendor_fields['audit']['serial'] for x in batch.frames],['12','13','12'])

    def test_malformed_audit_second_line_fails_closed_preserving_all_source(self):
        raw=A1+'\n'+'type=PATH msg=audit(1760870000.123:12): name="unterminated'+'\n'
        batch=self.check_integrity(raw,1)
        self.assertEqual(batch.frames[0].event.status,'RAW_ONLY')
        self.assertIn('FRAMING_AUDIT',str(batch.frames[0].event.issues))
        self.assertEqual(batch.frames[0].raw,raw)

    def test_cri_interleaved_p_and_f_group_one_exact_event(self):
        raw=C1+'\n'+C2+'\n'+C3+'\n'
        batch=self.check_integrity(raw,2)
        self.assertEqual(batch.frames[0].event.syntax,'CRI_PARTIAL_FINAL_GROUP')
        container=batch.frames[0].event.vendor_fields['cri']
        self.assertEqual(container['stream'],'stdout')
        self.assertEqual([f['tag'] for f in container['fragments']],['P','F'])
        self.assertEqual(container['fragments'][0]['content'],'안녕')
        self.assertEqual(container['fragments'][1]['content'],'하세요')
        self.assertEqual(batch.frames[1].event.vendor_fields['cri']['stream'],'stderr')
        for item in batch.frames[0].event.value_spans:
            node=batch.frames[0].event.vendor_fields
            for segment in item.source_segments:
                node=node[segment]
            lexical=batch.frames[0].raw.encode('utf8')[item.start_byte:item.end_byte].decode('utf8')
            self.assertEqual(lexical,node)
        self.assertEqual(preview_batch(raw)['eventCount'],2)

    def test_cri_invalid_truncated_and_interleaving_fail_closed(self):
        sources=[
            C1+'\n', # incomplete P chain
            C1+'\n'+C3+'\n'+C2+'\n', # cross-stream overlap cannot be a contiguous source frame
            '2026-13-19T08:20:01Z stdout F bad\n',
            '2026-10-19T08:20:00Z stdout X invalid\n',
            C2, # missing terminal LF
        ]
        for raw in sources:
            with self.subTest(raw=raw[:42]):
                batch=self.check_integrity(raw,1)
                self.assertEqual(batch.frames[0].event.status,'RAW_ONLY')

    def test_docker_json_file_preserves_original_quoted_multilingual_payload(self):
        raw=DOCKER1+'\n'+DOCKER2+'\n'
        batch=self.check_integrity(raw,2)
        self.assertTrue(all(f.event.syntax=='DOCKER_JSON_FILE' for f in batch.frames))
        self.assertEqual(batch.frames[0].event.vendor_fields['log'],'user=김민수\n')
        self.assertEqual(batch.frames[1].event.vendor_fields['stream'],'stderr')
        self.assertTrue(all(f.event.status=='PARTIAL' for f in batch.frames))
        self.assertEqual(preview_batch(raw)['eventCount'],2)

    def test_docker_malformed_and_wrong_metadata_are_never_source_parsed(self):
        invalid=[
            DOCKER1+'\n'+ '{"log":"bad","stream":"invalid","time":"2026-10-19T08:20:03Z"}'+'\n',
            DOCKER1+'\n'+ '{"log":"nope","stream":"stdout","time":"nonsense"}'+'\n',
            DOCKER1+'\n'+ '{"log":"unterminated"'+'\n',
            DOCKER1,  # incomplete json-file record without newline
            '{"log":"denied","stream":"stdout"}\n',  # missing time cannot count as plain JSON
            '{"log":"denied","time":"2026-10-19T08:20:01Z"}\n',
        ]
        for raw in invalid:
            with self.subTest(raw=raw[-35:]):
                batch=self.check_integrity(raw,1)
                self.assertEqual(batch.frames[0].event.status,'RAW_ONLY')

    def test_normal_plain_json_or_syslog_is_not_claimed_as_container(self):
        for raw in [
            '{"action":"deny","src_ip":"192.0.2.1"}\n',
            '<134>1 2026-10-19T08:20:00Z fw lab 12 action - user="abc"\n',
        ]:
            batch=parse_security_batch(raw)
            self.assertNotIn('FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER',
                             str(batch.frames[0].event.issues))
            assert_batch_accounting(batch)

if __name__=='__main__':
    unittest.main()
