"""Frozen synthetic original-source replay for common declared schema streams."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from multipass_preview_api import preview_batch
from security_framing import parse_security_batch,assert_batch_accounting

W3C = ('#Version: 1.0\r\n#Fields: date time cs-method cs-uri-stem sc-status cs(User-Agent)\r\n'
       '2026-10-19 08:22:00 GET /login 200 "봇 ""agent"""\r\n'
       '2026-10-19 08:22:01 POST /api 403 "safe agent"\r\n')
ZEEK = ('#separator \\x09\n#path\tconn\n'
        '#fields\tts\tuid\tid.orig_h\tid.resp_h\n'
        '#types\ttime\tstring\taddr\taddr\n'
        '1760870000.0\tCk1\t192.0.2.10\t198.51.100.2\n'
        '1760870001.0\tCk2\t192.0.2.11\t198.51.100.3\n'
        '#close\t2026-10-19\n')
class DeclaredSchemaStream(unittest.TestCase):
    def test_w3c_original_two_events_not_three_metadata_lines(self):
        result=preview_batch(W3C)
        self.assertEqual(result['eventCount'],2)
        self.assertTrue(all(e['preview']['syntax']=='W3C_EFL_DECLARED' for e in result['events']))
        self.assertEqual(result['events'][0]['preview']['fields']['cs(User-Agent)'],'봇 "agent"')
        self.assertTrue(all(e['preview']['status']=='PARTIAL' for e in result['events']))
        self.assertEqual(result['sourceBytes'],len(W3C.encode()))
        self.assertTrue(any(s['kind']=='SOURCE_METADATA' for s in result['separators']))
    def test_zeek_two_events_with_original_schema(self):
        result=preview_batch(ZEEK)
        self.assertEqual(result['eventCount'],2)
        self.assertEqual(result['events'][0]['preview']['fields']['id.orig_h'],'192.0.2.10')
        self.assertTrue(all(e['preview']['status']=='PARTIAL' for e in result['events']))
        self.assertTrue(any(s['kind']=='SOURCE_METADATA' for s in result['separators']))
    def test_exact_source_field_spans(self):
        result=preview_batch(W3C)
        blob=W3C.encode()
        first=result['events'][0]
        event=first['preview']
        value=next(s for s in event['spans'] if s['path']=='cs(User-Agent)')
        self.assertEqual(blob[first['startByte']+value['startByte']:first['startByte']+value['endByte']].decode(),'"봇 ""agent"""')
        self.assertTrue(all(item['endByte']<=event['sourceBytes'] for item in event['spans']))
    def test_bad_schema_is_never_complete(self):
        src='#Fields: date cs-method\n2026-10-19 GET EXTRA\n'
        result=preview_batch(src)
        self.assertTrue(all(e['preview']['status']!='SOURCE_PARSED' for e in result['events']))
    def test_non_schema_hash_line_falls_back_as_raw(self):
        result=preview_batch('# ordinary note\naction=allow\n')
        self.assertTrue(any(e['preview']['status']=='RAW_ONLY' for e in result['events']))
    def test_source_byte_accounting(self):
        for src in (W3C,ZEEK):
            batch=parse_security_batch(src)
            assert_batch_accounting(batch)
            self.assertEqual(sum(e.end_byte-e.start_byte for e in batch.frames)+sum(s.end_byte-s.start_byte for s in batch.separators),len(src.encode()))
if __name__=='__main__':unittest.main()
