"""Regression: multiline quoted delimited records remain one bounded source event."""
from __future__ import annotations
import os
import sys
import unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'runtime', 'multipass'))
from security_framing import parse_security_batch, assert_batch_accounting
from multipass_preview_api import preview_batch

class CsvLogicalFraming(unittest.TestCase):
    def test_quoted_multiline_preserves_record_boundaries_and_bytes(self):
        raw='id,action,detail\n1,deny,"multi line\nquoted ""message"", 계속"\n2,allow,"normal"'
        batch=parse_security_batch(raw)
        self.assertEqual(len(batch.frames), 3)
        self.assertEqual([frame.raw for frame in batch.frames], [
            'id,action,detail',
            '1,deny,"multi line\nquoted ""message"", 계속"',
            '2,allow,"normal"'])
        self.assertEqual(batch.frames[1].start_byte, len('id,action,detail\n'.encode()))
        self.assertEqual(batch.report()['input_bytes'], batch.report()['record_bytes'] + batch.report()['separator_bytes'])
        assert_batch_accounting(batch)

    def test_semicolon_and_tab_multiline_boundaries(self):
        for delimiter in (';', '\t'):
            raw=f'id{delimiter}note{delimiter}action\n1{delimiter}"first\nsecond"{delimiter}deny\n2{delimiter}plain{delimiter}allow'
            batch=parse_security_batch(raw)
            self.assertEqual(len(batch.frames), 3)
            self.assertEqual(batch.frames[1].raw, f'1{delimiter}"first\nsecond"{delimiter}deny')

    def test_syslog_or_kv_quoted_lines_never_cross_join(self):
        raw='Oct 19 08:00:01 firewall auth: action=deny message="unfinished\nOct 19 08:00:02 firewall auth: action=allow message=ok'
        batch=parse_security_batch(raw)
        self.assertEqual(len(batch.frames),2)
        self.assertNotEqual(batch.frames[0].event.status,'SOURCE_PARSED')

    def test_unclosed_quoted_csv_stays_incomplete_without_source_loss(self):
        raw='id,action,detail\n1,deny,"unfinished\nline\n2,allow,normal'
        batch=parse_security_batch(raw)
        self.assertEqual(len(batch.frames),2)
        self.assertEqual(batch.frames[1].raw, '1,deny,"unfinished\nline\n2,allow,normal')
        self.assertNotEqual(batch.frames[1].event.status,'SOURCE_PARSED')
        self.assertIn('FRAMING_TRUNCATED_CSV',batch.frames[1].event.issues)
        assert_batch_accounting(batch)

    def test_browser_api_keeps_framing_review_instead_of_discarding_it(self):
        raw='id,action,detail\n1,deny,"first\nsecond"\n2,allow,"normal"'
        result=preview_batch(raw)
        self.assertEqual(result['eventCount'],3)
        self.assertEqual(result['events'][1]['preview']['status'],'RAW_ONLY')
        self.assertIn('FRAMING_MULTILINE_CSV_REVIEW',
                      result['events'][1]['preview']['issues'])
        self.assertEqual(sum(e['endByte']-e['startByte'] for e in result['events'])
                         +sum(s['endByte']-s['startByte'] for s in result['separators']),
                         len(raw.encode()))

    def test_json_and_other_formats_stay_unchanged(self):
        raw='{"x":[1,2,3]}\nCEF:0|A|B|1|3|Name|5|src=192.0.2.1\nuser=alice action=deny'
        batch=parse_security_batch(raw)
        self.assertEqual(len(batch.frames),3)
        self.assertEqual(batch.frames[0].raw,'{"x":[1,2,3]}')
        assert_batch_accounting(batch)

if __name__=='__main__':
    unittest.main()
