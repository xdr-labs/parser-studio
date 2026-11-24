"""Owner decision D-2 (2026-11-25) in the Python Multi-Pass preview: a message that looks like CEF or LEEF but has no
valid header is not read as CEF or LEEF; the RFC 5424 / RFC 3164 envelope is read, the message stays one unparsed
region (kept as the original text), and the event is PARTIAL. The browser and the generated Ruby report PARTIAL with
the message kept as text (src/grammar/malformedFamilyClaimD2.test.ts). SYNTHETIC lines."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview

H5 = '<134>1 2026-11-24T10:00:00Z host1 app 123 - - '
H3 = '<134>Nov 24 10:00:00 host1 app: '


class MalformedClaimD2(unittest.TestCase):
    def test_envelope_read_message_kept_partial(self):
        for head in (H5, H3):
            for body in ('CEF : 3 alerts today', 'CEF :0|A|B|1|2|n|3|x', 'LEEF : 2 events', '﻿CEF : 3 alerts today'):
                line = head + body
                result = preview(line)
                self.assertEqual(result['status'], 'PARTIAL', line)
                self.assertNotIn('cef_header', str(result['fields']), line)
                self.assertNotIn('leef_header', str(result['fields']), line)
                syslog = result['fields']['syslog']
                self.assertEqual(syslog.get('hostname', syslog.get('host')), 'host1', line)
                start = len(head.encode('utf-8'))
                self.assertEqual(result['residuals'], [{'startByte': start, 'endByte': len(line.encode('utf-8'))}], line)

    def test_plain_messages_and_valid_cef_are_parsed(self):
        for head in (H5, H3):
            self.assertEqual(preview(head + 'service restarted')['status'], 'SOURCE_PARSED')
            self.assertEqual(preview(head + 'CEF team meeting at 10:00')['status'], 'SOURCE_PARSED')
            valid = preview(head + 'CEF:0|Acme|FW|1.0|100|Blocked|5|src=10.0.0.1 dst=10.0.0.2')
            self.assertEqual(valid['status'], 'SOURCE_PARSED')
            self.assertEqual(valid['fields']['body']['cef_extension']['src'], '10.0.0.1')


if __name__ == '__main__':
    unittest.main()
