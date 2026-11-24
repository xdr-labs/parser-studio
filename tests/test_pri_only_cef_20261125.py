"""A bare PRI before a CEF or LEEF event in the Python Multi-Pass preview, the same lines as
src/grammar/priOnlyCef20261125.test.ts (browser) and the generated Ruby: a valid PRI (0..191) and a valid CEF/LEEF
event are read with every value; anything else is never read as CEF or LEEF. SYNTHETIC lines."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview

CEF = ('CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|src=10.1.100.11 spt=54190 '
       'dst=52.53.140.235 dpt=443 act=close msg=a\\=b c\\\\d')
LEEF = 'LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=192.0.2.10^dst=172.50.123.1^sev=5^usrName=joe.black'


class PriOnlyCef(unittest.TestCase):
    def test_valid_pri_and_event_are_read(self):
        for line, pri in (('<189>' + CEF, '189'), ('<189>' + CEF.replace('CEF:0|', 'CEF: 0|'), '189'),
                          ('<0>' + CEF, '0'), ('<191>' + CEF, '191'), ('<189> ' + CEF, '189'),
                          ('<189>' + CEF + ' syslog_pri=7', '189')):
            result = preview(line)
            self.assertEqual(result['status'], 'SOURCE_PARSED', line)
            self.assertEqual(result['fields']['syslog']['pri'], pri, line)
            extension = result['fields']['body']['cef_extension']
            self.assertEqual((extension['src'], extension['dpt'], extension['msg']), ('10.1.100.11', '443', 'a=b c\\d'), line)
        leef = preview('<111>' + LEEF)
        self.assertEqual(leef['status'], 'SOURCE_PARSED')
        self.assertEqual(leef['fields']['body']['leef_extension']['usrName'], 'joe.black')

    def test_invalid_forms_are_never_read_as_cef_or_leef(self):
        for line in ('<192>' + CEF, '<1890>' + CEF, '<>' + CEF, '<189>' + CEF.replace('CEF:0|', 'CEF:1|'),
                     '<189>CEF:0|A|B|1|2|n|src=1.1.1.1', '<189>' + CEF.replace('CEF:0|', 'CEF :0|'),
                     '<189>' + CEF.replace('CEF:0|', 'CEF:  0|'), '<189>CEF : 3 alerts today', '<189>hello world',
                     '<111>' + LEEF.replace('LEEF:', 'LEEF: ')):
            result = preview(line)
            # Not read as CEF or LEEF: a CEF/LEEF attempt is refused (not SOURCE_PARSED) and no CEF/LEEF field is
            # produced; the Generic Structural reader may still keep the tokens of such a line.
            if 'CEF' in result['syntax'] or 'LEEF' in result['syntax']:
                self.assertNotEqual(result['status'], 'SOURCE_PARSED', line)
            self.assertNotIn('cef_extension', str(result['fields']), line)
            self.assertNotIn('leef_extension', str(result['fields']), line)


if __name__ == '__main__':
    unittest.main()
