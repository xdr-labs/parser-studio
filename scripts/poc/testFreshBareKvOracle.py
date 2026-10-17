#!/usr/bin/env python3
"""Synthetic-only negative controls for the third-party bare-KV holdout."""
import unittest
from createFreshBareKvOracle import qualify

GOOD='date=2026-10-17 time=12:34:56 srcip=192.0.2.1 dstip=198.51.100.1 action="allow"'

class TestFreshBareKvOracle(unittest.TestCase):
    def test_fresh_qualified_bare_kv_source(self):
        output=qualify(GOOD)
        self.assertIsNotNone(output)
        self.assertEqual(len(output),5)
    def test_reject_invalid_calendar_and_clock(self):
        for source in (
            GOOD.replace('2026-10-17','2026-02-31'),
            GOOD.replace('12:34:56','24:34:56'),
        ):
            self.assertIsNone(qualify(source))
    def test_reject_missing_required_source_evidence(self):
        for source in (
            GOOD.replace('dstip=','destination='),
            GOOD.replace('date=','timestamp='),
            'Fortinet firewall allowed TCP connection',
        ):
            self.assertIsNone(qualify(source))
    def test_reject_ambiguous_kv_and_quoted_prefix(self):
        for source in (
            GOOD+' action=deny',
            GOOD+' x-y=1 x_y=2',
            GOOD+' key="unterminated',
            GOOD+' key="one"two',
            GOOD+' __proto__=bad',
            GOOD+' bare-text',
        ):
            self.assertIsNone(qualify(source))
    def test_reject_control_characters(self):
        self.assertIsNone(qualify(GOOD+'\nkey=value'))
        self.assertIsNone(qualify(GOOD+'\x00key=value'))

if __name__=='__main__':
    unittest.main()
