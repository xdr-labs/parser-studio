#!/usr/bin/env python3
"""Synthetic-only negative controls for the independent KV source oracle."""
import unittest
from createSyslogKvFieldOracle import independent_fields, qualified_body

class TestIndependentKvOracle(unittest.TestCase):
    def test_direct_pri_and_yearless_header_are_qualified_without_synthetic_year(self):
        for source in (
            '<13>a=one b="two words"',
            'Oct  7 23:58:59 gateway.example a=one b="two words"',
        ):
            with self.subTest(kind=source[:3]):
                result=independent_fields(source)
                self.assertIsNotNone(result)
                self.assertEqual(len(result['fields']),2)
                self.assertNotIn('year',result)
                self.assertNotIn('timezone',result)

    def test_reject_bad_pri_and_ambiguous_envelopes(self):
        for source in (
            '<192>a=one b=two', '<999>a=one b=two', '<x>a=one b=two',
            '<14>Oct 10 12:00:00 gw a=one b=two',
            'Oct 10 24:00:00 gw a=one b=two',
            'Oct 10 12:00:00 : a=one b=two',
            'host a=one b=two',
        ):
            with self.subTest(kind=source[:16]):
                self.assertIsNone(qualified_body(source))

    def test_reject_duplicate_keys_and_canonical_collision(self):
        for source in ('<13>a=1 a=2','<13>a-b=1 a_b=2'):
            with self.subTest(source=source):
                self.assertIsNone(independent_fields(source))

    def test_reject_quote_drift_unkeyed_tokens_and_unsafe_names(self):
        for source in (
            '<13>a="unfinished b=two', '<13>a=one stray b=two',
            '<13>__proto__=one b=two', '<13>a=one',
            '<13>a="x"y b=two', '<13>a=x"y" b=two',
            '<13>a=one b=two\nthird=three',
        ):
            with self.subTest(kind=source[:20]):
                self.assertIsNone(independent_fields(source))

    def test_no_cisco_asa_prose_false_positive(self):
        self.assertIsNone(independent_fields(
            '<166>Oct 15 2026 00:05:03 EDGE : %ASA-6-302013: Built TCP connection'))

if __name__=='__main__':
    unittest.main()
