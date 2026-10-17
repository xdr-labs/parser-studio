#!/usr/bin/env python3
"""Synthetic-only escaped-value and physical-source qualification controls."""
import unittest
from createVersionedFortinetKvOracle import independently_qualified_versioned,physical_records

class TestIndependentEscapedOriginalOracle(unittest.TestCase):
    def test_quoted_unknown_backslash_value_keeps_source_literal(self):
        source=r'date=2026-10-17 time=12:00:00 srcip=192.0.2.1 dstip=198.51.100.1 type=traffic msg="alert\\?flag"'
        result=independently_qualified_versioned(source)
        self.assertIsNotNone(result)
        fields=dict(result[0])
        self.assertEqual(fields["msg"],r"alert\?flag")

    def test_duplicate_source_fields_and_fused_quotes_fail(self):
        for source in (
            'date=2026-10-17 time=12:00:00 srcip=192.0.2.1 dstip=198.51.100.1 type=traffic msg="bad"trailer',
            'date=2026-10-17 time=12:00:00 srcip=192.0.2.1 dstip=198.51.100.1 type=traffic msg=ok msg=duplicate',
        ):
            self.assertIsNone(independently_qualified_versioned(source))

    def test_quoted_in_record_control_cannot_be_treated_as_escaped_success(self):
        source='date=2026-10-17 time=12:00:00 srcip=192.0.2.1 dstip=198.51.100.1 type=traffic msg="before\fafter"'
        self.assertEqual(len(physical_records(source)),1)
        self.assertIsNone(independently_qualified_versioned(source))

    def test_unverified_free_prose_remains_unscorable(self):
        self.assertIsNone(independently_qualified_versioned(
            'FortiGate accepted connection and changed security action'))

if __name__=="__main__":
    unittest.main()
