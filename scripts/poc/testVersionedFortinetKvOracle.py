#!/usr/bin/env python3
"""Synthetic-only physical-record and independent KV qualification controls."""
import unittest
from createVersionedFortinetKvOracle import physical_records, independently_qualified_versioned

class TestVersionedFortinetSourceOracle(unittest.TestCase):
    def test_only_transport_line_endings_split_original_records(self):
        originals=physical_records("date=2026-10-17 time=12:00:00\r\n"
            "date=2026-10-17 time=12:00:01\n"
            "date=2026-10-17 time=12:00:02\r"
            "date=2026-10-17 time=12:00:03")
        self.assertEqual(len(originals),4)

    def test_form_feed_is_not_a_new_physical_syslog_record(self):
        synthetic="date=2026-10-17 time=12:00:00 msg=\"first\fform-feed\" srcip=192.0.2.1 dstip=198.51.100.1"
        self.assertEqual(len(physical_records(synthetic)),1)
        self.assertEqual(len(synthetic.splitlines()),2)
        # Legacy bare lexer alone is permissive, but this new source Oracle
        # must reject the control without altering earlier frozen references.
        self.assertIsNone(independently_qualified_versioned(synthetic))

    def test_illegal_pseudo_boundaries_and_quote_drift_remain_unscorable(self):
        for raw in (
            "date=2026-10-17 time=12:00:00 srcip=192.0.2.1 dstip=198.51.100.1 msg=\"unfinished",
            "date=2026-10-17 time=12:00:00 srcip=192.0.2.1 dstip=198.51.100.1 msg=\"x\"y",
        ):
            with self.subTest(length=len(raw)):
                self.assertIsNone(independently_qualified_versioned(raw))

    def test_blank_line_does_not_create_an_independent_source_event(self):
        self.assertEqual(physical_records("a=1 b=2\n\n\t\nc=3 d=4"),["a=1 b=2","c=3 d=4"])

if __name__=="__main__":
    unittest.main()
