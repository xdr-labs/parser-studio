"""Regression checks for malformed Syslog span/tree accounting (issue #212)."""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview, preview_batch
from source_parse import assert_source_accounting, parse_source
from structured_source import extract_rfc5424
from bounded_funnel import parse_security_funnel
from stellar_dictionary import normalize_stellar_dictionary


MALFORMED_QUOTED_KV = (
    '<134>Nov  5 13:00:01 fw01 firewall: '
    'action="deny src=192.0.2.1 dst=198.51.100.2 proto=6'
)
MISSING_RFC5424_SD = (
    r'<14>1 2026-11-05T13:00:01Z fw01 engine 10 \t0 SRC - '
    r'[id@123 action="deny"] action=deny src=192.0.2.1'
)


class MalformedSyslogSourceContract(unittest.TestCase):
    def test_residual_fanout_span_segments_exist_in_source_tree(self):
        event = parse_security_funnel(MALFORMED_QUOTED_KV)
        self.assertIn(event.status, ("PARTIAL", "RAW_ONLY"))
        assert_source_accounting(event)
        self.assertEqual(event.raw, MALFORMED_QUOTED_KV)
        for span in event.value_spans:
            if span.source_segments is None:
                continue
            value = event.vendor_fields
            for segment in span.source_segments:
                value = value[segment]
            self.assertIsNotNone(value)
        # Dictionary projection must not raise on any retained span.
        normalize_stellar_dictionary(event)

    def test_strict_rfc5424_missing_sd_clears_orphan_header_spans(self):
        strict, position = extract_rfc5424(MISSING_RFC5424_SD)
        self.assertIsNone(position)
        self.assertIn("RFC5424_STRUCTURED_DATA_MISSING", strict.issues)
        self.assertEqual({}, strict.fields)
        self.assertEqual([], strict.spans)
        self.assertEqual(0, strict.primitive_fields)
        preserving, position = extract_rfc5424(
            MISSING_RFC5424_SD, source_preserving=True
        )
        self.assertIsNone(position)
        self.assertIn("RFC5424_STRUCTURED_DATA_MISSING", preserving.issues)
        self.assertEqual(7, len(preserving.spans))
        self.assertIn("syslog", preserving.fields)
        event = parse_source(MISSING_RFC5424_SD)
        assert_source_accounting(event)
        self.assertEqual([], event.value_spans)

    def test_malformed_records_are_bounded_in_single_and_batch_preview(self):
        for raw in (MALFORMED_QUOTED_KV, MISSING_RFC5424_SD):
            with self.subTest(raw=raw):
                one = preview(raw)
                batch = preview_batch(raw)
                self.assertIn(one["status"], ("PARTIAL", "RAW_ONLY"))
                self.assertEqual(one["status"], batch["events"][0]["preview"]["status"])
                self.assertEqual(
                    hashlib.sha256(raw.encode("utf8")).hexdigest(),
                    one["sourceSha256"],
                )
                self.assertEqual(raw.encode("utf8").__len__(), one["sourceBytes"])
                self.assertFalse(one["nativeVerified"])
                self.assertEqual(1, batch["eventCount"])


if __name__ == "__main__":
    unittest.main()
