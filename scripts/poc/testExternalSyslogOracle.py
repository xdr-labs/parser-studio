#!/usr/bin/env python3
"""Negative and original-byte checks for the independent Go test-source oracle."""
import hashlib
import json
import stat
import unittest
from pathlib import Path

from freezeExternalSyslogOracle import (
    ROOT, RFC5424_MAP, rfc5424_cases, rfc3164_cases,
    split_full_rfc5424, expected_timestamp_valid, value_of,
)


class ExternalSyslogOracleTests(unittest.TestCase):
    def setUp(self):
        self.pins = json.loads((ROOT/"sources.pinned.json").read_text())
        self.summary = json.loads((ROOT/"oracle-summary.v2.pinned.json").read_text())
        self.rows = json.loads((ROOT/"golden-source-expected.v2.json").read_text())

    def test_upstream_corpus_immutable_and_distinct(self):
        self.assertEqual(len(self.pins["files"]), 2)
        self.assertEqual(len({f["source_sha256"] for f in self.pins["files"]}), 2)
        for entry in self.pins["files"]:
            data = (ROOT/"source"/(entry["id"]+".go")).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry["source_sha256"])
            self.assertEqual(len(data),entry["bytes"])
            self.assertEqual(entry["repo"],"jeromer/syslogparser")
            self.assertNotIn("elastic/integrations",entry["repo"])
            self.assertNotIn("influxdata/go-syslog",entry["repo"])

    def test_byte_source_and_independent_expected_sha_are_frozen(self):
        expected = (ROOT/"golden-source-expected.v2.json").read_bytes()
        actual = hashlib.sha256(expected).hexdigest()
        self.assertEqual(self.summary["oracle_sha256"],actual)
        pinned = (ROOT/"sources.pinned.json").read_bytes()
        self.assertEqual(self.summary["source_pin_sha256"],
                         hashlib.sha256(pinned).hexdigest())

    def test_exact_frozen_denominators_no_silent_exclusion(self):
        self.assertEqual(self.summary["original_events"],5)
        self.assertEqual(self.summary["independent_events"],5)
        self.assertEqual(self.summary["source_triples"],38)
        self.assertEqual(self.summary["unscorable"],0)
        self.assertEqual(self.summary["groups"]["RFC3164"]["scorable"],1)
        self.assertEqual(self.summary["groups"]["RFC5424"]["scorable"],4)
        self.assertEqual(len(self.rows),5)

    def test_each_native_source_field_span_replays_on_original_bytes(self):
        for row in self.rows:
            self.assertEqual(row["status"],"INDEPENDENT_UPSTREAM_FIELD_TRIPLES")
            raw = row["raw"].encode("utf8")
            self.assertEqual(hashlib.sha256(raw).hexdigest(),row["raw_sha256"])
            self.assertEqual(len(raw),row["raw_bytes"])
            names = []
            for field in row["field_triples"]:
                a,b=field["start_byte"],field["end_byte"]
                self.assertLessEqual(0,a)
                self.assertLess(a,b)
                self.assertLessEqual(b,len(raw))
                self.assertEqual(raw[a:b].decode("utf8"),field["value"])
                self.assertEqual(field["type"],"string")
                names.append(field["name"])
            self.assertEqual(len(names),len(set(names)))

    def test_non_utf8_and_non_dynamic_go_literal_behavior(self):
        self.assertEqual(value_of(chr(96)+"Hello"+chr(96)),"Hello")
        self.assertEqual(value_of('"\\u0061"'),"a")
        self.assertFalse(expected_timestamp_valid("not-a-timestamp",""))

    def test_bad_source_header_never_gets_independent_field_truth(self):
        expected={"block":'"priority": 1, "version": 1'}
        with self.assertRaises(ValueError):
            split_full_rfc5424("<200>1 - host app - - -",expected)

    def test_original_go_test_library_is_not_a_vendor_or_native_corpus(self):
        self.assertEqual(self.summary["claim_limits"],
            "LIBRARY_UNIT_CONFORMANCE_NOT_AUTHENTIC_DEVICE_OR_NATIVE_STELLAR")
        self.assertEqual(self.pins["data_handling"],"private_original_and_values_0600")
        for f in [ROOT/"sources.pinned.json",ROOT/"oracle-summary.v2.pinned.json",
                  ROOT/"golden-source-expected.v2.json",*list((ROOT/"source").glob("*.go"))]:
            self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)


if __name__=="__main__":
    unittest.main()
