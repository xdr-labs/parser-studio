#!/usr/bin/env python3
"""Synthetic self-checks for byte-span oracle; frozen real inputs remain private."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).with_name("createSourceKvUtf8SpanOracle.py")
spec = importlib.util.spec_from_file_location("independent_kv_byte_oracle", MODULE)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class IndependentByteSpanTests(unittest.TestCase):
    def assert_roundtrip(self, raw: str, expected: int, envelope: str) -> list:
        data = raw.encode("utf-8")
        found = oracle.scan_source(data)
        self.assertIsNotNone(found)
        self.assertEqual(found["envelope"], envelope)
        fields = found["fields"]
        self.assertEqual(len(fields), expected)
        for field in fields:
            self.assertEqual(data[field["nameStart"]:field["nameEnd"]].decode(), field["name"])
            self.assertEqual(data[field["nameEnd"]:field["valueStart"]], b"=")
            self.assertEqual(
                oracle.decoded_value(data[field["valueStart"]:field["valueEnd"]]),
                field["value"],
            )
            self.assertEqual(
                data[field["rawStart"]:field["rawEnd"]],
                data[field["nameStart"]:field["nameEnd"]] + b"=" +
                data[field["valueStart"]:field["valueEnd"]],
            )
        return fields

    def test_multibyte_unicode_positions_after_pri(self):
        raw = '<14>lang="price € 😀" next=ok'
        fields = self.assert_roundtrip(raw, 2, "pri_kv")
        self.assertEqual(fields[0]["rawStart"], 4)
        self.assertEqual(fields[0]["rawEnd"], len('<14>lang="price € 😀"'.encode()))
        self.assertEqual(fields[1]["rawStart"], len('<14>lang="price € 😀" '.encode()))
        self.assertEqual(fields[0]["value"], "price € 😀")

    def test_rfc3164_and_quoted_spaces(self):
        fields = self.assert_roundtrip('Oct  7 23:58:59 edge.example msg="two words" ok=yes',
                                       2, "yearless_rfc3164_kv")
        self.assertEqual(fields[0]["value"], "two words")
        self.assertTrue(fields[0]["rawStart"] > 23)

    def test_double_escape_conservative_semantics(self):
        fields = self.assert_roundtrip(
            r'<13>text="quote \"yes\" and \? literal" path="C:\\Temp" tail=ok',
            3, "pri_kv",
        )
        self.assertEqual(fields[0]["value"], 'quote "yes" and \\? literal')
        self.assertEqual(fields[1]["value"], 'C:\\Temp')

    def test_bare_escape_and_single_quote(self):
        fields = self.assert_roundtrip(r"alpha=one\ two beta='plain words'",
                                       2, "bare_kv")
        self.assertEqual(fields[0]["value"], "one two")
        self.assertEqual(fields[1]["value"], "plain words")

    def test_reject_unsafe_sources(self):
        invalid = [
            '<192>a=1 b=2', '<14>Oct 17 12:30:00 edge a=1 b=2',
            'a="broken b=ok', 'a=1 a=2',
            'a-b=1 a_b=2', 'a=1 __proto__=ok',
            'a="quoted"fused b=3', "a='unknown\\?escape' b=1",
            'a=one b=two\nthird=3', 'a=one b=two\u0000',
            'a=one b=two\tbad=\u0001', 'a=one',
        ]
        for raw in invalid:
            with self.subTest(length=len(raw)):
                self.assertIsNone(oracle.scan_source(raw.encode()))

    def test_reject_invalid_utf8_without_replacement(self):
        self.assertIsNone(oracle.scan_source(b'a=1 b=\xff'))
        self.assertIsNone(oracle.scan_source(b'a=1 b=2\xf0\x28\x8c\xbc'))


if __name__ == "__main__":
    unittest.main()
