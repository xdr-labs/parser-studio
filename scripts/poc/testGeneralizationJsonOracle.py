#!/usr/bin/env python3
"""Independent correctness/safety controls for original-byte JSON span oracles."""
import json
import unittest
from generalizationJsonOracle import (
    IndependentJsonByteOracle,
    OracleInvalid,
    json_file_records,
    parse_json_event,
)


class IndependentSourceByteOracleTests(unittest.TestCase):
    def test_utf8_and_nested_original_scalar_spans(self):
        raw = '{"outer":{"description":"한글🙂","items":[true,null,3]}}'.encode()
        found = parse_json_event(raw)
        actual = {field["path"]: field for field in found}
        for path, lexical in (
            ("/outer/description", '"한글🙂"'),
            ("/outer/items/0", "true"),
            ("/outer/items/1", "null"),
            ("/outer/items/2", "3"),
        ):
            entry = actual[path]
            start, end = entry["value_start_byte"], entry["value_end_byte"]
            self.assertEqual(raw[start:end], lexical.encode("utf8"))
            self.assertEqual(json.loads(raw[start:end]), entry["value"])

    def test_rejects_double_keys_and_unicode_aliases(self):
        for original in (b'{"k":1,"k":2}', b'{"k":1,"\\u006b":2}'):
            with self.subTest(case=original):
                with self.assertRaises(OracleInvalid):
                    parse_json_event(original)

    def test_rejects_trailing_syntax_and_invalid_escape(self):
        for original in (b'{"a":1} extra', b'{"a":"\\q"}', b'{"a":1,}',
                         b'{"a":"unterminated}', b'{"a":NaN}'):
            with self.subTest(case=original):
                with self.assertRaises(OracleInvalid):
                    parse_json_event(original)

    def test_rejects_unpaired_surrogates_and_non_utf8(self):
        for original in (b'{"a":"\\ud800"}', b'{"a":"\xff"}'):
            with self.subTest(case=original):
                with self.assertRaises((OracleInvalid, UnicodeError)):
                    parse_json_event(original)

    def test_top_level_array_has_independent_byte_range_slices(self):
        raw = b' [ {"a":1}, {"b": 2, "nested":[true,false]} ] '
        chunks = json_file_records(raw)
        self.assertEqual(len(chunks), 2)
        self.assertEqual([len(parse_json_event(c)) for c, _ in chunks], [1, 3])
        for original, status in chunks:
            self.assertEqual(status, "json")
            self.assertIn(original, raw)

    def test_jsonl_keeps_original_physical_record_bytes(self):
        raw = b'{"a":1}\r\n{"b":2}\r\n'
        chunks = json_file_records(raw)
        self.assertEqual(len(chunks), 2)
        self.assertEqual([a for a, _ in chunks], [b'{"a":1}', b'{"b":2}'])
        self.assertEqual([len(parse_json_event(a)) for a, _ in chunks], [1, 1])

    def test_rejects_unnamed_json_without_comparable_field(self):
        for original in (b'[]', b'[1,2]', b'{}'):
            with self.subTest(case=original):
                with self.assertRaises(OracleInvalid):
                    parse_json_event(original)

    def test_distinct_semantic_checks_guard_independent_scalar_replay(self):
        value = parse_json_event(b'{"i":9007199254740993,"flag":true,"n":null}')
        fields = {v["path"]: v for v in value}
        self.assertEqual(fields["/i"]["value"], 9007199254740993)
        self.assertEqual(fields["/i"]["type"], "integer")
        self.assertEqual(fields["/flag"]["value"], True)
        self.assertEqual(fields["/n"]["type"], "null")


if __name__ == "__main__":
    unittest.main()
