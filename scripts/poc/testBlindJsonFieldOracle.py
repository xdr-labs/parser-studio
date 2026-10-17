#!/usr/bin/env python3
"""Independent-source JSON reference negative controls (synthetic values only)."""
import json
import unittest

from createBlindJsonFieldOracle import bad_constant, field_map, reject_duplicate


class TestStrictIndependentOracle(unittest.TestCase):
    def test_preserves_nested_array_paths_without_dropping_types(self):
        original = {"a/b": {"~key": ["value", 0, True, None]}}
        self.assertEqual(field_map(original), {
            "/a~1b/~0key/0": "value",
            "/a~1b/~0key/1": 0,
            "/a~1b/~0key/2": True,
            "/a~1b/~0key/3": None,
        })

    def test_duplicate_json_source_members_rejected(self):
        with self.assertRaisesRegex(ValueError, "Repeated JSON source member"):
            json.loads('{"a":1,"a":2}', object_pairs_hook=reject_duplicate)

    def test_unsafe_key_and_large_number_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsafe JSON source key"):
            field_map(json.loads('{"constructor":1}'))
        with self.assertRaisesRegex(ValueError, "Unscoreable JSON numeric precision"):
            field_map({"n": 2**53 + 1})

    def test_unbounded_depth_and_nonfinite_constant_rejected(self):
        node = 1
        for _ in range(28):
            node = {"depth": node}
        with self.assertRaisesRegex(ValueError, "outside bounded"):
            field_map(node)
        with self.assertRaisesRegex(ValueError, "Forbidden JSON constant"):
            json.loads('{"n":NaN}', parse_constant=bad_constant)

    def test_vacuous_zero_field_success_forbidden(self):
        with self.assertRaisesRegex(ValueError, "Zero or excessive"):
            field_map({"empty": []})


if __name__ == "__main__":
    unittest.main()
