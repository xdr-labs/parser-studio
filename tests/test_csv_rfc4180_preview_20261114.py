"""The Multi-Pass preview offers a comma row as CSV only when RFC 4180 allows it.

Expectations are stated by hand from RFC 4180 section 2. The browser tokenizer
and the generated Ruby are held to the same rows by
scripts/verification/semantic-oracle.ts.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview


def offered(raw: str):
    result = preview(raw)
    fields = result.get("fields") or {}
    ok = ("CSV_UNLABELED_CANDIDATE" in (result.get("syntax") or "")
          and not any(issue.startswith("SOURCE_SYNTAX_ERROR") for issue in result["issues"])
          and "column_0" in fields)
    return [fields["column_%d" % index] for index in range(len(fields))] if ok else None


class Rfc4180Preview(unittest.TestCase):
    def test_valid_rows_carry_the_meant_values(self):
        self.assertEqual(["aaa", "bbb", "ccc"], offered("aaa,bbb,ccc"))
        self.assertEqual(["aaa", "b,bb", "ccc"], offered('"aaa","b,bb","ccc"'))
        self.assertEqual(["aaa", 'b"bb', "ccc"], offered('"aaa","b""bb","ccc"'))
        self.assertEqual(["aaa", "b b", "ccc"], offered("aaa,b b,ccc"))

    def test_a_double_quote_inside_a_bare_field_is_not_offered(self):
        # Rule 5: "If fields are not enclosed with double quotes, then double quotes may not appear inside the fields."
        for raw in ('aaa,b"bb,ccc', 'allow,10.1.1.1,443,hello world,ab"cd'):
            with self.subTest(raw=raw):
                self.assertIsNone(offered(raw))
                self.assertNotEqual("SOURCE_PARSED", preview(raw)["status"])

    def test_other_malformed_rows_are_not_offered(self):
        for raw in ('aaa,"bbb,ccc', 'aaa,"bb"b,ccc'):
            with self.subTest(raw=raw):
                self.assertIsNone(offered(raw))


if __name__ == "__main__":
    unittest.main()
