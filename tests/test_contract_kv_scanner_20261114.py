"""The Multi-Pass key=value scanner follows the shared grammar contract.

Every expectation below is the value the sender wrote, stated by hand; none is
derived from another parser. The browser parser (src/grammar/kvBody.test.ts)
and the generated Ruby Fragment are held to the same values by the Semantic
Oracle (scripts/verification/semantic-oracle.ts).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview
from source_kv import decode_source_kv, unescape_kv_value
from syslog_header_grammar_generated import SEMANTICS

HEADER = "<134>Nov 13 10:00:00 fw01 "


class ContractKeyValueScanner(unittest.TestCase):
    def test_only_sp_and_tab_separate_pairs(self):
        for inner in ("\u2028", "\u00a0", "\u3000", "\u2003", "\u0085"):
            with self.subTest(inner=repr(inner)):
                found = decode_source_kv("srcip=10.1.1.1 note=a" + inner + "b action=deny")
                self.assertEqual([], found.issues)
                self.assertEqual({"srcip": "10.1.1.1", "note": "a" + inner + "b", "action": "deny"}, found.fields)
        found = decode_source_kv("a=1\tb=2  c=3 \t ")
        self.assertEqual(({"a": "1", "b": "2", "c": "3"}, []), (found.fields, found.issues))

    def test_preview_reports_the_whole_value_around_u2028(self):
        raw = HEADER + "srcip=10.1.1.1 dstip=10.2.2.2 dstport=443 note=a\u2028b action=accept"
        result = preview(raw)
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual("a\u2028b", result["fields"]["body"]["note"])
        self.assertEqual("accept", result["fields"]["body"]["action"])
        self.assertEqual([], result["residuals"])

    def test_values_are_decoded_with_the_contract_escape_set(self):
        written = {
            'note="say \\"hi\\" now"': 'say "hi" now',
            "note='rock \\'n\\' roll'": "rock 'n' roll",
            'path="C:\\Users\\x"': "C:\\Users\\x",
            "path=C:\\Windows\\System32": "C:\\Windows\\System32",
            'path="a\\\\b"': "a\\b",
            "user=k\\=v": "k=v",
            "path=a\\ b": "a\\ b",
            'note="a=b c"': "a=b c",
        }
        for text, meant in written.items():
            with self.subTest(text=text):
                found = decode_source_kv("srcip=10.1.1.1 " + text + " action=deny")
                self.assertEqual([], found.issues)
                key = text.split("=", 1)[0]
                self.assertEqual(meant, found.fields[key])
                self.assertEqual("deny", found.fields["action"])
        self.assertEqual(sorted(["\\", '"', "'", "="]), sorted(SEMANTICS["kvUnescapedAfterBackslash"]))
        self.assertEqual("a\\tb", unescape_kv_value("a\\tb"))

    def test_value_spans_point_at_the_written_text(self):
        raw = 'a="x y" b=\'p q\' c=bare'
        found = decode_source_kv(raw)
        self.assertEqual(["x y", "p q", "bare"], [raw[start:end] for _key, start, end in found.spans])

    def test_a_quoted_value_may_be_followed_directly_by_the_next_key(self):
        found = decode_source_kv('note="hello world"dstip=8.8.8.8')
        self.assertEqual(({"note": "hello world", "dstip": "8.8.8.8"}, []), (found.fields, found.issues))

    def test_malformed_bodies_are_declined_and_keep_the_tail_raw(self):
        declined = {
            "a=1 stray b=2": "KV_TOKEN_UNRECOGNIZED",
            'a=1 tail="never closed': "KV_QUOTE_UNCLOSED",
            "a=1 b= c=3": "KV_EMPTY_UNQUOTED_VALUE",
            "a=1 __proto__=2": "KV_UNSAFE_SOURCE_KEY",
            "a=1 b=x\"y": "KV_TOKEN_UNRECOGNIZED",
        }
        for body, issue in declined.items():
            with self.subTest(body=body):
                found = decode_source_kv(body)
                self.assertEqual([issue], found.issues)
                self.assertEqual("1", found.fields["a"])
                self.assertNotIn("c", found.fields)
                self.assertNotEqual("SOURCE_PARSED", preview(HEADER + body)["status"])

    def test_information_separators_are_never_value_data_or_pair_separators(self):
        for code in (0x1C, 0x1D, 0x1E, 0x1F):
            control = chr(code)
            with self.subTest(control=hex(code)):
                self.assertNotEqual("SOURCE_PARSED", preview(HEADER + "srcip=10.1.1.1 action=" + control + "deny")["status"])
                self.assertNotEqual("SOURCE_PARSED", preview(HEADER + "srcip=10.1.1.1" + control + "action=deny")["status"])

    def test_pair_limit_comes_from_the_contract(self):
        limit = SEMANTICS["kvMaxPairs"]
        body = lambda size: " ".join("f%d=%d" % (at, at) for at in range(size))
        self.assertEqual([], decode_source_kv(body(limit)).issues)
        self.assertEqual(["KV_SOURCE_FIELD_LIMIT"], decode_source_kv(body(limit + 1)).issues)
        self.assertNotEqual("SOURCE_PARSED", preview(HEADER + body(limit + 1))["status"])

    def test_a_repeated_key_keeps_every_occurrence_in_order(self):
        found = decode_source_kv("srcip=192.0.2.10 srcip=198.51.100.10 srcip=203.0.113.7")
        self.assertEqual(["192.0.2.10", "198.51.100.10", "203.0.113.7"], found.fields["srcip"])
        self.assertEqual(3, len(found.spans))


if __name__ == "__main__":
    unittest.main()
