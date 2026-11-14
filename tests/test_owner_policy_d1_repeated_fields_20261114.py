"""Owner policy D-1 (decided 2026-11-14): a field written more than once in one event.

The source preview keeps the original key and every value in wire order, never
overwrites a value, and never reports the event as completely parsed. The same
rule holds for key=value bodies (bare and under a Syslog header), CEF and LEEF.
"""
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

import multipass_preview_api  # noqa: E402

CASES = [
    ("plain key=value", "srcip=192.0.2.10 dstip=198.51.100.7 srcip=203.0.113.5 action=deny srcip=192.0.2.99",
     (), "srcip", ["192.0.2.10", "203.0.113.5", "192.0.2.99"]),
    ("same value twice", "action=deny srcip=192.0.2.10 action=deny", (), "action", ["deny", "deny"]),
    ("quoted and bare", 'msg="first text" srcip=192.0.2.10 msg=second', (), "msg", ["first text", "second"]),
    ("RFC 3164 header", "<134>Nov 14 09:30:00 fw01 srcip=192.0.2.10 dstip=198.51.100.7 srcip=203.0.113.5",
     ("body",), "srcip", ["192.0.2.10", "203.0.113.5"]),
    ("CEF", "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|msg=first one src=10.0.0.1 msg=second msg=third one",
     ("cef_extension",), "msg", ["first one", "second", "third one"]),
    ("LEEF 1.0", "LEEF:1.0|Acme|FW|1.0|100|src=10.0.0.1\tdst=2.1.2.2\tsrc=10.0.0.9", ("leef_extension",), "src", ["10.0.0.1", "10.0.0.9"]),
    ("LEEF 2.0", "LEEF:2.0|Acme|FW|1.0|100|^|usrName=alice^src=10.0.0.1^usrName=bob", ("leef_extension",), "usrName", ["alice", "bob"]),
]


class RepeatedFieldPolicy(unittest.TestCase):
    def test_every_value_is_kept_in_order_and_the_event_is_never_completely_parsed(self):
        for name, raw, path, key, values in CASES:
            with self.subTest(name):
                result = multipass_preview_api.preview(raw)
                self.assertNotEqual(result["status"], "SOURCE_PARSED")
                self.assertIn("DUPLICATE_SOURCE_FIELD", result["issues"])
                container = result["fields"]
                for step in path:
                    container = container[step]
                self.assertEqual(container[key], values)
                self.assertFalse(result["targetVerified"])
                self.assertFalse(result["nativeVerified"])

    def test_the_issue_is_reported_once_however_often_a_field_repeats(self):
        result = multipass_preview_api.preview("a=1 a=2 a=3 b=1 b=2")
        self.assertEqual(result["issues"].count("DUPLICATE_SOURCE_FIELD"), 1)
        self.assertEqual(result["fields"], {"a": ["1", "2", "3"], "b": ["1", "2"]})

    def test_distinct_fields_are_still_a_complete_parse(self):
        result = multipass_preview_api.preview("srcip=192.0.2.10 dstip=198.51.100.7 action=deny")
        self.assertEqual(result["status"], "SOURCE_PARSED")
        self.assertEqual(result["issues"], [])
        # A name that differs only in letter case is a different field.
        result = multipass_preview_api.preview("Action=allow action=deny srcip=192.0.2.10")
        self.assertEqual(result["status"], "SOURCE_PARSED")


if __name__ == "__main__":
    unittest.main()
