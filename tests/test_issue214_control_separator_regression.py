"""Generic Structural must not promote physical control separators (issue #214)."""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from generic_structural_poc import parse_generic_structural
from multipass_preview_api import preview, preview_batch
from source_parse import assert_source_accounting


BASE = (
    "<134>Nov  5 13:00:01 fw01 firewall: "
    "action=deny src=192.0.2.1 dst=198.51.100.2 proto=6"
)
DISALLOWED = ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x1f", "\r")


class UnsafeControlSeparator(unittest.TestCase):
    def test_never_promotes_control_split_key_to_complete(self):
        for separator in DISALLOWED:
            raw = BASE.replace("action=deny", "action=" + separator + "deny")
            with self.subTest(separator=repr(separator)):
                generic = parse_generic_structural(raw)
                assert_source_accounting(generic)
                self.assertNotEqual("SOURCE_PARSED", generic.status)
                self.assertEqual(raw, generic.raw)
                one = preview(raw)
                batch = preview_batch(raw)["events"][0]["preview"]
                self.assertIn(one["status"], ("PARTIAL", "RAW_ONLY"))
                self.assertEqual(one["status"], batch["status"])
                self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), one["sourceSha256"])
                self.assertEqual(len(raw.encode()), one["sourceBytes"])
                self.assertTrue(one["issues"] or one["residuals"])
                self.assertFalse(one["nativeVerified"])

    def test_normal_syslog_kv_and_tab_separators_remain_supported(self):
        good = [BASE, BASE.replace("action=deny", "action=\tdeny")]
        for raw in good:
            with self.subTest(raw=repr(raw)):
                result = preview(raw)
                self.assertEqual("SOURCE_PARSED", result["status"])
                self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), result["sourceSha256"])

    def test_utf8_inside_other_values_is_preserved_and_not_misread_as_control(self):
        raw = BASE + " note=허용😀"
        result = preview(raw)
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual(len(raw.encode("utf8")), result["sourceBytes"])


if __name__ == "__main__":
    unittest.main()
