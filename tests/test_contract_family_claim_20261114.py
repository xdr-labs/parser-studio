"""A line that claims to be CEF or LEEF is parsed by that grammar or not at all.

Expectations are stated by hand from the formats' wire rules; none is derived
from another parser. The same lines are held against the browser extractor and
the generated Ruby by scripts/verification/semantic-oracle.ts.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from generic_structural_poc import parse_generic_structural
from multipass_preview_api import preview
from source_parse import assert_source_accounting


class StructuredFamilyClaim(unittest.TestCase):
    MALFORMED = (
        "CEF:0|Acme|FW|1.0|100|Name|src=10.1.1.1 msg=x y z dst=10.2.2.2",
        "LEEF:3.0|Acme|FW|1.0|100|src=10.1.1.1\tmsg=hello world\tdst=10.2.2.2",
        "CEF:0|Acme|Fire\\|wall|7.2.1|traffic:forward|Blocked flow|cs1=a\\=b suser=alice src=192.168.0.254 msg=x y z",
    )

    def test_malformed_family_line_is_never_reported_as_parsed(self):
        for raw in self.MALFORMED:
            with self.subTest(raw=raw):
                generic = parse_generic_structural(raw)
                assert_source_accounting(generic)
                self.assertNotEqual("SOURCE_PARSED", generic.status)
                self.assertEqual(raw, generic.raw)
                result = preview(raw)
                self.assertNotEqual("SOURCE_PARSED", result["status"])
                self.assertTrue(result["issues"] or result["residuals"])

    def test_valid_family_lines_keep_their_meant_values(self):
        result = preview("CEF:0|Acme|EDR|1.0|100|File created|5|filePath=C:\\\\Users\\\\new\\\\report.txt act=blocked a \\\\ dst=1.1.1.1")
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual({"filePath": "C:\\Users\\new\\report.txt", "act": "blocked a \\", "dst": "1.1.1.1"}, result["fields"]["cef_extension"])
        result = preview("LEEF:1.0|Acme|FW|1.0|100|share=\\\\server\\reports\tsrc=10.1.1.1")
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual({"share": "\\\\server\\reports", "src": "10.1.1.1"}, result["fields"]["leef_extension"])


class LeefContractValues(unittest.TestCase):
    def test_a_long_attribute_key_is_accepted_like_the_browser_and_ruby_accept_it(self):
        # LEEF does not bound the key length; the shared LEEF_KEY token does not either.
        key = "k" * 140
        result = preview("LEEF:1.0|Acme|FW|1.0|100|src=10.1.1.1\t" + key + "=v\tdst=10.2.2.2")
        self.assertEqual("SOURCE_PARSED", result["status"])
        self.assertEqual({"src": "10.1.1.1", key: "v", "dst": "10.2.2.2"}, result["fields"]["leef_extension"])

    def test_only_the_contract_versions_are_leef(self):
        self.assertEqual("SOURCE_PARSED", preview("LEEF:1.0|Acme|FW|1.0|100|src=10.1.1.1\tdst=10.2.2.2")["status"])
        self.assertEqual("SOURCE_PARSED", preview("LEEF:2.0|Acme|FW|1.0|100|^|src=10.1.1.1^dst=10.2.2.2")["status"])
        for raw in ("LEEF:3.0|Acme|FW|1.0|100|src=10.1.1.1\tdst=10.2.2.2", "LEEF:1.1|Acme|FW|1.0|100|src=10.1.1.1\tdst=10.2.2.2"):
            with self.subTest(raw=raw):
                self.assertNotEqual("SOURCE_PARSED", preview(raw)["status"])

    def test_cef_version_1_is_declined_like_the_generated_parser_declines_it(self):
        result = preview("CEF:1|Acme|FW|1.0|100|Name|5|src=10.1.1.1 dst=10.2.2.2")
        self.assertNotEqual("SOURCE_PARSED", result["status"])
        self.assertEqual("SOURCE_PARSED", preview("CEF:0|Acme|FW|1.0|100|Name|5|src=10.1.1.1 dst=10.2.2.2")["status"])


if __name__ == "__main__":
    unittest.main()
