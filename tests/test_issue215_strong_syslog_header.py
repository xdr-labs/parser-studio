"""Guard explicit malformed Syslog headers from Generic Structural false success (#215)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from generic_structural_poc import parse_generic_structural
from multipass_preview_api import preview, preview_batch
from security_source import parse_security_source
from source_parse import assert_source_accounting

RFC3164_INVALID = [
    "<134>Nov 32 13:00:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
    "<134>Feb 30 13:00:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
    "<134>Nov  5 25:00:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
    "<134>Nov  5 13:60:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
]
RFC5424_INVALID = [
    "<14>2 2026-11-05T13:00:01Z fw01 app 123 ID47 - action=deny src=192.0.2.1 dst=198.51.100.2",
    "<192>1 2026-11-05T13:00:01Z fw01 app 123 ID47 - action=deny src=192.0.2.1 dst=198.51.100.2",
]
VALID = [
    "<134>Nov  5 13:00:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
    "<14>1 2026-11-05T13:00:01Z fw01 app 123 ID47 - action=deny src=192.0.2.1 dst=198.51.100.2",
    "<134>action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
    "action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
]


class StrongHeaderFailClosed(unittest.TestCase):
    def test_invalid_strong_header_never_claims_complete(self):
        for raw in RFC3164_INVALID + RFC5424_INVALID:
            with self.subTest(raw=raw):
                standard=parse_security_source(raw)
                self.assertNotEqual(standard.status,"SOURCE_PARSED")
                generic=parse_generic_structural(raw)
                assert_source_accounting(generic)
                self.assertIn(generic.status,("PARTIAL","RAW_ONLY"))
                self.assertTrue(generic.issues or generic.unparsed)
                self.assertEqual(generic.raw,raw)
                single=preview(raw)
                batch=preview_batch(raw)
                self.assertIn(single["status"],("PARTIAL","RAW_ONLY"))
                self.assertEqual(single["status"],batch["events"][0]["preview"]["status"])
                self.assertEqual(single["sourceBytes"],len(raw.encode("utf8")))
                self.assertFalse(single["nativeVerified"])
                self.assertFalse(single["targetVerified"])

    def test_valid_standard_and_pri_only_generic_still_parse(self):
        for raw in VALID:
            with self.subTest(raw=raw):
                result=preview(raw)
                self.assertEqual("SOURCE_PARSED",result["status"])
                self.assertEqual(raw.encode("utf8").__len__(),result["sourceBytes"])


if __name__ == "__main__":
    unittest.main()
