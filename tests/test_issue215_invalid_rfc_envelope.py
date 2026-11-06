"""Regression: invalid strong RFC envelopes cannot be promoted by generic fallback."""
from __future__ import annotations
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime"/"multipass"))
from generic_structural_poc import parse_generic_structural
from multipass_preview_api import preview,preview_batch
from source_parse import assert_source_accounting

BODY="action=deny src=192.0.2.1 dst=198.51.100.2 proto=6"
INVALID=[
    "<134>Nov 32 13:00:01 fw01 firewall: "+BODY,
    "<134>Nov  5 25:00:01 fw01 firewall: "+BODY,
    "<14>2 2026-11-05T13:00:01Z fw01 app 123 ID47 - "+BODY,
    "<192>1 2026-11-05T13:00:01Z fw01 app 123 ID47 - "+BODY,
    "<14>1 2026-11-05T13:00:01Z fw01 app 123 ID47 [bad@123 action=\"deny\" "+BODY,
]
GOOD=[
    "<134>Nov  5 13:00:01 fw01 firewall: "+BODY,
    "<14>1 2026-11-05T13:00:01Z fw01 app 123 ID47 - "+BODY,
    "<134>action=deny src=192.0.2.1 dst=198.51.100.2 proto=6",
]

class InvalidStrongRfc(unittest.TestCase):
    def test_malformed_envelopes_never_claim_source_parsed(self):
        for raw in INVALID:
            with self.subTest(raw=raw):
                generic=parse_generic_structural(raw)
                self.assertNotEqual("SOURCE_PARSED",generic.status)
                self.assertTrue(generic.issues)
                assert_source_accounting(generic)
                one=preview(raw)
                batch=preview_batch(raw)["events"][0]["preview"]
                self.assertIn(one["status"],("PARTIAL","RAW_ONLY"))
                self.assertEqual(one["status"],batch["status"])
                self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(),one["sourceSha256"])
                self.assertEqual(len(raw.encode()),one["sourceBytes"])
    def test_valid_rfc_and_vendor_pri_kv_remain_accepted(self):
        for raw in GOOD:
            with self.subTest(raw=raw):
                generic=parse_generic_structural(raw)
                self.assertEqual("SOURCE_PARSED",generic.status)
                self.assertEqual("SOURCE_PARSED",preview(raw)["status"])

if __name__=="__main__":
    unittest.main()
