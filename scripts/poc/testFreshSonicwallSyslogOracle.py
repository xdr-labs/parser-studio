#!/usr/bin/env python3
"""Synthetic RFC3164 original-source KV oracle negative controls; no fixture values."""
import unittest
from createSyslogKvFieldOracle import independent_fields

HEADER="Oct 17 12:34:56 synthetic-host "
SAMPLE=HEADER+'id=firewall sn=XYZ event="allowed traffic"'

class TestFreshSonicwallSyslogOracle(unittest.TestCase):
    def test_yearless_header_and_source_fields_without_invented_year(self):
        result=independent_fields(SAMPLE)
        self.assertIsNotNone(result)
        self.assertEqual(result["variant"],"yearless")
        self.assertEqual(len(result["fields"]),3)
        self.assertNotIn("year",result)
        self.assertNotIn("timezone",result)
    def test_fused_or_broken_quoted_values_are_unscoreable(self):
        for body in (
            'id=firewall sn=XYZ event="allow"deny',
            'id=firewall sn=XYZ event=x"y"',
            'id=firewall sn=XYZ event="unclosed',
        ):
            with self.subTest(bodyType=len(body)):
                self.assertIsNone(independent_fields(HEADER+body))
    def test_unkeyed_or_duplicate_field_tokens_are_not_exact(self):
        for body in (
            'id=firewall sn=XYZ unmatched event=deny',
            'id=firewall sn=XYZ event=deny event=accept',
            'id=firewall sn=XYZ a-b=1 a_b=2',
        ):
            self.assertIsNone(independent_fields(HEADER+body))
    def test_refuses_uncertain_time_and_missing_envelope(self):
        for raw in (
            "Oct 17 25:34:56 synthetic-host id=firewall sn=XYZ event=deny",
            "synthetic-host id=firewall sn=XYZ event=deny",
        ):
            self.assertIsNone(independent_fields(raw))
    def test_newline_split_and_unsafe_keys_rejected(self):
        self.assertIsNone(independent_fields(SAMPLE+"\nextra=bad"))
        self.assertIsNone(independent_fields(HEADER+'id=firewall sn=XYZ __proto__=bad'))

if __name__=="__main__":
    unittest.main()
