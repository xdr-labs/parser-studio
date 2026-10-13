"""Cross-check parsed vendor fields against independent stdlib decoders."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from corpus import entries
from source_parse import parse_source
from evaluate_source import _independent_value_check,evaluate_source


class ReferenceDecoderTests(unittest.TestCase):
    def test_quoted_kv_reference_and_negative_mutation(self):
        raw='<189>date=2026-10-14 action="blocked" vendor_unknown="two words"'
        parsed=parse_source(raw)
        self.assertTrue(_independent_value_check(raw,parsed))
        parsed.vendor_fields["vendor_unknown"]="WRONG"
        self.assertFalse(_independent_value_check(raw,parsed))

    def test_structured_json_types_reference_and_negative_mutation(self):
        raw='{"vendor":{"status":7,"enabled":true,"name":"한😀"}}'
        parsed=parse_source(raw)
        self.assertTrue(_independent_value_check(raw,parsed))
        parsed.vendor_fields["vendor"]["status"]="7"
        self.assertFalse(_independent_value_check(raw,parsed))

    def test_positional_csv_empty_cell_reference_and_negative_mutation(self):
        raw="Oct 14 11:12:13 PA-220 1,TRAFFIC,,443"
        parsed=parse_source(raw)
        self.assertTrue(_independent_value_check(raw,parsed))
        parsed.vendor_fields["column_3"]="22"
        self.assertFalse(_independent_value_check(raw,parsed))

    @unittest.skipUnless(all(
        (Path(__file__).resolve().parent/".cache"/(e["id"]+".raw")).is_file()
        for e in entries()),
        "Pinned source fixtures are local only, never redistributed",
    )
    def test_all_256_pinned_events_match_three_independent_decoders(self):
        report=evaluate_source()
        self.assertEqual(256,report["raw_records_preserved"])
        self.assertEqual(256,report["independent_decoder_checked_events"])
        self.assertEqual(256,report["independent_decoder_agreement_events"])
        self.assertEqual(14645,report["source_field_values"])
        self.assertFalse(report["normalization_attempted"])
        self.assertFalse(report["native_verified"])


if __name__=="__main__":
    unittest.main()
