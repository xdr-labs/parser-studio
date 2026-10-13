"""Separate source-field gold from semantic vendor normalization."""
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_source_field_gold import _flatten,independent_source_fields,evaluate
from corpus import entries
from source_field_metrics import SourceField,SourceRecord,score_source_fields


class SourceGoldTests(unittest.TestCase):
    def test_nested_and_flat_dotted_names_never_collide(self):
        payload={"a.b":1,"a":{"b":2},"list":[None,False,"x"]}
        values=_flatten(payload)
        pairs={(x.path,x.value) for x in values}
        self.assertIn(("/a.b",1),pairs)
        self.assertIn(("/a/b",2),pairs)
        self.assertIn(("/list/0",None),pairs)
        self.assertIn(("/list/1",False),pairs)
        self.assertEqual(5,len(pairs))

    def test_positional_csv_preserves_empty_fields_without_semantic_guess(self):
        raw="Oct 14 11:12:13 PA-220 1,TRAFFIC,,443"
        values=independent_source_fields(raw)
        self.assertEqual([
            SourceField("/column_0","1"),
            SourceField("/column_1","TRAFFIC"),
            SourceField("/column_2",""),
            SourceField("/column_3","443"),
        ],values)

    def test_quoted_unknown_kv_preserves_original_key_and_value(self):
        raw='<189>date=2026-10-14 unknownVendorField="two words" srcip=192.0.2.1'
        values=independent_source_fields(raw)
        self.assertEqual([
            SourceField("/date","2026-10-14"),
            SourceField("/unknownVendorField","two words"),
            SourceField("/srcip","192.0.2.1"),
        ],values)
        self.assertNotIn("source.ip",str(values))

    def test_wrong_source_key_cannot_inflate_exact_field_metric(self):
        raw="raw"
        sha=hashlib.sha256(raw.encode()).hexdigest()
        before=SourceRecord(sha,(SourceField("/srcip","192.0.2.1"),),
                            "SOURCE_PARSED",3,0)
        wrong=SourceRecord(sha,(SourceField("/dstip","192.0.2.1"),),
                           "SOURCE_PARSED",3,0)
        metric=score_source_fields([before],[wrong])["exact_source_field"]
        self.assertEqual((0,1,1),(metric["TP"],metric["FP"],metric["FN"]))

    @unittest.skipUnless(all(
        (Path(__file__).resolve().parent/".cache"/(case["id"]+".raw")).is_file()
        for case in entries()),"Pinned research source cache unavailable")
    def test_all_14645_verified_fields_are_actual_source_not_dictionary(self):
        report=evaluate()
        self.assertEqual(256,report["total_records"])
        self.assertEqual(14645,report["reference_source_field_occurrences"])
        self.assertEqual(14645,report["exact_source_field_metrics"]["TP"])
        self.assertEqual(0,report["exact_source_field_metrics"]["FP"])
        self.assertEqual(0,report["exact_source_field_metrics"]["FN"])
        self.assertEqual(0,report["unparsed_bytes"])
        self.assertFalse(report["semantic_normalization_attempted"])
        self.assertFalse(report["native_verified"])


if __name__=="__main__":
    unittest.main()
