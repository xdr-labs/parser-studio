"""First-class source extraction tests; semantic/Dictionary mapping is optional."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from corpus import entries,load_case
from source_parse import assert_source_accounting,parse_source


class SourceSyntaxTests(unittest.TestCase):
    def test_quoted_kv_preserves_every_vendor_key_even_without_dictionary(self):
        raw=('<189>date=2026-10-14 srcip=192.0.2.1 action=deny '
             'mystery_field="two words" custom_value="x\\\"y" empty=""')
        event=parse_source(raw)
        self.assertEqual("SYSLOG_PRI_KV",event.syntax)
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual({
            "date":"2026-10-14","srcip":"192.0.2.1","action":"deny",
            "mystery_field":"two words","custom_value":'x"y',"empty":"",
        },event.vendor_fields)
        self.assertEqual(6,event.primitive_fields)
        self.assertFalse(event.normalization_attempted)
        self.assertEqual(0,event.residual_bytes)
        assert_source_accounting(event)

    def test_unwrapped_kv_keeps_custom_fields(self):
        event=parse_source("special_vendor=abc custom_metric=42 name=\"ACME VPN\"")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("ACME VPN",event.vendor_fields["name"])
        self.assertEqual("42",event.vendor_fields["custom_metric"])
        self.assertEqual("KV",event.syntax)
        assert_source_accounting(event)

    def test_csv_preserves_all_columns_including_empty(self):
        fields=["1","TRAFFIC","",'"quoted", inside',"192.0.2.1","","0"]
        import csv,io
        output=io.StringIO()
        csv.writer(output,lineterminator="").writerow(fields)
        raw="Oct 14 11:12:13 PA-220 "+output.getvalue()
        event=parse_source(raw)
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("SYSLOG_BSD_CSV",event.syntax)
        self.assertEqual({f"column_{i}":v for i,v in enumerate(fields)},
                         event.vendor_fields)
        self.assertEqual(len(fields),event.primitive_fields)
        self.assertEqual(len(fields),len(event.value_spans))
        self.assertEqual(0,event.residual_bytes)
        assert_source_accounting(event)

    def test_headerless_csv_field_identity_is_only_positional(self):
        event=parse_source("a,b,")
        self.assertEqual("CSV_UNLABELED_CANDIDATE",event.syntax)
        self.assertEqual("PARTIAL",event.status)
        self.assertIn("UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION",event.issues)
        self.assertEqual({"column_0":"a","column_1":"b","column_2":""},
                         event.vendor_fields)
        self.assertFalse(event.normalization_attempted)
        assert_source_accounting(event)

    def test_json_preserves_nested_unknown_fields_null_and_unicode(self):
        raw=json.dumps({
            "productCode":"custom","vendor":{"abc":42,"zero":None,
             "blob":[],"field":"한😀","nested":{"any":["v",None]}},
        },ensure_ascii=False,separators=(",",":"))
        event=parse_source(raw)
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("JSON",event.syntax)
        self.assertEqual(json.loads(raw),event.vendor_fields)
        self.assertEqual(6,event.primitive_fields)
        self.assertEqual(6,len(event.value_spans))
        self.assertTrue(any(s.end_byte>s.start_byte for s in event.value_spans))
        self.assertEqual(0,event.residual_bytes)
        assert_source_accounting(event)

    def test_json_ambiguous_dotted_path_retains_tree_and_all_source_identities(self):
        raw='{"a.b":1,"a":{"b":2},"vendor":true}'
        event=parse_source(raw)
        self.assertEqual(json.loads(raw),event.vendor_fields)
        self.assertNotIn("JSON_PATH_SPAN_COLLISION_OR_MISSING",event.issues)
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual({("a.b",),("a","b"),("vendor",)},
                         {x.source_segments for x in event.value_spans})
        self.assertEqual(0,event.residual_bytes)
        assert_source_accounting(event)

    def test_json_metadata_records_are_data_not_discarded(self):
        raw='{"meta":{"page":1,"next":null},"data":[]}'
        event=parse_source(raw)
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual(None,event.vendor_fields["meta"]["next"])
        self.assertEqual([],event.vendor_fields["data"])
        self.assertEqual(2,event.primitive_fields)
        assert_source_accounting(event)

    def test_duplicate_key_or_truncated_json_cannot_claim_success(self):
        for raw in ['{"a":1,"a":2}','{"some":"source",']:
            event=parse_source(raw)
            self.assertEqual("RAW_ONLY",event.status)
            self.assertEqual({},event.vendor_fields)
            self.assertEqual(event.source_bytes,event.residual_bytes)
            self.assertTrue(event.issues)
            assert_source_accounting(event)

    def test_malformed_kv_is_partial_not_silently_discarded(self):
        raw='<189>date=2026-10-14 custom_field=ok msg="open'
        event=parse_source(raw)
        self.assertEqual("PARTIAL",event.status)
        self.assertEqual("ok",event.vendor_fields["custom_field"])
        self.assertIn("KV_QUOTE_UNCLOSED",event.issues)
        self.assertGreater(event.residual_bytes,0)
        assert_source_accounting(event)

    def test_unknown_source_keeps_entire_raw_record(self):
        raw="mystery opaque record contains some log fragments"
        event=parse_source(raw)
        self.assertEqual("RAW_ONLY",event.status)
        self.assertEqual({},event.vendor_fields)
        self.assertEqual(len(raw.encode("utf8")),event.residual_bytes)
        assert_source_accounting(event)

    def test_public_metadata_does_not_contain_vendor_values(self):
        raw='<189>date=2026-10-14 user=very-sensitive-user custom_secret=abc'
        event=parse_source(raw)
        report=json.dumps(event.report())
        self.assertNotIn("very-sensitive-user",report)
        self.assertNotIn("custom_secret",report)
        self.assertFalse(event.native_verified)
        self.assertFalse(event.target_verified)

    @unittest.skipUnless(all(
        (Path(__file__).resolve().parent/".cache"/(e["id"]+".raw")).is_file()
        and (Path(__file__).resolve().parent/".cache"/(e["id"]+".gold.json")).is_file()
        for e in entries()
    ),"Local rights-restricted pinned fixture cache unavailable")
    def test_every_pinned_record_is_preserved_and_structural_counts_are_separate(self):
        total=0
        with_fields=0
        for case in entries():
            raw,_gold=load_case(case)
            for item in raw:
                total+=1
                event=parse_source(item)
                assert_source_accounting(event)
                self.assertEqual(item,event.raw)
                self.assertFalse(event.normalization_attempted)
                with_fields+=bool(event.vendor_fields)
        self.assertEqual(256,total)
        self.assertGreater(with_fields,200)


if __name__=="__main__":
    unittest.main()
