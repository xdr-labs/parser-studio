"""Original, unmasked source boundaries; no Dictionary or hidden-value inference.

All fixtures here are purpose-built regression inputs, not real-vendor
holdout evidence. Field values must come from exact original source spans.
"""
from pathlib import Path
import sys
import json
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_parse import parse_source,assert_source_accounting
from residual_kv import recover_kv_islands


class UnmaskedSourceBoundaryTests(unittest.TestCase):
    def test_all_twelve_months_with_and_without_priority(self):
        for month in "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split():
            for priority in ("","<134>"):
                with self.subTest(month=month,priority=bool(priority)):
                    raw=f'{priority}{month} 14 10:11:12 host-a agent: user=alice action=allow'
                    event=parse_source(raw)
                    self.assertEqual("SOURCE_PARSED",event.status)
                    self.assertEqual(month,event.vendor_fields["syslog"]["month"])
                    self.assertEqual({"user":"alice","action":"allow"},event.vendor_fields["body"])
                    span=next(x for x in event.value_spans if x.path=="syslog.month")
                    self.assertEqual(month,raw.encode()[span.start_byte:span.end_byte].decode())
                    self.assertEqual(raw,event.raw)
                    assert_source_accounting(event)

    def test_invalid_month_days_still_do_not_admit_envelopes(self):
        for prefix in ("Nov 31","Apr 31","Feb 30","Abc 14"):
            for pri in ("","<134>"):
                event=parse_source(f'{pri}{prefix} 10:11:12 host agent: user=alice action=allow')
                self.assertNotIn("syslog",event.vendor_fields)
                self.assertNotEqual("SOURCE_PARSED",event.status)
                assert_source_accounting(event)

    def test_bare_url_queries_are_not_vendor_fields(self):
        raw='NOTICE visit https://host.test/path?user=alice&action=deny&dst=edge status=403 owner=alice'
        result=recover_kv_islands(raw)
        self.assertEqual({"status":"403","owner":"alice"},result.values)
        self.assertEqual(2,result.field_count)

    def test_suffix_inside_path_is_not_a_new_key(self):
        raw='NOTICE file /var/log/vendor.user=alice status=403 owner=bob'
        result=recover_kv_islands(raw)
        self.assertEqual({"status":"403","owner":"bob"},result.values)

    def test_unowned_quoted_prose_does_not_supply_keys(self):
        raw='NOTICE "example user=alice action=deny" status=403 owner=bob'
        result=recover_kv_islands(raw)
        self.assertEqual({"status":"403","owner":"bob"},result.values)

    def test_malformed_quoted_value_does_not_promote_nested_keys(self):
        raw='NOTICE status=403 owner=bob message="truncated user=alice action=deny'
        result=recover_kv_islands(raw)
        self.assertEqual({"status":"403","owner":"bob"},result.values)
        event=parse_source(raw)
        self.assertEqual(raw,event.raw)
        self.assertEqual("PARTIAL",event.status)
        self.assertGreater(event.residual_bytes,0)
        assert_source_accounting(event)

    def test_quoted_value_retains_nested_equals_and_unicode(self):
        raw='NOTICE message="example user=Zoë action=deny" status=403 owner=bob'
        result=recover_kv_islands(raw)
        self.assertEqual({"message":"example user=Zoë action=deny","status":"403","owner":"bob"},result.values)
        event=parse_source(raw)
        span=next(x for x in event.value_spans if x.path=="embedded_kv.message")
        self.assertEqual(result.values["message"],raw.encode()[span.start_byte:span.end_byte].decode())
        assert_source_accounting(event)

    def test_explicit_island_delimiters_and_duplicate_values_survive(self):
        raw='NOTICE (user=alice,action=deny);owner=bob user=carol'
        result=recover_kv_islands(raw)
        self.assertEqual({"user":["alice","carol"],"action":"deny","owner":"bob"},result.values)
        self.assertEqual(4,result.field_count)


    def test_unmasked_regression_denominators_and_exact_source_truth(self):
        from benchmark_unmasked_boundaries import records,run_parser,HERE
        rows=records()
        self.assertEqual(84,len(rows))
        self.assertEqual(312,sum(len(x["spans"]) for x in rows))
        result=run_parser(HERE,rows)["total"]
        self.assertEqual((312,0,0),tuple(result[k] for k in ("TP","FP","FN")))
        self.assertEqual(84,result["exact_field_and_span_events"])
        self.assertEqual(84,result["original_records_preserved"])

    def test_published_metrics_do_not_claim_real_vendor_generalization(self):
        report=json.loads(Path(__file__).with_name("unmasked-boundary-summary.json").read_text())
        self.assertEqual("SYNTHETIC_REGRESSION_NOT_REAL_VENDOR_HOLDOUT",report["evidence_class"])
        self.assertEqual(report["all_events"],report["unmasked_events"]+report["masked_events"]+
                         report["unassessed_events"]+report["excluded_events"])
        self.assertEqual(0,report["excluded_events"])
        self.assertEqual(0,report["masked_events"])
        self.assertFalse(report["dictionary_attempted"])
        self.assertFalse(report["native_verified"])

    def test_contractions_do_not_hide_real_fields(self):
        raw="NOTICE don't lose user=alice action=deny"
        self.assertEqual({"user":"alice","action":"deny"},recover_kv_islands(raw).values)

    def test_quote_scanning_remains_bounded_and_tail_stays_raw(self):
        raw='NOTICE user=alice action=deny text="'+' text key=value'*4000
        result=recover_kv_islands(raw)
        self.assertEqual({"user":"alice","action":"deny"},result.values)
        self.assertEqual(2,result.field_count)


if __name__=="__main__":
    unittest.main()
