"""Prospective raw-framing admission result is recorded, including failure."""
from pathlib import Path
import sys
import json
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_framing_admission import (
    PIN_RAW,PIN_GOLD,source_train_only,evaluate,_audit_source_split,
)
from benchmark_new_families import ROOT


class HeaderAdmissionTests(unittest.TestCase):
    @unittest.skipUnless(all((ROOT/family).is_file() and
                             (ROOT/(family+"_structured.csv")).is_file()
                             for family in PIN_RAW),
                         "New pinned reference set unavailable locally")
    def test_gold_not_used_to_fit_and_no_identical_source_leak(self):
        with patch("benchmark_new_families._reference",
                   side_effect=AssertionError("REFERENCE_READ_DURING_TRAIN")) as gold:
            fitted=source_train_only()
            gold.assert_not_called()
        self.assertEqual(set(PIN_RAW),set(fitted))
        for name,item in fitted.items():
            self.assertTrue(set(x.sha for x in item["train"]).isdisjoint(
                set(x.sha for x in item["holdout"])
            ))
        name=next(iter(fitted))
        fitted[name]["holdout"].append(fitted[name]["train"][0])
        with self.assertRaisesRegex(ValueError,"SOURCE_SHA_LEAK"):
            _audit_source_split(fitted)

    @unittest.skipUnless(all((ROOT/family).is_file() and
                             (ROOT/(family+"_structured.csv")).is_file()
                             for family in PIN_RAW),
                         "New pinned reference set unavailable locally")
    def test_header_alone_does_not_safely_qualify_grammar(self):
        outcome=evaluate(source_train_only())
        self.assertEqual(1593,outcome["holdout_events"])
        self.assertEqual(1579,outcome["reference_scored_events"])
        self.assertEqual(14,outcome["excluded_reference_events"])
        self.assertEqual(14,sum(outcome["reference_exclusion_reasons"].values()))
        self.assertEqual(1593,outcome["source_records_preserved"])
        self.assertTrue(outcome["frozen_models_unchanged_after_reference_evaluation"])
        self.assertEqual(outcome["holdout_events"],outcome["reference_scored_events"]+
                         outcome["excluded_reference_events"])
        for family in outcome["families"]:
            self.assertEqual(family["test_events"],family["reference_scored"]+
                             family["excluded_reference_events"])
        self.assertEqual({"TP":381,"FP":1649,"FN":4101},
                         {k:outcome["results"]["framed_admission"][k]
                          for k in ("TP","FP","FN")})
        self.assertEqual(4482,outcome["reference_nonempty_spans"])
        self.assertEqual("REJECTED_FOR_AUTOMATIC_FAMILY_ROUTING",
                         outcome["adoption"])
        self.assertLess(outcome["results"]["framed_admission"]["f1"],
                        outcome["results"]["typed"]["f1"])
        self.assertGreater(outcome["results"]["typed"]["FP"],6000)
        self.assertFalse(outcome["dictionary_attempted"])
        self.assertFalse(outcome["native_verified"])


    def test_published_aggregate_denominators_and_no_source_values(self):
        path=Path(__file__).with_name("framing-admission-summary.json")
        outcome=json.loads(path.read_text())
        self.assertEqual("parser-studio.poc.independent-header-admission-v0.2",
                         outcome["contract"])
        self.assertEqual(outcome["holdout_events"],outcome["reference_scored_events"]+
                         outcome["excluded_reference_events"])
        self.assertEqual(outcome["holdout_events"],outcome["source_records_preserved"])
        self.assertEqual(outcome["excluded_reference_events"],
                         sum(outcome["reference_exclusion_reasons"].values()))
        for mode,result in outcome["results"].items():
            self.assertEqual(outcome["reference_nonempty_spans"],result["TP"]+result["FN"])
        def audit(value):
            if isinstance(value,dict):
                self.assertTrue(set(value).isdisjoint({
                    "raw","body","Content","EventTemplate","captures","values",
                    "templates","source_fields",
                }))
                for item in value.values():audit(item)
            elif isinstance(value,list):
                for item in value:audit(item)
        audit(outcome)


if __name__=="__main__":
    unittest.main()
