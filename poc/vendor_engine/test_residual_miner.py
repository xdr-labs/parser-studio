"""Drain3 residual span alignment remains provisional source extraction."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from residual_miner import (
    aligned_candidate,structural_candidate,run,ROOT,SAMPLE_SHA,
)


class ResidualMinerTests(unittest.TestCase):
    def test_same_ip_twice_has_distinct_byte_spans(self):
        raw="prefix src=192.0.2.8 dst=192.0.2.8 result=blocked"
        body=raw[len("prefix "):]
        template="src=<:IP:> dst=<:IP:> result=blocked"
        class Param:
            def __init__(self,value):self.value=value
        old=structural_candidate(template,body,[
            Param("192.0.2.8"),Param("192.0.2.8")
        ],len("prefix "),raw)
        self.assertEqual("AMBIGUOUS_VALUE_SPAN",old["status"])
        result=aligned_candidate(template,body,len("prefix "),raw,2)
        self.assertEqual("SOURCE_SPAN_CANDIDATE_ONLY",result["status"])
        self.assertEqual(2,len(result["captures"]))
        self.assertNotEqual(result["captures"][0]["start_byte"],
                            result["captures"][1]["start_byte"])
        for span in result["captures"]:
            value=raw.encode("utf8")[span["start_byte"]:span["end_byte"]]
            self.assertEqual("192.0.2.8",value.decode("utf8"))

    def test_unsupported_masks_or_untrained_templates_abstain(self):
        raw="prefix abc suffix suffix"
        self.assertEqual("ABSTAIN_UNQUALIFIED_CLUSTER",
                         aligned_candidate("prefix <*> suffix suffix",
                                           raw,0,raw,1)["status"])
        self.assertEqual("ABSTAIN_ADJACENT_VARIABLES",
                         aligned_candidate("prefix <*><*> suffix suffix",
                                           raw,0,raw,2)["status"])

    @unittest.skipUnless(all((ROOT/name).is_file() for name in SAMPLE_SHA),
                         "Pinned research-only Loghub source cache unavailable")
    def test_train_only_holdout_improves_candidate_span_coverage(self):
        try:
            from drain3 import TemplateMiner
        except ImportError:
            self.skipTest("Optional isolated Drain3 dependency unavailable")
        result=run()
        n=result["total"]
        self.assertEqual(1581,n["holdout_records"])
        self.assertEqual(1540,n["matched_holdout"])
        self.assertEqual(0,n["cross_family_template_match"])
        self.assertGreater(n["aligned_candidate_events"],n["candidate_events"])
        self.assertGreater(n["aligned_candidate_parameters"],n["candidate_parameters"])
        self.assertFalse(result["dictionary_attempted"])
        self.assertFalse(result["runtime_native_verified"])


if __name__=="__main__":
    unittest.main()
