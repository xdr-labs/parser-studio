"""Fresh OpenSSH/Proxifier families are reference-scored only after fitting."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_new_families import (
    RAW_DIGEST,GOLD_DIGEST,ROOT,raw_samples,blinded_fit,evaluate,
)


class UntouchedFamilyTests(unittest.TestCase):
    def test_header_and_unframed_source_keeps_raw_identity(self):
        cases={
            "OpenSSH_2k.log":"Dec 10 06:55:46 host sshd[123]: message",
            "Proxifier_2k.log":"[10.30 16:49:06] chrome.exe - example:443 open",
        }
        self.assertEqual(2,len(RAW_DIGEST))
        self.assertEqual(set(RAW_DIGEST),set(GOLD_DIGEST))
        self.assertNotEqual(cases["OpenSSH_2k.log"],
                            cases["Proxifier_2k.log"])

    @unittest.skipUnless(all((ROOT/key).is_file() and
                             (ROOT/(key+"_structured.csv")).is_file()
                             for key in RAW_DIGEST),
                         "Pinned independent Loghub research cache unavailable")
    def test_training_does_not_look_up_gold_and_split_excludes_same_sha(self):
        with patch("benchmark_new_families._reference",
                   side_effect=AssertionError("BLIND_TRAIN_CANNOT_READ_GOLD")) as gold:
            states=blinded_fit()
            gold.assert_not_called()
        for family,item in states.items():
            train={x.sha for x in item["train"]}
            heldout={x.sha for x in item["holdout"]}
            self.assertFalse(train&heldout)
            self.assertGreater(len(heldout),600)
            self.assertGreater(len(item["holdout"]),700)

    @unittest.skipUnless(all((ROOT/key).is_file() and
                             (ROOT/(key+"_structured.csv")).is_file()
                             for key in RAW_DIGEST),
                         "Pinned independent Loghub research cache unavailable")
    def test_first_run_source_span_stats_are_honest_including_worse_family(self):
        state=blinded_fit()
        result=evaluate(state)
        self.assertEqual(1578,result["heldout_events"])
        self.assertEqual(1578,result["gold_scored_events"])
        self.assertEqual(5882,result["nonempty_gold_variable_spans"])
        self.assertFalse(result["dictionary_attempted"])
        self.assertFalse(result["native_or_stellar_verified"])
        by_family={x["family"]:x for x in result["families"]}
        self.assertGreater(by_family["OpenSSH"]["typed_source_metrics"]["f1"],
                           by_family["OpenSSH"]["legacy_source_metrics"]["f1"])
        self.assertLess(by_family["Proxifier"]["typed_source_metrics"]["f1"],
                        by_family["Proxifier"]["legacy_source_metrics"]["f1"])
        self.assertGreater(result["corrected_typed_source_metrics"]["FP"],
                           result["legacy_source_metrics"]["FP"])


if __name__=="__main__":
    unittest.main()
