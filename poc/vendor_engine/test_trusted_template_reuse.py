"""Verified train-labeled grammar reuse is NOT unlabelled auto-learning."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from residual_miner import Residual,samples,train_holdout
from trusted_template_reuse import (
    CACHE,collect_labeled_training_only,fit_train_only,
    evaluate_heldout,framing_signature,route,_rule_matches,
)
from benchmark_residual_gold import LABEL_SHA,LABEL_COMMIT


def labeled_synthetic(rows):
    with tempfile.TemporaryDirectory() as dirname:
        path=Path(dirname)/"train.json"
        path.write_text(json.dumps({
            "contract":"parser-studio.poc.trusted-template-train-only.v0.1",
            "rows":rows,
        },sort_keys=True),encoding="utf8")
        return fit_train_only(path)


def sample_row(raw,body,template,framing="APACHE_ERROR"):
    return {"sha256":hashlib.sha256(raw.encode("utf8")).hexdigest(),
            "framing":framing,"template":template,
            "body":body,"raw":raw,"body_start":raw.index(body)}


class TrustedTemplateTests(unittest.TestCase):
    def test_two_training_examples_create_source_preserving_candidate(self):
        t="workerEnv.init() ok <*>"
        records=[
            sample_row("[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/a",
                       "workerEnv.init() ok /etc/a",t),
            sample_row("[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/b",
                       "workerEnv.init() ok /etc/b",t),
        ]
        candidate=labeled_synthetic(records)
        self.assertEqual(1,len(candidate["rules"]))
        hold_raw="[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/c"
        body="workerEnv.init() ok /etc/c"
        hold=Residual("unimportant",hold_raw,body,hold_raw.index(body),
                      len(hold_raw),hashlib.sha256(hold_raw.encode()).hexdigest())
        label,values=route(candidate,hold)
        self.assertEqual("VERIFIED_TRAIN_TEMPLATE_CANDIDATE",label)
        self.assertEqual(1,len(values))
        self.assertEqual(b"/etc/c",
                         hold_raw.encode("utf8")[values[0][0]:values[0][1]])

    def test_single_training_example_is_not_trusted(self):
        body="workerEnv.init() ok /etc/a"
        raw="[Sun Dec 04 04:47:44 2005] [notice] "+body
        rules=labeled_synthetic([sample_row(raw,body,"workerEnv.init() ok <*>")])
        self.assertEqual(0,len(rules["rules"]))
        self.assertIn("insufficient_distinct_training_samples",rules["rejected"])

    def test_wrong_framing_and_template_overcapture_are_not_allowed(self):
        body="workerEnv.init() ok /etc/a"
        raw="[Sun Dec 04 04:47:44 2005] [notice] "+body
        rows=[sample_row(raw,body,"workerEnv.init() ok <*>"),
              sample_row(raw.replace("/etc/a","/etc/b"),body.replace("/etc/a","/etc/b"),
                         "workerEnv.init() ok <*>")]
        rules=labeled_synthetic(rows)
        # Same body from BSD syslog must not be routed as Apache.
        foreign_raw="Jun 14 15:16:01 host app: "+body
        foreign=Residual("unimportant",foreign_raw,body,foreign_raw.index(body),
                         len(foreign_raw),hashlib.sha256(foreign_raw.encode()).hexdigest())
        self.assertEqual("BSD_SYSLOG",framing_signature(foreign_raw))
        self.assertEqual(("NO_VERIFIED_PROFILE",[]),route(rules,foreign))
        self.assertIsNone(_rule_matches("workerEnv.init() ok <*>",
                                        raw,body+" EXFIL",raw.index(body),2))

    def test_duplicate_source_value_span_retains_coordinates(self):
        template="User <*> from <*> securely authenticated"
        body="User alice from alice securely authenticated"
        raw="[Sun Dec 04 04:47:44 2005] [notice] "+body
        spans=_rule_matches(template,raw,body,raw.index(body),3)
        self.assertEqual(2,len(spans))
        self.assertNotEqual(spans[0],spans[1])
        self.assertTrue(all(raw.encode()[a:b]==b"alice" for a,b in spans))

    def test_corrupted_grammar_digest_rejected_before_gold_io(self):
        train_path=CACHE/"trusted_train_only.json"
        if not train_path.is_file():
            self.skipTest("Local source-only train snapshot absent")
        rules=fit_train_only(train_path)
        corrupted=copy.deepcopy(rules)
        corrupted["rules"].append({"injected":True})
        with patch("trusted_template_reuse.reference_labels",
                   side_effect=AssertionError("GOLD_READ_BEFORE_DIGEST")) as source:
            with self.assertRaisesRegex(ValueError,"FROZEN_TEMPLATE_REGISTRY_DIGEST"):
                evaluate_heldout(corrupted)
            source.assert_not_called()

    @unittest.skipUnless(all((CACHE/"loghub"/
                     (x.removesuffix(".log")+".log_structured.csv")).is_file()
                              for x in LABEL_SHA),"Pinned Loghub research gold cache absent")
    def test_fitting_receives_only_train_sha_and_reference_metric_is_not_semantic(self):
        labeled,held=collect_labeled_training_only()
        self.assertGreater(len(labeled),2000)
        train_digests={x["sha256"] for x in labeled}
        for family,rows in held.items():
            self.assertFalse(train_digests & {x.sha for x in rows})
        path=CACHE/"trusted_train_only.json"
        if not path.is_file():
            self.skipTest("Isolated training file not prepared")
        model=fit_train_only(path)
        result=evaluate_heldout(model)
        self.assertEqual(1581,result["holdout_records"])
        self.assertGreater(result["parameter_metrics"]["TP"],3000)
        self.assertGreater(result["parameter_metrics"]["f1"],0.95)
        self.assertEqual(0,result["parameter_metrics"]["FP"])
        self.assertFalse(result["stellar_dictionary_applied"])
        self.assertFalse(result["native_verified"])
        self.assertIn("annotated",result["training_type"])


if __name__=="__main__":
    unittest.main()
