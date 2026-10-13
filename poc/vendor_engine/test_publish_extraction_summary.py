"""Publishing never leaks original fields, values or annotated templates."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from publish_extraction_summary import render,ROOT


def metrics(tp,fp,fn):
    return {"TP":tp,"FP":fp,"FN":fn,
            "precision":round(tp/(tp+fp),4) if tp+fp else None,
            "recall":round(tp/(tp+fn),4) if tp+fn else None,
            "f1":round(2*tp/(2*tp+fp+fn),4) if 2*tp+fp+fn else None}


def fixtures():
    source={
        "contract":"parser-studio.poc.pinned-source-field-gold-v0.1",
        "total_records":256,"reference_source_field_occurrences":14645,
        "extracted_source_field_occurrences":14645,
        "exact_source_field_metrics":metrics(14645,0,0),"unparsed_bytes":0,
        "semantic_normalization_attempted":False,
        "native_verified":False,
        "raw":"DO_NOT_PUBLISH","username":"CUSTOMER_SECRET"}
    residual={
        "contract":"parser-studio.poc.loghub-reference-span-v0.1",
        "raw_event_count":1581,"reference_nonempty_variable_spans":3138,
        "baseline_exact_reference_parameter":metrics(518,73,2620),
        "anchored_exact_reference_parameter":metrics(744,73,2394),
        "train_data":{"raw_source":"DO_NOT_PUBLISH"},
        "template":"COPYRIGHT_SENSITIVE_TEMPLATE"}
    trained={
        "contract":"parser-studio.poc.retrieval-first-source-span-v0.1",
        "holdout_records":1581,"gold_nonempty_variable_spans":3138,
        "registered_profiles":24,
        "records_routed_to_train_verified_profile":1523,
        "parameter_metrics":metrics(3073,0,65),
        "stellar_dictionary_applied":False,"native_verified":False,
        "source_rule_literals":"DO_NOT_PUBLISH"}
    return source,residual,trained


class PublishTests(unittest.TestCase):
    def test_report_contains_only_qualified_values_and_not_logs(self):
        result=render(*fixtures())
        content=json.dumps(result)
        self.assertNotIn("DO_NOT_PUBLISH",content)
        self.assertNotIn("CUSTOMER_SECRET",content)
        self.assertNotIn("COPYRIGHT_SENSITIVE_TEMPLATE",content)
        self.assertEqual("NOT_YET_QUALIFIED",
                         result["research_decision"]["novel_unstructured_auto_parsing"])
        self.assertEqual("TRAIN_ANNOTATED_GRAMMAR_RETRIEVAL_NOT_UNSUPERVISED",
                         result["already_annotated_training_template_reuse"]["qualification"])
        self.assertEqual(14645,result["structured_and_semistructured"][
            "exact_source_field"]["TP"])

    def test_false_native_verification_cannot_be_published(self):
        src,res,train=fixtures()
        src["native_verified"]=True
        with self.assertRaisesRegex(ValueError,"FALSE_QUALIFICATION"):
            render(src,res,train)

    def test_bad_reference_denominator_fails_closed(self):
        src,res,train=fixtures()
        res["anchored_exact_reference_parameter"]["FN"]-=1
        with self.assertRaisesRegex(ValueError,"DENOMINATOR_INVALID"):
            render(src,res,train)

    def test_unfounded_improvement_cannot_be_published(self):
        src,res,train=fixtures()
        res["anchored_exact_reference_parameter"]=res[
            "baseline_exact_reference_parameter"]
        with self.assertRaisesRegex(ValueError,"UNVERIFIED_IMPROVEMENT"):
            render(src,res,train)

    def test_existing_report_is_value_only(self):
        file=ROOT/"extraction-summary.json"
        if not file.exists():
            self.skipTest("Aggregate report not generated yet")
        result=json.loads(file.read_text())
        self.assertEqual("parser-studio.poc.extraction-first-summary.v0.1",result["contract"])
        self.assertFalse("raw" in result)
        self.assertEqual(256,result["structured_and_semistructured"]["events_accounted"])


if __name__=="__main__":
    unittest.main()
