"""Public aggregate is allowlisted: raw/gold and learned source lookups never leave cache."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from report import render


class ReportTests(unittest.TestCase):
    def test_aggregate_keeps_only_whitelisted_counters(self):
        keys=("TP","FP","FN","gold_present","precision","recall","f1")
        def stat(**kw):
            value={k:0 for k in keys}
            value.update(kw)
            return value
        six_roles=("source.ip","destination.ip","source.port",
                   "destination.port","event.action","user.name")
        fixture_names=("fortinet_traffic","fortinet_event","fortinet_utm",
                       "palo_traffic","palo_threat","trellix_edr",
                       "trellix_epo","trend_vision")
        upper={
            "contract":"parser-studio.poc.benchmark-checkpoint.v0.1",
            "total_records":256,"sensitive_raw":"DO_NOT_PUBLISH_UPPER",
            "existing_ui_default_preview":{
                "browser_extracted_events":80,"browser_normalized_events":59,"records":256
            },
            "new_poc_field_level":{
                "roles":{role:stat() for role in six_roles},
                "micro_metrics":stat(),"same_fixture_latter_half_probe":stat(),
                "sensitive_nested":"DO_NOT_PUBLISH_NESTED",
            },
            "fixtures":[{
                "id":name,"events":1,"gold_event_records":1,
                "metadata_or_goldless_records":0,
                "field_evaluation":{
                    "true_fields":0,"extra_or_wrong":0,"missing_or_wrong":0,
                    "precision":1,"recall":1,"raw":"DO_NOT_PUBLISH_NESTED"
                },
            } for name in fixture_names]
        }
        browser={"contract":"parser-studio.poc.existing-browser-field-baseline.v0.2",
                 "records":256,"six_role_gold_present":1168,
                 "direct_extracted_role_metrics":stat(),
                 "normalized_role_metrics":stat(),
                 "raw_extracted_value_presence_without_semantic_assertion":{"source.ip":55},
                 "sensitive_raw":"DONT_PUBLISH_THIS"}
        learning={
            "contract":"parser-studio.poc.blind-holdout-result.v1",
            "split_seed":"fixed","split_sha256":"abc","grammar_sha256":"def",
            "train_records":156,"holdout_records":100,
            "holdout_metadata_or_goldless":1,"grammars_trained":8,
            "matched_own_grammar_records":98,"no_matching_grammar_records":2,
            "multiple_matching_grammars":0,
            "wrong_vendor_rule_matches":0,"wrong_vendor_grammar_activations":0,
            "holdout_field_metrics":stat(TP=433),
            "strict_unambiguous_holdout_field_metrics":stat(TP=299),
            "hand_profile_upper_control_same_holdout":stat(TP=436),
            "zero_shot_subtype_fields":stat(TP=22),
            "tentative_semantic_role_observations":134,
            "train_equivalent_mapping_ambiguities":[{
                "grammar":"palo_traffic:BSD_CSV","role":"destination.ip",
                "possible_source_paths":2}],
            "unqualified_single_example_profiles":2,
            "fixtures":[{"fixture":"a","train_records":156,"holdout_records":100,
                         "zero_shot_subtype_records":2,
                         "field_metrics":stat(TP=433),"raw":"DO_NOT_PUBLISH"}],
            "study_limitations":["No Stellar target qualification"],
            "raw_gold_records":[{"password":"DO_NOT_PUBLISH"}],
        }
        result=render(upper,browser,learning)
        text=json.dumps(result)
        self.assertNotIn("DONT_PUBLISH_THIS",text)
        self.assertNotIn("DO_NOT_PUBLISH",text)
        self.assertNotIn("raw_gold_records",text)
        self.assertEqual(433,result["auto_learned_blind_holdout"][
            "exploratory_value_agreement_metrics"]["TP"])
        self.assertEqual(299,result["auto_learned_blind_holdout"][
            "strict_unambiguous_only_metrics"]["TP"])
        self.assertFalse(result["auto_learned_blind_holdout"]["native_verified"])

    def test_missing_inputs_cannot_be_silently_published(self):
        with self.assertRaises(ValueError):
            render({},{"contract":"x"},{"contract":"y"})


if __name__=="__main__":
    unittest.main()
