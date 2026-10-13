"""Publish aggregate-only reproducible metrics. NEVER copy raw or gold data to Git."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

BASE=Path(__file__).resolve().parent
CACHE=BASE/".cache"
SUMMARY=BASE/"benchmark-summary.json"
FIELDS=("TP","FP","FN","gold_present","precision","recall","f1")


def safe_fields(obj:dict[str,Any]) -> dict[str,Any]:
    if not isinstance(obj,dict) or any(key not in obj for key in FIELDS):
        raise ValueError("BENCHMARK_METRIC_CONTRACT_INVALID")
    return {name:obj[name] for name in FIELDS}


def render(upper:dict[str,Any],browser:dict[str,Any],
           learning:dict[str,Any]) -> dict[str,Any]:
    if (upper.get("contract") not in {
        "parser-studio.poc.benchmark-checkpoint.v0.1",
        "parser-studio.poc.benchmark-checkpoint.v0.2"}
        or browser.get("contract")!="parser-studio.poc.existing-browser-field-baseline.v0.2"
        or learning.get("contract")!="parser-studio.poc.blind-holdout-result.v1"):
        raise ValueError("BENCHMARK_INPUT_CONTRACT_INVALID")
    if browser["records"]!=256 or upper["total_records"]!=256:
        raise ValueError("BENCHMARK_CORPUS_COUNT_MISMATCH")
    if (browser["six_role_gold_present"]!=1168
        or (learning["train_records"]+learning["holdout_records"])!=256
        or learning["holdout_field_metrics"]["gold_present"]>1168):
        raise ValueError("BENCHMARK_SPLIT_OR_GOLD_COUNT_MISMATCH")

    # Deliberately construct an allowlist: NEVER serialize training labels,
    # raw source bytes, source-derived string values or learned lookup tables.
    baseline={
        "records":browser["records"],
        "six_role_gold_present":browser["six_role_gold_present"],
        "direct_extracted_role_metrics":safe_fields(browser["direct_extracted_role_metrics"]),
        "normalized_role_metrics":safe_fields(browser["normalized_role_metrics"]),
        "raw_extracted_value_presence_without_semantic_assertion":{
            role:int(browser["raw_extracted_value_presence_without_semantic_assertion"].get(role,0))
            for role in ("source.ip","destination.ip","source.port",
                         "destination.port","event.action","user.name")
        },
        "warning":"Default product mappings are custom.*. Extracted value equality does not establish correct ECS role. No vendor-specific configuration.",
    }
    result={
        "stage":"ISOLATED_TRAIN_ONLY_BLIND_SAME_SOURCE_FIXTURE_HOLDOUT",
        "seed":learning["split_seed"],
        "split_sha256":learning["split_sha256"],
        "grammar_sha256":learning["grammar_sha256"],
        "train_records":learning["train_records"],
        "holdout_records":learning["holdout_records"],
        "holdout_metadata_or_goldless":learning["holdout_metadata_or_goldless"],
        "generated_grammar_profiles":learning["grammars_trained"],
        "own_grammar_matched_records":learning["matched_own_grammar_records"],
        "no_grammar_match_records":learning["no_matching_grammar_records"],
        "multiple_grammars_matched_records":learning["multiple_matching_grammars"],
        "wrong_vendor_rule_matches":learning["wrong_vendor_rule_matches"],
        "wrong_vendor_grammar_activations":learning["wrong_vendor_grammar_activations"],
        "exploratory_value_agreement_metrics":safe_fields(learning["holdout_field_metrics"]),
        "strict_unambiguous_only_metrics":safe_fields(
            learning["strict_unambiguous_holdout_field_metrics"]),
        "hand_profile_upper_control_same_holdout":safe_fields(
            learning["hand_profile_upper_control_same_holdout"]),
        "zero_shot_subtype_metrics":safe_fields(learning["zero_shot_subtype_fields"]),
        "tentative_semantic_role_observations":learning[
            "tentative_semantic_role_observations"],
        "train_equivalent_mapping_ambiguities":[
            {"grammar":x["grammar"],"role":x["role"],
             "possible_source_paths":x["possible_source_paths"]}
            for x in learning["train_equivalent_mapping_ambiguities"]],
        "unqualified_single_example_profiles":learning[
            "unqualified_single_example_profiles"],
        "fixtures":[
            {"id":f["fixture"],"train":f["train_records"],"heldout":f["holdout_records"],
             "zero_shot_subtype_records":f["zero_shot_subtype_records"],
             "field_metrics":safe_fields(f["field_metrics"])}
            for f in learning["fixtures"]],
        "constraints":learning["study_limitations"],
        "native_verified":False,
        "target_verified":False,
        "llm_used":False,
    }

    # The previous benchmark is an input artifact, not trusted output.
    # Whitelist its nested aggregate payload as well: an accidentally added
    # source or secret field must never be propagated by report regeneration.
    labels=("fortinet_traffic","fortinet_event","fortinet_utm",
            "palo_traffic","palo_threat","trellix_edr","trellix_epo",
            "trend_vision")
    metric_names=("TP","FP","FN","f1","precision","recall")
    legacy=upper["new_poc_field_level"]
    def legacy_metric(data:dict[str,Any]) -> dict[str,Any]:
        return {k:data[k] for k in metric_names}
    legacy_roles={
        r:legacy_metric(legacy["roles"][r])
        for r in ("source.ip","destination.ip","source.port",
                  "destination.port","event.action","user.name")
    }
    previous=upper["fixtures"]
    if len(previous)!=len(labels) or {f["id"] for f in previous}!=set(labels):
        raise ValueError("BENCHMARK_FIXTURE_ID_MISMATCH")
    old_fixtures=[
        {"id":f["id"],"events":int(f["events"]),
         "gold_event_records":int(f["gold_event_records"]),
         "metadata_or_goldless_records":int(f["metadata_or_goldless_records"]),
         "field_evaluation":{
             k:f["field_evaluation"][k]
             for k in ("true_fields","extra_or_wrong","missing_or_wrong",
                       "precision","recall")
         }}
        for f in previous
    ]
    old_events=upper["existing_ui_default_preview"]
    summary={
        "contract":"parser-studio.poc.benchmark-checkpoint.v0.2",
        "status":"LOCAL_EXPERIMENT_ONLY_NOT_NATIVE_NOT_TARGET",
        "total_records":256,
        "fixture_manifest":"manifest.json",
        "source_authorization":"Pinned upstream Elastic/x-pack read-only research; raw and gold never committed.",
        "existing_ui_default_preview":{
            "browser_extracted_events":int(old_events["browser_extracted_events"]),
            "browser_normalized_events":int(old_events["browser_normalized_events"]),
            "records":int(old_events["records"]),
            "warning":"Event-level default preview counts; not a field-level baseline.",
        },
        "new_poc_field_level":{
            "roles":legacy_roles,
            "micro_metrics":legacy_metric(legacy["micro_metrics"]),
            "same_fixture_latter_half_probe":legacy_metric(
                legacy["same_fixture_latter_half_probe"]),
            "caveat":"Hand-derived source profiles, not learned or blind generalization.",
        },
        "fixtures":old_fixtures,
        "existing_ui_same_six_roles":baseline,
        "auto_learned_blind_holdout":result,
        "native_fluentd_verified":False,
        "stellar_dp_verified":False,
        "sensor_or_network_io":False,
        "llm_used":False,
        "real_drain3_miner_used":False,
        "jsonata_used":False,
    }
    return summary


def main() -> None:
    upper=json.loads(SUMMARY.read_text("utf8"))
    browser=json.loads((CACHE/"current_baseline.json").read_text("utf8"))
    learning=json.loads((CACHE/"learned_result.json").read_text("utf8"))
    output=render(upper,browser,learning)
    SUMMARY.write_text(json.dumps(output,ensure_ascii=True,sort_keys=True,indent=2)+"\n","utf8")
    print("PUBLISHED AGGREGATES ONLY, INPUT",output["total_records"],
          "LEARNED HOLDOUT",output["auto_learned_blind_holdout"]["holdout_records"],
          "NO RAW/GOLD VALUES")


if __name__=="__main__":
    main()
