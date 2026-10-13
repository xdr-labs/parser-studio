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

    summary={
        **{k:v for k,v in upper.items() if k!="contract"},
        "contract":"parser-studio.poc.benchmark-checkpoint.v0.2",
        "existing_ui_same_six_roles":baseline,
        "auto_learned_blind_holdout":result,
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
