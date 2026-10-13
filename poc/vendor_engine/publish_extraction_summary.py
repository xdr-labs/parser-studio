"""Publish only independently measured extraction-first research aggregates.

No original logs, reference templates, learned literals, user identities,
private source values, source field names, or licensed dataset content may
appear in the tracked report.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parent
CACHE=ROOT/".cache"
KEYS=("TP","FP","FN","precision","recall","f1")


def _measured(values:dict[str,Any])->dict[str,Any]:
    if not isinstance(values,dict) or any(k not in values for k in KEYS):
        raise ValueError("FIELD_MEASUREMENT_CONTRACT_INVALID")
    return {k:values[k] for k in KEYS}


def render(source:dict[str,Any],
           unsupervised:dict[str,Any],
           trained:dict[str,Any])->dict[str,Any]:
    if (source.get("contract")!="parser-studio.poc.pinned-source-field-gold-v0.1"
        or unsupervised.get("contract")!="parser-studio.poc.loghub-reference-span-v0.1"
        or trained.get("contract")!="parser-studio.poc.retrieval-first-source-span-v0.1"):
        raise ValueError("EXTRACTION_REPORT_CONTRACT_MISMATCH")
    if (source["total_records"]!=256
        or source["reference_source_field_occurrences"]!=14645
        or source["extracted_source_field_occurrences"]!=14645
        or unsupervised["raw_event_count"]!=trained["holdout_records"]
        or unsupervised["reference_nonempty_variable_spans"]!=trained["gold_nonempty_variable_spans"]
        or unsupervised["raw_event_count"]<=0):
        raise ValueError("EXTRACTION_REPORT_DATASET_MISMATCH")
    if (source.get("semantic_normalization_attempted") is not False
        or trained.get("stellar_dictionary_applied") is not False
        or source.get("native_verified") is not False
        or trained.get("native_verified") is not False):
        raise ValueError("EXTRACTION_REPORT_FALSE_QUALIFICATION")
    a=_measured(unsupervised["baseline_exact_reference_parameter"])
    b=_measured(unsupervised["anchored_exact_reference_parameter"])
    c=_measured(trained["parameter_metrics"])
    s=_measured(source["exact_source_field_metrics"])
    if (a["TP"]+a["FN"]!=unsupervised["reference_nonempty_variable_spans"]
        or b["TP"]+b["FN"]!=unsupervised["reference_nonempty_variable_spans"]
        or c["TP"]+c["FN"]!=trained["gold_nonempty_variable_spans"]
        or s["TP"]+s["FN"]!=14645):
        raise ValueError("EXTRACTION_REPORT_METRIC_DENOMINATOR_INVALID")
    if (b["f1"] is None or a["f1"] is None or c["f1"] is None
        or b["f1"]<=a["f1"]):
        raise ValueError("EXTRACTION_REPORT_UNVERIFIED_IMPROVEMENT")
    return {
        "contract":"parser-studio.poc.extraction-first-summary.v0.1",
        "scope":"ISOLATED_RESEARCH_ONLY_NOT_PRODUCT_OR_NATIVE",
        "priority":["SOURCE_FIELD_EXTRACTION",
                    "UNSUPPORTED_RESIDUAL_EXTRACTION",
                    "OPTIONAL_STELLAR_DICTIONARY_NORMALIZATION"],
        "structured_and_semistructured":{
            "events_accounted":int(source["total_records"]),
            "independently_reference_scored_vendor_fields":int(source[
                "reference_source_field_occurrences"]),
            "exact_source_field":s,
            "unparsed_bytes":int(source["unparsed_bytes"]),
            "qualification":"ONLY_8_PINNED_KNOWN_FORMAT_SOURCE_FIXTURES",
        },
        "unknown_unstructured_without_training_labels":{
            "heldout_events":int(unsupervised["raw_event_count"]),
            "reference_nonempty_parameters":int(unsupervised[
                "reference_nonempty_variable_spans"]),
            "previous_drain3_span":a,
            "strict_anchor_span":b,
            "qualification":"DISJOINT_RAW_SHA_SAME_SOURCE_REVISION",
        },
        "already_annotated_training_template_reuse":{
            "heldout_events":int(trained["holdout_records"]),
            "independent_reference_nonempty_parameters":int(trained[
                "gold_nonempty_variable_spans"]),
            "trained_qualified_profiles":int(trained["registered_profiles"]),
            "matched_profile_events":int(trained[
                "records_routed_to_train_verified_profile"]),
            "exact_reference_span":c,
            "qualification":"TRAIN_ANNOTATED_GRAMMAR_RETRIEVAL_NOT_UNSUPERVISED",
        },
        "research_decision":{
            "structured_parsing":"SUPPORTED_WITHIN_PINNED_FIXTURE_SCOPE",
            "profile_retrieval":"PROMISING_WHEN_RIGHTS_CLEARED_AND_LABELED",
            "novel_unstructured_auto_parsing":"NOT_YET_QUALIFIED",
            "commercial_template_distribution":"LICENSE_REVIEW_REQUIRED",
            "native_ruby_conf":"NOT_VERIFIED",
            "stellar_target":"NOT_VERIFIED",
        },
        "critical_caveats":[
            "The 98.95 percent retrieval result depends on annotated training templates.",
            "The 37.62 percent unsupervised result is reference template-span F1, not all original vendor fields.",
            "The 100 percent structured source-field result is restricted to eight known-format pinned fixture sets.",
            "No original values, labels, or licensed profile literals are committed.",
        ],
    }


def main()->None:
    from benchmark_source_field_gold import evaluate as source_eval
    from benchmark_residual_gold import evaluate as residual_eval
    from trusted_template_reuse import (
        write_training_snapshot,fit_train_only,evaluate_heldout,
    )
    source=source_eval()
    residual=residual_eval("residual")
    write_training_snapshot()
    trained=evaluate_heldout(fit_train_only())
    result=render(source,residual,trained)
    path=ROOT/"extraction-summary.json"
    path.write_text(json.dumps(result,indent=2,sort_keys=True,
                               ensure_ascii=True)+"\n","utf8")
    print("VALUE_ONLY_EXTRACTION_SUMMARY",str(path),
          "known_source_TP",result["structured_and_semistructured"][
              "exact_source_field"]["TP"],
          "novel_F1",result["unknown_unstructured_without_training_labels"][
              "strict_anchor_span"]["f1"],
          "trained_retrieval_F1",result["already_annotated_training_template_reuse"][
              "exact_reference_span"]["f1"])


if __name__=="__main__":
    main()
