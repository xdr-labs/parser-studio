"""Third prospective source-only family validation (Mac and Hadoop).

Fixed admission hypothesis before gold: use corrected typed masks only for
events with structurally validated BSD Syslog header; otherwise use unchanged
legacy mode. Original source raw-only grammar training is complete BEFORE
reading any independent Loghub EventTemplate annotations. This intentionally
records the failed hypothesis: simple header gating is NOT product safe.

No source, gold, customer values or literal templates are published.
"""
from __future__ import annotations
from collections import Counter
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import benchmark_new_families as corpus
from residual_miner import aligned_candidate
from benchmark_residual_gold import oracle_spans,score,_metric
from structured_source import extract_plain_bsd

PIN_RAW={
    "Mac_2k.log":"d9ea495488728d8c989dc942fca3324a3cc7b19b0a6f409a5fd568ad547fd931",
    "Hadoop_2k.log":"9ecaeb807d50d5fb5a20982ea66f1c8d32545259a51ce7456c1ab78db0509732",
}
PIN_GOLD={
    "Mac_2k.log":"c8d5d74e0dcd923675ee944ea592abaf0eae91ef492435330694ce5008267c8d",
    "Hadoop_2k.log":"e88e5bf99d7f23f482517cc79290ad75b90d914af5d6114176e8bbf0f8ae0fad",
}


@contextmanager
def pinned_only():
    # The pinned corpus wrapper is borrowed only to avoid duplicated raw
    # source decoding and SHA validation; no user or product globals mutate.
    with patch.dict(corpus.RAW_DIGEST,PIN_RAW,clear=True),patch.dict(
        corpus.GOLD_DIGEST,PIN_GOLD,clear=True
    ):
        yield


def source_train_only():
    """Never calls a reference loader or reads a .csv gold during fit."""
    with pinned_only():
        return corpus.blinded_fit()


def _model_fingerprints(states:dict[str,Any])->dict[str,dict[str,str]]:
    """Publish only digests, never train-derived literal templates."""
    return {
        name:{mode:hashlib.sha256(json.dumps(sorted(
            (cluster.get_template(),cluster.size)
            for cluster in model.drain.clusters
        ),ensure_ascii=True).encode("utf8")).hexdigest()
              for mode,model in item["models"].items()}
        for name,item in states.items()
    }


def _audit_source_split(states:dict[str,Any])->None:
    if set(states)!=set(PIN_RAW):
        raise ValueError("FRAMING_SOURCE_FAMILY_SET_MISMATCH")
    for state in states.values():
        if {x.sha for x in state["train"]}&{x.sha for x in state["holdout"]}:
            raise ValueError("FRAMING_TRAIN_HOLDOUT_SOURCE_SHA_LEAK")
        if set(state["models"])!={"legacy","typed"}:
            raise ValueError("FRAMING_MODEL_VARIANTS_MISMATCH")
        for event in [*state["train"],*state["holdout"]]:
            if hashlib.sha256(event.raw.encode("utf8")).hexdigest()!=event.sha:
                raise ValueError("FRAMING_RAW_SOURCE_CHANGED")
            if event.start<0 or event.raw[event.start:event.end]!=event.body:
                raise ValueError("FRAMING_BODY_SOURCE_SLICE_CHANGED")


def evaluate(states:dict[str,Any])->dict[str,Any]:
    """Gold source labels are first opened AFTER source model fitting."""
    _audit_source_split(states)
    frozen=_model_fingerprints(states)
    exclusions=Counter()
    overall={mode:Counter() for mode in ("legacy","typed","framed_admission")}
    summaries=[]
    for name,state in sorted(states.items()):
        with pinned_only():
            labels=corpus._reference(name)
        family={mode:Counter() for mode in overall}
        count=Counter()
        for event in state["holdout"]:
            count["all_heldout_events"]+=1
            routed="typed" if extract_plain_bsd(event.raw) is not None else "legacy"
            count["typed_by_header_all"]+=routed=="typed"
            if event.sha not in labels:
                raise ValueError("FRAMING_REFERENCE_SOURCE_MISSING")
            status,expected=oracle_spans(event.raw,*labels[event.sha])
            if status!="VALID_REFERENCE":
                count[status]+=1
                exclusions[status]+=1
                continue
            count["reference_scored_events"]+=1
            count["reference_nonempty_spans"]+=len(expected)
            count["typed_by_header"]+=routed=="typed"
            candidates={}
            for variant,model in state["models"].items():
                cluster=model.match(event.body,full_search_strategy="always")
                result=aligned_candidate(
                    cluster.get_template(),event.body,event.start,event.raw,
                    cluster.size
                ) if cluster else {"captures":[]}
                candidates[variant]=[(x["start_byte"],x["end_byte"])
                                     for x in result["captures"]]
            candidates["framed_admission"]=candidates[routed]
            for mode,values in candidates.items():
                family[mode].update(score(expected,values))
        for key in overall:overall[key].update(family[key])
        summaries.append({
            "family":name.removesuffix("_2k.log"),
            "train_events":len(state["train"]),
            "test_events":len(state["holdout"]),
            "reference_scored":count["reference_scored_events"],
            "excluded_reference_events":len(state["holdout"])-count["reference_scored_events"],
            "reference_exclusion_reasons":{
                k:v for k,v in sorted(count.items()) if k.startswith("REFERENCE_")
            },
            "source_records_preserved":count["all_heldout_events"],
            "train_unique_source_hashes":len({x.sha for x in state["train"]}),
            "holdout_unique_source_hashes":len({x.sha for x in state["holdout"]}),
            "model_sha256":frozen[name],
            "gold_spans":count["reference_nonempty_spans"],
            "typed_by_raw_header_all_heldout":count["typed_by_header_all"],
            "typed_by_raw_header_reference_scored":count["typed_by_header"],
            "legacy":_metric(family["legacy"]),
            "typed":_metric(family["typed"]),
            "framed_admission":_metric(family["framed_admission"]),
        })
    if frozen!=_model_fingerprints(states):
        raise ValueError("FRAMING_MODEL_CHANGED_DURING_REFERENCE_EVALUATION")
    return {
        "contract":"parser-studio.poc.independent-header-admission-v0.2",
        "source":"logpai/loghub",
        "pinned_commit":corpus.COMMIT,
        "split_seed":corpus.SEED,
        "source_sha256":PIN_RAW,
        "labels_sha256":PIN_GOLD,
        "holdout_events":sum(x["test_events"] for x in summaries),
        "reference_scored_events":sum(x["reference_scored"] for x in summaries),
        "excluded_reference_events":sum(exclusions.values()),
        "reference_exclusion_reasons":dict(sorted(exclusions.items())),
        "source_records_preserved":sum(x["source_records_preserved"] for x in summaries),
        "metric_denominator":"reference-scored events only; excluded references are not successes",
        "source_redaction_assessment":"NOT_ASSESSED; raw source redaction is not inferred from annotation wildcards or internal masks",
        "reference_nonempty_spans":sum(x["gold_spans"] for x in summaries),
        "admission_policy":"BSD header verified by deterministic raw scanner -> typed, else legacy",
        "results":{k:_metric(v) for k,v in overall.items()},
        "families":summaries,
        "adoption":"REJECTED_FOR_AUTOMATIC_FAMILY_ROUTING",
        "reason":"Header presence does not qualify model variable boundaries; high false-positive source captures",
        "blind_train_gold_separation":True,
        "same_revision_hash_disjoint_heldout":True,
        "frozen_models_unchanged_after_reference_evaluation":True,
        "raw_and_gold_ignored":True,
        "dictionary_attempted":False,
        "native_verified":False,
    }


if __name__=="__main__":
    states=source_train_only()
    metrics=evaluate(states)
    path=Path(__file__).resolve().parent/"framing-admission-summary.json"
    path.write_text(json.dumps(metrics,indent=2,sort_keys=True)+"\n")
    print("FRAMING_ADMISSION_ACCOUNTED", "all_heldout",metrics["holdout_events"],
          "reference_scored",metrics["reference_scored_events"],
          "excluded",metrics["excluded_reference_events"],
          "exclusion_reasons",metrics["reference_exclusion_reasons"],
          "reference_spans",metrics["reference_nonempty_spans"],metrics["results"])
    for row in metrics["families"]:
        print(row["family"],row["test_events"],row["framed_admission"])
