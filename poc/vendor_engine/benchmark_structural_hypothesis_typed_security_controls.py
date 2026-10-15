"""Broad security-family abstention/regression gate for typed residual hypotheses.

This benchmark is value-free. It groups public/local research fixtures by
security-product family, performs three deterministic train/holdout splits, and
verifies that typed residual learning does not alter the current baseline
parser. Reference correctness of accepted Cisco ISE/Snort additions is scored
separately by benchmark_structural_hypothesis_typed_reference_multisplit.py.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import (
    LOCAL_CACHE,
    _events,
    _files,
)
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    augment_residual_hypothesis,
    learn_typed_residual_hypotheses,
    parse_with_typed_residual_hypotheses,
)

OUT=Path(__file__).resolve().parent/"structural-hypothesis-typed-security-controls-summary.json"
REFERENCE_VALIDATED_FAMILIES={"cisco_ise","snort"}


def _snort_full_events()->list[str]:
    lines=(LOCAL_CACHE/"snort_full.log").read_text("utf8").splitlines(keepends=True)
    out:list[str]=[]
    current=""
    for line in lines:
        if line.startswith("[**]") and current:
            while current.endswith("\n\n"):
                current=current[:-1]
            out.append(current)
            current=line
        else:
            current+=line
    if current:
        while current.endswith("\n\n"):
            current=current[:-1]
        out.append(current)
    return out


def _family_streams()->dict[str,dict[str,Any]]:
    grouped:dict[str,dict[str,Any]]={}
    for source in _files():
        path=Path(source["path"])
        if not path.exists():
            continue
        item=grouped.setdefault(
            source["family"],
            {"categories":set(),"events":[],"source_files":0},
        )
        item["categories"].add(source["category"])
        item["events"].extend(_events(path))
        item["source_files"]+=1

    snort=grouped.setdefault(
        "snort",
        {"categories":set(),"events":[],"source_files":0},
    )
    snort["categories"].add("IDS_IPS")
    snort["events"].extend(_events(LOCAL_CACHE/"snort_fast.log"))
    snort["events"].extend(_snort_full_events())
    snort["source_files"]+=2

    for item in grouped.values():
        # Preserve first occurrence while preventing duplicate raw events from
        # overweighting hypothesis support.
        item["events"]=list(dict.fromkeys(item["events"]))
        item["categories"]=sorted(item["categories"])
    return grouped


def run()->dict[str,Any]:
    streams=_family_streams()
    aggregate=Counter()
    by_family={}
    by_category:dict[str,Counter]=defaultdict(Counter)
    augmentation_families=set()
    unique_augmented=set()

    for family,item in sorted(streams.items()):
        rows=item["events"]
        family_metrics=Counter()
        split_rows=[]
        if len(rows)<3:
            family_metrics["events_too_small_for_learning"]=len(rows)
            by_family[family]={
                "categories":item["categories"],
                "source_files":item["source_files"],
                "unique_events":len(rows),
                "metrics":dict(family_metrics),
                "splits":[],
            }
            continue

        for seed in SEEDS:
            train,holdout=_split_seed(rows,seed)
            training=[parse_security_multipass(raw) for raw in train]
            hypotheses=learn_typed_residual_hypotheses(training)
            metrics=Counter()
            split_augmented=[]
            for raw in holdout:
                baseline=parse_security_multipass(raw)
                metrics["events"]+=1
                if baseline.status=="SOURCE_PARSED":
                    metrics["baseline_complete"]+=1
                    continue
                metrics["baseline_incomplete"]+=1
                candidate=parse_with_typed_residual_hypotheses(
                    raw,baseline,hypotheses
                )
                augmented=augment_residual_hypothesis(baseline,candidate)
                if augmented is None or candidate is None:
                    continue
                metrics["augmented_events"]+=1
                metrics["added_spans"]+=len(candidate.value_spans)
                if augmented.status!=baseline.status:
                    metrics["status_changed"]+=1
                if augmented.issues!=baseline.issues:
                    metrics["issues_changed"]+=1
                if augmented.raw!=baseline.raw:
                    metrics["raw_changed"]+=1
                import hashlib
                digest=hashlib.sha256(raw.encode("utf8")).hexdigest()
                split_augmented.append(digest)
                unique_augmented.add(digest)
                augmentation_families.add(family)

            family_metrics.update(metrics)
            aggregate.update(metrics)
            for category in item["categories"]:
                by_category[category].update(metrics)
            split_rows.append({
                "seed":seed,
                "train_events":len(train),
                "holdout_events":len(holdout),
                "hypotheses":{
                    kind:hypothesis.training_support
                    for kind,hypothesis in sorted(hypotheses.items())
                },
                "metrics":dict(metrics),
                "augmented_event_sha256":sorted(split_augmented),
            })

        by_family[family]={
            "categories":item["categories"],
            "source_files":item["source_files"],
            "unique_events":len(rows),
            "metrics":dict(family_metrics),
            "splits":split_rows,
        }

    unvalidated_augmentation_families=sorted(
        augmentation_families-REFERENCE_VALIDATED_FAMILIES
    )
    result={
        "contract":"parser-studio.poc.typed-residual-security-controls.v1",
        "scope":"SECURITY_PRODUCTS_ONLY_FAMILY_LEVEL",
        "source_engine_head":"4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "split_count":len(SEEDS),
        "family_count":len(streams),
        "categories":sorted(by_category),
        "learner_vendor_identity_used":False,
        "source_completeness_promotion_performed":False,
        "raw_values_published":False,
        "reference_validated_augmentation_families":sorted(
            REFERENCE_VALIDATED_FAMILIES
        ),
        "augmentation_families":sorted(augmentation_families),
        "unvalidated_augmentation_families":unvalidated_augmentation_families,
        "unique_augmented_events":len(unique_augmented),
        "aggregate_metrics":dict(aggregate),
        "by_category":{
            key:dict(value) for key,value in sorted(by_category.items())
        },
        "by_family":by_family,
        "gates":{
            "no_unvalidated_family_augmentation":(
                not unvalidated_augmentation_families
            ),
            "baseline_status_preserved":aggregate["status_changed"]==0,
            "baseline_issues_preserved":aggregate["issues_changed"]==0,
            "raw_preserved":aggregate["raw_changed"]==0,
        },
        "limitations":[
            "Families with fewer than three unique events are recorded but cannot train a batch hypothesis.",
            "This control benchmark does not score source correctness; exact ISE/Snort span correctness is a separate pinned-reference gate.",
            "The typed learner currently covers only strict SYSLOG_TIMESTAMP and SNORT_DATE shapes.",
        ],
    }
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n","utf8")
    return result


if __name__=="__main__":
    print(json.dumps(run(),indent=2,sort_keys=True))
