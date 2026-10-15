"""Negative framing audit for masked residual R-gram on Snort.

An earlier exploratory run treated Snort Full physical lines as events and
appeared to recover date fragments. That evidence is invalid because Snort Full
is multiline. This benchmark reconstructs logical events using the pinned
Elastic multiline contract and records the corrected negative result.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import LOCAL_CACHE, _events
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    augment_residual_hypothesis,
    learn_masked_residual_rgram_hypotheses,
    parse_with_masked_residual_rgram,
)

OUT=Path(__file__).resolve().parent/"structural-hypothesis-snort-reference-multisplit-summary.json"


def _snort_full_events()->list[str]:
    lines=(LOCAL_CACHE/"snort_full.log").read_text("utf8").splitlines(keepends=True)
    records:list[str]=[]
    current=""
    for line in lines:
        if line.startswith("[**]") and current:
            while current.endswith("\n\n"):
                current=current[:-1]
            records.append(current)
            current=line
        else:
            current+=line
    if current:
        while current.endswith("\n\n"):
            current=current[:-1]
        records.append(current)
    return records


def _expected_originals()->set[str]:
    payload=json.loads((LOCAL_CACHE/"snort_full_expected.json").read_text("utf8"))
    return {
        doc["event"]["original"]
        for doc in payload["expected"]
        if isinstance(doc.get("event",{}).get("original"),str)
    }


def _evaluate(name:str,rows:list[str],seed:str)->dict:
    train,holdout=_split_seed(rows,seed)
    training=[parse_security_multipass(raw) for raw in train]
    hypotheses=learn_masked_residual_rgram_hypotheses(training)
    metrics=Counter()
    for raw in holdout:
        baseline=parse_security_multipass(raw)
        if baseline.status=="SOURCE_PARSED":
            metrics["baseline_complete"]+=1
            continue
        metrics["baseline_incomplete"]+=1
        candidate=parse_with_masked_residual_rgram(raw,baseline,hypotheses)
        augmented=augment_residual_hypothesis(baseline,candidate)
        if augmented is not None:
            metrics["augmentations"]+=1
    return {
        "stream":name,
        "seed":seed,
        "train_events":len(train),
        "holdout_events":len(holdout),
        "hypothesis_count":len(hypotheses),
        "metrics":dict(metrics),
    }


def run()->dict:
    full=_snort_full_events()
    expected=_expected_originals()
    fast=_events(LOCAL_CACHE/"snort_fast.log")
    rows=[
        _evaluate(name,events,seed)
        for name,events in (
            ("snort_fast",fast),
            ("snort_full_logical",full),
        )
        for seed in SEEDS
    ]
    aggregate=Counter()
    for row in rows:
        aggregate.update(row["metrics"])
    result={
        "contract":"parser-studio.poc.masked-rgram-snort-framing-audit.v1",
        "status":"REJECTED_PHYSICAL_LINE_EVIDENCE",
        "scope":"SNORT_IDS_IPS_NEGATIVE_EVIDENCE",
        "source_completeness_promotion_performed":False,
        "raw_values_published":False,
        "elastic_integrations_revision":"57ac255efb40d98151337b4ff11b9015679391ed",
        "elastic_full_expected_blob_sha":"f1d170a48f4a8c33e73b130d5a2acf48e0dd0a4b",
        "elastic_full_multiline_config_blob_sha":"d6f314c62a78d34a051dc61d0e84289a0f7c5d4b",
        "multiline_first_line_pattern":"^[**]",
        "full_physical_lines":len((LOCAL_CACHE/"snort_full.log").read_text("utf8").splitlines()),
        "full_logical_events":len(full),
        "full_logical_events_matching_official_expected":sum(raw in expected for raw in full),
        "results":rows,
        "aggregate_metrics":dict(aggregate),
        "corrected_conclusion":(
            "Masked residual R-gram yields no qualified hypothesis on Snort Fast "
            "or correctly framed Snort Full in these three splits. Earlier "
            "physical-line gains are invalid and superseded."
        ),
    }
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n","utf8")
    return result


if __name__=="__main__":
    print(json.dumps(run(),indent=2,sort_keys=True))
