"""Blind reference-template benchmark: source variable spans, NOT ECS roles.

Train Drain3 using log bodies ONLY, freeze profile evidence/digest, then open
ignored local Loghub EventTemplate labels for holdout source-span scoring.
The annotated template is an independent third-party benchmark reference,
not a vendor field dictionary or proof of Stellar/native compatibility.

Loghub datasets: https://github.com/logpai/loghub (ISSRE 2023).
Raw and labels remain in .cache; only value-free aggregate counts are emitted.
"""
from __future__ import annotations
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from residual_miner import (
    ROOT, SAMPLE_SHA, samples, train_holdout, miner, structural_candidate,
    aligned_candidate,
)
from source_parse import assert_source_accounting, parse_source

LABEL_SHA={
    "Apache_2k.log":"54331d12eedf513f2127f4d89f0284c8b15fddfa5471103abf9db2c73d737778",
    "Linux_2k.log":"7c86d7b0ecb961a25f00d9475a154df97613b9974f31ce142a146caa2017c71e",
}
LABEL_COMMIT="dd61d0952749ee7963bde24220d1be5ede023033"
MAX_VARIABLES=24
MAX_MESSAGE=8192


def frozen_miners(mode:str="residual")->tuple[dict,dict[str,str]]:
    """Only raw training messages; no reference-label file access."""
    pools=samples(mode)
    states={}
    fingerprints={}
    for family,rows in sorted(pools.items()):
        train,holdout=train_holdout(rows)
        model=miner()
        for item in train:
            model.add_log_message(item.body)
        states[family]={"model":model,"train":train,"holdout":holdout}
        # A digest of the bounded source-derived grammar, not raw vendor text
        # published. Keep digest only in the aggregate report.
        templates=sorted((c.get_template(),c.size) for c in model.drain.clusters)
        fingerprints[family]=hashlib.sha256(json.dumps(
            templates,sort_keys=True,ensure_ascii=True
        ).encode("utf8")).hexdigest()
    return states,fingerprints


def reference_labels(family:str)->dict[str,tuple[str,str]]:
    """Load the pinned independent label AFTER train profiles are frozen."""
    path=ROOT/(family+"_structured.csv")
    content=path.read_bytes()
    if hashlib.sha256(content).hexdigest()!=LABEL_SHA[family]:
        raise ValueError("REFERENCE_LABEL_SHA256_MISMATCH")
    if len(content)>1048576:
        raise ValueError("REFERENCE_LABEL_SIZE_LIMIT")
    raw_lines=[
        s for s in (ROOT/family).read_text("utf8").splitlines() if s.strip()
    ]
    records=list(csv.DictReader(content.decode("utf8").splitlines()))
    if len(records)!=len(raw_lines) or len(records)!=2000:
        raise ValueError("SOURCE_REFERENCE_EVENT_ALIGNMENT_MISMATCH")
    by_hash={}
    for idx,(raw,row) in enumerate(zip(raw_lines,records),1):
        if int(row["LineId"])!=idx:
            raise ValueError("REFERENCE_LINE_NUMBER_MISMATCH")
        template=row["EventTemplate"]
        msg=row["Content"]
        if msg not in raw or not template:
            raise ValueError("REFERENCE_MESSAGE_NOT_IN_SOURCE")
        digest=hashlib.sha256(raw.encode("utf8")).hexdigest()
        if digest in by_hash and by_hash[digest]!=(template,msg):
            raise ValueError("REFERENCE_DUPLICATE_RAW_DISAGREEMENT")
        by_hash[digest]=(template,msg)
    return by_hash


def oracle_spans(raw:str,template:str,msg:str)->tuple[str,list[tuple[int,int]]]:
    """Independent escaped-literal fullmatch over annotated template.

    This is reference-label-derived positional correctness, not learned
    syntax; zero-length wildcard values are ignored as absent source values.
    Arbitrary regular expressions from the fixture are never executed.
    """
    if len(msg.encode("utf8"))>MAX_MESSAGE or template.count("<*>")>MAX_VARIABLES:
        return "REFERENCE_TOO_LARGE",[]
    origin=raw.find(msg)
    if origin<0 or raw.find(msg,origin+1)>=0:
        return "REFERENCE_MESSAGE_SPAN_AMBIGUOUS",[]
    literals=template.split("<*>")
    pattern=r"(?s)\A"+"(.*?)".join(re.escape(s) for s in literals)+r"\Z"
    found=re.fullmatch(pattern,msg)
    if found is None:
        return "REFERENCE_TEMPLATE_MISMATCH",[]
    captures=[]
    for group in range(1,len(found.groups())+1):
        start,end=found.span(group)
        if start==end:
            continue
        offset_a=len(raw[:origin+start].encode("utf8"))
        offset_b=len(raw[:origin+end].encode("utf8"))
        captures.append((offset_a,offset_b))
    return "VALID_REFERENCE",captures


def predicted_spans(evidence:dict[str,Any])->list[tuple[int,int]]:
    return [(x["start_byte"],x["end_byte"]) for x in evidence["captures"]]


def score(expected:list[tuple[int,int]],predicted:list[tuple[int,int]])->Counter:
    gold=Counter(expected)
    seen=Counter(predicted)
    correct=sum((gold&seen).values())
    false=sum((seen-gold).values())
    missed=sum((gold-seen).values())
    return Counter(TP=correct,FP=false,FN=missed)


def _metric(counts:Counter)->dict[str,Any]:
    tp,fp,fn=(counts["TP"],counts["FP"],counts["FN"])
    return {
        "TP":tp,"FP":fp,"FN":fn,
        "precision":round(tp/(tp+fp),4) if tp+fp else None,
        "recall":round(tp/(tp+fn),4) if tp+fn else None,
        "f1":round(2*tp/(2*tp+fp+fn),4) if 2*tp+fp+fn else None,
    }


def evaluate(mode:str="residual")->dict[str,Any]:
    # Train and hash the grammar BEFORE references enter the process.
    frozen,profile_hashes=frozen_miners(mode)
    totals=Counter()
    old_stats=Counter()
    new_stats=Counter()
    rows=[]
    for family,state in sorted(frozen.items()):
        reference=reference_labels(family)
        model=state["model"]
        counts=Counter()
        old=Counter()
        new=Counter()
        for item in state["holdout"]:
            # Original full event immutable; no random data mutation.
            parsed=parse_source(item.raw)
            assert_source_accounting(parsed)
            if parsed.raw!=item.raw:
                raise AssertionError("SOURCE_EVENT_LOSS")
            template,msg=reference[item.sha]
            category,expected=oracle_spans(item.raw,template,msg)
            counts["holdout_events"]+=1
            if category!="VALID_REFERENCE":
                counts[category]+=1
                continue
            counts["reference_valid_events"]+=1
            counts["reference_nonempty_variable_spans"]+=len(expected)
            cluster=model.match(item.body,full_search_strategy="always")
            if cluster is None:
                counts["template_no_match"]+=1
                old.update(score(expected,[]));new.update(score(expected,[]))
                continue
            counts["template_matched"]+=1
            source_template=cluster.get_template()
            candidates=model.extract_parameters(source_template,item.body,exact_matching=True)
            from_old=structural_candidate(source_template,item.body,candidates,item.start,item.raw)
            from_new=aligned_candidate(source_template,item.body,item.start,item.raw,cluster.size)
            if from_old["status"]=="CANDIDATE_ONLY":
                counts["old_candidate_events"]+=1
            if from_new["status"]=="SOURCE_SPAN_CANDIDATE_ONLY":
                counts["new_candidate_events"]+=1
            predicted_old=predicted_spans(from_old)
            predicted_new=predicted_spans(from_new)
            old.update(score(expected,predicted_old))
            new.update(score(expected,predicted_new))
            if sorted(expected)==sorted(predicted_new):
                counts["complete_gold_span_events"]+=1
            if set(predicted_new)&set(expected):
                counts["some_gold_span_events"]+=1
        totals.update(counts)
        old_stats.update(old)
        new_stats.update(new)
        rows.append({
            "family":family.removesuffix(".log"),
            "grammar_sha256":profile_hashes[family],
            "holdout_records":counts["holdout_events"],
            "scored_reference_events":counts["reference_valid_events"],
            "reference_nonempty_spans":counts["reference_nonempty_variable_spans"],
            "baseline_legacy_candidate_events":counts["old_candidate_events"],
            "anchored_candidate_events":counts["new_candidate_events"],
            "gold_exact_all_variable_events":counts["complete_gold_span_events"],
            "gold_at_least_one_variable_events":counts["some_gold_span_events"],
            "baseline_parameter_metrics":_metric(old),
            "anchored_parameter_metrics":_metric(new),
            "gold_exclusions":{k:v for k,v in counts.items() if k.startswith("REFERENCE_")},
        })
    return {
        "contract":"parser-studio.poc.loghub-reference-span-v0.1",
        "body_strategy":mode,
        "fixture_repo":"logpai/loghub",
        "pinned_reference_revision":LABEL_COMMIT,
        "source_sha256":SAMPLE_SHA,
        "label_sha256":LABEL_SHA,
        "evaluation":"same-source-revision disjoint SHA train/holdout; reference templates loaded after training",
        "raw_event_count":totals["holdout_events"],
        "reference_scored_events":totals["reference_valid_events"],
        "reference_nonempty_variable_spans":totals["reference_nonempty_variable_spans"],
        "template_matched_events":totals["template_matched"],
        "baseline_candidate_events":totals["old_candidate_events"],
        "anchored_candidate_events":totals["new_candidate_events"],
        "anchored_full_gold_span_events":totals["complete_gold_span_events"],
        "anchored_some_gold_span_events":totals["some_gold_span_events"],
        "baseline_exact_reference_parameter":_metric(old_stats),
        "anchored_exact_reference_parameter":_metric(new_stats),
        "family_metrics":rows,
        "limitations":[
            "Ground truth: Loghub independently annotated template VARIABLE spans, not named security vendor fields.",
            "Empty wildcards are not countable extracted source values.",
            "The same upstream log revision has disjoint raw SHA rows; this is NOT a new vendor/version holdout.",
            "Neither correctly matched templates nor capture candidates establish native Fluentd/Stellar compatibility.",
        ],
        "stellar_dictionary_applied":False,
        "native_verified":False,
    }


if __name__=="__main__":
    report=evaluate()
    file=ROOT.parent/"loghub_reference_span_result.json"
    file.write_text(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
    print("REFERENCE_SPAN_BENCHMARK",
          "holdout",report["raw_event_count"],
          "scored",report["reference_scored_events"],
          "gold_nonempty",report["reference_nonempty_variable_spans"],
          "legacy",report["baseline_exact_reference_parameter"],
          "anchored",report["anchored_exact_reference_parameter"],
          "anchored_full_events",report["anchored_full_gold_span_events"])
    for row in report["family_metrics"]:
        print(row["family"],"holdout",row["holdout_records"],
              "legacy",row["baseline_parameter_metrics"],
              "anchored",row["anchored_parameter_metrics"])
