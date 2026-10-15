"""Development-only evidence for CSV cell label refinement.

This primitive was designed after examining the first fresh holdout, so those
families cannot be used as prospective generalization evidence for it.
"""
from __future__ import annotations
from collections import Counter
import json
from pathlib import Path
from typing import Any

from benchmark_structural_hypothesis_fresh_holdout import (
    CACHE, MANIFEST, _events, _strict_split,
)
from benchmark_structural_hypothesis_multisplit import SEEDS
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    learn_csv_cell_label_hypotheses,
    refine_csv_cell_labels,
)

BASE=Path(__file__).resolve().parent
OUT=BASE/"structural-hypothesis-csv-label-development-summary.json"
SYM=CACHE/"symantec_system_expected.json"
NET=CACHE/"netscout_generated_expected.json"


def _leaves(value:Any)->list[str]:
    out=[]
    if isinstance(value,dict):
        for item in value.values():out.extend(_leaves(item))
    elif isinstance(value,list):
        for item in value:out.extend(_leaves(item))
    elif isinstance(value,str):
        out.append(value)
    return out


def run()->dict[str,Any]:
    manifest=json.loads(MANIFEST.read_text("utf8"))
    train=[];hold=[]
    for item in manifest["files"]:
        p=CACHE/item["family"]/Path(item["path"]).name
        rows=_events(p);tr,ho=_strict_split(rows,SEEDS[0])
        train.extend(parse_security_multipass(raw) for raw in tr)
        hold.extend((item["family"],p.name,raw) for raw in ho)
    hypotheses=learn_csv_cell_label_hypotheses(train)

    expected={
        "symantec_endpoint":json.loads(SYM.read_text("utf8"))["expected"],
        "netscout_sightline":json.loads(NET.read_text("utf8"))["expected"],
    }
    sym_map={
        doc.get("event",{}).get("original"):doc
        for doc in expected["symantec_endpoint"]
    }
    net_map={
        doc.get("message"):doc for doc in expected["netscout_sightline"]
    }
    metrics=Counter();by_family={}
    for family,name,raw in hold:
        baseline=parse_security_multipass(raw)
        refined=refine_csv_cell_labels(baseline,hypotheses)
        if refined is None:continue
        before={(s.path,s.source_segments,s.start_byte,s.end_byte) for s in baseline.value_spans}
        after={(s.path,s.source_segments,s.start_byte,s.end_byte) for s in refined.value_spans}
        if baseline.raw!=refined.raw or not before<=after:
            metrics["safety_rejected"]+=1;continue
        base_ranges={(s.start_byte,s.end_byte) for s in baseline.value_spans}
        additions=[s for s in refined.value_spans if (s.start_byte,s.end_byte) not in base_ranges]
        row=by_family.setdefault(family,Counter())
        row["events"]+=1;row["added_spans"]+=len(additions)
        metrics["events"]+=1;metrics["added_spans"]+=len(additions)
        if refined.status=="PARTIAL":
            row["remained_partial"]+=1;metrics["remained_partial"]+=1
        doc=(sym_map if family=="symantec_endpoint" else net_map).get(raw)
        flat=_leaves(doc) if doc else []
        raw_bytes=raw.encode("utf8")
        for span in additions:
            value=raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if value in flat:
                row["independent_exact_leaf"]+=1;metrics["independent_exact_leaf"]+=1
            elif any(value and value in leaf for leaf in flat):
                row["expected_message_substring_only"]+=1
                metrics["expected_message_substring_only"]+=1
            else:
                row["unmatched"]+=1;metrics["unmatched"]+=1
    result={
        "contract":"parser-studio.poc.csv-cell-label-development.v1",
        "scope":"DEVELOPMENT_EVIDENCE_ONLY_NOT_PROSPECTIVE",
        "prospective_claim_allowed":False,
        "reason":"Primitive designed after inspecting the first fresh holdout.",
        "raw_values_published":False,
        "semantic_mapping_scored":False,
        "hypothesis_widths":sorted(hypotheses),
        "metrics":dict(metrics),
        "by_family":{k:dict(v) for k,v in sorted(by_family.items())},
        "symantec_expected_blob_sha":"a56bba80b6d64426e2c01777b016c7b4f56c3016",
        "netscout_expected_blob_sha":"3fe09a7311ed7a22c9a88f582e4c2925e63a7216",
        "decision":"KEEP_FOR_POST_CHANGE_HOLDOUT_TESTING",
    }
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n","utf8")
    return result

if __name__=="__main__":
    print(json.dumps(run(),indent=2,sort_keys=True))
