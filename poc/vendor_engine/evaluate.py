"""Evaluate the isolated engine against the vendor's pinned expected outputs.

Scores are high-value FIELD VALUE agreement with source fixture's gold file,
NOT verified parsing on a real Stellar sensor, not deployment compatibility.
"""
from __future__ import annotations
from collections import Counter,defaultdict
import json
from pathlib import Path
from typing import Any
from corpus import entries,load_case
from engine import parse_event,ParseResult,mine_residual_templates

BASE=Path(__file__).resolve().parent
CORE_FIELDS=("source.ip","destination.ip","source.port","destination.port",
             "event.action","user.name")

def gold_path(record:dict,field:str) -> Any:
    if field in record:
        return record[field]
    node:Any=record
    for component in field.split("."):
        if not isinstance(node,dict) or component not in node:
            return None
        node=node[component]
    # ECS often writes user.name under source.user.name in a Fortinet event.
    return node


def expected_field(record:dict,field:str) -> Any:
    value=gold_path(record,field)
    if field=="user.name" and value is None:
        value=gold_path(record,"source.user.name")
    return value


def comparable(value:Any) -> Any:
    if value is None:
        return None
    if isinstance(value,list):
        return tuple(sorted(str(x) for x in value))
    if isinstance(value,dict):
        return json.dumps(value,sort_keys=True)
    return (str(value),)


def score_field(gold:Any,observed:Any) -> tuple[int,int,int,int]:
    if gold is None and observed is None:
        return (0,0,0,0)
    if gold is None:
        return (0,1,0,0)
    if observed is None:
        return (0,0,1,1)
    if comparable(gold)==comparable(observed):
        return (1,0,0,1)
    return (0,1,1,1)


def ensure_ranges(result:ParseResult) -> None:
    n=len(result.raw)
    for item in result.spans:
        if item.end>n or item.start<0 or item.end<=item.start:
            raise AssertionError("INVALID_CAPTURE_PROVENANCE")
    count=[0]*n
    for a,b in result.covered:
        for i in range(a,b):count[i]+=1
    for a,b in result.unparsed:
        for i in range(a,b):count[i]+=1
    if len(count)!=n or any(x<1 for x in count):
        raise AssertionError("SOURCE_GAP_OR_LOSS")


def evaluate() -> dict[str,Any]:
    matrix=[]
    all_stats=Counter()
    all_fields:dict[str,Counter]=defaultdict(Counter)
    total=0
    all_records:list[ParseResult]=[]
    for case in entries():
        raw,gold=load_case(case)
        results=[parse_event(s) for s in raw]
        assert len(results)==len(raw)==len(gold)
        counters=Counter()
        fields:dict[str,Counter]=defaultdict(Counter)
        variants=Counter()
        issues=Counter()
        statuses=Counter()
        eval_events=0
        for i,(r,g) in enumerate(zip(results,gold)):
            ensure_ranges(r)
            total+=1
            all_records.append(r)
            variants[r.variant]+=1
            statuses[r.status]+=1
            for v in r.issues:issues[v]+=1
            if g:eval_events+=1
            for key in CORE_FIELDS:
                tp,fp,fn,req=score_field(expected_field(g,key),r.fields.get(key))
                key_stats=fields[key]
                key_stats.update({"TP":tp,"FP":fp,"FN":fn,"gold_present":req})
                # Independently report raw fixture split; it is NOT a new vendor
                # version holdout and was not chosen without inspecting samples.
                if i>=len(raw)//2:
                    key_stats.update({"holdout_TP":tp,"holdout_FP":fp,
                                      "holdout_FN":fn,"holdout_gold":req})
        for key,counts in fields.items():
            all_fields[key].update(counts)
        metrics={k:dict(v) for k,v in fields.items()}
        aggregate=Counter()
        for item in fields.values():
            aggregate.update(item)
        all_stats.update(aggregate)
        def calc(c:Counter) -> dict[str,Any]:
            tp,fp,fn=c["TP"],c["FP"],c["FN"]
            return {"true_fields":tp,"extra_or_wrong":fp,"missing_or_wrong":fn,
                    "precision":round(tp/(tp+fp),4) if tp+fp else None,
                    "recall":round(tp/(tp+fn),4) if tp+fn else None}
        matrix.append({
            "fixture":case["id"],
            "source_upstream_commit":case["upstream_commit"],
            "raw_events_accounted":len(raw),
            "gold_event_records":eval_events,
            "metadata_or_goldless_records":len(raw)-eval_events,
            "structural_syntax_local_only":dict(sorted(statuses.items())),
            "detected_variants":dict(sorted(variants.items())),
            "diagnostics":dict(sorted(issues.items())),
            "field_evaluation":calc(aggregate),
            "field_role_counts":metrics,
            "browser_only":True,
            "native_ruby_verified":False,
            "stellar_target_verified":False
        })
    def total_calc(c:Counter,pre:str="") -> dict[str,Any]:
        tp,fp,fn=(c[pre+"TP"],c[pre+"FP"],c[pre+"FN"])
        return {"TP":tp,"FP":fp,"FN":fn,
                "precision":round(tp/(tp+fp),4) if tp+fp else None,
                "recall":round(tp/(tp+fn),4) if tp+fn else None,
                "f1":round(2*tp/(2*tp+fp+fn),4) if 2*tp+fp+fn else None}
    return {
        "contract":"parser-studio.poc.vendor-engine-result.v0.1",
        "fixture_license":"RESEARCH_LOCAL_READ_ONLY; do not redistribute vendor content",
        "assumptions":["handwritten source-derived profile rules, not automatically learned",
                       "golden data uses Elastic vendor pipeline expected outputs, not Stellar fields",
                       "within-fixture last-half is not independent product/version holdout"],
        "total_input_records":total,
        "all_bytes_accounted":True,
        "overall_field_value_metrics":total_calc(all_stats),
        "within_fixture_last_half_field_metrics":total_calc(all_stats,"holdout_"),
        "roles":{k:total_calc(v) for k,v in sorted(all_fields.items())},
        "unknown_residual_template_groups":len(mine_residual_templates(all_records)),
        "fixtures":matrix,
        "native_verified":False,
        "target_verified":False,
        "live_sensor_tested":False
    }


if __name__=="__main__":
    result=evaluate()
    # Output contains no original raw content or private field values.
    file=BASE/".cache"/"engine_result.json"
    file.write_text(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=True)+"\n")
    print("BENCHMARK",result["total_input_records"],
          "CORE_GOLD",result["overall_field_value_metrics"],
          "WITHIN_FIXTURE_LAST_HALF",result["within_fixture_last_half_field_metrics"])
    for item in result["fixtures"]:
        print(item["fixture"],"count",item["raw_events_accounted"],
              "profiled",item["structural_syntax_local_only"],
              "fields",item["field_evaluation"],"issues",item["diagnostics"])
    print("RESULT",file,"NO RAW CONTENT","NATIVE=FALSE","TARGET=FALSE")
