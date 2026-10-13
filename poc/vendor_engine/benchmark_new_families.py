"""Untouched-family source-only parser evaluation (OpenSSH and Proxifier).

This first-run evaluation is fixed before reading either family's Loghub gold.
It uses unchanged Drain3 depth4/sim_th .5/max256 and the two prior mask
modes (legacy/typed). Only unlabeled training source text is used to fit.
Gold template labels are opened afterward, for independent variable-span
TP/FP/FN on raw-SHA disjoint test rows. No semantic field mappings or DP IO.
"""
from __future__ import annotations
from collections import Counter,defaultdict
from dataclasses import dataclass
import csv
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from residual_miner import (
    ROOT, SEED, miner, aligned_candidate, train_holdout, Residual,
)
from benchmark_residual_gold import oracle_spans,score,_metric
from source_parse import parse_source,assert_source_accounting
from structured_source import extract_plain_bsd

COMMIT="dd61d0952749ee7963bde24220d1be5ede023033"
RAW_DIGEST={
    "OpenSSH_2k.log":"1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f",
    "Proxifier_2k.log":"94b6a9d98d76e7ad7841ed10caa463cd4e638a229b92a220a2bf1707552adbb9",
}
GOLD_DIGEST={
    "OpenSSH_2k.log":"c0996a11545f4b94b435993760afa441a9e373f7bfc9e787afdb8e62f65acb4f",
    "Proxifier_2k.log":"5aa88821bb217d82c3a964cbe9fdb0d67f235b0538ac164ef0a87e0ced4f2715",
}
PROXIFIER_HEADER=re.compile(r"^\[(\d{1,2})\.(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\] +")


def raw_samples()->dict[str,list[Residual]]:
    """No lookup of reference labels during train construction."""
    out={}
    for family,pin in RAW_DIGEST.items():
        blob=(ROOT/family).read_bytes()
        if hashlib.sha256(blob).hexdigest()!=pin or len(blob)>1048576:
            raise ValueError("EXTERNAL_RAW_SOURCE_PIN_OR_BOUND_INVALID")
        raws=[s for s in blob.decode("utf8","strict").splitlines() if s.strip()]
        if len(raws)!=2000:
            raise ValueError("EXTERNAL_SOURCE_LINE_COUNT_INVALID")
        data=[]
        for raw in raws:
            parsed=parse_source(raw)
            assert_source_accounting(parsed)
            if parsed.raw!=raw:
                raise AssertionError("EXTERNAL_RAW_RECORD_CHANGED")
            if (header:=extract_plain_bsd(raw)) is not None:
                offset=header[1]
            elif (match:=PROXIFIER_HEADER.match(raw)) is not None:
                values=[int(x) for x in match.groups()]
                mon,day,hr,minute,sec=values
                if not (1<=mon<=12 and 1<=day<=31 and hr<24 and minute<60 and sec<60):
                    offset=0
                else:
                    offset=match.end()
            else:
                offset=0
            if offset>=len(raw):
                offset=0
            body=raw[offset:]
            data.append(Residual(
                family,raw,body,offset,len(raw),
                hashlib.sha256(raw.encode("utf8")).hexdigest(),
            ))
        out[family]=data
    return out


def blinded_fit()->dict[str,Any]:
    train_states={}
    for family,records in raw_samples().items():
        train,hold=train_holdout(records)
        states={}
        for variant in ("legacy","typed"):
            model=miner(variant)
            for rec in train:
                model.add_log_message(rec.body)
            states[variant]=model
        train_states[family]={"models":states,"holdout":hold,"train":train}
    return train_states


def _reference(family:str)->dict[str,tuple[str,str]]:
    blob=(ROOT/(family+"_structured.csv")).read_bytes()
    if hashlib.sha256(blob).hexdigest()!=GOLD_DIGEST[family]:
        raise ValueError("EXTERNAL_LABEL_PIN_INVALID")
    rows=list(csv.DictReader(blob.decode("utf8").splitlines()))
    source=[s for s in (ROOT/family).read_text("utf8").splitlines() if s.strip()]
    if len(rows)!=2000 or len(source)!=2000:
        raise ValueError("EXTERNAL_REFERENCE_ROW_COUNT_INVALID")
    out={}
    for n,(raw,label) in enumerate(zip(source,rows),1):
        if int(label["LineId"])!=n:
            raise ValueError("EXTERNAL_REFERENCE_INDEX_INVALID")
        digest=hashlib.sha256(raw.encode("utf8")).hexdigest()
        value=(label["EventTemplate"],label["Content"])
        if digest in out and out[digest]!=value:
            raise ValueError("EXTERNAL_REFERENCE_DUPLICATE_DISAGREEMENT")
        if value[1] not in raw:
            raise ValueError("EXTERNAL_REFERENCE_CONTENT_NOT_IN_SOURCE")
        out[digest]=value
    return out


def evaluate(states:dict[str,Any])->dict[str,Any]:
    """Blind states must already be fit BEFORE independent labels are opened."""
    families=[]
    totals={x:Counter() for x in ("legacy","typed")}
    main=Counter()
    for family,state in sorted(states.items()):
        refs=_reference(family)
        family_scores={x:Counter() for x in ("legacy","typed")}
        counts=Counter()
        hold=state["holdout"]
        train=state["train"]
        if {x.sha for x in train}&{x.sha for x in hold}:
            raise ValueError("EXTERNAL_TRAIN_HOLDOUT_SOURCE_SHA_LEAK")
        for event in hold:
            raw=event.raw
            ref_type,reference=oracle_spans(raw,*refs[event.sha])
            counts["holdout_events"]+=1
            if ref_type!="VALID_REFERENCE":
                counts[ref_type]+=1
                continue
            counts["valid_gold"]+=1
            counts["reference_spans"]+=len(reference)
            for variant,model in state["models"].items():
                matched=model.match(event.body,full_search_strategy="always")
                if matched is None:
                    fields=[]
                    counts[f"{variant}_no_template_match"]+=1
                else:
                    evidence=aligned_candidate(
                        matched.get_template(),event.body,
                        event.start,raw,matched.size,
                    )
                    fields=[(x["start_byte"],x["end_byte"])
                            for x in evidence["captures"]]
                    counts[f"{variant}_aligned_candidates"]+=(
                        evidence["status"]=="SOURCE_SPAN_CANDIDATE_ONLY"
                    )
                family_scores[variant].update(score(reference,fields))
        main.update(counts)
        for variant in totals:
            totals[variant].update(family_scores[variant])
        families.append({
            "family":family.removesuffix("_2k.log"),
            "train_rows":len(train),"holdout_rows":len(hold),
            "gold_rows_scored":counts["valid_gold"],
            "reference_nonempty_spans":counts["reference_spans"],
            "gold_exclusions":counts["holdout_events"]-counts["valid_gold"],
            "legacy_source_metrics":_metric(family_scores["legacy"]),
            "typed_source_metrics":_metric(family_scores["typed"]),
        })
    return {
        "contract":"parser-studio.poc.new-families-blind-source-span.v0.1",
        "source_repo":"logpai/loghub",
        "pinned_commit":COMMIT,
        "raw_sha256":RAW_DIGEST,
        "labels_sha256":GOLD_DIGEST,
        "split_seed":SEED,
        "measurement":"untouched OpenSSH/Proxifier families, 60% raw-only training / 40% disjoint raw SHA holdout; labels loaded post-fit",
        "heldout_events":main["holdout_events"],
        "gold_scored_events":main["valid_gold"],
        "excluded_reference_events":main["holdout_events"]-main["valid_gold"],
        "nonempty_gold_variable_spans":main["reference_spans"],
        "legacy_source_metrics":_metric(totals["legacy"]),
        "corrected_typed_source_metrics":_metric(totals["typed"]),
        "families":families,
        "dictionary_attempted":False,
        "native_or_stellar_verified":False,
        "license_policy":"Research-only Loghub raw, gold and derived profiles remain in ignored .cache",
        "limitations":[
            "Both families have same pinned upstream source revision in train/test, not independent future software versions.",
            "Loghub EventTemplate annotations are variable-span ground truth, NOT vendor field names or Stellar Dictionary schema.",
            "Missing/ambiguous gold spans are explicitly excluded from scoring and counted.",
            "Corrected mask behavior was developed on Apache/Linux and fixed BEFORE this family evaluation.",
        ],
    }


if __name__=="__main__":
    states=blinded_fit()
    result=evaluate(states)
    # Only value-free counters and approved fixture hashes are published.
    path=Path(__file__).resolve().parent/"new-families-summary.json"
    path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("UNTOUCHED_FAMILY_BENCHMARK",
          "heldout",result["heldout_events"],
          "scored",result["gold_scored_events"],
          "reference_spans",result["nonempty_gold_variable_spans"],
          "baseline",result["legacy_source_metrics"],
          "typed",result["corrected_typed_source_metrics"])
    for item in result["families"]:
        print(item["family"],"holdout",item["holdout_rows"],
              "gold",item["reference_nonempty_spans"],
              "legacy",item["legacy_source_metrics"],
              "typed",item["typed_source_metrics"])
