#!/usr/bin/env python3
"""ACC-3 and ACC-4 isolated synthetic evaluation of existing funnel and roles.

No new grammar or parser runtime. Reuses product's bounded structural learning.
Training and holdouts do not overlap. Role suggestions cannot change normalized
fields. All examples are authored synthetic; output is value-free metadata.
"""
from __future__ import annotations
from collections import Counter
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"runtime"/"multipass"))
from bounded_funnel import (
    FunnelConfig, learn_funnel_hypotheses, run_funnel_event, _strict_no_loss
)
from multipass_adjudicator import parse_security_multipass
from role_evidence_shadow import infer_directional_roles
from source_parse import assert_source_accounting


def snort_record(i: int) -> str:
    return (
        f"07/16-09:23:{(35+i)%60:02d}.153899 "
        f'[**] [1:{1000000+i}:0] "SERVER-WEBAPP suspicious web request" [**] '
        f"[Classification: Attempted User Privilege Gain] "
        f"[Priority: {(i%3)+1}] [AppID: HTTP] "
        f"{{TCP}} 192.0.2.{i+1}:{50100+i} -> 198.51.100.{i+1}:80"
    )


def run_lowshot() -> dict:
    training=[snort_record(i) for i in range(10)]
    eval_raw=[snort_record(i) for i in range(10,14)]
    negatives=[
        '07/16-09:23:59.153899 [**] [1:999999:0] "unclosed message',
        'other network message -> 192.0.2.4 with no independent field grammar',
    ]
    configs=(3,5,10)
    results=[]
    for n in configs:
        learn=training[:n]
        frozen=[parse_security_multipass(raw) for raw in learn]
        hypotheses=learn_funnel_hypotheses(learn,frozen)
        recovered=regressed=claimed_complete=0
        baseline_partial=selected_partial=0
        check_count=0
        for raw in eval_raw + negatives:
            output=run_funnel_event(
                raw,hypotheses,config=FunnelConfig(max_passes=6,beam_width=4)
            )
            assert_source_accounting(output.baseline)
            assert_source_accounting(output.selected)
            if not _strict_no_loss(output.baseline,output.selected):
                regressed+=1
            old={(s.path,s.start_byte,s.end_byte) for s in output.baseline.value_spans}
            new={(s.path,s.start_byte,s.end_byte) for s in output.selected.value_spans}
            recovered+=len(new-old)
            baseline_partial+=output.baseline.status=="PARTIAL"
            selected_partial+=output.selected.status=="PARTIAL"
            if output.baseline.status!="SOURCE_PARSED" and output.selected.status=="SOURCE_PARSED":
                claimed_complete+=1
            check_count+=1
        results.append({
            "train_count":n,"holdout_count":len(eval_raw),
            "negative_controls":len(negatives),
            "observations":check_count,
            "baseline_partial":baseline_partial,
            "selected_partial":selected_partial,
            "added_source_claims_unscored":recovered,
            "source_loss_regressions":regressed,
            "complete_promotions_require_oracle":claimed_complete,
            "source_value_precision":"NOT_SCORABLE_WITHOUT_INDEPENDENT_FIELD_GOLD",
        })
    return {
        "contract":"parser-studio.lowshot-residual-shadow.v0.1",
        "provenance":"SELF_AUTHORED_SYNTHETIC_SAME_FAMILY_NOT_BLIND_VENDOR_GOLD",
        "training_holdout_disjoint":True,
        "results":results,
        "existing_funnel_reused":True,
        "new_runtime_grammar":False,
    }


def role_cases():
    return [
        ("192.0.2.1:51000 -> 198.51.100.20:443 TCP allow",True,
            {"srcip":"192.0.2.1","srcport":"51000","dstip":"198.51.100.20","dstport":"443"}),
        ("192.0.2.2:65000 => 198.51.100.21:443 UDP deny",True,
            {"srcip":"192.0.2.2","srcport":"65000","dstip":"198.51.100.21","dstport":"443"}),
        ("192.0.2.3|198.51.100.22|allow",False,{}),
        ("192.0.2.3:22 198.51.100.22:443",False,{}),
        ("999.0.2.3:22 -> 198.51.100.22:443 TCP",False,{}),
        ("192.0.2.3:99999 -> 198.51.100.22:443 TCP",False,{}),
        ('message="192.0.2.3:22 -> 198.51.100.22:443"',False,{}),
        ("192.0.2.3:22 -> 198.51.100.22:443 -> 203.0.113.8:4",False,{}),
    ]


def run_roles() -> dict:
    reviewed=abstained=wrong=bad_spans=0
    for raw,has_evidence,expected in role_cases():
        decision=infer_directional_roles(raw)
        observed={s.role:s.value for s in decision.suggestions}
        if has_evidence:
            reviewed+=decision.state=="EVIDENCED_SUGGESTION_REVIEW_ONLY"
            wrong+=observed!=expected
        else:
            abstained+=decision.state=="ABSTAIN"
            wrong+=bool(observed)
        raw_bytes=raw.encode("utf8")
        for proposal in decision.suggestions:
            if raw_bytes[proposal.start_byte:proposal.end_byte].decode("utf8")!=proposal.value:
                bad_spans+=1
    return {
        "contract":"parser-studio.directional-role-shadow.v0.1",
        "provenance":"SELF_AUTHORED_SYNTHETIC_NOT_INDEPENDENT_ROLE_GOLD",
        "cases":len(role_cases()),
        "positive_proposals_review_only":reviewed,
        "ambiguous_or_invalid_abstentions":abstained,
        "wrong_role_tests":wrong,
        "source_span_errors":bad_spans,
        "normalization_changes":0,
        "target_dictionary":"7.0_ONLY_NO_MAPPING_WRITTEN",
        "manufacturer_role_accuracy":"NOT_SCORED",
    }


def main():
    import argparse
    p=argparse.ArgumentParser(description="Offline low-shot and role evidence research")
    p.add_argument("--mode",choices=("all","lowshot","roles"),default="all")
    a=p.parse_args()
    out={}
    if a.mode in ("all","lowshot"):out["lowshot"]=run_lowshot()
    if a.mode in ("all","roles"):out["roles"]=run_roles()
    print(json.dumps(out,sort_keys=True,indent=2))


if __name__=="__main__":main()
