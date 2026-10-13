"""Training-label-assisted known grammar retrieval, NEVER LLM or ECS mapping.

Proof of retrieval-first source extraction: derive reusable source grammar from
ONLY explicitly labeled training examples. The Loghub EventTemplate labels
are research annotations, not something an unseen product automatically has.
Raw/gold files and learned template literals stay in ignored local .cache;
only aggregate metrics are publishable.

Unlabeled logs still use separate deterministic source extraction and
unqualified Drain3 residual candidate routing. No source values are invented.
"""
from __future__ import annotations
from collections import Counter,defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from residual_miner import Residual,samples,train_holdout,miner,aligned_candidate
from benchmark_residual_gold import reference_labels,oracle_spans,score,_metric
from span_alignment import align_template
from structured_source import extract_apache_error,extract_plain_bsd
from source_parse import parse_source,assert_source_accounting

BASE=Path(__file__).resolve().parent
CACHE=BASE/".cache"
MIN_RULE_SUPPORT=2
MAX_RULES=256


def framing_signature(raw:str)->str:
    """Raw-header-based routing only, no externally supplied vendor flag."""
    if extract_apache_error(raw) is not None:return "APACHE_ERROR"
    if extract_plain_bsd(raw) is not None:return "BSD_SYSLOG"
    return "UNKNOWN"


def collect_labeled_training_only()->tuple[list[dict[str,Any]],dict[str,list[Residual]]]:
    """Project pinned training samples to an isolated training-only recipe."""
    out=[]
    held={}
    for _fixture,examples in sorted(samples("source_message").items()):
        train,hold=train_holdout(examples)
        held[_fixture]=hold
        # The licensed reference file is read only in this preparation step.
        # Holdout templates are never put into the training recipe.
        labels=reference_labels(_fixture)
        for event in train:
            template,content=labels[event.sha]
            if event.body!=content:
                continue  # An independently labeled source span is mandatory.
            if len(template)>8192 or template.count("<*>")>24:
                continue
            out.append({
                "sha256":event.sha,
                "framing":framing_signature(event.raw),
                "template":template,
                "body":event.body,
                "raw":event.raw,
                "body_start":event.start,
            })
    return out,held


def write_training_snapshot()->dict[str,Any]:
    rows,_held=collect_labeled_training_only()
    # Isolated file contains ONLY train source and train annotations, never
    # holdout annotations. It is ignored and must never be redistributed.
    data={
        "contract":"parser-studio.poc.trusted-template-train-only.v0.1",
        "rows":rows,
        "training_type":"annotated-template-retrieval-NOT-unsupervised",
    }
    file=CACHE/"trusted_train_only.json"
    content=json.dumps(data,ensure_ascii=True,sort_keys=True,
                       separators=(",",":")).encode("utf8")
    file.write_bytes(content+b"\n")
    return {"training_rows":len(rows),
            "train_sha256":hashlib.sha256(file.read_bytes()).hexdigest()}


def _rule_matches(template:str,raw:str,body:str,start:int,support:int)->list[tuple[int,int]]|None:
    """Train-verified template matcher with exact value byte spans."""
    if "<*>" not in template:
        return [] if body==template else None
    result=align_template(template,body,raw=raw,body_start_char=start,
                          cluster_support=support,trusted_profile=True)
    if result.status!="SOURCE_SPAN_CANDIDATE_ONLY":
        return None
    return [(cap.start_byte,cap.end_byte) for cap in result.captures]


def fit_train_only(train_file:Path=CACHE/"trusted_train_only.json")->dict[str,Any]:
    """Fit only from the frozen isolated TRAIN file; never access holdout gold."""
    blob=train_file.read_bytes()
    payload=json.loads(blob)
    if payload.get("contract")!="parser-studio.poc.trusted-template-train-only.v0.1":
        raise ValueError("UNTRUSTED_TRAINING_CONTRACT")
    grouped:dict[tuple[str,str],list[dict[str,Any]]]=defaultdict(list)
    for row in payload["rows"]:
        grouped[(row["framing"],row["template"])].append(row)
    if len(grouped)>MAX_RULES:
        raise ValueError("TEMPLATE_REGISTRY_TOO_LARGE")
    rules=[]
    reject=Counter()
    for (framing,template),examples in sorted(grouped.items()):
        support=len({row["sha256"] for row in examples})
        if support<MIN_RULE_SUPPORT:
            reject["insufficient_distinct_training_samples"]+=1
            continue
        matched=0
        for row in examples:
            if (_rule_matches(template,row["raw"],row["body"],
                              row["body_start"],support) is not None):
                matched+=1
        if matched<2 or matched/max(1,len(examples))<0.80:
            reject["insufficient_source_span_training_agreement"]+=1
            continue
        literal_length=sum(len(part) for part in template.split("<*>"))
        rules.append({
            "framing":framing,"template":template,
            "support":support,"train_match_count":matched,
            "static_length":literal_length,
            "allow_raw_capture":False,
            "native_verified":False,
        })
    model={
        "contract":"parser-studio.poc.retrieval-grammar.v0.1",
        "rules":rules,
        "train_input_sha256":hashlib.sha256(blob).hexdigest(),
        "rejected":dict(reject),
        "fit_uses_training_annotations":True,
        "holdout_gold_unread_by_fit":True,
        "stellar_mapping_attempted":False,
    }
    model["grammar_digest"]=hashlib.sha256(json.dumps(
        model,sort_keys=True,ensure_ascii=True,separators=(",",":")
    ).encode("utf8")).hexdigest()
    return model


def route(model:dict[str,Any],event:Residual)->tuple[str,list[tuple[int,int]]]:
    """Never emit an ambiguous rule or any unlabeled semantic interpretation."""
    framing=framing_signature(event.raw)
    candidates=[]
    for rule in model["rules"]:
        if rule["framing"]!=framing:
            continue
        spans=_rule_matches(rule["template"],event.raw,event.body,
                            event.start,rule["support"])
        if spans is not None:
            candidates.append((rule["static_length"],rule["support"],
                               rule["template"],spans))
    if not candidates:
        return "NO_VERIFIED_PROFILE",[]
    candidates.sort(key=lambda x:(-x[0],-x[1],x[2]))
    # A more specific confirmed literal pattern can be preferred, but if two
    # profiles have equal static specificity, abstain instead of guessing.
    best=candidates[0]
    if len(candidates)>1 and candidates[1][0]==best[0]:
        return "AMBIGUOUS_PROFILE_MATCH",[]
    return "VERIFIED_TRAIN_TEMPLATE_CANDIDATE",best[3]


def evaluate_heldout(model:dict[str,Any])->dict[str,Any]:
    """Reference labels are loaded only AFTER the trained profile is frozen."""
    expected_digest=model.get("grammar_digest")
    current={k:v for k,v in model.items() if k!="grammar_digest"}
    if hashlib.sha256(json.dumps(current,sort_keys=True,ensure_ascii=True,
                                separators=(",",":")).encode("utf8")).hexdigest()!=expected_digest:
        raise ValueError("FROZEN_TEMPLATE_REGISTRY_DIGEST_MISMATCH")
    source=samples("source_message")
    totals=Counter()
    total_scores=Counter()
    rows=[]
    for family,examples in sorted(source.items()):
        _train,held=train_holdout(examples)
        labels=reference_labels(family)
        stats=Counter()
        metrics=Counter()
        for event in held:
            template,content=labels[event.sha]
            status,expected=oracle_spans(event.raw,template,content)
            if status!="VALID_REFERENCE":
                stats["skipped_reference"]+=1
                continue
            parsed=parse_source(event.raw)
            assert_source_accounting(parsed)
            if parsed.raw!=event.raw:raise AssertionError("SOURCE_EVENT_LOSS")
            classification,captures=route(model,event)
            stats["holdout_records"]+=1
            stats["gold_variables"]+=len(expected)
            stats["routed"]+=classification=="VERIFIED_TRAIN_TEMPLATE_CANDIDATE"
            stats["ambiguous"]+=classification=="AMBIGUOUS_PROFILE_MATCH"
            stats["no_rule"]+=classification=="NO_VERIFIED_PROFILE"
            metrics.update(score(expected,captures))
            stats["exact_complete_events"]+=sorted(expected)==sorted(captures)
        rows.append({"family":family.removesuffix(".log"),
                     "records":stats["holdout_records"],
                     "routed":stats["routed"],
                     "ambiguous":stats["ambiguous"],
                     "unmatched":stats["no_rule"],
                     "gold_variables":stats["gold_variables"],
                     "exact_complete_events":stats["exact_complete_events"],
                     "field_span_metrics":_metric(metrics)})
        totals.update(stats)
        total_scores.update(metrics)
    return {
        "contract":"parser-studio.poc.retrieval-first-source-span-v0.1",
        "training_type":"explicit_annotated_templates_in_train_ONLY",
        "source_revision_policy":"same-pinned-source,disjoint-row-SHA",
        "frozen_grammar_digest":expected_digest,
        "registered_profiles":len(model["rules"]),
        "holdout_records":totals["holdout_records"],
        "gold_nonempty_variable_spans":totals["gold_variables"],
        "records_routed_to_train_verified_profile":totals["routed"],
        "ambiguous_profile_events":totals["ambiguous"],
        "unmatched_profile_events":totals["no_rule"],
        "exact_complete_gold_variable_events":totals["exact_complete_events"],
        "parameter_metrics":_metric(total_scores),
        "families":rows,
        "caveats":[
            "This is prebuilt-grammar retrieval using Loghub annotated templates, NOT automatic unsupervised grammar discovery.",
            "Trained template literals and licensed raw remain in ignored local cache, NOT committed/redistributed.",
            "Loghub wildcard locations are source-value reference spans, NOT Stellar/ECS/vendor semantics.",
            "Not tested on genuinely unseen vendor software revisions; native Fluentd and Stellar target unverified.",
        ],
        "stellar_dictionary_applied":False,
        "native_verified":False,
    }


if __name__=="__main__":
    state=write_training_snapshot()
    qualified=fit_train_only()
    outfile=CACHE/"trusted_profile_frozen.json"
    outfile.write_text(json.dumps(qualified,ensure_ascii=True,sort_keys=True,
                                  indent=2)+"\n")
    metrics=evaluate_heldout(qualified)
    (CACHE/"trusted_profile_metrics.json").write_text(
        json.dumps(metrics,ensure_ascii=True,sort_keys=True,indent=2)+"\n"
    )
    print("TRAIN_ONLY",state,"PROFILES",len(qualified["rules"]),
          "REJECTED",qualified["rejected"])
    print("REFERENCE EVAL",metrics["holdout_records"],
          "GOLD",metrics["gold_nonempty_variable_spans"],
          "MATCHED",metrics["records_routed_to_train_verified_profile"],
          "SCORES",metrics["parameter_metrics"])
    for family in metrics["families"]:
        print(family["family"],"records",family["records"],
              "routed",family["routed"],
              "scores",family["field_span_metrics"])
