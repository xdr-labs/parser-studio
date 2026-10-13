"""Bounded train-only user-confirmed span feedback for semantic alias ambiguity.

This is an isolated research helper, not AI, an automatic truth oracle, or a
product UI. If raw training labels leave two source paths indistinguishable,
no deterministic rule may silently choose one. A human-supplied exact source
span AND explicit negative spans can resolve only that ONE role rule. No
holdout gold, remote provider, untrusted regex or native export is involved.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any

from evaluate import CORE_FIELDS, expected_field, comparable
from learn import canonical, digest, observe, guard_matches, convert_for_role


def _byte_range(raw:str,begin:int,end:int) -> tuple[int,int]:
    return (len(raw[:begin].encode("utf8")),len(raw[:end].encode("utf8")))


def _source_assertion(raw:str, tokens:dict[str,tuple[Any,int,int]],
                      assertion:dict[str,Any]) -> tuple[str,Any]:
    path=assertion.get("source_path")
    if not isinstance(path,str) or path not in tokens:
        raise ValueError("FEEDBACK_SOURCE_PATH_NOT_IN_TRAIN_SAMPLE")
    value,start,end=tokens[path]
    if end<=start:
        raise ValueError("FEEDBACK_EMPTY_SOURCE_SPAN")
    first,last=_byte_range(raw,start,end)
    if assertion.get("start_byte")!=first or assertion.get("end_byte")!=last:
        raise ValueError("FEEDBACK_BYTE_SPAN_MISMATCH")
    return path,value


def repair_frozen_rule_from_confirmed_train_span(
    frozen:dict[str,Any],
    train:dict[str,Any],
    fixture:str,
    train_index:int,
    role:str,
    positive:dict[str,Any],
    negatives:list[dict[str,Any]],
) -> dict[str,Any]:
    """Return a NEW digest-bound grammar; never mutate the original.

    Caller must have explicit positive and negative source-span assertions
    from the training record. Reading a holdout record would be a violation
    of this contract and is prevented by train source-index membership.
    """
    if role not in CORE_FIELDS:
        raise ValueError("FEEDBACK_ROLE_NOT_ALLOWLISTED")
    if train.get("contract")!="parser-studio.poc.isolated-train-only.v1":
        raise ValueError("FEEDBACK_TRAIN_CONTRACT_INVALID")
    if (train.get("split_sha256")!=frozen.get("split_sha256")
        or hashlib.sha256(canonical(train)+b"\n").hexdigest()!=
           frozen.get("train_file_sha256")):
        raise ValueError("FEEDBACK_TRAIN_SNAPSHOT_DIGEST_INVALID")
    before={k:v for k,v in frozen.items() if k!="grammar_sha256"}
    if digest(before)!=frozen.get("grammar_sha256"):
        raise ValueError("FEEDBACK_GRAMMAR_DIGEST_INVALID")
    if len(negatives)>12 or not negatives:
        raise ValueError("FEEDBACK_NEGATIVE_BOUNDS")
    matches=[
        row for row in train["rows"]
        if row.get("fixture")==fixture and row.get("source_index")==train_index
    ]
    if len(matches)!=1:
        raise ValueError("FEEDBACK_NOT_AN_EXACT_TRAIN_ROW")
    row=matches[0]
    raw=row["raw"]
    o=observe(raw)
    matching=[g for g in frozen["grammars"] if guard_matches(o,g)]
    if len(matching)!=1 or matching[0]["id"]!=fixture+":"+o.syntax:
        raise ValueError("FEEDBACK_GRAMMAR_NOT_UNIQUE")
    current=matching[0]
    rule=current["role_rules"].get(role)
    if not rule or rule.get("kind")!="direct" or not rule.get(
        "role_assignment_not_uniquely_identified",False
    ):
        raise ValueError("FEEDBACK_ROLE_NOT_AMBIGUOUS")
    possible={rule["path"],*rule["train_equivalent_alternative_paths"]}
    path,value=_source_assertion(raw,o.tokens,positive)
    if path not in possible:
        raise ValueError("FEEDBACK_POSITIVE_NOT_A_TIED_CANDIDATE")
    gold=expected_field(row["gold"],role)
    converted=convert_for_role(role,value,rule["transform"])
    if gold is None or converted is None or comparable(gold)!=comparable(converted):
        raise ValueError("FEEDBACK_POSITIVE_CONTRADICTS_TRAIN_GOLD")
    rejected=set()
    for negative in negatives:
        neg_path,_=_source_assertion(raw,o.tokens,negative)
        if neg_path==path or neg_path not in possible or neg_path in rejected:
            raise ValueError("FEEDBACK_INVALID_NEGATIVE_SPAN")
        rejected.add(neg_path)
    if rejected!=possible-{path}:
        raise ValueError("FEEDBACK_ALTERNATIVES_NOT_FULLY_EXCLUDED")
    candidate=copy.deepcopy(frozen)
    updated=next(g for g in candidate["grammars"] if g["id"]==current["id"])
    amended=updated["role_rules"][role]
    amended["path"]=path
    amended["train_equivalent_alternative_paths"]=[]
    amended["role_assignment_not_uniquely_identified"]=False
    amended["source_role_evidence"]="EXPLICIT_CONFIRMED_POSITIVE_NEGATIVE_TRAIN_SPANS"
    amended["negative_source_paths"]=sorted(rejected)
    candidate.setdefault("span_feedback_audit",[]).append({
        "grammar":current["id"],"role":role,"source_index":train_index,
        "source_sha256":hashlib.sha256(raw.encode("utf8")).hexdigest(),
        "positive_path":path,"excluded_path_count":len(rejected),
        "native_verified":False,
    })
    candidate.pop("grammar_sha256",None)
    candidate["grammar_sha256"]=digest(candidate)
    return candidate
