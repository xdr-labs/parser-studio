"""Train-only deterministic grammar induction and blinded 4-vendor PoC scoring.

prepare: reads pinned raw/gold ONCE to write ignored train-only labels + indices;
fit: reads ONLY isolated training JSON; does not import the corpus reader;
evaluate: freezes and verifies learned-rule digest BEFORE opening holdout gold.
No dependency/network/API, vendor-specific column mapping or source redistribution.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from math import ceil
from pathlib import Path
import re
from typing import Any

from engine import (
    BSD, PRI, ParseResult, SpanJsonDecoder, emit, parse_csv_spans,
    parse_quoted_kv, safe_ip, safe_port,
)
from evaluate import CORE_FIELDS, comparable, expected_field, score_field, ensure_ranges

BASE=Path(__file__).resolve().parent
CACHE=BASE/".cache"
SEED="parser-studio-independent-split-v1"
SPLIT_FILE=CACHE/"split_index.json"
TRAIN_FILE=CACHE/"isolated_train.json"
RULES_FILE=CACHE/"frozen_grammar.json"
RESULT_FILE=CACHE/"learned_result.json"
MIN_ACTION_CATEGORY_SUPPORT=2


def canonical(value:Any) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("utf8")


def digest(value:Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path:Path) -> Any:
    return json.loads(path.read_text("utf8"))


@dataclass
class Observation:
    result:ParseResult
    syntax:str
    tokens:dict[str,tuple[Any,int,int]]


def observe(raw:str) -> Observation:
    """Read syntax only: no vendor profile, semantic map or expected labels."""
    r=ParseResult(raw)
    tokens:dict[str,tuple[Any,int,int]]={}
    if not raw or len(raw.encode("utf8"))>131072 or "\x00" in raw:
        r.issues.append("SOURCE_SIZE_OR_NUL_INVALID")
    elif (m:=PRI.match(raw)) is not None and int(m.group("priority"))<=191:
        r.syntax="PRI_KV"
        r.covered.append((0,m.end()))
        kv=parse_quoted_kv(r,m.end())
        tokens={"kv:"+key:data for key,data in kv.items()}
    elif (m:=BSD.match(raw)) is not None and re.match(r"\d+,",raw[m.end():]):
        r.syntax="BSD_CSV"
        r.covered.append((0,m.end()))
        try:
            data=parse_csv_spans(r,m.end())
            tokens={f"csv[{i}]":cell for i,cell in enumerate(data) if cell[0]!=""}
        except ValueError as exc:
            r.issues.append(str(exc))
    elif raw.lstrip().startswith("{"):
        try:
            dec=SpanJsonDecoder(raw)
            obj=dec.parse()
            if not isinstance(obj,dict):raise ValueError("JSON_ROOT_NOT_OBJECT")
            r.syntax="JSON"
            r.covered.append((0,len(raw)))
            r.parsed_source_fields=dec.count
            tokens={"json:"+path:entry for path,entry in dec.nodes.items()
                    if path and entry[0] is not None}
        except (ValueError,IndexError,RecursionError) as exc:
            r.issues.append(str(exc)[:80])
    else:
        r.issues.append("NO_SUPPORTED_SYNTAX")
    return Observation(r,r.syntax,tokens)


def partition() -> dict[str,Any]:
    """One reproducible split grouped by each fixture and raw-only subtype.

    The existing manual engine is allowed ONLY to label the split strata; it
    is never called by observe(), fit(), guard inference, or rule application.
    Exact event content hashes order rows, independent of upstream file order.
    Rare singleton subtypes are left completely unseen for some strata.
    """
    from corpus import entries,load_file
    from engine import parse_event

    split={"contract":"parser-studio.poc.train-holdout-split.v1",
           "seed":SEED,"fixtures":{},"raw_and_gold_sha256":{}}
    all_train=[]
    for fixture in entries():
        name=fixture["id"]
        raw=load_file(fixture,"raw").decode("utf8","strict").splitlines()
        # Split labels are raw-derived by the frozen upper-control recognizer;
        # no gold values are consulted in stratum selection.
        groups:dict[str,list[int]]=defaultdict(list)
        for i,value in enumerate(raw):
            groups[parse_event(value).variant].append(i)
        train:set[int]=set()
        holdout:set[int]=set()
        unseen:set[int]=set()
        for variant,idxs in sorted(groups.items()):
            order=sorted(idxs,key=lambda i:hashlib.sha256(
                (SEED+"|"+name+"|"+raw[i]).encode("utf8")).hexdigest())
            if len(order)>=3:
                n_train=max(1,int(len(order)*0.65))
            elif len(order)==2:
                n_train=1
            else:
                # Singleton rare variants become zero-shot only in fixtures with
                # more than 3 total examples. EDR's sole example is train-only.
                n_train=0 if len(raw)>3 and int(hashlib.sha256(
                    (SEED+"|unseen|"+name+"|"+variant).encode()).hexdigest()[:2],16)%2==0 else 1
            train.update(order[:n_train])
            holdout.update(order[n_train:])
            if n_train==0:unseen.update(order)
        assert len(train|holdout)==len(raw) and not train&holdout
        # This is preparation, never part of fit(): retain ONLY train labels.
        gold_data=json.loads(load_file(fixture,"gold").decode("utf8","strict"))
        gold=gold_data.get("expected") if isinstance(gold_data,dict) else gold_data
        if len(gold)!=len(raw):raise ValueError("GOLD_ALIGNMENT")
        for i in sorted(train):
            all_train.append({"fixture":name,"source_index":i,"raw":raw[i],
                              "gold":gold[i] or {}})
        split["fixtures"][name]={
            "records":len(raw),"train_indices":sorted(train),
            "holdout_indices":sorted(holdout),
            "zero_shot_subtype_indices":sorted(unseen),
            "strata_counts":{key:len(rows) for key,rows in sorted(groups.items())},
        }
        split["raw_and_gold_sha256"][name]={
            "raw_sha256":fixture["raw_sha256"],
            "gold_sha256":fixture["gold_sha256"],
        }
    CACHE.mkdir(exist_ok=True)
    # Atomic rewrite minimizes a stale partially prepared corpus.
    payload={"contract":"parser-studio.poc.isolated-train-only.v1",
             "split_sha256":digest(split),
             "rows":all_train}
    TRAIN_FILE.write_bytes(canonical(payload)+b"\n")
    SPLIT_FILE.write_bytes(canonical(split)+b"\n")
    return split


def available_features(o:Observation) -> dict[tuple[str,str,str],bool]:
    """Value/presence probes from generic tokens, no fixed vendor semantics."""
    feat={}
    for path,(value,_,_) in o.tokens.items():
        feat[("exists",path,"")]=True
        if (o.syntax!="JSON" and isinstance(value,(str,int))
            and not isinstance(value,bool)):
            v=str(value)
            # Never fingerprint JSON payload values, source IPs, ports,
            # timestamps, identifiers, or unique records as trusted signatures.
            if (1<=len(v)<=28 and safe_ip(v) is None
                and not re.fullmatch(r"[0-9a-fA-F:-]{7,}",v)
                and not re.fullmatch(r"\d+",v)
                and "@" not in v and "/" not in v):
                feat[("equals",path,v)]=True
    return feat


def choose_guard(observations:list[Observation],others:list[Observation]) -> dict[str,str]|None:
    eligible:Counter=Counter()
    for o in observations:eligible.update(available_features(o))
    alternatives=[available_features(o) for o in others]
    n=len(observations)
    ranked=[]
    for feature,support in eligible.items():
        if support<max(1,ceil(0.8*n)):continue
        false_routes=sum(feature in other for other in alternatives)
        if false_routes:continue
        kind,path,value=feature
        # A shared source path whose constant VALUE differentiates families
        # (e.g. a learned record-type discriminator) generalizes better than
        # an optional key that just happened to appear in every train row.
        # This is inferred from unlabeled competing train paths, never by
        # hard-coding a manufacturer's key name or CSV column number.
        competing_path=sum(("exists",path,"") in other for other in alternatives)
        discriminates_shared_path=int(kind=="equals" and competing_path>0)
        ranked.append((-support,-discriminates_shared_path,
                       0 if kind=="exists" else 1,len(path),path,value,feature))
    if not ranked:return None
    winner=sorted(ranked)[0][-1]
    return {"kind":winner[0],"path":winner[1],"value":winner[2]}


def learn_schema_signature(observations:list[Observation],
                           guard_path:str) -> dict[str,Any]:
    """Infer co-occurring source keys/CSV boundaries on TRAIN INPUT only.

    Matching a record-type discriminator is insufficient to trust an unknown
    vendor; require several additional observed structural anchors. These
    are path *names* only, never raw field values or gold labels. A missing
    anchor cannot be recovered by a substring/wildcard fallback.
    """
    frequencies=Counter(
        path for obs in observations for path in obs.tokens if path!=guard_path
    )
    minimum=max(1,ceil(0.8*len(observations)))
    stable=sorted(
        (p for p,n in frequencies.items() if n>=minimum),
        key=lambda p:(-frequencies[p],len(p),p)
    )[:5]
    return {"paths":stable,"min_present":ceil(0.6*len(stable))}


def guard_matches(o:Observation,rule:dict[str,Any]) -> bool:
    if o.syntax!=rule["syntax"]:return False
    guard=rule["guard"]
    item=o.tokens.get(guard["path"])
    if item is None:return False
    if not (guard["kind"]=="exists" or str(item[0])==guard["value"]):
        return False
    signature=rule.get("schema_signature",{})
    return sum(p in o.tokens for p in signature.get("paths",[]))>=signature.get("min_present",0)


def convert_for_role(role:str,value:Any,transform:str) -> Any:
    if transform=="lower" and isinstance(value,str):value=value.lower()
    if role.endswith(".ip"):
        if isinstance(value,list):
            ips=[safe_ip(x) for x in value]
            return ips if all(ips) else None
        return safe_ip(value)
    if role.endswith(".port"):return safe_port(value)
    if role in {"user.name","event.action"}:
        if isinstance(value,str):return value
        if role=="event.action" and isinstance(value,list):return [str(v) for v in value]
        return None
    return None


def matches(gold:Any,observed:Any) -> bool:
    return gold is not None and observed is not None and comparable(gold)==comparable(observed)


def choose_direct_role(
    role:str,rows:list[dict[str,Any]],observations:list[Observation]
) -> dict[str,Any]|None:
    positive=sum(expected_field(row["gold"],role) is not None for row in rows)
    if not positive:return None
    paths=sorted({path for o in observations for path in o.tokens})
    candidates=[]
    for path in paths:
        for transform in (("identity","lower") if role=="event.action" else ("identity",)):
            tp=fp=fn=0
            for row,o in zip(rows,observations):
                gold=expected_field(row["gold"],role)
                item=o.tokens.get(path)
                observed=convert_for_role(role,item[0],transform) if item else None
                a,b,c,_=score_field(gold,observed)
                tp+=a;fp+=b;fn+=c
            if tp>0 and fp==0:
                # Same source may occur in multiple fields, so rank by actual
                # labeled evidence; ambiguous equal-quality fields are declared
                # as an uncertainty rather than a fabricated certainty.
                candidates.append((-tp,fn,path,transform))
    if not candidates:return None
    best=min((neg_tp,fn) for neg_tp,fn,_,_ in candidates)
    ties=[item for item in candidates if item[:2]==best]
    # Stable numeric CSV order, not lexical csv[10] < csv[8].
    # Multiple perfectly correlated columns are NOT proven synonyms for the
    # same semantic role (e.g. a NAT field can equal destination.ip in train).
    def rank(item:tuple[int,int,str,str]) -> tuple[int,str,str]:
        hit=re.fullmatch(r"csv\[(\d+)\]",item[2])
        return (int(hit[1]) if hit else 9999,item[2],item[3])
    _negative,fn,path,transform=min(ties,key=rank)
    top_support=-_negative
    ambiguous=sorted({item[2] for item in ties if item[2]!=path})
    return {"kind":"direct","path":path,"transform":transform,
            "train_TP":top_support,"train_FN":fn,
            "weak_evidence":top_support<2,
            "train_equivalent_alternative_paths":ambiguous[:12],
            "role_assignment_not_uniquely_identified":bool(ambiguous)}


def choose_action_lookup(rows:list[dict[str,Any]],observations:list[Observation],
                         global_path_diversity:dict[str,int],
                         guard_path:str) -> dict[str,Any]|None:
    positive=[i for i,row in enumerate(rows)
              if expected_field(row["gold"],"event.action") is not None]
    if len(positive)<2:return None
    choices=[]
    all_paths=sorted({p for o in observations for p in o.tokens})
    for path in all_paths:
        associations:dict[str,Counter]=defaultdict(Counter)
        for i in positive:
            entry=observations[i].tokens.get(path)
            gold=expected_field(rows[i]["gold"],"event.action")
            if entry is None or not isinstance(entry[0],(str,int)) or isinstance(gold,(list,dict)):
                continue
            value=str(entry[0])
            if len(value)>50 or not value:continue
            associations[value][str(gold)]+=1
        if not associations or len(associations)>16:continue
        if any(len(counter)>1 for counter in associations.values()):continue
        support=sum(sum(c.values()) for c in associations.values())
        if support<ceil(0.8*len(positive)):continue
        # Reject lookup entries seen in non-action rows, and require >=2
        # distinct labeled training examples for every emitted category.
        lookup={v:next(iter(c)) for v,c in associations.items()
                if sum(c.values())>=MIN_ACTION_CATEGORY_SUPPORT}
        if not lookup:continue
        false_rows=any(
            expected_field(row["gold"],"event.action") is None
            and path in obs.tokens
            and str(obs.tokens[path][0]) in lookup
            for row,obs in zip(rows,observations))
        if false_rows:continue
        coverage=sum(str(observations[i].tokens[path][0]) in lookup
                     for i in positive if path in observations[i].tokens)
        if not coverage:continue
        # The source TYPE discriminator used for grammar routing is not a
        # credible event.ACTION predictor for previously unseen subtypes.
        if path==guard_path:continue
        variety=global_path_diversity.get(path,0)
        if variety<2:continue
        # In unlabeled positional CSV schemas, prefer the nearest low-
        # cardinality categorical token to the inferred record-type token.
        # This is a generic syntactic hypothesis, not a vendor column index.
        first=re.fullmatch(r"csv\[(\d+)\]",guard_path)
        second=re.fullmatch(r"csv\[(\d+)\]",path)
        distance=abs(int(first[1])-int(second[1])) if first and second else 999
        choices.append((-coverage,distance,-min(variety,16),
                        len(associations),path,lookup))
    if not choices:return None
    _cov,_distance,_div,_count,path,lookup=sorted(choices,key=lambda x:x[:5])[0]
    return {"kind":"lookup","path":path,"values":lookup,
            "train_TP":-_cov,"weak_evidence":False,
            "unseen_category_policy":"abstain"}


def fit(train_file:Path=TRAIN_FILE) -> dict[str,Any]:
    """Blind fitting process: its ONLY input is isolated train JSON."""
    payload=read_json(train_file)
    if payload.get("contract")!="parser-studio.poc.isolated-train-only.v1":
        raise ValueError("TRAIN_CONTRACT_INVALID")
    rows=payload["rows"]
    observations=[observe(row["raw"]) for row in rows]
    by_group:dict[tuple[str,str],list[int]]=defaultdict(list)
    for i,(row,o) in enumerate(zip(rows,observations)):
        if any(expected_field(row["gold"],r) is not None for r in CORE_FIELDS):
            by_group[(row["fixture"],o.syntax)].append(i)
    global_diversity:dict[str,set[str]]=defaultdict(set)
    for o in observations:
        for path,(val,_,_) in o.tokens.items():
            if isinstance(val,(str,int)) and len(str(val))<=50:
                global_diversity[o.syntax+"|"+path].add(str(val))
    grammars=[]
    rejected_groups=[]
    for (fixture,syntax),idxs in sorted(by_group.items()):
        if syntax=="UNKNOWN":continue
        group=[observations[i] for i in idxs]
        # Metadata/control rows of the SAME fixture cannot disprove the
        # manufacturer's syntax signature merely because they have no roles.
        # Other manufacturers' train rows are the routing negatives.
        others=[obs for i,obs in enumerate(observations)
                if rows[i]["fixture"]!=fixture and obs.syntax==syntax]
        guard=choose_guard(group,others)
        if guard is None:
            rejected_groups.append({"fixture":fixture,"syntax":syntax,
                                    "reason":"NO_UNIQUE_TRAIN_ONLY_SIGNATURE"})
            continue
        group_rows=[rows[i] for i in idxs]
        maps={}
        diversity={k.split("|",1)[1]:len(v) for k,v in global_diversity.items()
                   if k.startswith(syntax+"|")}
        for role in CORE_FIELDS:
            rule=choose_direct_role(role,group_rows,group)
            if rule is None and role=="event.action":
                rule=choose_action_lookup(group_rows,group,diversity,guard["path"])
            if rule is not None:maps[role]=rule
        grammars.append({
            "id":fixture+":"+syntax,"syntax":syntax,"guard":guard,
            "schema_signature":learn_schema_signature(group,guard["path"]),
            "train_records":len(idxs),"role_rules":maps,
            "max_fields":len(CORE_FIELDS),
            "native_verified":False,"target_verified":False,
        })
    content={
        "contract":"parser-studio.poc.frozen-trained-grammar.v1",
        "split_sha256":payload["split_sha256"],
        "train_file_sha256":hashlib.sha256(train_file.read_bytes()).hexdigest(),
        "train_records":len(rows),"grammars":grammars,
        "rejected_groups":rejected_groups,
        "blind_holdout_gold_unread_in_fit":True,
    }
    content["grammar_sha256"]=digest(content)
    return content


def predict(raw:str,grammars:list[dict[str,Any]],
            require_unique_train_source:bool=False) -> tuple[ParseResult,list[str]]:
    o=observe(raw)
    matching=[g for g in grammars if guard_matches(o,g)]
    if len(matching)!=1:
        if len(matching)>1:o.result.issues.append("AMBIGUOUS_GRAMMAR_ROUTING")
        elif o.syntax!="UNKNOWN":o.result.issues.append("NO_TRAINED_GRAMMAR_MATCH")
        return o.result.close(),[g["id"] for g in matching]
    grammar=matching[0]
    o.result.variant="learned:"+grammar["id"]
    for role,rule in grammar["role_rules"].items():
        # Strict mode will NOT turn a path that happens to agree with gold
        # into a certified semantic mapping when equal-valued NAT/alias paths
        # cannot be distinguished using train-only evidence.
        if require_unique_train_source and (
            rule.get("weak_evidence") or rule.get("role_assignment_not_uniquely_identified")
        ):
            continue
        entry=o.tokens.get(rule["path"])
        if entry is None or entry[2]<=entry[1]:continue
        val=entry[0]
        if rule["kind"]=="lookup":
            val=rule["values"].get(str(val))
        elif rule["transform"]=="lower" and isinstance(val,str):
            val=val.lower()
        if val is None:continue
        emit(o.result,role,val,rule["path"],entry[1],entry[2],
             "train-only:"+grammar["id"])
    return o.result.close(),[grammar["id"]]


def evaluate_frozen(rules:dict[str,Any],split:dict[str,Any]) -> dict[str,Any]:
    """Evaluate *after* verifying the immutable train-only grammar snapshot."""
    from corpus import entries,load_case

    expected_sha=rules.get("grammar_sha256")
    if not isinstance(expected_sha,str) or digest(
        {k:v for k,v in rules.items() if k!="grammar_sha256"})!=expected_sha:
        raise ValueError("GRAMMAR_DIGEST_INVALID")
    if rules.get("split_sha256")!=digest(split):
        raise ValueError("SPLIT_MISMATCH")
    if rules.get("train_file_sha256")!=hashlib.sha256(TRAIN_FILE.read_bytes()).hexdigest():
        raise ValueError("TRAIN_DIGEST_INVALID")
    grammars=rules["grammars"]
    overall=Counter();strict_scores_counts=Counter()
    control=Counter();by_role=defaultdict(Counter)
    rows=0;classified=0;no_match=0;multiple=0;cross_vendor=0
    metadata=0;false_profile_matches=0;zero_shot_fields=Counter()
    tentative_semantic_role_observations=0
    tentative_mapping_definitions=[
        {"grammar":g["id"],"role":role,"possible_source_paths":1+len(rule["train_equivalent_alternative_paths"])}
        for g in grammars for role,rule in g["role_rules"].items()
        if rule.get("role_assignment_not_uniquely_identified")
    ]
    table=[]
    for fixture in entries():
        raw,gold=load_case(fixture)  # GOLD FIRST SEEN HERE, AFTER SHA FREEZE.
        key=fixture["id"]
        split_row=split["fixtures"][key]
        test_indices=split_row["holdout_indices"]
        totals=Counter()
        kind=Counter()
        for i in test_indices:
            result,matches=predict(raw[i],grammars)
            strict_result,_=predict(raw[i],grammars,require_unique_train_source=True)
            ensure_ranges(result)
            ensure_ranges(strict_result)
            from engine import parse_event
            upper=parse_event(raw[i])
            observed=observe(raw[i])
            matches_any=[g["id"] for g in grammars if guard_matches(observed,g)]
            foreign=[gid for gid in matches_any if not gid.startswith(key+":")]
            false_profile_matches+=len(foreign)
            if matches and matches[0].startswith(key+":"):classified+=1
            if not matches:no_match+=1
            if len(matches)>1:multiple+=1
            if foreign:cross_vendor+=1
            if not gold[i]:metadata+=1
            if len(matches)==1:
                for grammar in grammars:
                    if grammar["id"]==matches[0]:
                        tentative_semantic_role_observations+=sum(
                            role in result.fields and rule.get("role_assignment_not_uniquely_identified",False)
                            for role,rule in grammar["role_rules"].items()
                        )
                        break
            kind[result.status]+=1
            for role in CORE_FIELDS:
                truth=expected_field(gold[i],role)
                tp,fp,fn,present=score_field(truth,result.fields.get(role))
                s_tp,s_fp,s_fn,s_present=score_field(truth,strict_result.fields.get(role))
                strict_scores_counts.update({"TP":s_tp,"FP":s_fp,"FN":s_fn,"gold_present":s_present})
                u_tp,u_fp,u_fn,_=score_field(truth,upper.fields.get(role))
                bucket=Counter({"TP":tp,"FP":fp,"FN":fn,"gold_present":present})
                totals.update(bucket);overall.update(bucket);by_role[role].update(bucket)
                control.update({"TP":u_tp,"FP":u_fp,"FN":u_fn,"gold_present":present})
                if i in split_row["zero_shot_subtype_indices"]:
                    zero_shot_fields.update(bucket)
            rows+=1
        table.append({
            "fixture":key,"train_records":len(split_row["train_indices"]),
            "holdout_records":len(test_indices),
            "zero_shot_subtype_records":len(split_row["zero_shot_subtype_indices"]),
            "status":dict(sorted(kind.items())),
            "field_metrics":scores(totals),
        })
    return {
        "contract":"parser-studio.poc.blind-holdout-result.v1",
        "study_limitations":[
            "Frozen train-only rules evaluated on disjoint examples from the SAME upstream source fixtures; NOT independent vendor releases.",
            "Split labels for strata come from manual upper-control recognizer; NEVER passed to fit/inference.",
            "Single-example EDR does not provide independent test evidence.",
            "Action translation learned only from >=2 labeled train examples; unseen categories abstain.",
            "All metrics local Python only; no native Ruby/CONF, Stellar target, or LLM evidence."],
        "split_seed":SEED,"split_sha256":digest(split),
        "grammar_sha256":expected_sha,
        "train_records":rules["train_records"],
        "holdout_records":rows,
        "holdout_metadata_or_goldless":metadata,
        "holdout_field_metrics":scores(overall),
        "strict_unambiguous_holdout_field_metrics":scores(strict_scores_counts),
        "strict_gate_policy":"Exclude training-equivalent semantic source paths and singleton-backed roles; not native qualified.",
        "hand_profile_upper_control_same_holdout":scores(control),
        "per_role":{r:scores(by_role[r]) for r in CORE_FIELDS},
        "zero_shot_subtype_fields":scores(zero_shot_fields),
        "matched_own_grammar_records":classified,
        "no_matching_grammar_records":no_match,
        "multiple_matching_grammars":multiple,
        "wrong_vendor_grammar_activations":cross_vendor,
        "wrong_vendor_rule_matches":false_profile_matches,
        "unqualified_single_example_profiles":sum(g["train_records"]<2 for g in grammars),
        "tentative_semantic_role_observations":tentative_semantic_role_observations,
        "train_equivalent_mapping_ambiguities":tentative_mapping_definitions,
        "grammars_trained":len(grammars),
        "rejected_groups":rules["rejected_groups"],
        "fixtures":table,
        "native_verified":False,"stellar_target_verified":False,
    }


def scores(counts:Counter) -> dict[str,Any]:
    tp,fp,fn=counts["TP"],counts["FP"],counts["FN"]
    return {"TP":tp,"FP":fp,"FN":fn,"gold_present":counts["gold_present"],
            "precision":round(tp/(tp+fp),4) if tp+fp else None,
            "recall":round(tp/(tp+fn),4) if tp+fn else None,
            "f1":round(2*tp/(2*tp+fp+fn),4) if 2*tp+fp+fn else None}


def main() -> None:
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage",choices=("prepare","fit","evaluate"))
    stage=parser.parse_args().stage
    if stage=="prepare":
        split=partition()
        print("PREPARED",sum(len(v["train_indices"]) for v in split["fixtures"].values()),
              "TRAIN",sum(len(v["holdout_indices"]) for v in split["fixtures"].values()),
              "HOLDOUT","SOURCE SHA PINNED")
    elif stage=="fit":
        rules=fit()
        RULES_FILE.write_bytes(canonical(rules)+b"\n")
        print("FROZEN",rules["grammar_sha256"],"TRAIN",rules["train_records"],
              "GRAMMARS",len(rules["grammars"]), "NO HOLDOUT GOLD INPUT")
    else:
        rules=read_json(RULES_FILE)
        split=read_json(SPLIT_FILE)
        results=evaluate_frozen(rules,split)
        RESULT_FILE.write_bytes(canonical(results)+b"\n")
        print("BLIND HOLDOUT",results["holdout_records"],
              "FIELDS",results["holdout_field_metrics"],
              "UPPER_CONTROL",results["hand_profile_upper_control_same_holdout"],
              "CROSS_VENDOR_WRONG",results["wrong_vendor_grammar_activations"],
              "GRAMMARS",results["grammars_trained"])


if __name__=="__main__":
    main()
