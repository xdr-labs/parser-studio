"""Offline evaluation of MIT Drain3 on *residual* plain-text log messages.

No field semantics are claimed. Drain3 template alignment can suggest value
boundaries only if source-byte spans are unique and exact. Samples used to
form templates cannot be present in blind test by exact raw SHA digest.
The dependency is optional and pinned under ignored .cache/drain_deps.
"""
from __future__ import annotations

from collections import Counter,defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from source_parse import parse_source,assert_source_accounting
from structured_source import extract_plain_bsd,extract_apache_error
from span_alignment import align_template

HERE=Path(__file__).resolve().parent
ROOT=HERE/".cache"/"loghub"
SAMPLE_SHA={
    "Apache_2k.log":"c7efa3eb686e3a96bd2f8f4457b2a7887e9cf2f3649327f1b4e87af841363ce8",
    "Linux_2k.log":"b3e20bc1afe732ab1bf3ed1de4bf9c809e4194e02f7dea911d918e5342e8e173",
}
SEED="extraction-first-residual-sha-split-20261014-v1"
MAX_CLUSTER=256
MAX_SPANS=20


@dataclass(frozen=True)
class Residual:
    family:str
    raw:str
    body:str
    start:int
    end:int
    sha:str


def samples(mode:str="residual")->dict[str,list[Residual]]:
    if mode not in {"residual","source_message"}:
        raise ValueError("UNSUPPORTED_BODY_SELECTION_MODE")
    out={}
    for family,sha in sorted(SAMPLE_SHA.items()):
        content=(ROOT/family).read_bytes()
        if hashlib.sha256(content).hexdigest()!=sha:
            raise ValueError("PINNED_RESIDUAL_SOURCE_SHA_MISMATCH")
        lines=[x for x in content.decode("utf8","strict").splitlines() if x.strip()]
        if len(lines)!=2000:raise ValueError("RESIDUAL_SOURCE_COUNT_MISMATCH")
        entries=[]
        for line in lines:
            parsed=parse_source(line)
            assert_source_accounting(parsed)
            if mode=="source_message":
                # The message body is identified from grammar framing, NEVER
                # from independent gold. Recovered KV islands may split the
                # residual into several spans, so training only those spans
                # loses the context necessary for template mining.
                envelope=(extract_apache_error(line)
                          if family.startswith("Apache") else extract_plain_bsd(line))
                begin=envelope[1] if envelope is not None else 0
                suffix=line[begin:]
                leading=len(suffix)-len(suffix.lstrip())
                body=suffix.strip()
                if not body:
                    continue
                a=begin+leading
                b=a+len(body)
            else:
                spans=[(a,b) for a,b in parsed.unparsed if line[a:b].strip()]
                if len(spans)!=1:
                    # Never concatenate disjoint source bytes into invented
                    # continuous spans.
                    continue
                a,b=spans[0]
                body=line[a:b]
            entries.append(Residual(family,line,body,a,b,
                                    hashlib.sha256(line.encode("utf8")).hexdigest()))
        out[family]=entries
    return out


def train_holdout(lines:list[Residual])->tuple[list[Residual],list[Residual]]:
    groups:dict[str,list[Residual]]=defaultdict(list)
    for row in lines:groups[row.sha].append(row)
    ordered=sorted(groups,key=lambda h:hashlib.sha256(
        (SEED+"|"+h).encode()).hexdigest())
    cutoff=round(len(ordered)*0.6)
    training={k for k in ordered[:cutoff]}
    train=[row for row in lines if row.sha in training]
    heldout=[row for row in lines if row.sha not in training]
    if set(row.sha for row in train)&set(row.sha for row in heldout):
        raise ValueError("RESIDUAL_SPLIT_LEAK")
    return train,heldout


def miner(masking_variant:str="legacy"):
    """Keep the legacy unmasked baseline for fair exact-head comparisons.

    The original patterns were accidentally double-escaped and did not
    match IP/number tokens. Typed mode uses correctly scoped masks and is
    separately reported, never silently replacing the historical baseline.
    """
    if masking_variant not in {"legacy","typed"}:
        raise ValueError("UNSUPPORTED_MASKING_VARIANT")
    try:
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
        from drain3.masking import MaskingInstruction
    except ImportError as exc:
        raise RuntimeError(
            "DRAIN3_OPTIONAL_DEPENDENCY_MISSING_INSTALL_IN_IGNORED_CACHE"
        ) from exc
    config=TemplateMinerConfig()
    config.drain_sim_th=0.5
    config.drain_depth=4
    config.drain_max_children=100
    config.drain_max_clusters=MAX_CLUSTER
    if masking_variant=="legacy":
        config.masking_instructions=[
            MaskingInstruction(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b","IP"),
            MaskingInstruction(r"\\b\\d+(?:\\.\\d+)?\\b","NUMBER"),
        ]
    else:
        # Real Drain3 emits these labels as <IP> and <NUMBER>, not <:IP:>.
        config.masking_instructions=[
            MaskingInstruction(r"\b(?:\d{1,3}\.){3}\d{1,3}\b","IP"),
            MaskingInstruction(r"\b\d+(?:\.\d+)?\b","NUMBER"),
        ]
    return TemplateMiner(config=config)


def structural_candidate(template:str,body:str,extracted:list[Any]|None,
                         start:int=0,raw:str|None=None)->dict[str,Any]:
    """Return source-backed candidate only, never normalized semantic roles."""
    if extracted is None or template.count("<*>")>MAX_SPANS:
        return {"status":"ABSTAIN","captures":[]}
    constants=[s for s in re.split(r"<[^>]+>",template) if s.strip()]
    if len(constants)<2 or sum(len(x.strip()) for x in constants)<9:
        return {"status":"ABSTAIN","captures":[]}
    if not extracted:return {"status":"TEMPLATE_MATCHED_NO_PARAMETERS","captures":[]}
    captures=[]
    for param in extracted:
        val=param.value
        if not isinstance(val,str) or not val or len(val)>256:
            return {"status":"ABSTAIN","captures":[]}
        first=body.find(val)
        if first<0 or body.find(val,first+1)>=0:
            return {"status":"AMBIGUOUS_VALUE_SPAN","captures":[]}
        if raw is not None:
            begin=len(raw[:start+first].encode("utf8"))
            end=len(raw[:start+first+len(val)].encode("utf8"))
            if raw.encode("utf8")[begin:end].decode("utf8")!=val:
                return {"status":"SOURCE_BYTE_MISMATCH","captures":[]}
            captures.append({"start_byte":begin,"end_byte":end})
        else:
            captures.append({"start_char":first,"end_char":first+len(val)})
    return {"status":"CANDIDATE_ONLY","captures":captures}


def aligned_candidate(template:str,body:str,start:int,raw:str,
                      cluster_support:int)->dict[str,Any]:
    """Source-byte-anchored candidate; independent of Drain3 regex extraction.

    The match is train-frozen and only an explicitly tentative positional
    capture. Repeated identical values can be disambiguated by source anchors,
    but any competing anchor layouts must be rejected.
    """
    result=align_template(template,body,raw=raw,body_start_char=start,
                          cluster_support=cluster_support)
    return {"status":result.status,
            "captures":[{"source_path":x.path,"mask":x.mask,
                         "start_byte":x.start_byte,"end_byte":x.end_byte}
                        for x in result.captures]}


def run(masking_variant:str="legacy")->dict[str,Any]:
    sources=samples()
    rows={}
    for family,events in sources.items():
        train,hold=train_holdout(events)
        m=miner(masking_variant)
        for row in train:
            m.add_log_message(row.body)
        rows[family]={"miner":m,"train":train,"holdout":hold}
    per_family=[]
    grand=Counter()
    for family,item in rows.items():
        m=item["miner"]
        counters=Counter()
        counters["train_records"]=len(item["train"])
        counters["holdout_records"]=len(item["holdout"])
        counters["train_unique_digests"]=len({x.sha for x in item["train"]})
        counters["holdout_unique_digests"]=len({x.sha for x in item["holdout"]})
        counters["clusters"]=len(m.drain.clusters)
        negative_miner=next(x["miner"] for k,x in rows.items() if k!=family)
        for row in item["holdout"]:
            match=m.match(row.body,full_search_strategy="always")
            if match is None:
                counters["unmatched_holdout"]+=1
                continue
            counters["matched_holdout"]+=1
            template=match.get_template()
            if not template:
                counters["empty_template"]+=1
                continue
            extracted=m.extract_parameters(template,row.body,exact_matching=True)
            if extracted is not None:
                counters["extraction_regex_matched"]+=1
            evidence=structural_candidate(template,row.body,extracted,row.start,row.raw)
            counters["status_"+evidence["status"]]+=1
            if evidence["status"]=="CANDIDATE_ONLY":
                counters["candidate_parameters"]+=len(evidence["captures"])
            aligned=aligned_candidate(template,row.body,row.start,row.raw,match.size)
            counters["aligned_"+aligned["status"]]+=1
            if aligned["status"]=="SOURCE_SPAN_CANDIDATE_ONLY":
                counters["aligned_candidate_parameters"]+=len(aligned["captures"])
            foreign=negative_miner.match(row.body,full_search_strategy="always")
            counters["cross_family_template_match"]+=foreign is not None
        grand.update(counters)
        per_family.append({
            "family":family.removesuffix(".log"),
            **dict(counters),
            "holdout_template_match_rate":round(
                counters["matched_holdout"]/max(1,len(item["holdout"])),4),
        })
    return {
        "contract":"parser-studio.poc.residual-drain3-holdout.v0.1",
        "dependency":"Drain3 pinned MIT 0.9.11 local optional prototype only",
        "masking_variant":masking_variant,
        "seed":SEED,
        "same_revision_disjoint_source_hash_holdout":True,
        "families":per_family,
        "total":{
            "train_records":grand["train_records"],
            "holdout_records":grand["holdout_records"],
            "matched_holdout":grand["matched_holdout"],
            "unmatched_holdout":grand["unmatched_holdout"],
            "candidate_events":grand["status_CANDIDATE_ONLY"],
            "abstained_events":grand["status_ABSTAIN"],
            "ambiguous_span_events":grand["status_AMBIGUOUS_VALUE_SPAN"],
            "candidate_parameters":grand["candidate_parameters"],
            "aligned_candidate_events":grand["aligned_SOURCE_SPAN_CANDIDATE_ONLY"],
            "aligned_candidate_parameters":grand["aligned_candidate_parameters"],
            "aligned_ambiguous_events":grand["aligned_AMBIGUOUS_ANCHOR_LAYOUT"],
            "aligned_weak_anchor_abstentions":grand["aligned_ABSTAIN_WEAK_ANCHORS"],
            "aligned_unqualified_cluster_abstentions":grand["aligned_ABSTAIN_UNQUALIFIED_CLUSTER"],
            "cross_family_template_match":grand["cross_family_template_match"],
        },
        "conclusion":"Template candidate only; no semantic/Dictionary mapping or native compiler proof.",
        "runtime_native_verified":False,
        "dictionary_attempted":False,
        "raw_not_published":True,
    }


if __name__=="__main__":
    outcome=run()
    file=HERE/".cache"/"residual_miner_result.json"
    file.write_text(json.dumps(outcome,sort_keys=True,indent=2)+"\n")
    print("RESIDUAL DRAIN3",outcome["total"])
    for f in outcome["families"]:
        print(f["family"],"train",f["train_records"],"heldout",f["holdout_records"],
              "clusters",f["clusters"],"matched",f["matched_holdout"],
              "candidate",f["status_CANDIDATE_ONLY"],
              "anchored_candidates",f["aligned_SOURCE_SPAN_CANDIDATE_ONLY"],
              "foreign_matches",f["cross_family_template_match"])
