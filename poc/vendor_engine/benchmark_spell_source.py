"""Optional Apache-2.0 Spell versus exact Loghub variable-span references.

The external LogPai Spell implementation is NOT vendored or bundled.
Source: https://github.com/logpai/logparser commit
d9d4180784cde9afef990eeeb458591011933f9b, individual Spell Apache-2.0.
Install optional pandas/regex only into ignored local research cache.
This algorithm learns event templates from unlabeled TRAIN sources, but its
delimited-token templates may not preserve variable source byte boundaries.
No classifier/template accuracy is misrepresented as field extraction F1.
"""
from __future__ import annotations
from collections import Counter
import csv
import hashlib
from pathlib import Path
import re

from residual_miner import ROOT,samples,train_holdout
from benchmark_residual_gold import reference_labels,oracle_spans,score,_metric

CACHE=ROOT.parent/"spell_evidence"
SOURCE_COMMIT="d9d4180784cde9afef990eeeb458591011933f9b"
SPLIT=re.compile(r"[^\s=:,]+")
MAX_TOKENS=200
MAX_WILDCARDS=20
MAX_PATHS=5000


def match_tokenized_template(
    template:str,
    raw:str,
    body:str,
    start:int,
)->list[tuple[int,int]]|None:
    """Source-byte-coordinate alignment using LogPai Spell token convention.

    Conservative no-overlap/ambiguous abstention; no arbitrary regex execute.
    This intentionally preserves the weaknesses of Spell token granularity
    as evidence, rather than heuristically fixing them using holdout gold.
    """
    rule=template.split()
    tokens=[(m.group(),m.start(),m.end()) for m in SPLIT.finditer(body)]
    if (not rule or len(rule)>MAX_TOKENS or len(tokens)>MAX_TOKENS
        or rule.count("<*>")>MAX_WILDCARDS
        or any(x==y=="<*>" for x,y in zip(rule,rule[1:]))):
        return None
    const=sum(x!="<*>" for x in rule)
    if const<1 or const/len(rule)<0.33:
        return None
    possibilities=[]
    attempts=0

    def recur(i:int,j:int,spans:list[tuple[int,int]])->None:
        nonlocal attempts
        if len(possibilities)>1 or attempts>MAX_PATHS:
            return
        if i==len(rule):
            if j==len(tokens):
                possibilities.append(spans)
            return
        if rule[i]!="<*>":
            if j<len(tokens) and tokens[j][0]==rule[i]:
                recur(i+1,j+1,spans)
            return
        for end in range(j,min(len(tokens),j+8)+1):
            attempts+=1
            if end==j:
                recur(i+1,end,spans)
            else:
                a,b=tokens[j][1],tokens[end-1][2]
                raw_a=len(raw[:start+a].encode("utf8"))
                raw_b=len(raw[:start+b].encode("utf8"))
                recur(i+1,end,spans+[(raw_a,raw_b)])
            if len(possibilities)>1 or attempts>MAX_PATHS:
                break
    recur(0,0,[])
    if attempts>MAX_PATHS or len(possibilities)!=1:
        return None
    return possibilities[0]


def evaluate()->dict:
    """Independent label CSVs are opened ONLY after train parsing completes."""
    try:
        from logparser.Spell import Spell
    except ImportError as exc:
        raise RuntimeError(
            "ISOLATED_LOGPARSER_SPELL_RESEARCH_DEPENDENCY_NOT_INSTALLED"
        ) from exc
    root=ROOT.parent/"logparser"
    import subprocess
    githead=subprocess.run(
        ["git","-C",str(root),"rev-parse","HEAD"],
        check=True,capture_output=True,text=True,
    ).stdout.strip()
    if githead!=SOURCE_COMMIT:
        raise ValueError("SPELL_UPSTREAM_SOURCE_COMMIT_CHANGED")
    path_in=CACHE/"input"
    path_out=CACHE/"output"
    path_in.mkdir(parents=True,exist_ok=True)
    path_out.mkdir(parents=True,exist_ok=True)
    results=[]
    total=Counter()
    measured=Counter()
    for family,rows in samples("source_message").items():
        train,holdout=train_holdout(rows)
        file=family.removesuffix(".log")+".train"
        (path_in/file).write_text(
            "\n".join(row.body for row in train)+"\n",encoding="utf8"
        )
        parser=Spell.LogParser(
            indir=str(path_in),outdir=str(path_out),
            log_format="<Content>",tau=0.5,keep_para=False,
        )
        parser.parse(file)
        with (path_out/(file+"_templates.csv")).open() as filehandle:
            templates=list(csv.DictReader(filehandle))
        qualified=[
            (row["EventTemplate"],int(row["Occurrences"]))
            for row in templates if int(row["Occurrences"])>=2
        ]
        # This is deliberately AFTER the above rule construction. There are
        # no labeled event templates in Spell's training file.
        references=reference_labels(family)
        counts=Counter()
        fields=Counter()
        for event in holdout:
            status,gold=oracle_spans(event.raw,*references[event.sha])
            if status!="VALID_REFERENCE":
                counts["invalid_gold"]+=1
                continue
            matches=[]
            for grammar,support in qualified:
                captured=match_tokenized_template(
                    grammar,event.raw,event.body,event.start
                )
                if captured is not None:
                    specificity=sum(x!="<*>" for x in grammar.split())
                    matches.append((specificity,support,grammar,captured))
            matches.sort(key=lambda x:(-x[0],-x[1],x[2]))
            if not matches:
                predicted=[]
                counts["abstained"]+=1
            elif len(matches)>1 and matches[0][0]==matches[1][0]:
                predicted=[]
                counts["ambiguous"]+=1
            else:
                predicted=matches[0][3]
                counts["routed"]+=1
            fields.update(score(gold,predicted))
            counts["holdout"]+=1
        total.update(counts)
        measured.update(fields)
        results.append({
            "family":family.removesuffix(".log"),
            "train":len(train),"holdout":counts["holdout"],
            "qualified_grammar_templates":len(qualified),
            "routed":counts["routed"],"ambiguous":counts["ambiguous"],
            "exact_reference_span_metrics":_metric(fields),
        })
    return {
        "contract":"parser-studio.poc.spell-reference-negative.v0.1",
        "algorithm":"LogPai Spell (Apache-2.0, isolated optional research)",
        "source_sha":SOURCE_COMMIT,
        "holdout_records":total["holdout"],
        "exact_variable_span":_metric(measured),
        "families":results,
        "adoption":"REJECTED_FOR_UNLABELED_SOURCE_VARIABLE_EXTRACTION",
        "reason":"Token normalization loses original delimiter boundaries and produces false template-variable captures",
        "not_a_semantic_dictionary_test":True,
        "native_or_stellar_verified":False,
    }


if __name__=="__main__":
    import json
    summary=evaluate()
    # Only aggregate metric counts are published; raw and learned templates
    # remain under .cache, not committed.
    path=ROOT.parent/"spell_comparison_result.json"
    path.write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("SPELL_RESEARCH_NEGATIVE",summary["holdout_records"],
          "REFERENCE_SPAN",summary["exact_variable_span"])
    for family in summary["families"]:
        print(family["family"],"train",family["train"],
              "holdout",family["holdout"],
              "routed",family["routed"],
              "exact",family["exact_reference_span_metrics"])
