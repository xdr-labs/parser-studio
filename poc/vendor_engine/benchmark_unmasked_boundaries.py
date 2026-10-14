"""Exact original-field regression benchmark on deliberately unmasked inputs.

Purpose-built fixtures are NOT independent vendor/generalization evidence.
Gold paths, values and UTF-8 spans are recorded while assembling each input,
without calling the parser. Baseline and candidate run in separate processes.
Only aggregate metrics and source-code/corpus hashes leave those processes.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE=Path(__file__).resolve().parent
REPO=HERE.parent.parent
BASELINE="24d232178a11b59db67afedd198374c5fdf702c8"
MODULES=("engine.py","source_parse.py","structured_source.py","residual_kv.py")


class SourceBuilder:
    def __init__(self,family:str):
        self.family=family
        self.raw=""
        self.fields={}
        self.spans=[]

    def text(self,value:str):
        self.raw+=value
        return self

    def value(self,path:str,value:str):
        start=len(self.raw.encode("utf8"))
        self.raw+=value
        self.spans.append([path,start,len(self.raw.encode("utf8"))])
        node=self.fields
        parts=path.split(".")
        for part in parts[:-1]:
            node=node.setdefault(part,{})
        node[parts[-1]]=value
        return self

    def record(self):
        return {"family":self.family,"raw":self.raw,
                "fields":self.fields,"spans":self.spans}


def records()->list[dict]:
    """All 84 inputs have literal visible values; none is redacted or masked."""
    out=[]
    for month in "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split():
        for priority in (False,True):
            b=SourceBuilder("calendar_envelope")
            if priority:
                b.text("<").value("syslog.pri","134").text(">")
            b.value("syslog.month",month).text(" ").value("syslog.day","14").text(" ")
            b.value("syslog.time","10:11:12").text(" ")
            b.value("syslog.host" if priority else "syslog.hostname","host-a").text(" ")
            b.value("syslog.tag" if priority else "syslog.app_tag","agent").text(": ")
            b.text("user=").value("body.user","alice").text(" action=").value("body.action","allow")
            out.append(b.record())
    for i in range(12):
        user=f"analyst{i}"
        status=str(400+i)
        for family in ("bare_url","path_suffix","quoted_prose","malformed_quote"):
            b=SourceBuilder(family).text("NOTICE ")
            if family=="bare_url":
                b.text(f"visit https://host.test/path?user={user}&action=deny&dst=edge ")
            elif family=="path_suffix":
                b.text(f"file /var/log/vendor.user={user} ")
            elif family=="quoted_prose":
                b.text(f'"example user={user} action=deny" ')
            b.text("status=").value("embedded_kv.status",status)
            b.text(" owner=").value("embedded_kv.owner",user)
            if family=="malformed_quote":
                b.text(f' message="truncated user={user} action=deny')
            out.append(b.record())
        b=SourceBuilder("owned_quoted_value").text('NOTICE message="')
        b.value("embedded_kv.message",f"example user=Zoë{i} action=deny").text('" status=')
        b.value("embedded_kv.status",status).text(" owner=").value("embedded_kv.owner",user)
        out.append(b.record())
    return out


# Trusted repository parser code receives only synthetic fixture data here.
# All scoring occurs in the child; stdout cannot contain raw records/values.
RUNNER=r'''
from collections import Counter
import json,sys
from source_parse import parse_source,assert_source_accounting
rows=json.load(sys.stdin)
totals=Counter()
families={}
for row in rows:
    out=parse_source(row["raw"])
    assert_source_accounting(out)
    gold=Counter(tuple(x) for x in row["spans"])
    actual=Counter((x.path,x.start_byte,x.end_byte) for x in out.value_spans)
    counts=Counter(events=1,gold_fields=sum(gold.values()),
                   TP=sum((gold&actual).values()),FP=sum((actual-gold).values()),
                   FN=sum((gold-actual).values()),
                   original_records_preserved=int(out.raw==row["raw"]),
                   exact_field_tree_events=int(out.vendor_fields==row["fields"]),
                   exact_field_and_span_events=int(out.vendor_fields==row["fields"] and gold==actual))
    totals.update(counts)
    families.setdefault(row["family"],Counter()).update(counts)
def metric(value):
    tp,fp,fn=(value[k] for k in ("TP","FP","FN"))
    return {**dict(value),"precision":round(tp/(tp+fp),6) if tp+fp else None,
            "recall":round(tp/(tp+fn),6) if tp+fn else None,
            "f1":round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None}
json.dump({"total":metric(totals),"families":{k:metric(v) for k,v in sorted(families.items())}},sys.stdout)
'''


def run_parser(directory:Path,rows:list[dict])->dict:
    completed=subprocess.run(
        [sys.executable,"-c",RUNNER],cwd=directory,
        env={**os.environ,"PYTHONPATH":str(directory)},
        input=json.dumps(rows,ensure_ascii=True),text=True,capture_output=True,
        check=True,timeout=30,
    )
    return json.loads(completed.stdout)


def evaluate()->dict:
    rows=records()
    if not re.fullmatch(r"[0-9a-f]{40}",BASELINE):
        raise ValueError("BASELINE_MUST_BE_AN_EXACT_COMMIT")
    with TemporaryDirectory(prefix="parser-boundary-baseline-") as tmp:
        baseline_dir=Path(tmp)
        for name in MODULES:
            content=subprocess.run(
                ["git","show",f"{BASELINE}:poc/vendor_engine/{name}"],cwd=REPO,
                check=True,capture_output=True,timeout=10,
            ).stdout
            (baseline_dir/name).write_bytes(content)
        old=run_parser(baseline_dir,rows)
    current=run_parser(HERE,rows)
    return {
        "contract":"parser-studio.poc.unmasked-boundary-regression-v0.1",
        "evidence_class":"SYNTHETIC_REGRESSION_NOT_REAL_VENDOR_HOLDOUT",
        "baseline_revision":BASELINE,
        "corpus_sha256":hashlib.sha256(json.dumps(rows,sort_keys=True,ensure_ascii=True).encode()).hexdigest(),
        "candidate_module_sha256":{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in MODULES},
        "all_events":len(rows),"unmasked_events":len(rows),
        "masked_events":0,"unassessed_events":0,"excluded_events":0,
        "expected_source_fields":sum(len(x["spans"]) for x in rows),
        "measurement":"Original field path + exact UTF-8 span TP/FP/FN; typed field tree equality checked separately",
        "baseline":old,"candidate":current,
        "no_training_or_reference_reuse":True,
        "dictionary_attempted":False,"native_verified":False,
        "limitations":[
            "Inputs deliberately cover reproduced bugs; improvements are not population accuracy or unseen-vendor generalization.",
            "This report does not replace or revise the frozen Mac/Hadoop negative benchmark.",
            "Unresolved prose and malformed tails stay in the original raw event, not invented fields.",
        ],
    }


if __name__=="__main__":
    result=evaluate()
    (HERE/"unmasked-boundary-summary.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("UNMASKED_REGRESSION",result["all_events"],"events",result["expected_source_fields"],"fields")
    print("BASELINE",result["baseline"]["total"])
    print("CANDIDATE",result["candidate"]["total"])
