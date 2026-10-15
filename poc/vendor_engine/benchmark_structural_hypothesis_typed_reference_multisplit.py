"""Independent multi-split validation for typed residual hypotheses.

Security-product-only PoC. The learner sees raw source structure and the current
baseline parser result only. Official Elastic expected outputs are evaluation
oracles and are never passed into hypothesis learning.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import (
    LOCAL_CACHE,
    POSTFREEZE,
    _events,
)
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    augment_residual_hypothesis,
    learn_typed_residual_hypotheses,
    parse_with_typed_residual_hypotheses,
)

OUT=Path(__file__).resolve().parent/"structural-hypothesis-typed-reference-multisplit-summary.json"

ISE_TIMESTAMP=re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"[ ]+(?P<day>\d{1,2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
)
SNORT_TIMESTAMP=re.compile(
    r"^(?P<month>\d{1,2})/(?P<day>\d{1,2})"
    r"(?:/(?P<year>\d{2,4}))?-"
    r"(?P<hour>\d{1,2}):(?P<minute>\d{2}):"
    r"(?P<second>\d{2}(?:\.\d+)?)"
)
SNORT_TIMESTAMP_MULTILINE=re.compile(SNORT_TIMESTAMP.pattern,re.MULTILINE)
MONTH_NUMBER={
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12,
}

ISE_EXPECTED={
    "test-pipeline-administrative-and-operational-audit.log":
        LOCAL_CACHE/"cisco_ise_administrative-and-operational-audit.log-expected.json",
    "test-pipeline-cise-alarm.log":
        LOCAL_CACHE/"cisco_ise_cise-alarm.log-expected.json",
    "test-pipeline-guest.log":
        LOCAL_CACHE/"cisco_ise_guest.log-expected.json",
    "test-pipeline-identity-stores-diagnostics.log":
        LOCAL_CACHE/"cisco_ise_identity-stores-diagnostics.log-expected.json",
}
ISE_EXPECTED_SHA={
    "test-pipeline-administrative-and-operational-audit.log":
        "82b9ec6813c716deb45ef87977095f00aac816ac",
    "test-pipeline-cise-alarm.log":
        "69067ea045c2f1db99674e77dd954796a78ea525",
    "test-pipeline-guest.log":
        "8f916a66302492099540b9e46f1632ec71ddbc37",
    "test-pipeline-identity-stores-diagnostics.log":
        "b73a87ef52faeb7e3bb3535db112081e0897b78a",
}
SNORT_EXPECTED={
    "snort_fast.log":LOCAL_CACHE/"snort_fast_expected.json",
    "snort_full.logical":LOCAL_CACHE/"snort_full_expected.json",
}
SNORT_EXPECTED_SHA={
    "snort_fast.log":"d0daa4817ee0d8b01ba2bd68c7ab67ab8e71a7d3",
    "snort_full.logical":"f1d170a48f4a8c33e73b130d5a2acf48e0dd0a4b",
}


def _snort_full_events()->list[str]:
    lines=(LOCAL_CACHE/"snort_full.log").read_text("utf8").splitlines(keepends=True)
    out:list[str]=[]
    current=""
    for line in lines:
        if line.startswith("[**]") and current:
            while current.endswith("\n\n"):
                current=current[:-1]
            out.append(current)
            current=line
        else:
            current+=line
    if current:
        while current.endswith("\n\n"):
            current=current[:-1]
        out.append(current)
    return out


def _streams()->list[dict[str,Any]]:
    rows=[]
    root=POSTFREEZE/"cisco_ise"
    for name,expected in ISE_EXPECTED.items():
        rows.append({
            "family":"cisco_ise",
            "category":"NAC_IDENTITY_SECURITY",
            "name":name,
            "kind":"SYSLOG_TIMESTAMP",
            "events":_events(root/name),
            "expected":expected,
        })
    rows.extend([
        {
            "family":"snort",
            "category":"IDS_IPS",
            "name":"snort_fast.log",
            "kind":"SNORT_DATE",
            "events":_events(LOCAL_CACHE/"snort_fast.log"),
            "expected":SNORT_EXPECTED["snort_fast.log"],
        },
        {
            "family":"snort",
            "category":"IDS_IPS",
            "name":"snort_full.logical",
            "kind":"SNORT_DATE",
            "events":_snort_full_events(),
            "expected":SNORT_EXPECTED["snort_full.logical"],
        },
    ])
    return rows


def _expected_by_original(path:Path)->dict[str,list[dict[str,Any]]]:
    payload=json.loads(path.read_text("utf8"))
    result:dict[str,list[dict[str,Any]]]=defaultdict(list)
    for doc in payload["expected"]:
        raw=doc.get("event",{}).get("original")
        if isinstance(raw,str):
            result[raw].append(doc)
    return result


def _source_match(raw:str,kind:str):
    return (ISE_TIMESTAMP if kind=="SYSLOG_TIMESTAMP" else SNORT_TIMESTAMP).match(raw)


def _source_field(raw:str,kind:str)->tuple[int,int,str]|None:
    match=_source_match(raw,kind)
    if match is None and kind=="SNORT_DATE":
        # Snort Full places the date on a later logical line.
        match=SNORT_TIMESTAMP_MULTILINE.search(raw)
    if match is None:
        return None
    if kind=="SYSLOG_TIMESTAMP":
        start=match.start("month")
    else:
        start=match.start()
    return start,match.end(),raw[start:match.end()]


def _timestamp_consistent(raw:str,kind:str,docs:list[dict[str,Any]])->bool:
    field=_source_field(raw,kind)
    if field is None or not docs:
        return False
    start,end,_value=field
    fragment=raw[start:end]
    match=(
        re.match(
            r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r"[ ]+(?P<day>\d{1,2}) (?P<hour>\d{2}):"
            r"(?P<minute>\d{2}):(?P<second>\d{2})",
            fragment,
        )
        if kind=="SYSLOG_TIMESTAMP"
        else SNORT_TIMESTAMP.match(fragment)
    )
    if match is None:
        return False
    month=MONTH_NUMBER[match.group("month")] if kind=="SYSLOG_TIMESTAMP" else int(match.group("month"))
    second_int,_,fraction=match.group("second").partition(".")
    for doc in docs:
        stamp=doc.get("@timestamp")
        if not isinstance(stamp,str):
            continue
        try:
            parsed=datetime.fromisoformat(stamp)
        except ValueError:
            continue
        if (
            parsed.month==month
            and parsed.day==int(match.group("day"))
            and parsed.hour==int(match.group("hour"))
            and parsed.minute==int(match.group("minute"))
            and parsed.second==int(second_int)
        ):
            if not fraction:
                return True
            if fraction[:3]==f"{parsed.microsecond:06d}"[:3]:
                return True
    return False


def _corrupt_typed_field(raw:str,kind:str)->list[str]:
    field=_source_field(raw,kind)
    if field is None:
        return []
    start,end,value=field
    mutations=[]
    if kind=="SYSLOG_TIMESTAMP":
        mutations.append(raw[:start]+"Xxx"+raw[start+3:])
        # Invalidate day while preserving width.
        day=value.find(" ")+1
        mutations.append(raw[:start+day]+"99"+raw[start+day+2:])
        colon=raw.find(":",start,end)
        if colon!=-1:
            mutations.append(raw[:colon]+raw[colon+1:])
    else:
        slash=raw.find("/",start,end)
        dash=raw.find("-",start,end)
        mutations.append(raw[:start]+"99"+raw[start+2:])
        if slash!=-1:
            mutations.append(raw[:slash]+raw[slash+1:])
        if dash!=-1:
            mutations.append(raw[:dash]+raw[dash+1:])
    midpoint=start+(end-start)//2
    mutations.append(raw[:midpoint]+"\x00"+raw[midpoint:])
    return list(dict.fromkeys(item for item in mutations if item!=raw))


def _evaluate_stream(stream:dict[str,Any],seed:str)->dict[str,Any]:
    train,holdout=_split_seed(stream["events"],seed)
    training_events=[parse_security_multipass(raw) for raw in train]
    hypotheses=learn_typed_residual_hypotheses(training_events)
    expected=_expected_by_original(stream["expected"])
    metrics=Counter()
    augmented_hashes=[]
    for raw in holdout:
        baseline=parse_security_multipass(raw)
        if baseline.status=="SOURCE_PARSED":
            metrics["baseline_complete"]+=1
            continue
        metrics["baseline_incomplete"]+=1
        candidate=parse_with_typed_residual_hypotheses(raw,baseline,hypotheses)
        augmented=augment_residual_hypothesis(baseline,candidate)
        if candidate is None or augmented is None:
            continue
        metrics["augmented_events"]+=1
        if augmented.status==baseline.status:
            metrics["completeness_preserved"]+=1
        if augmented.issues==baseline.issues:
            metrics["issues_preserved"]+=1
        augmented_hashes.append(hashlib.sha256(raw.encode("utf8")).hexdigest())

        official=_source_field(raw,stream["kind"])
        if official is None:
            metrics["missing_official_source_field"]+=1
            continue
        start,end,value=official
        expected_key=(
            len(raw[:start].encode("utf8")),
            len(raw[:end].encode("utf8")),
        )
        additions=[
            span for span in candidate.value_spans
            if (span.start_byte,span.end_byte)
            not in {(s.start_byte,s.end_byte) for s in baseline.value_spans}
        ]
        metrics["added_spans"]+=len(additions)
        raw_bytes=raw.encode("utf8")
        for span in additions:
            observed=raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if (span.start_byte,span.end_byte)==expected_key and observed==value:
                metrics["official_source_exact_span_value"]+=1
            else:
                metrics["unvalidated_spans"]+=1
        docs=expected.get(raw,[])
        if docs:
            metrics["events_with_expected_doc"]+=1
        if _timestamp_consistent(raw,stream["kind"],docs):
            metrics["expected_timestamp_consistent"]+=1
        elif docs:
            metrics["expected_timestamp_inconsistent"]+=1

        for mutated in _corrupt_typed_field(raw,stream["kind"]):
            metrics["mutation_attempts"]+=1
            mb=parse_security_multipass(mutated)
            mc=parse_with_typed_residual_hypotheses(mutated,mb,hypotheses)
            ma=augment_residual_hypothesis(mb,mc)
            if ma is not None:
                metrics["mutation_augmentations"]+=1

    metrics["independently_validated_spans"]=metrics["official_source_exact_span_value"]
    return {
        "family":stream["family"],
        "category":stream["category"],
        "stream":stream["name"],
        "kind":stream["kind"],
        "seed":seed,
        "train_events":len(train),
        "holdout_events":len(holdout),
        "hypotheses":{
            key:value.training_support for key,value in sorted(hypotheses.items())
        },
        "metrics":dict(metrics),
        "augmented_event_sha256":sorted(augmented_hashes),
    }


def run()->dict[str,Any]:
    streams=_streams()
    results=[
        _evaluate_stream(stream,seed)
        for stream in streams
        for seed in SEEDS
    ]
    aggregate=Counter()
    by_family:dict[str,Counter]=defaultdict(Counter)
    by_kind:dict[str,Counter]=defaultdict(Counter)
    unique=set()
    for row in results:
        aggregate.update(row["metrics"])
        by_family[row["family"]].update(row["metrics"])
        by_kind[row["kind"]].update(row["metrics"])
        unique.update(row["augmented_event_sha256"])

    result={
        "contract":"parser-studio.poc.typed-residual-security-reference-multisplit.v1",
        "scope":"SECURITY_PRODUCTS_TYPED_RESIDUAL_AUGMENTATION_ONLY",
        "source_engine_head":"4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "learner_vendor_identity_used":False,
        "learner_reference_values_used":False,
        "source_completeness_promotion_performed":False,
        "raw_values_published":False,
        "elastic_integrations_revision":"57ac255efb40d98151337b4ff11b9015679391ed",
        "elastic_default_cisco_ise_pipeline_blob_sha":"0674392df50caf70303f451935210ed0056f926c",
        "elastic_snort_plaintext_pipeline_blob_sha":"197aa96409995a42bba8f4c86ad1b01557724198",
        "expected_blob_shas":{
            **ISE_EXPECTED_SHA,
            **SNORT_EXPECTED_SHA,
        },
        "stream_count":len(streams),
        "split_count":len(SEEDS),
        "results":results,
        "aggregate_metrics":dict(aggregate),
        "by_family":{k:dict(v) for k,v in sorted(by_family.items())},
        "by_kind":{k:dict(v) for k,v in sorted(by_kind.items())},
        "unique_augmented_events":len(unique),
        "gates":{
            "all_added_spans_independently_validated":(
                aggregate["augmented_events"]>0
                and aggregate["missing_official_source_field"]==0
                and aggregate["augmented_events"]==aggregate["added_spans"]
                and aggregate["added_spans"]==aggregate["independently_validated_spans"]
                and aggregate["unvalidated_spans"]==0
            ),
            "all_expected_timestamps_consistent":(
                aggregate["augmented_events"]>0
                and aggregate["events_with_expected_doc"]==aggregate["augmented_events"]
                and aggregate["events_with_expected_doc"]==aggregate["expected_timestamp_consistent"]
                and aggregate["expected_timestamp_inconsistent"]==0
            ),
            "completeness_preserved":(
                aggregate["augmented_events"]>0
                and aggregate["augmented_events"]==aggregate["completeness_preserved"]
            ),
            "issues_preserved":(
                aggregate["augmented_events"]>0
                and aggregate["augmented_events"]==aggregate["issues_preserved"]
            ),
            "typed_field_corruption_fail_closed":(
                aggregate["mutation_attempts"]>0
                and aggregate["mutation_augmentations"]==0
            ),
        },
    }
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n","utf8")
    return result


if __name__=="__main__":
    print(json.dumps(run(),indent=2,sort_keys=True))
